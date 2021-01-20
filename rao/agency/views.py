# -*- coding: utf-8 -*-
# Stdlib imports
import datetime
import json
import logging

# Core Django imports
import re
from codicefiscale import codicefiscale
from django.conf import settings
from django.core import signing
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

# Imports from your apps
import agency
from rao.settings import BASE_URL
from .classes.choices import AlertType, StatusCode, PageRedirect
from .decorators import login_required, admin_required, operator_required, only_one_admin
from .forms import LoginForm, NewOperatorForm, NewIdentityForm, \
    ChangePasswordForm, SetupForm, RecoveryForm, ChangePinForm, NewOperatorPinForm, ChangePinFileForm, \
    NewIdentityPinForm, EmailSetupForm, CertSetupForm, ErrorSetupForm
from .utils.mail_utils import send_email
from .utils.utils import check_operator, display_alert, render_to_pdf, page_manager, is_admin, \
    capitalize_text, download_pdf, get_certificate, from_utc_to_local, set_client_ip, verify_cf
from .utils.utils_api import activate_op_api, update_cert
from .utils.utils_db import get_all_operator, get_attributes_RAO, update_password_operator, \
    search_filter, create_operator, get_all_idr, create_identity, get_operator_by_username, \
    create_identity_request, get_identification_report, get_verify_mail_by_token, send_recovery_link, \
    create_verify_mail_token, set_is_verified, get_idr_filter_operator, get_status_operator, \
    delete_identity_request, update_sign_field_operator, update_status_operator, update_emailrao, \
    update_is_activated_field_operator
from .utils.utils_setup import configuration_check, init_settings_rao, necessary_data_check, init_user
from .utils.utils_token import signed_token, create_token_file, delete_token_file

LOG = logging.getLogger(__name__)

'''AUTH'''


@only_one_admin
def logout_agency(request):
    """
    Logout Admin/Operatore RAO e delete dati di sessione.
    :param request: request
    """
    try:
        request.session["is_authenticated"] = False
        setup_ok = True if 'setup_ok' in request.session else False
        pin_changed_ok = True if 'pinChanged' in request.session else False
        password_changed_ok = True if 'passwordChanged' in request.session else False
        key_list = []
        for sesskey in request.session.keys():
            key_list.append(sesskey)

        for key in key_list:
            del request.session[key]
        if setup_ok:
            request.session['setup_ok_redirect'] = True
        elif pin_changed_ok:
            request.session['pin_changed_redirect'] = True
        elif password_changed_ok:
            request.session['password_changed_redirect'] = True
    except Exception as e:
        LOG.error("Errore in decorator login_required: " + str(e), extra=set_client_ip(request))
        HttpResponseRedirect(reverse('agency:login'))
    return HttpResponseRedirect(reverse('agency:login'))


def login(request):
    """
    Login Admin/Operatore RAO.
    :param request: request
    """
    try:
        if not configuration_check():
            return HttpResponseRedirect(reverse('agency:setup'))

        request.session["is_authenticated"] = False
        messages = []
        form = LoginForm()

        params = {
            'rao': get_attributes_RAO()
        }

        if request.method == 'POST':

            form = LoginForm(request.POST)
            username = re.sub(r"[\n\t\s]*", "", request.POST.get('usernameField').upper())
            password = request.POST.get('passwordField')

            if form.is_valid():
                error = "Username o password errati"
                if not username or not password:
                    error = "I campi username e password sono obbligatori"
                else:
                    result = check_operator(username, password, request)
                    if result in (StatusCode.OK.value, StatusCode.EXPIRED_TOKEN.value, StatusCode.FORBIDDEN.value):
                        request.session["username"] = username
                        params = {
                            'username': username,
                        }
                        if result == StatusCode.EXPIRED_TOKEN.value:
                            params['psw_expired'] = True
                            t = signing.dumps(params)
                            request.session['redirect'] = True
                            LOG.info("{} - Credenziali dell'utente scadute".format(username), extra=set_client_ip(request))
                            return HttpResponseRedirect(reverse('agency:change_password', kwargs={'t': t}))
                        else:
                            params['is_admin'] = is_admin(username)
                            t = signing.dumps(params)
                            request.session["is_authenticated"] = True
                            LOG.info("{} - Utente loggato".format(username), extra=set_client_ip(request))
                            return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t': t, 'page': 1}))
                    elif result == StatusCode.SIGN_NOT_AVAILABLE.value:
                        params = {
                            'username': username,
                        }
                        t = signing.dumps(params)
                        return HttpResponseRedirect(reverse('agency:change_pin', kwargs={'t': t}))
                    elif result == StatusCode.UNAUTHORIZED.value:
                        error = "Credenziali bloccate. Contattare l'amministratore per reimpostare la password " \
                                "attraverso l'invio di una nuova mail dalla sezione 'Lista Operatori' "
                        LOG.info("{} - Credenziali bloccate.".format(username), extra=set_client_ip(request))

                messages = display_alert(AlertType.DANGER, error)

        return render(request, settings.TEMPLATE_URL_AGENCY + 'login.html', {'form': form, 'params': params,
                                                                             'messages': messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO(),
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html', {"statusCode": StatusCode.EXC.value,
                                                                             'params': params,
                                                                             "message": "Errore durante la login"})


@only_one_admin
def recovery_password(request):
    """
        Recupero password.
        :param request: request
    """
    params = {
        'rao': get_attributes_RAO()
    }
    try:

        messages = None
        form = RecoveryForm()
        success = False
        if request.method == 'POST':
            form = RecoveryForm(request.POST)
            username = re.sub(r"[\n\t\s]*", "", request.POST.get('usernameField').upper())
            if form.is_valid():
                operator = get_operator_by_username(username)
                if operator.status:
                    result = send_recovery_link(username, PageRedirect.CHANGE_PSW.value)
                else:
                    result = StatusCode.ERROR.value

                if result == StatusCode.OK.value:
                    LOG.info("{} - Mail per cambio password inviata".format(username), extra=set_client_ip(request))
                    messages = display_alert(AlertType.SUCCESS,
                                             "È stata inviata una mail di verifica all'indirizzo mail fornito!")
                    success = True
                elif result == StatusCode.NOT_FOUND.value:
                    messages = display_alert(AlertType.DANGER, "Utente non presente sul sistema.")
                    LOG.warning("{} - Utente non trovato".format(username), extra=set_client_ip(request))
                elif result == StatusCode.ERROR.value:
                    messages = display_alert(AlertType.DANGER, "Credenziali bloccate. Contattare l'amministratore per "
                                                               "reimpostare la password attraverso l'invio di una nuova "
                                                               "mail dalla sezione 'Lista Operatori' ")
                    LOG.warning("{} - Utente disabilitato".format(username), extra=set_client_ip(request))
                else:
                    messages = display_alert(AlertType.DANGER, "Si è verificato un errore!")
                    LOG.error("{} - Errore durante il recupero password utente".format(username), extra=set_client_ip(request))

        return render(request, settings.TEMPLATE_URL_AGENCY + 'recovery_password.html', {'success': success,
                                                                                         'form': form,
                                                                                         'params': params,
                                                                                         'messages': messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html', {"statusCode": StatusCode.EXC.value,
                                                                             'params': params,
                                                                             "message": "Errore durante la login"})


'''VIEW ADMIN'''


@only_one_admin
@login_required
@admin_required
def list_operator(request, page, t):
    """
    Lista operatori.
    :param request: request
    :param page: num. di pagina corrente
    :param t: token
    """

    params = {
        'rao': get_attributes_RAO(),
        'is_admin': is_admin(request.session['username']),
        'active_operator': get_operator_by_username(request.session['username'])
    }
    try:
        if 'operator_filter' in request.session:
            pages = page_manager(page, search_filter(request.session['operator_filter'], 'op'))
        else:
            pages = page_manager(page, get_all_operator())

        params['page'] = int(page)
        if request.method == 'POST':
            if 'autocomplete-id' in request.POST:
                request.session['operator_filter'] = request.POST.get('autocomplete-id')
                pages = page_manager(page, search_filter(request.session['operator_filter'], 'op'))

        params['operators'] = pages['entries']
        params['next_page'] = pages['next']
        params['previous_page'] = pages['previous']
        return render(request, settings.TEMPLATE_URL_AGENCY + 'list_operator.html', {'params': params, 'token': t})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante il caricamento della lista"})


@only_one_admin
@login_required
@admin_required
def add_operator(request, t):
    """
    Aggiunta un nuovo operatore.
    :param request: request
    :param t: token
    """
    try:
        messages = None
        admin = get_operator_by_username(request.session['username'])
        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(request.session['username']),
            'active_operator': admin
        }
        form = ()
        if request.method == 'POST':
            if 'add_operator' not in request.POST:
                form = NewOperatorForm(request.POST)
            else:
                form = NewOperatorPinForm(request.POST)

            if form.is_valid():
                params['operator'] = re.sub(r"[\n\t\s]*", "", request.POST.get('fiscalNumber').upper())

                if 'add_operator' not in request.POST:
                    return render(request, settings.TEMPLATE_URL_AGENCY + 'add_operator.html',
                                  {'params': params, 'token': t, 'form': form})
                elif admin and not admin.signStatus:
                    return HttpResponseRedirect(reverse('agency:logout_agency'))
                else:
                    result, pin = create_operator(request.session['username'], request.POST)
                    if result == StatusCode.OK.value:
                        params = {
                            'username': request.session['username'],
                            'operator': request.POST.get('fiscalNumber').upper(),
                            'is_admin': is_admin(request.session['username']),
                            'timestamp': datetime.datetime.strftime(datetime.datetime.utcnow(), '%Y-%m-%d %H:%M')
                        }
                        request.session['pin'] = pin
                        t = signing.dumps(params)
                        LOG.info("admin: {}, operator: {} - Operatore creato con successo".format(
                            request.session['username'], request.POST.get('fiscalNumber').upper()),
                            extra=set_client_ip(request))
                        return HttpResponseRedirect(reverse('agency:list_operator', kwargs={'t': t, 'page': 1}))
                    elif result == StatusCode.ERROR.value:
                        messages = display_alert(AlertType.DANGER,
                                                 "Si è verificato un problema durante l'inserimento del nuovo operatore."
                                                 " Controlla che non esista un operatore con gli stessi dati!")
                    else:
                        messages = display_alert(AlertType.DANGER,
                                                 "Si è verificato un problema durante l'inserimento del nuovo operatore."
                                                 " Invio della mail non riuscito!")

        return render(request, settings.TEMPLATE_URL_AGENCY + 'add_operator.html',
                      {'params': params, 'token': t, 'form': form, 'messages': messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(request.session['username']),
            'active_operator': get_operator_by_username(request.session['username'])
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante l'inserimento nuovo operatore"})


@only_one_admin
@login_required
@admin_required
def dashboard(request, t):
    """
    Dashboard.
    :param request: request
    :param t: token
    """
    params = {
        'rao': get_attributes_RAO(),
        'active_operator': get_operator_by_username(request.session['username'])
    }
    try:
        params['reports'] = get_identification_report()
        params['is_admin'] = is_admin(request.session['username'])
        return render(request, settings.TEMPLATE_URL_AGENCY + 'dashboard.html', {'params': params, 'token': t})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))

        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante il caricamento dei dati"})


'''VIEW OPERATORE'''


@only_one_admin
@login_required
def list_identity(request, page, t):
    """
    Lista delle pratiche lavorate.
    :param request: request
    :param page: num. di pagina corrente
    :param t: token
    """

    params = {
        'rao': get_attributes_RAO(),
        'is_admin': is_admin(request.session['username']),
        'active_operator': get_operator_by_username(request.session['username'])
    }
    try:
        messages = None
        request.session['identified'] = False
        if 'identity_filter' in request.session:
            if not is_admin(request.session['username']):
                pages = page_manager(page, search_filter(request.session['identity_filter'], 'id',
                                                         get_operator_by_username(request.session['username'])))
            else:
                pages = page_manager(page, search_filter(request.session['identity_filter'], 'id'))
        else:
            if not is_admin(request.session['username']):
                pages = page_manager(page,
                                     get_idr_filter_operator(get_operator_by_username(request.session['username'])))
            else:
                pages = page_manager(page, get_all_idr())

        params['page'] = int(page)
        if request.method == 'POST':
            if 'autocomplete-id' in request.POST:
                request.session['identity_filter'] = request.POST.get('autocomplete-id')
                pages = page_manager(page, search_filter(request.session['identity_filter'], 'id'))

        params['list_identity'] = pages['entries']
        params['next_page'] = pages['next']
        params['previous_page'] = pages['previous']
        return render(request, settings.TEMPLATE_URL_AGENCY + 'list_identity.html',
                      {"params": params, "token": t, "messages": messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante il caricamento della lista"})


@only_one_admin
@login_required
@operator_required
def add_identity(request, t):
    """
    Aggiunta nuova identità.
    :param request: request
    :param t: token
    """
    try:
        active_operator = get_operator_by_username(request.session['username'])
        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(request.session['username']),
            'active_operator': active_operator
        }
        messages = None
        form = NewIdentityForm()
        if request.method == 'POST':
            if 'identifica' not in request.POST:
                form = NewIdentityForm(request.POST)
            else:
                form = NewIdentityPinForm(request.POST)

            if form.is_valid():
                if request.session['identified'] is True and \
                        request.session['last_cf'] == request.POST.get('fiscalNumber').upper():
                    return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t': t, 'page': 1}))
                else:
                    request.session['identified'] = False
                    ud = create_identity(request, active_operator.id)
                    if ud:
                        params = {
                            'username': request.session['username'],
                            'user_detail': ud,
                            'is_admin': is_admin(request.session['username']),
                        }
                        if 'identifica' not in request.POST:
                            verify_cf_dic = verify_cf(request)

                            params['active_operator'] = active_operator

                            params['verify_cf_dic'] = verify_cf_dic

                            return render(request, settings.TEMPLATE_URL_AGENCY + 'add_identity.html',
                                          {'params': params, 'token': t, 'form': form})
                        else:
                            params['user_detail'] = json.dumps(ud.to_json())
                            params['pin'] = request.POST.get('pinField')
                            t = signing.dumps(params)
                            request.session['last_cf'] = ud.fiscalNumber
                            LOG.info("operator: {}, {} - Step1 identificazione OK - Form compilato".format(
                                request.session['username'], ud.fiscalNumber), extra=set_client_ip(request))
                            return HttpResponseRedirect(reverse('agency:summary_identity', kwargs={'t': t}))
                    else:
                        messages = display_alert(AlertType.DANGER, "Errore durante inserimento richiesta")
            else:
                params = {
                    'username': request.session['username'],
                    'request': request,
                    'rao': get_attributes_RAO(),
                    'is_admin': is_admin(request.session['username']),
                    'active_operator': active_operator
                }
                messages = display_alert(AlertType.DANGER, "Campi della form vuoti o non validi")
                LOG.warning("{} - Campi della form vuoti o non validi".format(
                    request.session['username']), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'add_identity.html',
                      {'params': params, 'token': t, 'form': form, 'messages': messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO(),
            'active_operator': get_operator_by_username(request.session['username']),
            'is_admin': is_admin(request.session['username']),
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value,
                       'params': params, "message": "Errore durante l'inserimento della nuova identità"})


@only_one_admin
@login_required
@operator_required
def summary_identity(request, t):
    """
    Pagina di conferma creazione richiesta di identificazione.
    :param request: request
    :param t: token
    """

    id_request = None
    try:
        params = signing.loads(t)
        operator = get_operator_by_username(request.session['username'])

        if not operator.signStatus:
            LOG.info(
                "operator: {}, - Il PIN è bloccato. Impossibile generare la richiesta di identificazione.".format(
                    request.session['username']), extra=set_client_ip(request))
            return HttpResponseRedirect(reverse('agency:logout_agency'))

        if request.session['identified']:
            messages = display_alert(AlertType.DANGER, "Identificazione già effettuata")
        else:
            if 'user_detail' in params:
                identity = json.loads(json.loads(params['user_detail']))
                identity['dateOfBirth'] = datetime.datetime.strptime(identity['dateOfBirth'], '%d/%m/%Y')
                identity['idCardIssueDate'] = datetime.datetime.strptime(identity['idCardIssueDate'], '%d/%m/%Y')
                identity['idCardExpirationDate'] = datetime.datetime.strptime(identity['idCardExpirationDate'],
                                                                              '%d/%m/%Y')
                identity['identificationExpirationDate'] = datetime.datetime.strptime(
                    identity['identificationExpirationDate'], '%d/%m/%Y')
                id_request = create_identity_request(request, identity)
                pin = params['pin']
                dict_token = signed_token(identity, request.session['username'], pin)

                if not id_request or dict_token['statusCode'] is not StatusCode.OK.value:
                    if id_request:
                        delete_identity_request(id_request)

                    LOG.warning("operator: {}, {} - Step2 identificazione KO - Token non creato".format(
                        request.session['username'],identity['fiscalNumber']), extra=set_client_ip(request))
                    if dict_token['statusCode'] == StatusCode.UNAUTHORIZED.value:
                        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                                      {"statusCode": StatusCode.UNAUTHORIZED.value,
                                       "message": "Il pin inserito non è corretto."})
                    elif dict_token['statusCode'] == StatusCode.SIGN_NOT_AVAILABLE.value:
                        update_sign_field_operator(request.session['username'], False)
                        return HttpResponseRedirect(reverse('agency:logout_agency'))
                    else:
                        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                                      {"statusCode": StatusCode.ERROR.value,
                                       "message": "Errore durante la creazione del token"})
                params = {
                    'username': request.session['username'],
                    'fiscalNumber': identity['fiscalNumber'],
                    'passphrase1': dict_token['passphrase'][0:6],
                    'passphrase2': dict_token['passphrase'][6:12],
                    'is_admin': is_admin(request.session['username']),
                    'id': str(id_request.uuid_identity),
                    'pdf_object': 'SPID - Identificazione presso Sportello Pubblico',
                    'name_user': identity['name'],
                    'surname_user': identity['familyName'],
                    'timestamp': datetime.datetime.strftime(id_request.timestamp_identification, '%Y-%m-%d %H:%M')
                }

                t = signing.dumps(params)
                params['identity'] = identity
                params['rao'] = get_attributes_RAO()
                params['active_operator'] = get_operator_by_username(request.session['username'])
                timestamp = from_utc_to_local(id_request.timestamp_identification)

                mail_elements = {
                    'base_url': BASE_URL,
                    'rao_name': get_attributes_RAO().name,
                    'name_user': identity['name'],
                    'surname_user': identity['familyName'],
                    'date': timestamp.strftime('%d/%m/%Y'),
                    'time': timestamp.strftime('%H:%M')
                }
                messages = display_alert(AlertType.SUCCESS, "Identificazione avvenuta con successo!")
                request.session['identified'] = True

                email_status_code = send_email([identity['email']], "SPID - Identificazione presso Sportello Pubblico",
                                               settings.TEMPLATE_URL_MAIL + 'mail_passphrase.html',
                                               {'passphrase2': dict_token['passphrase'][6:12],
                                                'mail_elements': mail_elements},
                                               create_token_file(dict_token,
                                                                 str(id_request.uuid_identity) + "_tuo_token.txt"))

                if email_status_code == StatusCode.OK.value:
                    delete_token_file(str(id_request.uuid_identity) + "_tuo_token.txt")
                    LOG.info("operator: {}, {} - Step2 identificazione OK - Token creato".format(
                        request.session['username'], identity['fiscalNumber']), extra=set_client_ip(request))
                else:
                    if id_request:
                        delete_identity_request(id_request)
                    LOG.warning("operator: {}, {} - Step2 identificazione - Invio mail non riuscita".format(
                        request.session['username'],identity['fiscalNumber']), extra=set_client_ip(request))
                    return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                                  {"statusCode": StatusCode.ERROR.value,
                                   "message": "Errore durante l'invio della mail"})
            else:
                return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t': t, 'page': 1}))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'summary_identity.html',
                      {'params': params, 'token': t, 'messages': messages})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(request.session['username']),
            'active_operator': get_operator_by_username(request.session['username'])
        }
        if id_request:
            delete_identity_request(id_request)
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value,
                       'params': params, "message": "Errore durante il riepilogo dell'identificazione"})


@only_one_admin
@login_required
@operator_required
def pdf_view(request, t):
    """
    Apertura pdf passphrase.
    :param request: request
    :param t: token
    """
    try:
        params = signing.loads(t)
        if 'passphrase1' in params:
            settings_rao = get_attributes_RAO()
            name = settings_rao.name
            op = get_operator_by_username(request.session['username'])

            if 'timestamp' in params:
                date = datetime.datetime.strptime(params['timestamp'], '%Y-%m-%d %H:%M') + datetime.timedelta(days=30)
                token_expiration_date = date.strftime('%d/%m/%Y %H:%M')
            else:
                token_expiration_date = None

            return render_to_pdf(
                settings.TEMPLATE_URL_PDF + 'pdf_template.html',
                {
                    'pagesize': 'A4',
                    'passphrase': params['passphrase1'],
                    'RAO_name': name,
                    'operator': op,
                    'name_user': params['name_user'] if 'name_user' in params else None,
                    'surname_user': params['surname_user'] if 'surname_user' in params else None,
                    'pdf_object': params['pdf_object'] if 'pdf_object' in params else None,
                    'token_expiration_date': token_expiration_date
                })

        LOG.error("{} - Errore nella visualizzazione del pdf di: {} ".format(request.session['username'],
                                                                             params['fiscalNumber']),
                  extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'apertura del pdf"})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'apertura del pdf"})


@only_one_admin
@login_required
def pdf_download(request, t):
    """
    Download pdf passphrase/pin temporaneo operatore
    :param request: request
    :param t: token
    """
    try:
        params = signing.loads(t)
        if 'passphrase1' in params:
            return download_pdf(params, params['passphrase1'])
        elif 'pin' in request.session and request.session['pin']:
            pin = request.session['pin']
            del request.session['pin']
            return download_pdf(params, None, pin)

        LOG.error("Errore durante l'apertura del pdf.", extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'apertura del pdf"})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'apertura del pdf"})


'''GESTIONE CREDENZIALI'''


@only_one_admin
def change_pin(request, t):
    """
    Cambio pin operatore.
    :param request: request
    :param t: token
    """

    try:
        params_t = signing.loads(t)
        username = params_t['username']
        if 'alert_type' in params_t and 'alert_message' in params_t:
            messages = display_alert(AlertType.DANGER, params_t.pop('alert_message')) if params_t.pop('alert_type') == 'danger' \
                else display_alert(AlertType.SUCCESS, params_t.pop('alert_message'))

        else:
            messages = []

        error_form = None
        error = "Si è verificato un problema con l'aggiornamento, riprova inserendo i dati corretti."
        if get_operator_by_username(username).signStatus:
            LOG.warning("{} - Accesso negato.".format(username), extra=set_client_ip(request))
            return HttpResponseRedirect(reverse('agency:logout_agency'))

        if is_admin(username):
            form = ChangePinFileForm()
        else:
            form = ChangePinForm()

        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(username)
        }
        if request.method == 'POST':
            if is_admin(username):
                form = ChangePinFileForm(request.POST, request.FILES)
            else:
                form = ChangePinForm(request.POST)

            if form.is_valid():
                old_pin = int(request.POST.get('oldPinField'))
                new_pin = int(request.POST.get('newPinField'))
                if is_admin(username):
                    certificate = get_certificate(request.FILES['uploadPrivateKey']) + "\n" + get_certificate(request.FILES['uploadCertificate'])
                    status_code_activate = activate_op_api(username, old_pin, new_pin, certificate)
                else:
                    status_code_activate = activate_op_api(username, old_pin, new_pin)

                if status_code_activate == StatusCode.OK.value:
                    update_sign_field_operator(username)
                    update_is_activated_field_operator(username)
                    if is_admin(username):
                        request.session['setup_ok'] = True
                    else:
                        request.session['pinChanged'] = True
                    if 'passwordChanged' in request.session:
                        del request.session['passwordChanged']
                    LOG.info("{} - PIN modificato.".format(username), extra=set_client_ip(request))
                    return HttpResponseRedirect(reverse('agency:logout_agency'))
                elif status_code_activate == StatusCode.ERROR.value:
                    if is_admin(username):
                        error_form = ErrorSetupForm()
                        messages = display_alert(AlertType.DANGER, error, "Verifica dati inseriti",
                                                 "$('#modal').modal('show');")
                        params['fiscalNumber'] = username
                        params['issuerCode'] = get_attributes_RAO().issuerCode
                    else:
                        messages = display_alert(AlertType.DANGER, error)
            if messages.__len__() == 0:
                messages = display_alert(AlertType.DANGER, error)

        return render(request, settings.TEMPLATE_URL_AGENCY + 'change_pin.html',
                      {'form': form, 'error_form': error_form, 'params': params, 'messages': messages, 'token': t})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO()
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante il cambio pin"})


@only_one_admin
def change_password(request, t):
    """
    Cambio password operatore.
    :param request: request
    :param t: token
    """
    try:
        if not 'redirect' in request.session:
            return HttpResponseRedirect(reverse('agency:redirect', kwargs={'t': t}))

        params_t = signing.loads(t)
        username = params_t['username']
        messages = []
        form = ChangePasswordForm()
        params = {
            'rao': get_attributes_RAO(),
            'first_pass': get_status_operator(username)
        }
        if request.method == 'POST':
            form = ChangePasswordForm(request.POST)
            password = request.POST.get('passwordField')
            if form.is_valid():
                if 'is_admin' in params_t and not configuration_check():
                    request.session['nameField'] = params_t['name']
                    request.session['surnameField'] = params_t['familyName']
                    request.session['usernameField'] = username
                    request.session['passwordField'] = password
                    request.session['emailField'] = params_t['email']
                    request.session['activation_token'] = t
                    request.session['initial_setup'] = True

                    params = {
                        'rao': get_attributes_RAO(),
                        'init_setup': True,
                    }
                    if necessary_data_check():
                        init_user(request)
                        update_status_operator(username, True)
                        LOG.info("{} - Cambio password avvenuto.".format(username), extra=set_client_ip(request))
                        return HttpResponseRedirect(reverse('agency:change_pin', kwargs={'t': t}))
                    return render(request, settings.TEMPLATE_URL_AGENCY + 'change_password.html',
                                  {'params': params, 'messages': messages, 'token': t})
                elif 'is_admin' not in params_t:
                    operator = get_operator_by_username(username)
                    result = update_password_operator(username, password, operator.status, request)
                    if result == StatusCode.OK.value:
                        if 'psw_expired' not in params_t:
                            set_is_verified(t)
                        request.session['passwordChanged'] = True
                        LOG.info("{} - Cambio password avvenuto.".format(username), extra=set_client_ip(request))
                        if not operator.isActivated:
                            return HttpResponseRedirect(reverse('agency:change_pin', kwargs={'t': t}))
                        return HttpResponseRedirect(reverse('agency:logout_agency'))
                    elif result == StatusCode.LAST_PWD.value:
                        LOG.warning("{} - Nuova password uguale alla precedente.".format(username), extra=set_client_ip(request))
                        messages = display_alert(AlertType.DANGER,
                                                 "La nuova password inserita corrisponde a quella precendente!")
                    else:
                        error = "Si è verificato un problema con l'aggiornamento della password, riprova."
                        messages = display_alert(AlertType.DANGER, error)
                elif 'is_admin' in params_t and configuration_check():
                    update_status_operator(username, True)
                    LOG.info("{} - Cambio password avvenuto.".format(username), extra=set_client_ip(request))
                    return HttpResponseRedirect(reverse('agency:change_pin', kwargs={'t': t}))
                else:
                    return HttpResponseRedirect(reverse('agency:logout_agency'))
            else:
                LOG.warning("{} - Password non valida.".format(username), extra=set_client_ip(request))
                error = "Si è verificato un problema con l'aggiornamento della password, riprova."
                messages = display_alert(AlertType.DANGER, error)


        return render(request, settings.TEMPLATE_URL_AGENCY + 'change_password.html',
                      {'form': form, 'params': params, 'messages': messages, 'token': t})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO()
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params,
                       "message": "Errore durante il cambio password"})


@only_one_admin
@login_required
@admin_required
def admin_setup(request, t):
    """
    Pagina impostazioni per l'aggiornamento del certificato/config. SMTP
    :param request: request
    :param t: token
    """
    try:
        form_email = EmailSetupForm()
        form_cert = CertSetupForm()
        messages = None
        active_operator = get_operator_by_username(request.session['username'])
        params = {
            'rao': get_attributes_RAO(),
            'is_admin': is_admin(request.session['username']),
            'active_operator': active_operator
        }

        request.session["is_authenticated"] = True
        if request.POST:
            if 'update_cert' in request.POST:
                form_cert = CertSetupForm(request.POST, request.FILES)
                if form_cert.is_valid():
                    certificate = get_certificate(request.FILES['uploadPrivateKey']) + "\n" + get_certificate(request.FILES['uploadCertificate'])
                    status_code = update_cert(request.POST['pinField'], request.session['username'], certificate)
                    if status_code != StatusCode.OK.value:
                        messages = display_alert(AlertType.DANGER,
                                                 "Si è verificato un errore durante l'aggiornamento dei dati.")
                        return render(request, settings.TEMPLATE_URL_AGENCY + 'setup.html',
                                      {'form_email': form_email, 'messages': messages, 'params': params, 'token': t})

                    return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t': t, 'page': 1}))
            else:

                form_email = EmailSetupForm(request.POST)

                if form_email.is_valid():
                    rao_email = form_email.cleaned_data['emailRAOField']
                    rao_host = form_email.cleaned_data['hostField']
                    rao_pwd = form_email.cleaned_data['pwdRAOField']
                    rao_email_crypto_type = form_email.cleaned_data['cryptoMailField']
                    rao_email_port = form_email.cleaned_data['emailPortField']
                    smtp_mail_from_field = form_email.cleaned_data['smtpMailFromField']
                    is_updated = update_emailrao(active_operator, get_attributes_RAO().name, rao_email, rao_host, rao_pwd,
                                                 rao_email_crypto_type, rao_email_port, smtp_mail_from_field)
                    if not is_updated:
                        LOG.warning("{}, {} - Configurazione SMTP non riuscita.".format(agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                                                                        request.session['username']), extra=set_client_ip(request))
                        messages = display_alert(AlertType.DANGER,
                                                 "Si è verificato un errore durante l'aggiornamento dei dati.")
                        return render(request, settings.TEMPLATE_URL_AGENCY + 'setup.html',
                                      {'form_email': form_email, 'messages': messages, 'params': params, 'token': t})
                    LOG.info("{}, {} - Configurazione SMTP modificata.".format(agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                                                               request.session['username']), extra=set_client_ip(request))
                    return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t': t, 'page': 1}))

        return render(request, settings.TEMPLATE_URL_AGENCY + 'setup.html',
                      {'form_email': form_email, 'form_cert': form_cert, 'messages': messages, 'params': params,
                       'token': t})

    except Exception as e:
        LOG.error("{}, {} - Exception: {}".format(agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                                  request.session['username'],str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'aggiornamento dei dati"})


def initial_setup(request):
    """
    Setup iniziale
    :param request: request
    """
    try:
        messages = None
        if not configuration_check():
            form = SetupForm(initial=settings.TEST_FORMSETUP_DATA if hasattr(settings, 'TEST_FORMSETUP_DATA') else {})

            if request.POST:
                form = SetupForm(request.POST)

                if form.is_valid():
                    if 'rao_email' in request.session and \
                            request.session['rao_email'] == form.cleaned_data['emailRAOField']:

                        messages = display_alert(AlertType.DANGER, "Email già inviata")
                    else:
                        name = capitalize_text(form.cleaned_data['nameField'])
                        surname = capitalize_text(form.cleaned_data['surnameField'])
                        email = form.cleaned_data['usernameField']
                        username = form.cleaned_data['fiscalNumberField'].upper()
                        issuer_code = re.sub(r"[\n\t\s]*", "", form.cleaned_data['issuerCodeField'])
                        rao_name = form.cleaned_data['nameRAOField']
                        rao_email = form.cleaned_data['emailRAOField']
                        rao_host = form.cleaned_data['hostField']
                        rao_pwd = form.cleaned_data['pwdRAOField']
                        rao_email_crypto_type = form.cleaned_data['cryptoMailField']
                        rao_email_port = form.cleaned_data['emailPortField']
                        smtp_mail_from_field = form.cleaned_data['smtpMailFromField']
                        init_settings_rao(rao_name, issuer_code, rao_email, rao_host, rao_pwd, rao_email_crypto_type,
                                          rao_email_port, smtp_mail_from_field)

                        params = {
                            'is_admin': True,
                            'username': username,
                            'name': name,
                            'familyName': surname,
                            'email': email,
                        }

                        t = signing.dumps(params)

                        mail_elements = {
                            'base_url': BASE_URL,
                            'nameUser': name,
                            'familyNameUser': surname,
                            'rao_name': rao_name,
                            'is_admin': True
                        }

                        try:
                            mail_sent = send_email([email], "Attivazione ADMIN R.A.O.",
                                                   settings.TEMPLATE_URL_MAIL + 'mail_activation.html',
                                                   {'activation_link': BASE_URL + str(
                                                       reverse('agency:redirect', kwargs={'t': t}))[1:],
                                                    'mail_elements': mail_elements
                                                    })
                            if mail_sent == StatusCode.OK.value:
                                request.session['rao_email'] = rao_email
                                create_verify_mail_token(email, t)
                                messages = display_alert(AlertType.SUCCESS,
                                                         "È stata appena inviata una mail di verifica "
                                                         "all'indirizzo indicato. Puoi chiudere questa finestra e "
                                                         "proseguire con le istruzioni che troverai nella email inviata.")
                                LOG.info("IPA: {}, {} - Form compilato con successo.".format(issuer_code,username),
                                         extra=set_client_ip(request))
                            else:
                                LOG.warning("{} - Configurazione SMTP errata.".format(username),
                                            extra=set_client_ip(request))
                                messages = display_alert(AlertType.DANGER,
                                                         "Si è verificato un errore durante l'invio della mail "
                                                         "di verifica, controlla che la configurazione SMTP "
                                                         "sia corretta.")
                        except Exception as e:
                            LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
                            messages = display_alert(AlertType.DANGER,
                                                     "Si è verificato un errore durante l'invio della mail di verifica,"
                                                     " controlla che la configurazione SMTP sia corretta.")
                else:
                    LOG.warning("Errore nella compilazione del form",extra=set_client_ip(request))
            return render(request, settings.TEMPLATE_URL_AGENCY + 'init_setup.html',
                          {'form': form, 'messages': messages})
        else:
            return HttpResponseRedirect(reverse('agency:login'))
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante l'installazione"})


@only_one_admin
def redirect_page(request, t):
    """
    Verifica token per reindirizzare su change_password o change pin
    :param request: request
    :param t: token
    """
    try:

        params_t = signing.loads(t)
        if 'psw_expired' in params_t:
            result = StatusCode.OK.value
        else:
            vm = get_verify_mail_by_token(t)
            result = vm.isValid(token=t)

        if result == StatusCode.OK.value:
            request.session['redirect'] = True

            LOG.info("{} - Link verificato.".format(params_t['username']),
                     extra=set_client_ip(request))

            if 'change_pin' in params_t:
                return HttpResponseRedirect(reverse('agency:change_pin', kwargs={'t': t}))
            else:
                return HttpResponseRedirect(reverse('agency:change_password', kwargs={'t': t}))
        elif result == StatusCode.EXPIRED_TOKEN.value:

            LOG.warning("{} - Link scaduto.".format(params_t['username']),
                        extra=set_client_ip(request))
            return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                          {"statusCode": StatusCode.EXPIRED_TOKEN.value, "message": "Errore link scaduto!"})
        elif result == StatusCode.ERROR.value:

            LOG.warning("{} - Link già utilizzato.".format(params_t['username']),
                        extra=set_client_ip(request))
            return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                          {"statusCode": StatusCode.ERROR.value, "message": "Errore link già utilizzato!"})
        elif result == StatusCode.NOT_FOUND.value:
            LOG.warning("{} - Link non trovato o non valido.".format(params_t['username']),
                        extra=set_client_ip(request))
            return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                          {"statusCode": StatusCode.NOT_FOUND.value,
                           "message": "Errore link non trovato o non valido!"})
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        params = {
            'rao': get_attributes_RAO()
        }
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, 'params': params, "message": "Link non valido!"})


'''GESTIONE HTTP ERROR'''


def handler404(request, exception):
    """
    Gestisce l'errore HTTP 404
    :param request: request
    :param exception: eccezione scatenata
    """

    url = request.get_full_path()[1:]
    LOG.error('handler404 => %s' % url, extra=set_client_ip(request))
    params = {
        'rao': get_attributes_RAO()
    }
    return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                  {"statusCode": StatusCode.NOT_FOUND.value, 'params': params,
                   "message": "La pagina non è stata trovata"})

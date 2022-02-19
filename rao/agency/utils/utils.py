# -*- coding: utf-8 -*-
# Stdlib imports
import base64
import datetime
import hashlib
import json

import jwt
import logging
import re
import threading
from io import BytesIO

# Imports from your apps
from operator import add

# Third-party app imports
from dateutil.relativedelta import relativedelta
from codicefiscale import codicefiscale
from dateutil import tz
from django.conf import settings
from django.http import HttpResponse, JsonResponse
# Core Django imports
from django.shortcuts import render
from django.template.loader import get_template
from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode
from xhtml2pdf import pisa

from agency.classes.choices import RoleTag, StatusCode, SUPRESSED_COUNTRY
from agency.models import Operator, AddressMunicipality, AddressCity, AddressNation, SetupTask
from .utils_db import get_attributes_RAO, get_operator_by_username

LOG = logging.getLogger(__name__)


def set_client_ip(request=None):
    """
    Restituisce il dizionario "extra" da aggiungere alle chiamate dei LOG
    :param request: request
    :return: dizionario "extra"
    """
    ip = get_client_ip(request)
    d = {'client_ip': ip}
    return d


def get_client_ip(request):
    """
    Restituisce l'IP del client
    :param request: request
    :return: IP del client
    """

    if not request:
        return "N.D."

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', None)
    client_ip = request.META.get('HTTP_CLIENT_IP', None)

    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    elif client_ip:
        ip = client_ip
    else:
        ip = request.META.get('REMOTE_ADDR', None)
    return ip


def json_default(value):
    """
    Funzione per convertire un attributo di una classe in formato JSON
    :param value: attrivuto della classe
    :return: attributo in JSON
    """
    if isinstance(value, datetime.date):
        return dict(year=value.year, month=value.month, day=value.day)
    else:
        return value.__dict__


def format_crypto(crypto_mail, tag):
    """
    Genera un valore booleano sulla base del tag passato in input
    :param crypto_mail: valore impostato tabella settings per l'invio della mail
    :param tag: CryptoTag
    :return: True/False
    """
    if crypto_mail == tag:
        return True
    return False


def calculate_age(born):
    """
    Calcola gli anni a partire dalla data di nascita
    :born: data di nascita
    :return: Età
    """
    today = datetime.date.today()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def verify_cf(request):
    """
    Verifica che il codice fiscale sia conforme ai dati inseriti nel form, altrimenti mostra quali dati sono errati
    :request: request contenente i dati del cittadino
    :return: dic con True/False
    """

    try:
        fiscal_code = request.POST.get('fiscalNumber').upper()
        centenario = request.POST.get('formCentenario')
        LOG.info(centenario)
        if centenario == 'S':
            data_di_nascita = (codicefiscale.decode(fiscal_code)['birthdate'] - relativedelta(years=100))
        else:
            data_di_nascita = codicefiscale.decode(fiscal_code)['birthdate']

        belfiore_code = request.POST.get('placeOfBirth') if request.POST.get('placeOfBirth') else request.POST.get(
            'nationOfBirth')
        verify_fiscal_code = {
            'familyName': fiscal_code[0:3] == codicefiscale.encode_surname(request.POST.get('familyName')),
            'name': fiscal_code[3:6] == codicefiscale.encode_name(request.POST.get('name')),
            'gender': codicefiscale.decode(fiscal_code)['sex'] == request.POST.get('gender'),
            'dateOfBirth': data_di_nascita == datetime.datetime.strptime(
                request.POST.get('dateOfBirth'), '%d/%m/%Y'),
            'belfiore_code': codicefiscale.decode(fiscal_code)['raw']['birthplace'] == belfiore_code
        }

        if belfiore_code == 'Z998':
            verify_fiscal_code['status_code'] = StatusCode.BAD_REQUEST.value
            return verify_fiscal_code

        if all(value is True for value in verify_fiscal_code.values()):
            verify_fiscal_code['status_code'] = StatusCode.OK.value
        else:
            verify_fiscal_code['status_code'] = StatusCode.ERROR.value


    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
        verify_fiscal_code = {
            'status_code': StatusCode.EXC.value,
        }

    return verify_fiscal_code


def render_to_pdf(template_src, context_dict):
    """
    Genera un file pdf
    :param template_src: template .html del pdf
    :param context_dict: dict contenente alcuni dati/settings (es. pagesize)
    :return: pagina pdf
    """
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()

    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type='application/pdf')
    return Exception()


def download_pdf(params, passphrase=None, pin=None):
    """
    Download di un file pdf
    :param params: dic contenente informazioni come username dell'operatore, timestamp creazione richiesta etc..
    :param passphrase: parte della passphrase da inserire sul pdf (nel caso di un'identificazione)
    :param pin: pin temporaneo da inserire sul pdf (nel caso della creazione di un operatore)
    :return: pagina pdf
    """

    op = get_operator_by_username(params['username'])

    if 'timestamp' in params:
        timestamp_to_datetime = datetime.datetime.strptime(params['timestamp'], '%Y-%m-%d %H:%M')
        token_expiration_datetime = from_utc_to_local(timestamp_to_datetime) + datetime.timedelta(days=30)
        token_expiration_datetime = token_expiration_datetime.strftime('%d/%m/%Y %H:%M')
    else:
        token_expiration_datetime = None

    context_dict = {
        'pagesize': 'A4',
        'RAO_name': get_attributes_RAO().name,
        'operator': op,
        'token_expiration_date': token_expiration_datetime
    }

    if passphrase:
        context_dict['passphrase'] = passphrase
        context_dict['pdf_object'] = params['pdf_object'] if 'pdf_object' in params else ""
        context_dict['name_user'] = params['name_user'] if 'name_user' in params else ""
        context_dict['surname_user'] = params['surname_user'] if 'surname_user' in params else ""

        template = get_template(settings.TEMPLATE_URL_PDF + 'pdf_template.html')
    else:
        context_dict['pin'] = pin
        template = get_template(settings.TEMPLATE_URL_PDF + 'pdf_pin_template.html')

    html = template.render(context_dict)
    result = BytesIO()

    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    cf_user = params['fiscalNumber'] if passphrase else params['username']
    if not pdf.err:
        LOG.info("{} - PDF scaricato".format(cf_user), extra=set_client_ip())
        filename = params['id'] + ".pdf" if passphrase else params['operator'] + ".pdf"
        response = HttpResponse(result.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename=' + filename
        return response

    LOG.warning("{} - PDF non scaricato - download automatico non riuscito".format(cf_user), extra=set_client_ip())
    return Exception()


def date_converter(date_with_slash):
    """
    Converte una data dal formato dd/mm/YYYY a YYYY-mm-dd
    :param date_with_slash: data in formato dd/mm/YYYY
    :return: data in formato YYYY-mm-dd
    """
    date_object = datetime.datetime.strptime(date_with_slash, '%d/%m/%Y')
    return date_object.strftime('%Y-%m-%d')


def from_utc_to_local(utc_datetime):
    """
    Converte una datetime utc in un datetime locale
    :param utc_datetime: datetime in uct
    :return: datetime locale
    """
    local_date = utc_datetime.replace(tzinfo=tz.tzutc())
    local_date = local_date.astimezone(tz.tzlocal())
    return local_date


def capitalize_text(text):
    """
    Converte una stringa in miniscolo con le iniziali in maiuscolo
    :param text: stringa da convertire
    :return: stringa convertita
    """
    array_string = text.lower().split(' ')

    for i, tmp_name in enumerate(array_string):
        array_string[i] = tmp_name.capitalize()

    return ' '.join(array_string)


def check_ts(number):
    """
    Verifica la validità del codice di identificazione della tessera sanitaria
    :param number: codice di identificazione da verificare
    :return: True/False
    """

    if not number.isdigit():
        return False

    if len(number) != 20:
        return False

    if number[0:5] != "80380":
        return False

    even = [sum([int(digit) for digit in str(int(x) * 2)]) for x in number[-2::-2]]
    odd = [int(x) for x in number[-1::-2]]
    tot = sum(map(add, even, odd))

    if tot % 10 != 0:
        return False

    return True


def delete_session_key(request):
    """
    Cancellazione chiave di sessione
    :param request: request
    :return:
    """
    try:
        key_name = request.GET.get('key_name')

        if key_name and key_name in request.session:
            del request.session[key_name]

    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=set_client_ip(request))

    return HttpResponse("Chiave Cancellata")


def load_select(request):
    """
    Caricamento dinamico select.
    :param request: request
    """
    code = request.GET.get('code')
    try:
        if request.GET.get('select') == 'placeOfBirth':
            if request.GET.get('birth_date') and str(request.GET.get('is_form')) == 'false':
                data = AddressMunicipality.objects.filter(city__code=code,
                                                          dateStart__lt=request.GET.get('birth_date'),
                                                          dateEnd__gt=request.GET.get('birth_date')).order_by('name')
            else:
                data = AddressMunicipality.objects.filter(city__code=code).order_by('name')
            return render(request, settings.TEMPLATE_URL_AGENCY + 'dropdown_options.html',
                          {'list': data, 'municipality': True})
        elif request.GET.get('select') == 'addressMunicipality':
            data = AddressMunicipality.objects.filter(city__code=code,
                                                      dateEnd__gt=datetime.date.today()).order_by('name')
            return render(request, settings.TEMPLATE_URL_AGENCY + 'dropdown_options.html',
                          {'list': data, 'municipality': False})

        elif (request.GET.get('select') == 'countyOfBirth' or request.GET.get(
                'select') == 'addressCountry') and request.GET.get('code') == "Z000":
            data = AddressCity.objects.all().order_by('name')
        elif request.GET.get('select') == 'nationOfBirth':
            data = AddressNation.objects.all().order_by('name')
        elif request.GET.get('select') == 'addressNation':
            data = AddressNation.objects.all().exclude(code__in=SUPRESSED_COUNTRY)
        else:
            data = None

    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                      {"statusCode": StatusCode.EXC.value, "message": "Errore durante il caricamento della Select"})

    return render(request, settings.TEMPLATE_URL_AGENCY + 'dropdown_options.html', {'list': data})


def page_manager(current_page, list_view, entry_view=settings.ENTRY_FOR_PAGE):
    """
    Data una lista e la pagina attuale, restituisce un dizionario per la gestione del relativo paginator
    :param current_page: pagina della lista visualizzata
    :param list_view: elenco da visualizzare (es. operator/request_identity)
    :param entry_view: num. di entry da visualizzare per pagina (di default 5)
    :return: dizionario con num. di pagina prec./attuale/succ. + entry da visualizzare
    """
    if list_view is None:
        pages = {
            'current': 1,
            'previous': None,
            'next': None,
            'entries': list_view
        }
        return pages

    count_all_entries = list_view.count()

    first_entry = entry_view * (int(current_page) - 1)
    last_entry = entry_view * int(current_page)
    max_n_page = count_all_entries / entry_view if count_all_entries % entry_view == 0 else (count_all_entries /
                                                                                             entry_view) + 1
    pages = {
        'current': int(current_page),
        'previous': int(current_page) - 1 if int(current_page) - 1 > 0 else None,
        'next': int(current_page) + 1 if int(current_page) + 1 <= int(max_n_page) else None,
        'entries': list_view[first_entry:last_entry]
    }
    return pages


def check_password(username, password, status, request=None):
    """
    Verifica se l'operatore esiste, è attivo e se la pass è errata/scaduta
    :param request: request
    :param username: codiceFiscale/username dell'operatore
    :param password: password dell'operatore
    :param status: status dell'operatore
    :return: StatusCode
    """
    hash_pass_insert = hashlib.sha256(password.encode()).hexdigest()
    user = Operator.objects.filter(fiscalNumber=username.upper(), status=status).last()
    if user:
        if not user.signStatus:
            return StatusCode.SIGN_NOT_AVAILABLE.value
        hash_pass = user.password
        try:
            jwt.decode(hash_pass, hash_pass_insert)
            return StatusCode.OK.value
        except jwt.ExpiredSignatureError:
            return StatusCode.EXPIRED_TOKEN.value
        except jwt.InvalidSignatureError:
            return StatusCode.ERROR.value
        except Exception as e:
            LOG.warning('[{}] eccezione durante la verifica della password: {}'.format(username, e),
                        extra=set_client_ip(request))
    return StatusCode.EXC.value


def check_operator(username, password, request=None):
    """
    Verifica se l'operatore esiste, è attivo e se la pass è errata/scaduta
    :param request: request
    :param username: codiceFiscale/username dell'operatore
    :param password: password dell'operatore
    :return: StatusCode
    """
    hash_pass_insert = hashlib.sha256(password.encode()).hexdigest()
    user = Operator.objects.filter(fiscalNumber=username.upper()).last()
    if user:
        if not user.status:
            return StatusCode.UNAUTHORIZED.value
        hash_pass = user.password
        try:
            jwt.decode(hash_pass, hash_pass_insert)
            user.failureCounter = 0
            user.save()
            if not user.signStatus and user.isActivated:
                return StatusCode.FORBIDDEN.value
            elif not user.signStatus and not user.isActivated:
                return StatusCode.SIGN_NOT_AVAILABLE.value

            return StatusCode.OK.value
        except jwt.ExpiredSignatureError:
            return StatusCode.EXPIRED_TOKEN.value
        except jwt.InvalidSignatureError:
            user.failureCounter += 1
            user.failureTimestamp = datetime.datetime.utcnow()
            if user.failureCounter >= 3:
                user.status = False
                user.save()
                LOG.warning("{} - Credenziali errate, Utente bloccato".format(username), extra=set_client_ip(request))
                return StatusCode.UNAUTHORIZED.value
            else:
                LOG.warning("{} - Credenziali errate".format(username), extra=set_client_ip(request))
            user.save()
            return StatusCode.ERROR.value
        except Exception as e:
            LOG.warning('[{}] eccezione durante la verifica della password: {}'.format(username, e),
                        extra=set_client_ip(request))
            return StatusCode.EXC.value
    return StatusCode.NOT_FOUND.value


def is_admin(username):
    """
    Verifica se l'operatore ha il ruolo "ADMIN" ed è attivo
    :param username: email/username dell'operatore
    :return: True/False
    """
    user = Operator.objects.filter(fiscalNumber=username, idRole__role=RoleTag.ADMIN.value, status=True).last()
    if user:
        return True
    else:
        return False


def display_alert(alert_type, body_message, link_message=None, link=None):
    """
    Genera un messaggio di errore/successo
    :param alert_type: enum AlertType: info, warning, success o danger
    :param body_message: testo del messaggio da mostrare
    :param link_message:
    :param link:
    :return: lista di dict con campi 'tags' e 'body'
    """

    return [{'tags': alert_type.value, 'body': body_message, 'link_message': link_message, 'link': link}]


def get_certificate(crt):
    """
    Converte in stringa il certificato in input
    :param crt: certificato
    :return: stringa convertita
    """
    try:
        cert = ''
        for chunk in crt.chunks():
            cert = cert + chunk.decode('UTF-8')
        return cert

    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=set_client_ip())
    return


def get_city_id(municipality_value, bith_date):
    """
    Riceve in input il codice catastale del comune di nascita e la data di nascita, dai quali risalire alla
    città di nascita
    :param municipality_value: codice catastale del comune di nascita
    :param bith_date: data di nascita in formato YYYY-mm-dd
    :return: StatusCode e sigla della città di nascita
    """
    try:
        municipality = AddressMunicipality.objects.filter(code=municipality_value, dateStart__lt=bith_date,
                                                          dateEnd__gt=bith_date).first()

        if municipality is not None:
            city = municipality.city
            return StatusCode.OK.value, city.code

        return StatusCode.ERROR.value, None

    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=set_client_ip())
        return StatusCode.EXC.value, None


def decode_fiscal_number(request):
    """
    Estrae i dati a partire dal codice fiscale
    :return: JsonResponse con statusCode e dati (in caso di successo)
    """
    cf = request.GET.get('CF').upper()
    centenario = request.GET.get('centenario')
    try:
        isvalid = codicefiscale.is_valid(cf) or codicefiscale.is_omocode(cf)
        decode_cf = codicefiscale.decode(cf)
        birth_date = decode_cf['birthdate']
        LOG.info(calculate_age(birth_date))
        if int(centenario) == 1:
            data_di_nascita = (decode_cf['birthdate'] - relativedelta(years=100)).strftime('%d/%m/%Y')
        else:
            data_di_nascita = decode_cf['birthdate'].strftime('%d/%m/%Y')
        if isvalid:
            am = AddressMunicipality.objects.filter(code__iexact=decode_cf['raw']['birthplace']).first()
            if am:
                nation_code = 'Z000'
            else:
                nation_code = decode_cf['raw']['birthplace']
                return JsonResponse({'statusCode': StatusCode.OK.value,
                                     'codeOfNation': nation_code,
                                     'placeOfBirth': '',
                                     'countyOfBirth': '',
                                     'dateOfBirth': data_di_nascita,
                                     'gender': decode_cf['sex']
                                     })

            status_code_city, city = get_city_id(decode_cf['raw']['birthplace'],
                                                 decode_cf['birthdate'].strftime('%Y-%m-%d'))

            if status_code_city == StatusCode.OK.value:
                return JsonResponse({'statusCode': StatusCode.OK.value,
                                     'codeOfNation': nation_code,
                                     'placeOfBirth': decode_cf['raw']['birthplace'],
                                     'countyOfBirth': city,
                                     'dateOfBirth': data_di_nascita,  # decode_cf['birthdate'].strftime('%d/%m/%Y'),
                                     'gender': decode_cf['sex'],
                                     'age': calculate_age(birth_date)

                                     })

    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return JsonResponse({'statusCode': StatusCode.EXC.value})

    return JsonResponse({'statusCode': StatusCode.ERROR.value})


def format_id_card_issuer(id_card_issuer):
    """
    Rimuove le preposizioni dall'ente di rilascio del documento
    :param id_card_issuer: comune/nome ente di rilascio
    :return: stringa con preposizioni rimosse
    """
    exclusions = ['di', 'delle', 'e', 'a', 'con', 'da', 'su', 'tra', 'fra']
    exclusions = '|'.join(['\\b%s\\b' % x for x in exclusions])
    id_card_issuer = re.sub(exclusions, '', id_card_issuer)
    id_card_issuer = id_card_issuer.replace('dell\'', '').replace('d\'', '')
    id_card_issuer = re.sub('\s+', '', id_card_issuer)
    return id_card_issuer[0].lower() + id_card_issuer[1:]


def encrypt_data(payload, passphrase):
    """
    Crypta un payload in ingresso utilizzando la passphrase inserita
    :param payload: oggetto da cryptare
    :param passphrase: password da utilizzare per l'encrypt
    :return: payload cryptato
    """
    try:
        if type(passphrase) == bytes:
            hash_passphrase = hashlib.sha512(passphrase).digest()
        else:
            hash_passphrase = hashlib.sha512(passphrase.encode()).digest()
        key_base64 = base64.urlsafe_b64encode(hash_passphrase)
        kjs = json.dumps({'k': key_base64.decode('utf-8', 'strict'), 'kty': 'oct'})
        key = jwk.JWK.from_json(kjs)
        token = jwe.JWE(payload, json_encode({"alg": "dir", "enc": "A256CBC-HS512"}))
        token.add_recipient(key)
        return token.serialize(compact=True)
    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=set_client_ip())
        return None


def decrypt_data(encrypted_data, passphrase):
    """
    Decrypta un payload in ingresso utilizzando la passphrase inserita
    :param encrypted_data: payload cryptato da decryptare
    :param passphrase: password da utilizzare per il decrypt
    :return: payload decryptato
    """
    try:
        if type(passphrase) == bytes:
            hash_passphrase = hashlib.sha512(passphrase).digest()
        else:
            hash_passphrase = hashlib.sha512(passphrase.encode()).digest()
        key_base64 = base64.urlsafe_b64encode(hash_passphrase)
        kjs = json.dumps({'k': key_base64.decode('utf-8', 'strict'), 'kty': 'oct'})
        key = jwk.JWK.from_json(kjs)

        jwetoken = jwe.JWE()
        jwetoken.deserialize(encrypted_data, key=key)
        return jwetoken.payload.decode()
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
        return None


def do_import(task_id, request):
    """
    Task in background eseguito per effettuare l'import dei dati
    """
    from agency.utils.utils_setup import init_nation, init_prefix, init_county, init_municipality, init_user
    task = SetupTask.objects.get(pk=task_id)

    try:
        init_nation(None)
        task.percentage = 15
        task.save()
        init_prefix(None)
        task.percentage = 33
        task.save()
        init_county(None)
        task.percentage = 66
        task.save()
        init_municipality(None)
        task.percentage = 99
        task.save()
        init_user(request)
        task.status = 'completed'
        task.percentage = 100
        task.save()
    except Exception as e:
        task.status = 'failed'
        task.error = str(e)
        task.save()


def check_import(request):
    """
    Verifica lo stato di completamento del task in background
    """
    task = SetupTask.objects.first()

    if task.status == 'completed':
        LOG.info("Setup completato con successo.", extra=set_client_ip(request))
    elif task.status == 'failed':
        LOG.error("Errore durante il caricamento dati.", extra=set_client_ip(request))
    return JsonResponse({
        'statusCode': StatusCode.OK.value,
        'status': task.status,
        'percentage': task.percentage,
        'error': task.error
    })


def start_import(request):
    """
    Avvia il processo di setup dei dati in background
    """
    if SetupTask.objects.count() == 0:
        task = SetupTask()
        task.status = 'in_progress'
        task.percentage = 0
        task.error = ''
        task.save()
        t = threading.Thread(target=do_import, args=[task.id, request])
        t.setDaemon(True)

        t.start()

        return JsonResponse({'statusCode': StatusCode.OK.value})
    else:
        last_row = SetupTask.objects.last()
        if last_row.status == "failed":
            last_row.delete()
            return start_import(request)

        return JsonResponse({'statusCode': StatusCode.OK.value})

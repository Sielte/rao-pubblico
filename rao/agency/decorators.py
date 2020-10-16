# -*- coding: utf-8 -*-
# Stdlib imports
import logging

# Core Django imports
from django.core import signing
from django.shortcuts import redirect, render
from django.http import HttpResponseRedirect
from django.urls import reverse

# Imports from your apps
from agency.classes.choices import StatusCode
from agency.utils.utils import is_admin, set_client_ip
from agency.utils.utils_db import check_db_not_altered, get_attributes_RAO
from django.conf import settings

LOG = logging.getLogger(__name__)


def login_required(function):
    """
    Permette di limitare l'accesso ad una view ai soli utenti loggati
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            try:
                token = str(request.path)
                token = token.split("/")[-2]
                params = signing.loads(token, max_age=3600)

                if (not 'is_authenticated' in request.session) or (not request.session['is_authenticated']):
                    return redirect(settings.LOGIN_URL)

                if (not 'username' in params) or (not params['username']):
                    return HttpResponseRedirect(reverse('agency:logout_agency'))
                if (not 'username' in request.session) or (not request.session['username']):
                    return HttpResponseRedirect(reverse('agency:logout_agency'))

                if not params['username'] == request.session['username']:
                    return HttpResponseRedirect(reverse('agency:logout_agency'))
                return function(request, *args, **kwargs)
            except Exception as e:
                LOG.error("Errore in decorator login_required: {}".format(str(e)), extra=set_client_ip(request))
                return HttpResponseRedirect(reverse('agency:logout_agency'))

        return onCall

    return decorator(function)


def admin_required(function):
    """
    Permette di limitare l'accesso ad una view ai soli utenti con ruolo Operatore
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            try:
                token = str(request.path)
                token = token.split("/")[-2]
                params = signing.loads(token, max_age=3600)
                if is_admin(params['username']):
                    return function(request, *args, **kwargs)
                else:
                    LOG.error("Errore in decorator admin_required non sei utente Admin", extra=set_client_ip(request))
                    return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t', token}))
            except Exception as e:
                LOG.error("Errore in decorator admin_required:{}".format(str(e)), extra=set_client_ip(request))
                return redirect(settings.LOGIN_URL)

        return onCall

    return decorator(function)


def operator_required(function):
    """
    Permette di limitare l'accesso ad una view ai soli utenti con ruolo Operator
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            try:
                token = str(request.path)
                token = token.split("/")[-2]
                params = signing.loads(token, max_age=3600)
                if not is_admin(params['username']):
                    return function(request, *args, **kwargs)
                else:
                    LOG.error("Errore in decorator operator_required non sei utente Operator", extra=set_client_ip(request))
                    return HttpResponseRedirect(reverse('agency:list_identity', kwargs={'t', token}))
            except Exception as e:
                LOG.error("Errore in decorator operator_required: {}".format(str(e)), extra=set_client_ip(request))
                return redirect(settings.LOGIN_URL)

        return onCall

    return decorator(function)


def only_one_admin(function):
    """
    Limita l'accesso ad un SOLO admin
    """

    def decorator(function):
        def onCall(request, *args, **kwargs):
            try:
                if check_db_not_altered():
                    return function(request, *args, **kwargs)
                else:
                    LOG.error("Errore in decorator only_one_admin il db è stato alterato.", extra=set_client_ip(request))
                    params = {
                        'rao': get_attributes_RAO(),
                    }
                    return render(request, settings.TEMPLATE_URL_AGENCY + 'error.html',
                                  {"statusCode": StatusCode.EXC.value, 'params': params,
                                   "message": "Abbiamo rilevato un problema con l’amministratore del sistema. Contatta l’assistenza tecnica."})
            except Exception as e:
                LOG.error("Errore in decorator only_one_admin: {}".format(str(e)), extra=set_client_ip(request))
                return redirect(settings.LOGIN_URL)

        return onCall

    return decorator(function)

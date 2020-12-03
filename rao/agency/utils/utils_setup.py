# -*- coding: utf-8 -*-

# Stdlib imports
import csv
import logging
import os
import sys
import traceback

# Imports from your apps
from django.conf import settings
# Core Django imports
from django.http import JsonResponse

import agency
from agency.classes.choices import StatusCode
from agency.models import AddressNation, AddressCity, AddressMunicipality, Role, Operator, SettingsRAO, VerifyMail
from agency.utils.utils import set_client_ip
from agency.utils.utils_db import populate_role, create_first_operator

LOG = logging.getLogger(__name__)


def init_nation(request, file='nazioni.csv'):
    """
    Popola la tabella delle nazioni
    :param request:
    :param file: file nazioni in formato csv
    :return: JsonResponse con statusCode
    """
    try:
        table = AddressNation.objects.all()
        if table:
            table.delete()
        with open(os.path.join(settings.DATA_FILES_PATH, file), encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file, delimiter=';', skipinitialspace=True)
            for row in reader:
                if row["Denominazione IT"] == '':
                    continue

                code = row["Codice AT"] if row["Codice AT"] != 'n.d.' else "Z998"

                an = AddressNation(name=row["Denominazione IT"],
                                   code=code if row["Denominazione IT"] != 'Italia' else "Z000",
                                   lettersCode=row["Codice ISO 3166 alpha3"])
                an.save()
        return JsonResponse({'statusCode': StatusCode.OK.value})
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip(request))
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip(request))

    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value})


def init_county(request, file='province.csv'):
    """
    Popola le province
    :param request: request
    :param file: file province in formato csv
    :return: JsonResponse con statusCode
    """
    try:
        table = AddressMunicipality.objects.all()
        if table:
            table.delete()

        table = AddressCity.objects.all()
        if table:
            table.delete()
        with open(os.path.join(settings.DATA_FILES_PATH, file), encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file, delimiter=';', skipinitialspace=True)
            sa = ''
            for row in reader:
                if sa != row["Sigla automobilistica"]:
                    sa = row["Sigla automobilistica"]
                    ac = AddressCity(name=row["Città"],
                                     code=row["Sigla automobilistica"])
                    ac.save()
        return JsonResponse({'statusCode': StatusCode.OK.value})
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip(request))
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip(request))
    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value})


def init_municipality(request, file='ANPR_archivio_comuni.csv'):
    """
        Popola i comuni
        :param request: request
        :param file: file comuni in formato csv
        :return: JsonResponse con statusCode
        """
    try:
        with open(os.path.join(settings.DATA_FILES_PATH, file), encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file, delimiter=',', skipinitialspace=True)
            buffer = []
            mun_name = ''
            prov_sigla = ''

            for row in reader:
                try:
                    ac = AddressCity.objects.filter(code=row['SIGLAPROVINCIA']).first()
                    if not ac:
                        ac = AddressCity(name=row['SIGLAPROVINCIA'],
                                         code=row['SIGLAPROVINCIA'])
                        ac.save()

                    if mun_name == row["DENOMINAZIONE_IT"] and prov_sigla == row['SIGLAPROVINCIA']:
                        am = buffer.pop()
                        am.dateEnd = row['DATACESSAZIONE'].strip()
                    else:
                        am = AddressMunicipality(name=row["DENOMINAZIONE_IT"],
                                                 code=row["CODCATASTALE"],
                                                 dateStart=row['DATAISTITUZIONE'].strip(),
                                                 dateEnd=row['DATACESSAZIONE'].strip(),
                                                 city=ac)

                    buffer.append(am)
                    mun_name = row["DENOMINAZIONE_IT"]
                    prov_sigla = row["SIGLAPROVINCIA"]

                except Exception as e:
                    LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
            AddressMunicipality.objects.bulk_create(buffer)
        return JsonResponse({'statusCode': StatusCode.OK.value})
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip(request))
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip(request))
    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value})


def init_prefix(request, file='prefissi.csv', encoding='utf-8'):
    """
    Popola i prefissi sulla tabella delle nazioni
    :param request: request
    :param file: file prefissi in formato csv
    :param encoding: default 'utf-8'
    :return: JsonResponse con statusCode
    """
    try:
        with open(os.path.join(settings.DATA_FILES_PATH, file), encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file, delimiter=';', skipinitialspace=True)
            for row in reader:
                try:
                    an = AddressNation.objects.filter(name=row['Nazione']).first()
                    if an:
                        an.prefix = row['Prefisso']
                        an.save()
                except Exception as e:
                    LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        return JsonResponse({'statusCode': StatusCode.OK.value})
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip(request))
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip(request))
    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value})


def init_user(request):
    """
    Popola la tabella ruoli, inserisce il primo operatore e imposta il token di verifica a True
    :param request
    :return: JsonResponse con statusCode
    """
    try:
        response_role = populate_role()
        response_op = create_first_operator(request)
        if response_op and response_role:
            if request.session['activation_token']:
                vms = VerifyMail.objects.filter(token=request.session['activation_token']).last()
                vms.isVerified = True
                vms.save()
                return JsonResponse({'statusCode': StatusCode.OK.value})
            LOG.error("Errore durante la verifica dell'operatore activation_token")
            return JsonResponse({'statusCode': StatusCode.ERROR.value})
        else:
            LOG.error("Errore durante il popolamento tabella ruoli operatori")
            return JsonResponse({'statusCode': StatusCode.ERROR.value})
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip(request))
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip(request))
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip(request))
    return JsonResponse({'statusCode': StatusCode.BAD_REQUEST.value})


def init_settings_rao(rao_name, issuer_code, rao_email, rao_host, rao_pwd, email_crypto_type,
                      email_port, smtp_mail_from=""):
    """
    Popola la tabella impostazioni del RAO
    :param rao_name: nome visualizzato sul template
    :param issuer_code: codice identificativo IPA
    :param rao_email: nome di chi invia l'email
    :param rao_host: host dell'email
    :param rao_pwd: password dell'email
    :param email_crypto_type: tipo di Crittografia (Nessuna/TLS/SSL)
    :param email_port: porta in uscita
    :param smtp_mail_from:
    :return: True/False
    """

    try:
        password = None
        if rao_pwd:
            password = agency.utils.utils.encrypt_data(rao_pwd, settings.SECRET_KEY_ENC)
        entry_rao = SettingsRAO.objects.first()
        if not entry_rao:
            entry_rao = SettingsRAO(name=rao_name, issuerCode=issuer_code,
                                    username=rao_email, host=rao_host, password=password, port=email_port,
                                    crypto=email_crypto_type, email=smtp_mail_from)
        else:
            entry_rao.name = rao_name
            entry_rao.issuerCode = issuer_code
            entry_rao.email = smtp_mail_from
            entry_rao.username = rao_email
            entry_rao.host = rao_host
            entry_rao.password = password
            entry_rao.port = email_port
            entry_rao.crypto = email_crypto_type
        entry_rao.save()
        return True
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip())
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip())
    return False


def configuration_check():
    """
    Verifica se è stata già eseguita la configurazione
    :return: True/False
    """
    try:
        table = Operator.objects.all()
        if not table:
            return False
        table = SettingsRAO.objects.all()
        if not table:
            return False
        return True
    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
    return False


def necessary_data_check():
    """
    Verifica se i dati necessari al corretto funzionamento sono già in tabella
    :return: True/False
    """
    try:
        table = AddressNation.objects.all()
        if not table:
            return False
        table = AddressCity.objects.all()
        if not table:
            return False
        table = AddressMunicipality.objects.all()
        if not table:
            return False
        table = Role.objects.all()
        if not table:
            return False
        return True
    except Exception as e:
        ype, value, tb = sys.exc_info()
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
        LOG.error('exception_value = %s, value = %s' % (value, type,), extra=set_client_ip())
        LOG.error('tb = %s' % traceback.format_exception(type, value, tb), extra=set_client_ip())
    return False


# -*- coding: utf-8 -*-

import base64
import calendar
import datetime
import json
import logging
import os
import random
import re

from agency.classes.choices import StatusCode
from agency.classes.regex import passphrase_expression
from agency.models import IdentityRequest, SettingsRAO, TokenUser
from agency.utils.utils import format_id_card_issuer, encrypt_data, set_client_ip
from agency.utils.utils_api import sign_token_api
from rao import settings

LOG = logging.getLogger(__name__)


def is_valid(passphrase):
    """
    Verifica se la passphrase rispetta i vincoli presenti sulle linee guida
    :param passphrase: passphrase di 12 caratteri da verificare
    :return: True/False
    """
    matching = re.match(passphrase_expression, passphrase)
    if not matching:
        return False
    return True


def generate_passphrase():
    """
    genera una passhprase verificando il rispetto dei vincoli presenti sulle linee guida
    :return: passprase di 12 caratteri
    """
    passphrase = ""
    while not is_valid(passphrase):
        passphrase = "".join(
            [random.choice("ABCDEFGHIJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!$?#=*+-.:") for i in range(12)])
    return passphrase


def user_token(creation_time, user, rao, request_identity):
    """
    Generazione dell'encryptedData e della passphrase
    :param creation_time: tempo di creazione
    :param user: dict contenente i dati dell'utente
    :param rao: entry del db contenente i settings del rao
    :param request_identity: richiesta di identificazione generata relativa ad user
    :return: dict con encryptedData e passphrase
    """

    passphrase = generate_passphrase()

    ICRequestData = generate_ICRequestData(creation_time, user, rao, request_identity)

    enc = encrypt_data(ICRequestData, passphrase)
    user_token = {
        'encryptedData': str(enc),
        'passphrase': passphrase,
    }
    return user_token


def generate_ICRequestData(creation_time, user, rao, request_identity):
    """
    Genera l'ICRequestData
    :param creation_time: tempo di creazione
    :param user: dict contenente i dati dell'utente
    :param rao: entry del db contenente i settings del rao
    :param request_identity: richiesta di identificazione generata relativa ad user
    :return: ICRequestData in JSon
    """

    ICRequestData = {
        "info": {
            "id": str(request_identity.uuid_identity),
            "issueInstant": creation_time,
            "issuer": {
                "issuerCode": rao.issuerCode,
                "issuerInternalReference": user['id_operator']
            }
        },
        "electronicIdentification": {
            "identificationType": user['identificationType'],
            "identificationSerialCode": user['identificationSerialCode'],
            "identificationExpirationDate": user['identificationExpirationDate'].strftime("%Y-%m-%d")
        },
        "spidAttributes": {
            "mandatoryAttributes": {
                "name": user['name'],
                "familyName": user['familyName'],
                "placeOfBirth": user['placeOfBirth']['code'],
                "countyOfBirth": user['countyOfBirth']['code'],
                "nationOfBirth": user['nationOfBirth']['code'],
                "dateOfBirth": user['dateOfBirth'].strftime("%Y-%m-%d"),
                "gender": user['gender'],
                "fiscalNumber": "TINIT-" + user['fiscalNumber'],
                "email": user['email'],
                "idCard": {
                    "idCardType": user['idCardType'],
                    "idCardDocNumber": user['idCardDocNumber'],
                    "idCardIssuer": format_id_card_issuer(user['idCardIssuer']),
                    "idCardIssueDate": user['idCardIssueDate'].strftime("%Y-%m-%d"),
                    "idCardExpirationDate": user['idCardExpirationDate'].strftime("%Y-%m-%d")
                },
                "mobilePhone": {
                    "countryCallingCode": user['countryCallingCode'],
                    "phoneNumber": user['phoneNumber']
                },
                "address": {
                    "addressType": user['addressType'],
                    "addressName": user['addressName'],
                    "addressNumber": user['addressNumber'],
                    "postalCode": user['addressPostalCode'],
                    "municipality": user['addressMunicipality']['code'],
                    "county": user['addressCountry']['code'],
                    "nation": user['addressNation']['code']
                }
            }
        }
    }


    if user['pec']:
        ICRequestData['spidAttributes'].__setitem__('optionalAttributes', {"digitalAddress": user['pec']})
    ICRequestData = json.dumps(ICRequestData)
    return ICRequestData


def signed_token(user, op_username, pin):
    """
    Creazione token_sigillato
    :param user: dict contenente i dati dell'utente
    :param op_username: username dell'operatore
    :param pin: pin dell'operatore
    :return: dict con statusCode, token e passphrase
    """
    creation_time = datetime.datetime.utcnow()
    expiration_time = creation_time + datetime.timedelta(days=30)

    rao = SettingsRAO.objects.last()

    request_identity = IdentityRequest.objects.filter(fiscalNumberUser=user['fiscalNumber']).order_by(
        'timestamp_identification').last()
    token_to_update = TokenUser.objects.get(uuid_token_user=request_identity.token.uuid_token_user)

    userToken = user_token(calendar.timegm(creation_time.utctimetuple()), user, rao, request_identity)

    if token_to_update:
        token_to_update.token_user = userToken['encryptedData']
        token_to_update.save()

    b64_issuer_code = base64.b64encode(rao.issuerCode.encode())

    b64_issuer_internal_reference = base64.b64encode(user['id_operator'].encode())

    merge_iss = b64_issuer_code.decode("utf-8") + "." + b64_issuer_internal_reference.decode("utf-8")

    payload = {
        "iss": merge_iss,
        "sub": str(request_identity.uuid_identity),
        "jti": str(request_identity.token.uuid_token_user),
        "iat": calendar.timegm(creation_time.utctimetuple()),
        "exp": calendar.timegm(expiration_time.utctimetuple()),
        "fiscalNumber": user['fiscalNumber'],
        "encryptedData": userToken['encryptedData']
    }
    tokenSigillato = None

    try:
        dict_signature = sign_token_api(op_username, payload, pin)
        if dict_signature:
            if type(dict_signature) == int:
                obj = {"statusCode": dict_signature}
                return obj
            b64_signature = dict_signature.get("sign")
            x5c = dict_signature.get("cert")
            alg = dict_signature.get("alg")

            headers = {'typ': "JWT", 'alg': alg, 'x5c': [x5c]}

            b64_all = base64.urlsafe_b64encode(json.dumps(headers).encode()).decode().rstrip("=") + "." + \
                      base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

            tokenSigillato = b64_all + "." + b64_signature

        else:
            obj = {"statusCode": StatusCode.ERROR.value}
            return obj

    except Exception as e:
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
        obj = {"statusCode": StatusCode.EXC.value}
        return obj

    obj = {"statusCode": StatusCode.OK.value, "token_sigillato": tokenSigillato, "passphrase": userToken['passphrase']}
    return obj


def create_token_file(token, file_name=None):
    """
    Creazione token_file
    :param token: token da scrivere su file
    :param file_name: nome file ('tuo_token' se non viene passato il parametro)
    :return:
    """
    name = 'tuo_token.txt' if file_name is None else file_name
    f = open(os.path.join(settings.DATA_FILES_PATH, name), 'w')
    token = token['token_sigillato']
    f.write(token)
    f.close()
    return [name]


def delete_token_file(name='tuo_token.txt'):
    """
    Cancellazione token_file
    :param name: nome del token_file (default: tuo_token)
    :return:
    """
    if os.path.exists(os.path.join(settings.DATA_FILES_PATH, name)):
        os.remove(os.path.join(settings.DATA_FILES_PATH, name))
    return True

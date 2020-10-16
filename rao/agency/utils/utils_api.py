import hmac
import json
import logging
from urllib import request, parse

from django.conf import settings
from django.http import HttpResponse

import agency
from ..classes.choices import StatusCode, EndpointSign

LOG = logging.getLogger(__name__)


def create_api(pin, admin_username, op_username):
    """
    API per la creazione di un nuovo operatore
    :param pin: pin di Firma dell'admin
    :param admin_username: username dell'admin
    :param op_username: username dell'operatore da creare
    :return: StatusCode, message (-1 in caso di errore)
    """
    LOG.info("Api: {}".format(settings.SIGN_URL + EndpointSign.CREATE.value), extra=agency.utils.utils.set_client_ip())
    try:
        auth_token = hmac.new(str(pin).zfill(6).encode(), (admin_username + op_username).encode(), 'SHA256').hexdigest()

        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'username': op_username})
        data = data.encode()
        rec = request.Request(settings.SIGN_URL + EndpointSign.CREATE.value, data=data,
                              headers={"Authorization": auth_token, "Username": admin_username})
        content = request.urlopen(rec)
        response = content.read().decode()
        dic = json.loads(response)

        if dic['statusCode'] == 200:
            return StatusCode.OK.value, dic['message']
        elif dic['statusCode'] == -5:
            LOG.warning("{} - PIN ADMIN bloccato".format(admin_username), extra=agency.utils.utils.set_client_ip())
        elif dic['statusCode'] == 401:
            LOG.warning("{} - Non autorizzato. Controlla i LOG sul Sistema di Firma".format(admin_username),
                        extra=agency.utils.utils.set_client_ip())
        return StatusCode.ERROR.value, -1
    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
        return StatusCode.EXC.value, -1


def reset_pin_api(pin, admin_username, op_username):
    """
    API per generare un nuovo pin temporaneo per un operatore
    :param pin: pin di Firma dell'admin
    :param admin_username: username dell'admin
    :param op_username: username dell'operatore da creare
    :return: StatusCode, message (-1 in caso di errore)
    """
    LOG.info("Api: {}".format(settings.SIGN_URL + EndpointSign.RESET.value), extra=agency.utils.utils.set_client_ip())
    try:
        auth_token = hmac.new(str(pin).zfill(6).encode(), (admin_username + op_username).encode(), 'SHA256').hexdigest()

        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'username': op_username})
        data = data.encode()
        rec = request.Request(settings.SIGN_URL + EndpointSign.RESET.value, data=data,
                              headers={"Authorization": auth_token, "Username": admin_username})

        content = request.urlopen(rec)
        response = content.read().decode()
        dic = json.loads(response)
        if dic['statusCode'] == 200:
            LOG.info("admin: {}, {} - PIN resettato".format(admin_username,op_username),
                     extra=agency.utils.utils.set_client_ip())
            return StatusCode.OK.value, dic['message']
        elif dic['statusCode'] == -5:
            LOG.warning("{} - PIN ADMIN bloccato".format(admin_username), extra=agency.utils.utils.set_client_ip())
        elif dic['statusCode'] == 401:
            LOG.warning("admin: {}, {} - Non autorizzato. Controlla i LOG sul Sistema di Firma".format(admin_username,op_username),
                        extra=agency.utils.utils.set_client_ip())
        return StatusCode.ERROR.value, -1
    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
        return StatusCode.EXC.value, -1


def disable_operator_api(pin, admin_username, op_username):
    """
    API per disabilitare un operatore sul server di Firma
    :param pin: pin di Firma dell'admin
    :param admin_username: username dell'admin
    :param op_username: username dell'operatore da creare
    :return: StatusCode, message (-1 in caso di errore)
    """
    LOG.info("Api:{}".format(settings.SIGN_URL + EndpointSign.DISABLE.value), extra=agency.utils.utils.set_client_ip())
    try:
        auth_token = hmac.new(str(pin).zfill(6).encode(), (admin_username + op_username).encode(), 'SHA256').hexdigest()

        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'username': op_username})
        data = data.encode()
        rec = request.Request(settings.SIGN_URL + EndpointSign.DISABLE.value, data=data,
                              headers={"Authorization": auth_token, "Username": admin_username})

        content = request.urlopen(rec)
        response = content.read().decode()
        dic = json.loads(response)
        if dic['statusCode'] == 200:
            LOG.info("admin: {}, {} - Operatore disabilitato".format(admin_username,op_username),
                     extra=agency.utils.utils.set_client_ip())
            return StatusCode.OK.value
        elif dic['statusCode'] == -5:
            LOG.warning("{} - PIN ADMIN bloccato".format(admin_username), extra=agency.utils.utils.set_client_ip())
        elif dic['statusCode'] == 401:
            LOG.warning("admin: {}, {} - Non autorizzato. Controlla i LOG sul Sistema di Firma".format(admin_username,op_username),
                        extra=agency.utils.utils.set_client_ip())
        return StatusCode.ERROR.value
    except Exception as e:
        HttpResponse()
        LOG.warning("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
        return StatusCode.EXC.value


def activate_op_api(username, old_pin, new_pin, cert=None):
    """
    API per l'attivazione di un operatore
    :param username: username dell'operatore da attivare
    :param old_pin: pin di Firma temporaneo fornito al momento della creazione
    :param new_pin: nuovo pin di Firma scelto dall'operatore
    :param cert: certificato da caricare (solo nel caso di attivazione di un admin)
    :return: StatusCode
    """
    LOG.info("Api: {}".format(settings.SIGN_URL + EndpointSign.ACTIVATE.value), extra=agency.utils.utils.set_client_ip())
    auth_token = hmac.new(str(old_pin).zfill(6).encode(), (username + str(new_pin).zfill(6)).encode(),
                          'SHA256').hexdigest()
    if cert:
        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'cert': cert,
                                'new_pin': str(new_pin).zfill(6)})
    else:
        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'new_pin': str(new_pin).zfill(6)})

    data = data.encode()
    rec = request.Request(settings.SIGN_URL + EndpointSign.ACTIVATE.value, data=data,
                          headers={"Authorization": auth_token, "Username": username})
    content = request.urlopen(rec)
    response = content.read().decode()
    dic = json.loads(response)
    if dic['statusCode'] == 200:
        return StatusCode.OK.value
    elif dic['statusCode'] == -5:
        LOG.warning("{} - PIN bloccato".format(username), extra=agency.utils.utils.set_client_ip())
    elif dic['statusCode'] == 401:
        LOG.warning(
            "{} - Non autorizzato. Controlla i LOG sul Sistema di Firma".format(username),
            extra=agency.utils.utils.set_client_ip())
    return StatusCode.ERROR.value


def update_cert(pin, admin_username, cert):
    """
    API per aggiornare il certificato sul server di Firma
    :param pin: pin di Firma dell'admin
    :param admin_username: username dell'admin
    :param cert: certificato aggiornato da caricare
    :return: StatusCode
    """
    try:
        LOG.info("Api: {}".format(settings.SIGN_URL + EndpointSign.UPLOAD.value), extra=agency.utils.utils.set_client_ip())
        auth_token = hmac.new(str(pin).zfill(6).encode(), (admin_username + cert).encode(), 'SHA256').hexdigest()

        data = parse.urlencode({'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                'cert': cert,
                                'username': admin_username})
        data = data.encode()
        rec = request.Request(settings.SIGN_URL + EndpointSign.UPLOAD.value, data=data,
                              headers={"Authorization": auth_token, "Username": admin_username})

        content = request.urlopen(rec)
        response = content.read().decode()
        dic = json.loads(response)
        if dic['statusCode'] == 200:
            LOG.info("{}, {} - Certificato aggiornato".format(agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                                              admin_username),
                     extra=agency.utils.utils.set_client_ip())
            return StatusCode.OK.value
        LOG.warning("{}, {} - Aggiornamento certificato non riuscito".format(agency.utils.utils_db.get_attributes_RAO().issuerCode,
                                                             admin_username),
                    extra=agency.utils.utils.set_client_ip())
        return StatusCode.ERROR.value
    except Exception as e:
        LOG.warning("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
        return StatusCode.EXC.value


def sign_token_api(username, payload, pin):
    """
    API per applicare la firma su un payload
    :param username: username dell'operatore
    :param payload: payload da firmare
    :param pin: pin di Firma dell'operatore
    :return: dic con parametri 'cert', 'alg' e 'sign'
    """
    LOG.info("Api: {}".format(settings.SIGN_URL + EndpointSign.SIGN.value), extra=agency.utils.utils.set_client_ip())
    json_payload = json.dumps(payload)
    auth_token = hmac.new(str(pin).zfill(6).encode(), (username + json_payload).encode(), 'SHA256').hexdigest()
    data = parse.urlencode({'payload': json_payload,
                            'entity': agency.utils.utils_db.get_attributes_RAO().issuerCode})
    data = data.encode()
    rec = request.Request(settings.SIGN_URL + EndpointSign.SIGN.value, data=data,
                          headers={"Authorization": auth_token, "Username": username})
    content = request.urlopen(rec)
    response = content.read().decode()
    dic = json.loads(response)
    if dic['statusCode'] == 200:
        response_dict = {
            'cert': dic['cert'],
            'alg': dic['alg'],
            'sign': dic['sign']
        }
        return response_dict
    else:
        return dic['statusCode']







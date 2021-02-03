# -*- coding: utf-8 -*-
# Stdlib imports
import base64
import datetime
import hashlib
import logging
import os
import sys
import traceback

import requests
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import UserNotice
from cryptography.x509.oid import ExtensionOID

from agency.classes.choices import StatusCode, CertRef, POLICY_OID
from agency.utils.utils import set_client_ip
from rao import settings

LOG = logging.getLogger(__name__)


def check_expiration_certificate(cert_string):
    """

    :param cert_string:
    :return:
    """
    try:
        certificate = x509.load_pem_x509_certificate(cert_string.encode(), default_backend())
        if certificate.not_valid_after > datetime.datetime.now() > certificate.not_valid_before:
            return True
    except Exception as e:
        LOG.warning('Errore su check_expiration_certificate: {}'.format(str(e)), extra=set_client_ip())
    return False


def verify_policy_certificate(cert_string):
    """
    Verifica la presenza degli oid nel certificato
    :param cert_string: stringa del certificato, in formato PEM, da esaminare
    :return:
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_string.encode(), default_backend())
        certificate_policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        for p in certificate_policies:
            if p.policy_identifier.dotted_string in POLICY_OID:
                qualifiers = p.policy_qualifiers
                for qualifier in qualifiers:
                    if isinstance(qualifier, UserNotice):
                        return True
                return False
        return False
    except Exception as e:
        LOG.warning('Errore su check_certificate: {}'.format(str(e)), extra=set_client_ip())
        return False


def verify_certificate_chain(cert_string):
    """
    Verifica la CRL del certificato
    :param cert_string: stringa del certificato, in formato PEM, da esaminare
    :return: StatusCode
    """
    try:
        status, message = StatusCode.OK.value, "Certificato verificato"
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string.encode())
        cert_x509 = x509.load_pem_x509_certificate(cert_string.encode(), default_backend())
    except Exception as e:
        LOG.warning(str(e), extra=set_client_ip())
        return StatusCode.ERROR.value, "Il certificato selezionato non è valido"

    try:
        store = crypto.X509Store()
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)

        for tag in list(CertRef):
            cer = download_http_cert(tag.value)
            if cer:
                try:
                    store.add_cert(cer)
                except:
                    pass

        try:
            aki_bin = cert_x509.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
            aki = format_ki(aki_bin)
            certificate_policies = cert_x509.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        except x509.extensions.ExtensionNotFound:
            LOG.warning(cert_string)
            return StatusCode.NOT_FOUND.value, "Chiave dell'IA non trovata"

        crl_uri = get_crl_endpoint(certificate_policies)
        if crl_uri is None:
            LOG.warning('Impossibile stabilire endpoint per CRL con aki = {}'.format(aki), extra=set_client_ip())
            return StatusCode.NOT_FOUND.value, "Impossibile stabilire l'endpoint per CRL con aki = {}".format(aki)

        crl_latest = make_crl_store_path(crl_uri, aki) + ".crl"

        if not exists_crl(crl_uri, aki):
            status, message = download_crl(crl_uri, aki)

        with open(crl_latest) as f:
            crl_content = f.read()

        crl = x509.load_pem_x509_crl(crl_content.encode(), default_backend())
        crl_crypto = crypto.CRL.from_cryptography(crl)

        if crl.next_update < datetime.datetime.now():
            status, message = download_crl(crl_uri, aki)
            crl = x509.load_pem_x509_crl(crl_content.encode(), default_backend())
            crl_crypto = crypto.CRL.from_cryptography(crl)

        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
        store.add_crl(crl_crypto)
        store_ctx = crypto.X509StoreContext(store, certificate)

        store_ctx.verify_certificate()
        return status, message
    except Exception as e:
        type, value, tb = sys.exc_info()
        LOG.error(e, extra=set_client_ip())
        LOG.error('exception_value = {0}, value = {1}'.format(str(value), str(type)), extra=set_client_ip())
        LOG.error('tb = {}'.format(traceback.format_exception(type, value, tb)), extra=set_client_ip())
        return StatusCode.EXC.value, "Errore durante la verifica del certificato"


def encode_crl_endpoint(value):
    """
    Codifica l'url della CRL
    :param value: url della CRL
    :return: String
    """
    return hashlib.md5(base64.b64encode(value.encode())).hexdigest()


def make_crl_store_path(endpoint, key_identifier):
    """
    Crea il path per la cartella temporanea dove depositare le crl scaricate
    :param endpoint: url della crl
    :param key_identifier: chiave identificativa dell'issuer del certificato
    :return: String
    """
    if endpoint is None:
        raise Exception("Endpoint empty")

    if key_identifier is None:
        raise Exception("key_identifier empty")

    dir_name = os.path.join(settings.CRL_PATH, key_identifier)

    if not os.path.exists(dir_name):
        os.mkdir(dir_name)

    if endpoint.startswith(u'ttp'):
        endpoint = 'h' + endpoint

    return os.path.join(dir_name, encode_crl_endpoint(endpoint))


def format_ki(key_identifier):
    """
    Restituisce la chiave identificativa dell'issuer del certificato
    :param key_identifier: chiave identificativa dell'issuer del certificato
    :return: chiave identificativa dell'issuer formattata
    """
    return "-".join("{:02x}".format(c) for c in key_identifier)


def get_crl_endpoint(certificate_policies):
    """
    Recupera il primo endpoint per il download della CRL
    :param certificate_policies: Policy contente i punti di distribuzione CRL
    :return: String
    """
    for crl_point in certificate_policies:
        crl_endpoint = crl_point.full_name[0].value
        if 'ldap' not in crl_endpoint and isinstance(crl_endpoint, str):
            return crl_endpoint
    LOG.error('Nessun endpoint trovato.', extra=set_client_ip())
    return None


def exists_crl(endpoint, key_identifier):
    """
    :param endpoint: url della crl
    :param key_identifier: chiave identificativa dell'issuer del certificato
    :return: True/False
    """
    return os.path.exists(make_crl_store_path(endpoint, key_identifier))


def _download_http_crl(endpoint, key_identifier):
    """
    :param endpoint: url della crl
    :param key_identifier: chiave identificativa dell'issuer del certificato
    :return:
    """

    crl_dest = make_crl_store_path(endpoint, key_identifier) + ".crl"
    crl_meta_dest = make_crl_store_path(endpoint, key_identifier) + ".txt"

    try:
        r = requests.get(endpoint)
        if r.status_code == 200:
            try:
                crl = crypto.load_crl(crypto.FILETYPE_PEM, r.content)
            except:
                crl_x509 = x509.load_der_x509_crl(r.content, default_backend())
                crl = crypto.CRL.from_cryptography(crl_x509)
            with open(crl_dest, 'w') as f:
                f.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode())
            with open(crl_meta_dest, 'w') as f:
                f.write(endpoint)
            status = StatusCode.OK.value
            message = "Status ok"
        else:
            LOG.error('Errore durante il download della CRL con endpoint = {}'.format(endpoint), extra=set_client_ip())
            status = StatusCode.ERROR.value
            message = "Errore durante il download della CRL con endpoint = {}".format(endpoint)
    except Exception as e:
        LOG.error('Eccezione durante il download della CRL con key_identifier = {}'.format(key_identifier), extra=set_client_ip())
        message = "Errore durante il download della CRL"
        status = StatusCode.EXC.value
        LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
    return status, message

def download_crl(endpoint, key_identifier):
    """
    Scarica la CRL dall'endpoint e lo mette nello store delle CRL
    :param endpoint: url della crl
    :param key_identifier: chiave identificativa dell'issuer del certificato
    :return:
    """
    if endpoint.startswith(u'http'):
        status, message = _download_http_crl(endpoint, key_identifier)
    elif endpoint.startswith(u'ttp'):
        endpoint = 'h' + endpoint
        status, message = _download_http_crl(endpoint, key_identifier)
    else:
        status = StatusCode.NOT_FOUND.value
        message = "Controllo sull'endpoint non riuscito"
    return status, message

def download_http_cert(endpoint):
    """
    Scarica i certificati root e sub CA dall'endpoint
    :param endpoint: url del certificato da scaricare
    :return: restituisce il certificato scaricato
    """
    cert = None
    try:
        r = requests.get(endpoint)
        if r.status_code == 200:
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, r.content)
            except:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, r.content)
        else:
            LOG.error('Errore durante il download della CRL con endpoint = {}'.format(endpoint), extra=set_client_ip())
    except Exception as e:
        LOG.error('Eccezione durante il download della CRL con endpoint = {}'.format(endpoint), extra=set_client_ip())
        LOG.error(str(e), extra=set_client_ip())
    return cert

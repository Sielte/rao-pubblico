# -*- coding: utf-8 -*-
import logging
import time

from django.core.mail import get_connection, send_mail, EmailMessage
from django.template.loader import render_to_string

import agency
from agency.classes.choices import CryptoTag, StatusCode
from agency.models import SettingsRAO
from agency.utils import utils
from rao import settings

LOG = logging.getLogger(__name__)


def get_conn_from_db(label, tmp_settings=None):
    """
    Restituisce la connection identificata tramite label
    :param tmp_settings: settings temporanei per l'invio della mail (test della configurazione SMTP)
    :param label:
    :return: Connection identificata tramite label
    """

    email_connections = {}
    if not tmp_settings:
        sr = SettingsRAO.objects.filter(host__isnull=False).first()
    else:
        sr = tmp_settings
    if sr:
        password = None
        error = False
        if sr.password:
            try:
                password = utils.decrypt_data(sr.password, settings.SECRET_KEY_ENC)
            except Exception as e:
                error = True
                LOG.error("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
        if not error:
            email_connections = {
                'default': {
                    'from_email': sr.email,
                    'host': sr.host,
                    'username': sr.username,
                    'password': password,
                    'port': sr.port,
                    'use_tls': agency.utils.utils.format_crypto(sr.crypto, CryptoTag.TLS.value),
                    'use_ssl': agency.utils.utils.format_crypto(sr.crypto, CryptoTag.SSL.value),
                },
            }

    connections = email_connections
    if not label in email_connections:
        err = 'Configurazione email ''%s'' non definita.' % (label,)
        LOG.error(err, extra=agency.utils.utils.set_client_ip())
        raise Exception(err)
    options = connections[label]
    return options, get_connection(**options)


def send_email(to_email, subject, template, data, attachment=None, attachment_name=None, conn_label='default',
               conn_settings=None):
    """
    Invia una mail
    :param to_email: Indirizzo del destinatario
    :param subject: Oggetto della mail
    :param template: Template HTML della mail
    :param data: Dati da passare al template
    :param attachment: File da allegare alla mail
    :param attachment_name: nome da dare all'allegato
    :param conn_label:
    :param conn_settings: Settings per invio della mail diversi da quelli riportati sul db (test config. SMTP)
    """
    html_msg = render_to_string(template, data)
    options, connection = get_conn_from_db(conn_label, conn_settings)
    if 'from_email' in options:
        from_email = options['from_email']
    else:
        from_email = options['username']

    for i in range(5):
        try:
            if not attachment:
                send_mail(subject, '', from_email, to_email, html_message=html_msg, connection=connection)
            else:
                email = EmailMessage(subject, html_msg, from_email, to_email, connection=connection)
                for attach in attachment:
                    with open(settings.DATA_FILES_PATH + attach, 'r') as file:
                        email.attach(attach if not attachment_name else attachment_name, file.read(), 'text/csv')
                email.content_subtype = "html"
                email.send()
            LOG.info('[%s] Mail con oggetto "%s" inviata - Connection: %s' % (to_email, subject, conn_label), extra=agency.utils.utils.set_client_ip())
            return StatusCode.OK.value
        except Exception as e:
            LOG.error('[%s] Errore nell\'invio della mail con oggetto "%s" - Connection: %s' % (
                to_email, subject, conn_label), extra=agency.utils.utils.set_client_ip())
            LOG.error("Exception: {}".format(str(e)), extra=agency.utils.utils.set_client_ip())
            time.sleep(5)
            return StatusCode.EXC.value

    return StatusCode.ERROR.value

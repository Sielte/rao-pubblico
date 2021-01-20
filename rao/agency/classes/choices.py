import logging
from enum import Enum

import agency

LOG = logging.getLogger(__name__)

CHOICE_SEX = (
    ('M', 'M'),
    ('F', 'F'),
)

ADDRESS_TYPE = (
    ('Via', 'Via'),
    ('Viale', 'Viale'),
    ('Vicolo', 'Vicolo'),
    ('Strada', 'Strada'),
    ('Piazza', 'Piazza'),
    ('Piazzale', 'Piazzale'),
    ('Largo', 'Largo'),
    ('Corso', 'Corso'),
    ('Contrada', 'Contrada'),
    ('Altro', 'Altro'),
)

CARD_TYPE = (
    ('cartaIdentita', "Carta d' Identità"),
    ('passaporto', 'Passaporto'),
    ('patenteGuida', 'Patente di Guida')
)

ISSUER_TYPE = (
    ('comune', 'Comune'),
    ('questura', 'Questura'),
    ('prefettura', 'Prefettura'),
    ('motorizzazione', 'Motorizzazione'),
    ('ministeroTrasporti', 'MIT'),
    ('consolato', 'Consolato'),
    ('ambasciata', 'Ambasciata'),
)

POLICY_OID = {
    '1.3.76.16.4.1.1',
    '1.3.76.16.4.5',
    '1.3.76.16.4.12',
    '1.3.76.16.4.2.4'
}

SUPRESSED_COUNTRY = [
    'Z157',
    'Z118',
    'Z105',
    'Z135',
    'Z111',
    'Z250',
]

class CryptoTag(Enum):
    NESSUNA = 'NESSUNA'
    TLS = 'TLS'
    SSL = 'SSL'


class RequestStatus:
    IDENTIFIED = 1
    ERROR = -1
    INPROGRESS = 0


class RoleTag(Enum):
    ADMIN = 'ADMIN'
    OPERATOR = 'OPERATOR'


class AlertType(Enum):
    INFO = 'info'
    SUCCESS = 'success'
    WARNING = 'warning'
    DANGER = 'danger'


class EndpointSign(Enum):
    CREATE = 'api/create'
    ACTIVATE = 'api/activate'
    SIGN = 'api/sign'
    RESET = 'api/reset_pin'
    DISABLE = 'api/deactivate'
    UPLOAD = 'api/update_cert'
    SEND_TOKEN = 'api/send_token'
    CHANGE_SO = 'api/change_so'


class StatusCode(Enum):
    OK = 200
    ERROR = -1
    EXC = 500
    EXPIRED_TOKEN = -2
    BAD_REQUEST = 400
    NOT_FOUND = 404
    LAST_PWD = -4
    SIGN_NOT_AVAILABLE = -5
    UNAUTHORIZED = 401
    FORBIDDEN = 403


class PageRedirect(Enum):
    CHANGE_PSW = 'change_password'
    CHANGE_PIN = 'change_pin'

class CertRef(Enum):
    RootCA = "https://eidas.agid.gov.it/certificati/AgID_eIDAS_Root_CA.cer"
    SubCAIdP = "https://eidas.agid.gov.it/certificati/Sub_CA_SPID_IdP.cer"
    SubCAPriv = "https://eidas.agid.gov.it/certificati/Sub_CA_SPID_privati.cer"
    SubCAPub = "https://eidas.agid.gov.it/certificati/Sub_CA_SPID_pubblici.cer"



def get_choices_cryptotag():
    """
    Restituisce i tipi di Crittografia relativi alla config. SMTP
    :return:
    """
    try:
        return [(i.value, i.value) for i in CryptoTag]
    except:
        return []


def get_choices_roles():
    """
    Restituisce i ruoli utente (Admin/Operator)
    :return:
    """
    try:
        return [(i.role, i.role) for i in agency.models.Role.objects.all().order_by('role')]
    except:
        return []


def get_choices_address_municipality():
    """
    Restituisce i comuni e le nazioni
    :return:
    """
    try:
        municipality = [(i.code, i.name) for i in agency.models.AddressMunicipality.objects.all().order_by('name')]
        nations = get_choices_address_nation()
        return municipality + nations
    except:
        return []


def get_choices_address_city():
    """
    Restituisce le città
    :return:
    """
    try:
        return [(i.code, i.name) for i in agency.models.AddressCity.objects.all().order_by('name')]
    except:
        return []


def get_choices_address_nation():
    """
    Restituisce le nazioni
    :return:
    """
    try:
        return [(i.code, i.name) for i in agency.models.AddressNation.objects.all().order_by('name')]
    except:
        return []


def get_choices_prefix():
    """
    Restituisce i prefissi telefonici
    :return:
    """
    try:
        return [(i.prefix, i.prefix) for i in agency.models.AddressNation.objects.filter(prefix__isnull=False)]
    except:
        return []

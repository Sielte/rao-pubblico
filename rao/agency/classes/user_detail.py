# -*- coding: utf-8 -*-
# Stdlib imports
import json

# Third-party app imports

# Core Django imports

# Imports from your apps
import logging
from datetime import datetime

import agency
from agency.classes.foreign_country import ForeignCountry
from agency.models import AddressMunicipality, AddressCity, AddressNation

LOG = logging.getLogger(__name__)


class UserDetail:

    def __init__(self, identity, id_operator):
        self.id_operator = str(id_operator)
        self.name = agency.utils.utils.fix_name_surname(identity.get('name'))
        self.email = identity.get('email')
        self.familyName = agency.utils.utils.fix_name_surname(identity.get('familyName'))
        self.identificationType = 'TS'
        self.identificationSerialCode = identity.get('identificationSerialCode')
        self.identificationExpirationDate = identity.get('identificationExpirationDate')
        self.fiscalNumber = identity.get('fiscalNumber').upper()

        self.gender = identity.get('gender')
        self.pec = identity.get('formPEC') if identity.get('formPEC') != '' else None

        self.countryCallingCode = identity.get('countryCallingCode')
        self.phoneNumber = identity.get('phoneNumber')

        self.dateOfBirth = identity.get('dateOfBirth')
        self.nationOfBirth = AddressNation.objects.get(code=identity.get('nationOfBirth'))
        if self.nationOfBirth.code == 'Z000':
            self.countyOfBirth = AddressCity.objects.get(code=identity.get('countyOfBirth'))
            self.placeOfBirth = AddressMunicipality.objects.filter(code=identity.get('placeOfBirth')) \
                .exclude(dateEnd__lt=agency.utils.utils.date_converter(self.dateOfBirth)).last()
        else:
            self.countyOfBirth = ForeignCountry('EE')
            self.placeOfBirth = ForeignCountry(self.nationOfBirth.code)

        self.addressType = identity.get('addressType')
        self.addressName = identity.get('addressName')
        self.addressNumber = identity.get('addressNumber')
        self.addressPostalCode = identity.get('addressPostalCode')
        self.addressNation = AddressNation.objects.get(code=identity.get('addressNation'))
        if self.addressNation.code == 'Z000':
            self.addressCountry = AddressCity.objects.get(code=identity.get('addressCountry'))
            self.addressMunicipality = AddressMunicipality.objects.filter(code=identity.get('addressMunicipality')) \
                .exclude(dateEnd__lt=datetime.utcnow()).last()
        else:
            self.addressCountry = ForeignCountry('EE')
            self.addressMunicipality = ForeignCountry(self.addressNation.code)

        self.idCardType = identity.get('idCardType')
        self.idCardDocNumber = identity.get('idCardDocNumber').replace(' ', '').upper()
        if identity.get('typeDocRelease') != "ministeroTrasporti":
            self.idCardIssuer = identity.get('typeDocRelease') + " " + identity.get('idCardIssuer')
        else:
            self.idCardIssuer = identity.get('typeDocRelease')
        self.idCardIssueDate = identity.get('idCardIssueDate')
        self.idCardExpirationDate = identity.get('idCardExpirationDate')

    def to_json(self):
        """
        converte in Json un oggetto UserDetail
        :return:
        """
        return json.dumps(self, default=agency.utils.utils.json_default)

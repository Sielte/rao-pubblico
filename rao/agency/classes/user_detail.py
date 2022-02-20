# -*- coding: utf-8 -*-
# Stdlib imports
import json

# Third-party app imports

# Core Django imports

# Imports from your apps
import logging
from datetime import datetime
import re

import agency
from agency.classes.foreign_country import ForeignCountry
from agency.models import AddressMunicipality, AddressCity, AddressNation

LOG = logging.getLogger(__name__)


class UserDetail:

    def __init__(self, identity, id_operator):
        self.id_operator = str(id_operator)
        self.name = agency.utils.utils.capitalize_text(identity.get('name'))
        self.email = re.sub(r"[\n\t\s]*", "", identity.get('email'))
        self.familyName = agency.utils.utils.capitalize_text(identity.get('familyName'))
        self.identificationType = 'TS'
        self.identificationSerialCode = re.sub(r"[\n\t\s]*", "", identity.get('identificationSerialCode'))
        self.identificationExpirationDate = re.sub(r"[\n\t\s]*", "", identity.get('identificationExpirationDate'))
        self.fiscalNumber = re.sub(r"[\n\t\s]*", "", identity.get('fiscalNumber').upper())

        self.gender = identity.get('gender')
        self.pec = re.sub(r"[\n\t\s]*", "", identity.get('formPEC')) if identity.get('formPEC') != '' else None
        ####
        self.formCentenario = re.sub(r"[\n\t\s]*", "", identity.get('formCentenario')) if identity.get('formCentenario') != '' else None
        ####
        self.countryCallingCode = identity.get('countryCallingCode')
        self.phoneNumber = re.sub(r"[\n\t\s]*", "", identity.get('phoneNumber'))

        self.dateOfBirth = identity.get('dateOfBirth')
        self.nationOfBirth = AddressNation.objects.filter(code=identity.get('nationOfBirth')).first()
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
        self.addressPostalCode = re.sub(r"[\n\t\s]*", "", identity.get('addressPostalCode'))
        self.addressNation = AddressNation.objects.get(code=identity.get('addressNation'))
        if self.addressNation.code == 'Z000':
            self.addressCountry = AddressCity.objects.get(code=identity.get('addressCountry'))
            self.addressMunicipality = AddressMunicipality.objects.filter(code=identity.get('addressMunicipality')) \
                .exclude(dateEnd__lt=datetime.utcnow()).last()
        else:
            self.addressCountry = ForeignCountry('EE')
            self.addressMunicipality = ForeignCountry(self.addressNation.code)

        self.idCardType = identity.get('idCardType')
        self.idCardDocNumber = re.sub(r"[\n\t\s]*", "", identity.get('idCardDocNumber').upper())
        if identity.get('typeDocRelease') != "ministeroTrasporti":
            self.idCardIssuer = identity.get('typeDocRelease') + " " + agency.utils.utils.capitalize_text(identity.get('idCardIssuer'))
        else:
            self.idCardIssuer = identity.get('typeDocRelease')
        self.idCardIssueDate = re.sub(r"[\n\t\s]*", "", identity.get('idCardIssueDate'))
        self.idCardExpirationDate = re.sub(r"[\n\t\s]*", "", identity.get('idCardExpirationDate'))

    def to_json(self):
        """
        converte in Json un oggetto UserDetail
        :return:
        """
        return json.dumps(self, default=agency.utils.utils.json_default)

# -*- coding: utf-8 -*-
# Stdlib imports
import logging
import re
from datetime import datetime
from dateutil.relativedelta import relativedelta
from OpenSSL import crypto
# Third-party app imports
from codicefiscale import codicefiscale
# Core Django imports
from django.core.validators import RegexValidator
from django.forms import CharField, Form, PasswordInput, TextInput, ValidationError, ChoiceField, Select, FileField, \
    FileInput

# Imports from your apps
from .classes.choices import CARD_TYPE, ADDRESS_TYPE, CHOICE_SEX, CHOICE_CENTENARIO, ISSUER_TYPE, \
    get_choices_address_nation, \
    get_choices_address_city, get_choices_address_municipality, get_choices_prefix, \
    get_choices_cryptotag, StatusCode
from .classes.regex import regex_cap, regex_cie, regex_cf, regex_date, regex_email, regex_number, \
    regex_name, regex_password, regex_surname, regex_doc, regex_rao_name, regex_issuercode, \
    regex_pwd_email, regex_patente, regex_email_port, regex_pin, regex_dim_pin, regex_id_card_issuer
from .utils.utils import check_ts, get_certificate, set_client_ip, calculate_age
from .utils.utils_cert import verify_policy_certificate, check_expiration_certificate, verify_certificate_chain, \
    check_keylength_certificate
from .utils.utils_db import get_all_operator_cf

LOG = logging.getLogger(__name__)


class RecoveryForm(Form):
    """
    Recupero password
    """
    usernameField = CharField(widget=TextInput(attrs={'id': 'usernameField', 'name': 'usernameField'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'},
                              validators=[regex_cf])


class SetupForm(Form):
    """
    Setup iniziale
    """
    nameField = CharField(widget=TextInput(attrs={'id': 'nameField', 'name': 'nameField'}),
                          required=True,
                          error_messages={'required': 'Campo obbligatorio!'},
                          validators=[regex_name])

    surnameField = CharField(widget=TextInput(attrs={'id': 'surnameField', 'name': 'surnameField'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_surname])

    fiscalNumberField = CharField(widget=TextInput(attrs={'id': 'fiscalNumberField', 'name': 'fiscalNumberField'}),
                                  required=True,
                                  error_messages={'required': 'Campo obbligatorio!'},
                                  validators=[regex_cf])

    usernameField = CharField(widget=TextInput(attrs={'id': 'usernameField', 'name': 'usernameField'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'},
                              validators=[regex_email])

    confirmUsernameField = CharField(
        widget=TextInput(attrs={'id': 'confirmUsernameField', 'name': 'confirmUsernameField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_email])

    nameRAOField = CharField(
        widget=TextInput(attrs={'id': 'nameRAOField', 'name': 'nameRAOField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_rao_name])

    issuerCodeField = CharField(
        widget=TextInput(attrs={'id': 'issuerCodeField', 'name': 'issuerCodeField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_issuercode])

    emailRAOField = CharField(
        widget=TextInput(attrs={'id': 'emailRAOField', 'name': 'emailRAOField'}),
        required=False,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    smtpMailFromField = CharField(
        widget=TextInput(attrs={'id': 'smtpMailFromField', 'name': 'smtpMailFromField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    hostField = CharField(
        widget=TextInput(attrs={'id': 'hostField', 'name': 'hostField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    pwdRAOField = CharField(
        widget=TextInput(attrs={'id': 'pwdRAOField', 'name': 'pwdRAOField'}),
        required=False,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_pwd_email])

    cryptoMailField = ChoiceField(
        widget=Select(attrs={'id': 'cryptoMailField', 'name': 'cryptoMailField', 'title': 'Crittografia'}),
        required=True,
        choices=get_choices_cryptotag(),
        initial=None,
        error_messages={'required': 'Campo obbligatorio!'})

    emailPortField = CharField(
        widget=TextInput(attrs={'id': 'emailPortField', 'name': 'emailPortField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_email_port])

    def clean_confirmUsernameField(self):
        formUsername = self.cleaned_data.get('usernameField')
        formConfirmUsername = self.cleaned_data.get('confirmUsernameField')

        if formUsername and formUsername != formConfirmUsername:
            raise ValidationError("Le email non corrispondono!")

    def clean_hostField(self):
        host = self.cleaned_data.get('hostField')
        validIP = RegexValidator(
            regex="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", )
        validHost = RegexValidator(
            regex="^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$",
            message="Host non valido")

        try:
            validIP(host)
            return host
        except:
            pass
        validHost(host)
        return host


class LoginForm(Form):
    """
    Login
    """
    usernameField = CharField(widget=TextInput(attrs={'id': 'usernameField', 'name': 'usernameField'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'},
                              validators=[regex_cf])

    passwordField = CharField(widget=PasswordInput(attrs={'id': 'passwordField', 'name': 'passwordField'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'})


class ChangePasswordForm(Form):
    """
    Cambio password
    """
    passwordField = CharField(widget=PasswordInput(attrs={'id': 'passwordField', 'name': 'passwordField'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'},
                              validators=[regex_password])

    confirmPasswordField = CharField(
        widget=PasswordInput(attrs={'id': 'confirmPasswordField', 'name': 'confirmPasswordField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    def clean_confirmPasswordField(self):
        formPassword = self.cleaned_data.get('passwordField')
        formConfirmPassword = self.cleaned_data.get('confirmPasswordField')

        if formPassword and formPassword != formConfirmPassword:
            LOG.warning("Conferma password diversa da password.", extra=set_client_ip())
            raise ValidationError("Le password non corrispondono!")
        return


class ChangePinFileForm(Form):
    """
    Cambio pin con upload del certificato
    """
    oldPinField = CharField(widget=PasswordInput(attrs={'id': 'oldPinField', 'name': 'oldPinField'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_dim_pin])

    newPinField = CharField(widget=PasswordInput(attrs={'id': 'newPinField', 'name': 'newPinField'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_dim_pin])

    confirmPinField = CharField(widget=PasswordInput(attrs={'id': 'confirmPinField', 'name': 'confirmPinField'}),
                                required=True,
                                error_messages={'required': 'Campo obbligatorio!'},
                                validators=[regex_dim_pin])

    uploadCertificate = FileField(required=True,
                                  error_messages={'required': 'Campo obbligatorio!'},
                                  widget=FileInput(
                                      attrs={'id': 'uploadCertificate'}))
    uploadPrivateKey = FileField(required=True,
                                 error_messages={'required': 'Campo obbligatorio!'},
                                 widget=FileInput(
                                     attrs={'id': 'uploadPrivateKey'}))

    formPin = None
    cert = None

    def clean_newPinField(self):
        self.formPin = self.cleaned_data.get('newPinField')
        if not self.formPin or (self.formPin and re.match(regex_pin, self.formPin)):
            raise ValidationError("Il pin non può avere cifre uguali o crescenti!")
        return

    def clean_confirmPinField(self):
        formConfirmPin = self.cleaned_data.get('confirmPinField')

        if not self.formPin or (self.formPin and self.formPin != formConfirmPin):
            raise ValidationError("I PIN non corrispondono!")
        return

    def clean_uploadCertificate(self):
        uploadCertificate = self.cleaned_data.get('uploadCertificate')
        if not uploadCertificate:
            raise ValidationError("Il certificato selezionato non è valido!")
        self.cert = get_certificate(uploadCertificate)
        if "BEGIN RSA PRIVATE KEY" in self.cert:
            self.cert = None
            LOG.error("Chiave privata presente - Certificato non valido", extra=set_client_ip())
            raise ValidationError("Il certificato non deve contenere la chiave privata!")
        if not check_keylength_certificate(self.cert):
            LOG.error("Lunghezza chiave non conforme", extra=set_client_ip())
            raise ValidationError("Lunghezza chiave non conforme")
        if not check_expiration_certificate(self.cert):
            LOG.error("Certificato scaduto", extra=set_client_ip())
            raise ValidationError("Certificato scaduto")
        if not verify_policy_certificate(self.cert):
            LOG.error("Policy del certificato non valide", extra=set_client_ip())
            raise ValidationError("Policy del certificato non valide")
        result, message = verify_certificate_chain(self.cert)
        if result != StatusCode.OK.value:
            raise ValidationError(message)
        return

    def clean_uploadPrivateKey(self):
        uploadPrivateKey = self.cleaned_data.get('uploadPrivateKey')
        if not self.cert:
            raise ValidationError("Devi prima caricare il certificato!")
        if not uploadPrivateKey:
            raise ValidationError("La chiave privata selezionata non è valida!")
        pk = get_certificate(uploadPrivateKey)
        if "BEGIN CERTIFICATE" in pk:
            LOG.error("Certificato presente - Chiave privata non valida", extra=set_client_ip())
            raise ValidationError("La chiave privata non deve contenere il certificato!")
        cert = pk + "\n" + self.cert
        try:
            crypto.load_certificate(crypto.FILETYPE_PEM, cert.encode())
        except Exception as e:
            LOG.error("Warning: {}".format(str(e)), extra=set_client_ip())
            raise ValidationError("La chiave privata selezionata non è valida!")
        try:
            crypto.load_privatekey(crypto.FILETYPE_PEM, cert.encode())
        except Exception as e:
            LOG.error("Warning: {}".format(str(e)), extra=set_client_ip())
            raise ValidationError("La chiave privata selezionata non è valida!")
        return


class ChangePinForm(Form):
    """
    Cambio pin
    """
    oldPinField = CharField(widget=PasswordInput(attrs={'id': 'oldPinField', 'name': 'oldPinField'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_dim_pin])

    newPinField = CharField(widget=PasswordInput(attrs={'id': 'newPinField', 'name': 'newPinField'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_dim_pin])

    confirmPinField = CharField(widget=PasswordInput(attrs={'id': 'confirmPinField', 'name': 'confirmPinField'}),
                                required=True,
                                error_messages={'required': 'Campo obbligatorio!'},
                                validators=[regex_dim_pin])

    formPin = None

    def clean_newPinField(self):
        self.formPin = self.cleaned_data.get('newPinField')
        if not self.formPin or (self.formPin and re.match(regex_pin, self.formPin)):
            raise ValidationError(
                "Il PIN inserito deve essere formato da 6 cifre numeriche. Non può essere una sequenza decrescente o"
                " crescente o ripetizione di caratteri uguali.")
        return

    def clean_confirmPinField(self):
        formConfirmPin = self.cleaned_data.get('confirmPinField')

        if not self.formPin or (self.formPin and self.formPin != formConfirmPin):
            raise ValidationError("I PIN non corrispondono!")
        return


class NewOperatorForm(Form):
    """
    Inserimento nuovo operatore
    """
    name = CharField(widget=TextInput(attrs={'id': 'name', 'name': 'name'}),
                     required=True,
                     error_messages={'required': 'Campo obbligatorio!'},
                     validators=[regex_name])

    familyName = CharField(widget=TextInput(attrs={'id': 'familyName', 'name': 'familyName'}),
                           required=True,
                           error_messages={'required': 'Campo obbligatorio!'},
                           validators=[regex_surname])

    fiscalNumber = CharField(widget=TextInput(attrs={'id': 'fiscalNumber', 'name': 'fiscalNumber'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_cf])

    email = CharField(widget=TextInput(attrs={'id': 'email', 'name': 'email'}),
                      required=True,
                      error_messages={'required': 'Campo obbligatorio!'},
                      validators=[regex_email])

    confirmEmail = CharField(widget=TextInput(attrs={'id': 'confirmEmail', 'name': 'confirmEmail'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_email])

    def clean_confirmEmail(self):
        email = self.cleaned_data.get('email')
        confirmEmail = self.cleaned_data.get('confirmEmail')

        if email and email != confirmEmail:
            raise ValidationError("Le email non corrispondono!")
        return

    def clean_fiscalNumber(self):
        surname_name_cf = self.cleaned_data.get('fiscalNumber').upper()[0:6]
        try:
            encode_name_surname = codicefiscale.encode_surname(self.cleaned_data.get('familyName')) + \
                                  codicefiscale.encode_name(self.cleaned_data.get('name'))

            if surname_name_cf == encode_name_surname:
                return
            else:
                raise ValidationError("Il codice fiscale non corrisponde con i dati inseriti")
        except Exception as e:
            LOG.warning(
                "{} - Codice fiscale non corrisponde con dati anagrafici".format(self.cleaned_data.get('fiscalNumber')),
                extra=set_client_ip())
            raise ValidationError("Il codice fiscale non corrisponde con i dati inseriti")


class NewOperatorPinForm(Form):
    """
    Inserimento nuovo operatore con controllo su pin
    """
    name = CharField(widget=TextInput(attrs={'id': 'name', 'name': 'name'}),
                     required=True,
                     error_messages={'required': 'Campo obbligatorio!'},
                     validators=[regex_name])

    familyName = CharField(widget=TextInput(attrs={'id': 'familyName', 'name': 'familyName'}),
                           required=True,
                           error_messages={'required': 'Campo obbligatorio!'},
                           validators=[regex_surname])

    fiscalNumber = CharField(widget=TextInput(attrs={'id': 'fiscalNumber', 'name': 'fiscalNumber'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_cf])

    email = CharField(widget=TextInput(attrs={'id': 'email', 'name': 'email'}),
                      required=True,
                      error_messages={'required': 'Campo obbligatorio!'},
                      validators=[regex_email])

    confirmEmail = CharField(widget=TextInput(attrs={'id': 'confirmEmail', 'name': 'confirmEmail'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_email])

    pinField = CharField(widget=TextInput(attrs={'id': 'pinField', 'name': 'pinField'}),
                         required=True,
                         error_messages={'required': 'Campo obbligatorio!'},
                         validators=[regex_dim_pin])

    def clean_confirmEmail(self):
        email = self.cleaned_data.get('email')
        confirmEmail = self.cleaned_data.get('confirmEmail')

        if email and email != confirmEmail:
            raise ValidationError("Le email non corrispondono!")
        return

    def clean_fiscalNumber(self):
        surname_name_cf = self.cleaned_data.get('fiscalNumber').upper()[0:6]
        try:
            encode_name_surname = codicefiscale.encode_surname(self.cleaned_data.get('familyName')) + \
                                  codicefiscale.encode_name(self.cleaned_data.get('name'))

            if surname_name_cf == encode_name_surname:
                return
            else:
                raise ValidationError("Il codice fiscale non corrisponde con i dati inseriti")
        except Exception as e:
            LOG.warning("Warning: {}".format(str(e)), extra=set_client_ip())
            raise ValidationError("Il codice fiscale non corrisponde con i dati inseriti")


class NewIdentityForm(Form):
    """
    Nuova richiesta identità
    """

    def __init__(self, *args, **kwargs):
        super(NewIdentityForm, self).__init__(*args, **kwargs)
        self.fields['countryCallingCode'].choices = get_choices_prefix()
        self.fields['nationOfBirth'].choices = get_choices_address_nation()
        self.fields['countyOfBirth'].choices = get_choices_address_city()
        self.fields['placeOfBirth'].choices = get_choices_address_municipality()
        self.fields['addressNation'].choices = get_choices_address_nation()
        self.fields['addressCountry'].choices = get_choices_address_city()
        self.fields['addressMunicipality'].choices = get_choices_address_municipality()

    name = CharField(widget=TextInput(attrs={'id': 'name', 'name': 'name'}),
                     required=True,
                     error_messages={'required': 'Campo obbligatorio!'},
                     validators=[regex_name])

    familyName = CharField(widget=TextInput(attrs={'id': 'familyName', 'name': 'familyName'}),
                           required=True,
                           error_messages={'required': 'Campo obbligatorio!'},
                           validators=[regex_surname])

    gender = ChoiceField(widget=Select(attrs={'id': 'gender', 'name': 'gender'}),
                         required=True,
                         choices=CHOICE_SEX,
                         error_messages={'required': 'Campo obbligatorio!'})

    identificationSerialCode = CharField(
        widget=TextInput(attrs={'id': 'identificationSerialCode', 'name': 'identificationSerialCode'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    identificationExpirationDate = CharField(
        widget=TextInput(attrs={'id': 'identificationExpirationDate', 'name': 'identificationExpirationDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    dateOfBirth = CharField(widget=TextInput(attrs={'id': 'dateOfBirth', 'name': 'dateOfBirth'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_date])

    nationOfBirth = ChoiceField(widget=Select(
        attrs={'id': 'nationOfBirth', 'name': 'nationOfBirth', 'title': 'Nazione*',
               'aria-describedby': 'nationOfBirthHelp'}),
        choices=get_choices_address_nation(),
        initial=0,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    countyOfBirth = ChoiceField(widget=Select(
        attrs={'id': 'countyOfBirth', 'name': 'countyOfBirth'}),
        choices=get_choices_address_city(),
        required=False)

    placeOfBirth = ChoiceField(widget=Select(attrs={'id': 'placeOfBirth', 'name': 'placeOfBirth'}),
                               choices=get_choices_address_municipality(),
                               required=False)

    fiscalNumber = CharField(widget=TextInput(attrs={'id': 'fiscalNumber', 'name': 'fiscalNumber'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_cf])

    email = CharField(widget=TextInput(attrs={'id': 'email', 'name': 'email'}),
                      required=True,
                      error_messages={'required': 'Campo obbligatorio!'},
                      validators=[regex_email])

    confirmEmail = CharField(widget=TextInput(attrs={'id': 'confirmEmail', 'name': 'confirmEmail'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_email])

    countryCallingCode = ChoiceField(widget=Select(
        attrs={'id': 'countryCallingCode', 'name': 'countryCallingCode', 'title': 'Prefisso Internazionale*',
               'aria-describedby': "countryCallingCodeHelp", "data-live-search": "true",
               "data-live-search-placeholder": "Seleziona il prefisso",
               }),
        initial='+39',
        choices=get_choices_prefix(),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    phoneNumber = CharField(widget=TextInput(attrs={'id': 'phoneNumber', 'name': 'phoneNumber'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_number])

    confirmPhoneNumber = CharField(widget=TextInput(attrs={'id': 'confirmPhoneNumber', 'name': 'confirmPhoneNumber'}),
                                   required=True,
                                   error_messages={'required': 'Campo obbligatorio!'},
                                   validators=[regex_number])

    formPEC = CharField(widget=TextInput(attrs={'id': 'formPEC', 'name': 'formPEC'}),
                        required=False,
                        validators=[regex_email])

    addressType = ChoiceField(widget=Select(
        attrs={'id': 'addressType', 'name': 'addressType', 'title': 'Tipo*', 'aria-describedby': "addressTypeHelp"}),
        choices=ADDRESS_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    addressName = CharField(widget=TextInput(attrs={'id': 'addressName', 'name': 'addressName'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'}, )

    addressNumber = CharField(widget=TextInput(attrs={'id': 'addressNumber', 'name': 'addressNumber'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'})

    addressPostalCode = CharField(widget=TextInput(attrs={'id': 'addressPostalCode', 'name': 'addressPostalCode'}),
                                  required=True,
                                  error_messages={'required': 'Campo obbligatorio!'},
                                  validators=[regex_cap])

    addressNation = ChoiceField(widget=Select(
        attrs={'id': 'addressNation', 'name': 'addressNation', 'title': 'Nazione Domicilio*',
               'aria-describedby': "addressNationHelp", 'data-live-search': "true",
               'data-live-search-placeholder': "Cerca la tua nazione"}),
        choices=get_choices_address_nation(),
        initial=('Z000', 'Italia'),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    addressCountry = ChoiceField(widget=Select(
        attrs={'id': 'addressCountry', 'name': 'addressCountry', 'title': 'Provincia/Stato Estero*',
               'aria-describedby': "addressCountryHelp"}),
        choices=get_choices_address_city(),
        required=False)

    addressMunicipality = ChoiceField(widget=Select(
        attrs={'id': 'addressMunicipality', 'name': 'addressMunicipality'}),
        choices=get_choices_address_municipality(),
        required=False)

    idCardType = ChoiceField(widget=Select(
        attrs={'id': 'idCardType', 'name': 'idCardType', 'title': 'Tipo*', 'aria-describedby': "idCardTypeHelp"}),
        choices=CARD_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    idCardDocNumber = CharField(widget=TextInput(attrs={'id': 'idCardDocNumber'}),
                                required=True,
                                error_messages={'required': 'Campo obbligatorio!'})

    typeDocRelease = ChoiceField(widget=Select(
        attrs={'id': 'typeDocRelease', 'name': 'typeDocRelease', 'title': 'Ente*',
               'aria-describedby': "typeDocReleaseHelp"}),
        choices=ISSUER_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    idCardIssuer = CharField(widget=TextInput(attrs={'id': 'idCardIssuer'}),
                             required=False,
                             error_messages={'required': 'Campo obbligatorio!'})

    idCardIssueDate = CharField(
        widget=TextInput(attrs={'id': 'idCardIssueDate', 'name': 'idCardIssueDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    idCardExpirationDate = CharField(
        widget=TextInput(attrs={'id': 'idCardExpirationDate', 'name': 'idCardExpirationDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    # formCentenario = CharField(widget=TextInput(attrs={'id': 'formCentenario', 'name': 'formCentenario'}),
    #                           required=False)
    formCentenario = ChoiceField(widget=Select(attrs={'id': 'formCentenario', 'name': 'formCentenario'}),
                                 required=False,
                                 choices=CHOICE_CENTENARIO)

    def clean_addressCountry(self):
        addressNation = self.cleaned_data.get('addressNation')
        addressCountry = self.cleaned_data.get('addressCountry')
        if addressNation == 'Z000' and not addressCountry:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_addressMunicipality(self):
        addressNation = self.cleaned_data.get('addressNation')
        addressMunicipality = self.cleaned_data.get('addressMunicipality')
        if addressNation == 'Z000' and not addressMunicipality:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_countyOfBirth(self):
        nationOfBirth = self.cleaned_data.get('nationOfBirth')
        countyOfBirth = self.cleaned_data.get('countyOfBirth')
        if nationOfBirth == 'Z000' and not countyOfBirth:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_placeOfBirth(self):
        nationOfBirth = self.cleaned_data.get('nationOfBirth')
        placeOfBirth = self.cleaned_data.get('placeOfBirth')
        if nationOfBirth == 'Z000' and not placeOfBirth:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_fiscalNumber(self):
        fiscalNumber = self.cleaned_data.get('fiscalNumber').upper()
        message = "Il codice fiscale inserito non è valido"
        try:
            isvalid = codicefiscale.is_valid(fiscalNumber) or codicefiscale.is_omocode(fiscalNumber)
            birth_date = codicefiscale.decode(fiscalNumber)['birthdate']
            if isvalid and calculate_age(birth_date) < 18:
                isvalid = False
                message = "Il codice fiscale inserito deve appartenere ad un maggiorenne"

            if isvalid and fiscalNumber in get_all_operator_cf():
                isvalid = False
                message = "Il codice fiscale inserito non deve appartenere ad un operatore/admin"

        except Exception as e:
            LOG.warning("Warning: {}".format(str(e)), extra=set_client_ip())
            isvalid = False

        if not isvalid:
            raise ValidationError(message)
        return

    def clean_confirmPhoneNumber(self):
        phoneNumber = self.cleaned_data.get('phoneNumber')
        confirmPhoneNumber = self.cleaned_data.get('confirmPhoneNumber')

        if phoneNumber and phoneNumber != confirmPhoneNumber:
            raise ValidationError("I numeri di telefono non corrispondono!")

        return

    def clean_confirmEmail(self):
        email = self.cleaned_data.get('email')
        confirmEmail = self.cleaned_data.get('confirmEmail')

        if email and email != confirmEmail:
            raise ValidationError("Le email non corrispondono!")
        return

    def clean_identificationSerialCode(self):
        identificationSerialCode = self.cleaned_data.get('identificationSerialCode')
        if check_ts(identificationSerialCode.replace(' ', '')):
            return
        raise ValidationError("Codice di identificazione non valido!")

    id_card_type = None

    def clean_idCardDocNumber(self):
        idCardDocNumber = self.cleaned_data.get('idCardDocNumber')
        self.id_card_type = self.cleaned_data.get('idCardType')

        if self.id_card_type == 'cartaIdentita':
            is_valid = (re.compile(regex_cie.regex).match(idCardDocNumber) or re.compile(regex_doc.regex).match(
                idCardDocNumber))
        elif self.id_card_type == 'patenteGuida':
            is_valid = re.compile(regex_patente.regex).match(idCardDocNumber)
        else:
            is_valid = re.compile(regex_doc.regex).match(idCardDocNumber)

        if not is_valid:
            raise ValidationError("Numero di documento non valido!")
        return

    issue_date = None

    def clean_idCardIssuer(self):
        type_doc_release = self.cleaned_data.get('typeDocRelease')
        if type_doc_release != 'ministeroTrasporti':
            id_card_issuer = self.cleaned_data.get('idCardIssuer')
            if id_card_issuer == '':
                raise ValidationError("Campo obbligatorio!")
            elif not re.match(regex_id_card_issuer, id_card_issuer):
                raise ValidationError("Il campo deve iniziare con una maiuscola, seguito da minuscole.")
        return

    def clean_idCardIssueDate(self):
        self.issue_date = datetime.strptime(self.cleaned_data.get('idCardIssueDate'), '%d/%m/%Y').date()
        today = datetime.today().date()
        if self.issue_date <= today:
            return
        raise ValidationError("Data di rilascio non valida.")


class NewIdentityPinForm(Form):
    """
    Nuova richiesta identità con verifica sul pin
    """

    def __init__(self, *args, **kwargs):
        super(NewIdentityPinForm, self).__init__(*args, **kwargs)
        self.fields['countryCallingCode'].choices = get_choices_prefix()
        self.fields['nationOfBirth'].choices = get_choices_address_nation()
        self.fields['countyOfBirth'].choices = get_choices_address_city()
        self.fields['placeOfBirth'].choices = get_choices_address_municipality()
        self.fields['addressNation'].choices = get_choices_address_nation()
        self.fields['addressCountry'].choices = get_choices_address_city()
        self.fields['addressMunicipality'].choices = get_choices_address_municipality()

    name = CharField(widget=TextInput(attrs={'id': 'name', 'name': 'name'}),
                     required=True,
                     error_messages={'required': 'Campo obbligatorio!'},
                     validators=[regex_name])

    familyName = CharField(widget=TextInput(attrs={'id': 'familyName', 'name': 'familyName'}),
                           required=True,
                           error_messages={'required': 'Campo obbligatorio!'},
                           validators=[regex_surname])

    gender = ChoiceField(widget=Select(attrs={'id': 'gender', 'name': 'gender'}),
                         required=True,
                         choices=CHOICE_SEX,
                         error_messages={'required': 'Campo obbligatorio!'})

    identificationSerialCode = CharField(
        widget=TextInput(attrs={'id': 'identificationSerialCode', 'name': 'identificationSerialCode'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    identificationExpirationDate = CharField(
        widget=TextInput(attrs={'id': 'identificationExpirationDate', 'name': 'identificationExpirationDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    dateOfBirth = CharField(widget=TextInput(attrs={'id': 'dateOfBirth', 'name': 'dateOfBirth'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_date])

    nationOfBirth = ChoiceField(widget=Select(
        attrs={'id': 'nationOfBirth', 'name': 'nationOfBirth', 'title': 'Nazione*',
               'aria-describedby': 'nationOfBirthHelp'}),
        choices=get_choices_address_nation(),
        initial=0,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    countyOfBirth = ChoiceField(widget=Select(
        attrs={'id': 'countyOfBirth', 'name': 'countyOfBirth'}),
        choices=get_choices_address_city(),
        required=False)

    placeOfBirth = ChoiceField(widget=Select(attrs={'id': 'placeOfBirth', 'name': 'placeOfBirth'}),
                               choices=get_choices_address_municipality(),
                               required=False)

    fiscalNumber = CharField(widget=TextInput(attrs={'id': 'fiscalNumber', 'name': 'fiscalNumber'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_cf])

    email = CharField(widget=TextInput(attrs={'id': 'email', 'name': 'email'}),
                      required=True,
                      error_messages={'required': 'Campo obbligatorio!'},
                      validators=[regex_email])

    confirmEmail = CharField(widget=TextInput(attrs={'id': 'confirmEmail', 'name': 'confirmEmail'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_email])

    countryCallingCode = ChoiceField(widget=Select(
        attrs={'id': 'countryCallingCode', 'name': 'countryCallingCode', 'title': 'Prefisso Internazionale*',
               'aria-describedby': "countryCallingCodeHelp", "data-live-search": "true",
               "data-live-search-placeholder": "Seleziona il prefisso",
               }),
        initial='+39',
        choices=get_choices_prefix(),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    phoneNumber = CharField(widget=TextInput(attrs={'id': 'phoneNumber', 'name': 'phoneNumber'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'},
                            validators=[regex_number])

    confirmPhoneNumber = CharField(widget=TextInput(attrs={'id': 'confirmPhoneNumber', 'name': 'confirmPhoneNumber'}),
                                   required=True,
                                   error_messages={'required': 'Campo obbligatorio!'},
                                   validators=[regex_number])

    formPEC = CharField(widget=TextInput(attrs={'id': 'formPEC', 'name': 'formPEC'}),
                        required=False,
                        validators=[regex_email])

    addressType = ChoiceField(widget=Select(
        attrs={'id': 'addressType', 'name': 'addressType', 'title': 'Tipo*', 'aria-describedby': "addressTypeHelp"}),
        choices=ADDRESS_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    addressName = CharField(widget=TextInput(attrs={'id': 'addressName', 'name': 'addressName'}),
                            required=True,
                            error_messages={'required': 'Campo obbligatorio!'}, )

    addressNumber = CharField(widget=TextInput(attrs={'id': 'addressNumber', 'name': 'addressNumber'}),
                              required=True,
                              error_messages={'required': 'Campo obbligatorio!'})

    addressPostalCode = CharField(widget=TextInput(attrs={'id': 'addressPostalCode', 'name': 'addressPostalCode'}),
                                  required=True,
                                  error_messages={'required': 'Campo obbligatorio!'},
                                  validators=[regex_cap])

    addressNation = ChoiceField(widget=Select(
        attrs={'id': 'addressNation', 'name': 'addressNation', 'title': 'Nazione Domicilio*',
               'aria-describedby': "addressNationHelp", 'data-live-search': "true",
               'data-live-search-placeholder': "Cerca la tua nazione"}),
        choices=get_choices_address_nation(),
        initial=('Z000', 'Italia'),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    addressCountry = ChoiceField(widget=Select(
        attrs={'id': 'addressCountry', 'name': 'addressCountry', 'title': 'Provincia/Stato Estero*',
               'aria-describedby': "addressCountryHelp"}),
        choices=get_choices_address_city(),
        required=False)

    addressMunicipality = ChoiceField(widget=Select(
        attrs={'id': 'addressMunicipality', 'name': 'addressMunicipality'}),
        choices=get_choices_address_municipality(),
        required=False)

    idCardType = ChoiceField(widget=Select(
        attrs={'id': 'idCardType', 'name': 'idCardType', 'title': 'Tipo*', 'aria-describedby': "idCardTypeHelp"}),
        choices=CARD_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    idCardDocNumber = CharField(widget=TextInput(attrs={'id': 'idCardDocNumber'}),
                                required=True,
                                error_messages={'required': 'Campo obbligatorio!'})

    typeDocRelease = ChoiceField(widget=Select(
        attrs={'id': 'typeDocRelease', 'name': 'typeDocRelease', 'title': 'Ente*',
               'aria-describedby': "typeDocReleaseHelp"}),
        choices=ISSUER_TYPE,
        required=True,
        error_messages={'required': 'Campo obbligatorio!'})

    idCardIssuer = CharField(widget=TextInput(attrs={'id': 'idCardIssuer'}),
                             required=False,
                             error_messages={'required': 'Campo obbligatorio!'})

    idCardIssueDate = CharField(
        widget=TextInput(attrs={'id': 'idCardIssueDate', 'name': 'idCardIssueDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    idCardExpirationDate = CharField(
        widget=TextInput(attrs={'id': 'idCardExpirationDate', 'name': 'idCardExpirationDate'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_date])

    pinField = CharField(widget=TextInput(attrs={'id': 'pinField', 'name': 'pinField'}),
                         required=True,
                         error_messages={'required': 'Campo obbligatorio!'},
                         validators=[regex_dim_pin])

    formCentenario = ChoiceField(widget=Select(attrs={'id': 'formCentenario', 'name': 'formCentenario'}),
                                 required=False,
                                 choices=CHOICE_CENTENARIO)

    def clean_addressCountry(self):
        addressNation = self.cleaned_data.get('addressNation')
        addressCountry = self.cleaned_data.get('addressCountry')
        if addressNation == 'Z000' and not addressCountry:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_pinField(self):
        pinField = self.cleaned_data.get('pinField')
        if pinField and re.match(regex_pin, pinField):
            raise ValidationError("Il pin non può avere cifre uguali o crescenti!")
        return

    def clean_addressMunicipality(self):
        addressNation = self.cleaned_data.get('addressNation')
        addressMunicipality = self.cleaned_data.get('addressMunicipality')
        if addressNation == 'Z000' and not addressMunicipality:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_countyOfBirth(self):
        nationOfBirth = self.cleaned_data.get('nationOfBirth')
        countyOfBirth = self.cleaned_data.get('countyOfBirth')
        if nationOfBirth == 'Z000' and not countyOfBirth:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_placeOfBirth(self):
        nationOfBirth = self.cleaned_data.get('nationOfBirth')
        placeOfBirth = self.cleaned_data.get('placeOfBirth')
        if nationOfBirth == 'Z000' and not placeOfBirth:
            raise ValidationError("Campo obbligatorio!")
        return

    def clean_fiscalNumber(self):
        fiscalNumber = self.cleaned_data.get('fiscalNumber').upper()
        message = "Il codice fiscale inserito non è valido"
        try:
            isvalid = codicefiscale.is_valid(fiscalNumber) or codicefiscale.is_omocode(fiscalNumber)
            birth_date = codicefiscale.decode(fiscalNumber)['birthdate']
            if isvalid and calculate_age(birth_date) < 18:
                isvalid = False
                message = "Il codice fiscale inserito deve appartenere ad una persona maggiorenne"

            if isvalid and fiscalNumber in get_all_operator_cf():
                isvalid = False
                message = "Il codice fiscale inserito non deve appartenere ad un operatore/admin"

        except Exception as e:
            LOG.warning("Warning: {}".format(str(e)), extra=set_client_ip())
            isvalid = False

        if not isvalid:
            raise ValidationError(message)
        return

    def clean_confirmPhoneNumber(self):
        phoneNumber = self.cleaned_data.get('phoneNumber')
        confirmPhoneNumber = self.cleaned_data.get('confirmPhoneNumber')

        if phoneNumber and phoneNumber != confirmPhoneNumber:
            raise ValidationError("I numeri di telefono non corrispondono!")

        return

    def clean_confirmEmail(self):
        email = self.cleaned_data.get('email')
        confirmEmail = self.cleaned_data.get('confirmEmail')

        if email and email != confirmEmail:
            raise ValidationError("Le email non corrispondono!")
        return

    def clean_identificationSerialCode(self):
        identificationSerialCode = self.cleaned_data.get('identificationSerialCode')
        if check_ts(identificationSerialCode.replace(' ', '')):
            return
        raise ValidationError("Codice di identificazione non valido!")

    id_card_type = None

    def clean_idCardDocNumber(self):
        idCardDocNumber = self.cleaned_data.get('idCardDocNumber')
        self.id_card_type = self.cleaned_data.get('idCardType')

        if self.id_card_type == 'cartaIdentita':
            is_valid = (re.compile(regex_cie.regex).match(idCardDocNumber) or re.compile(regex_doc.regex).match(
                idCardDocNumber))
        elif self.id_card_type == 'patenteGuida':
            is_valid = re.compile(regex_patente.regex).match(idCardDocNumber)
        else:
            is_valid = re.compile(regex_doc.regex).match(idCardDocNumber)

        if not is_valid:
            raise ValidationError("Numero di documento non valido!")
        return

    issue_date = None

    def clean_idCardIssuer(self):
        type_doc_release = self.cleaned_data.get('typeDocRelease')
        if type_doc_release != 'ministeroTrasporti':
            id_card_issuer = self.cleaned_data.get('idCardIssuer')
            if id_card_issuer == '':
                raise ValidationError("Campo obbligatorio!")
            elif not re.match(regex_id_card_issuer, id_card_issuer):
                raise ValidationError("Il campo deve iniziare con una maiuscola, seguito da minuscole.")

        return

    def clean_idCardIssueDate(self):
        self.issue_date = datetime.strptime(self.cleaned_data.get('idCardIssueDate'), '%d/%m/%Y').date()
        today = datetime.today().date()
        if self.issue_date <= today:
            return
        raise ValidationError("Data di rilascio non valida.")


class ErrorSetupForm(Form):
    """
    Modifica dati nel messaggio di errore del setup
    """
    fiscalNumber = CharField(widget=TextInput(attrs={'id': 'fiscalNumber', 'name': 'fiscalNumber'}),
                             required=True,
                             error_messages={'required': 'Campo obbligatorio!'},
                             validators=[regex_cf])

    issuerCode = CharField(
        widget=TextInput(attrs={'id': 'issuerCode', 'name': 'issuerCode'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_issuercode])


class CertSetupForm(Form):
    """
    Upload certificato
    """
    uploadCertificate = FileField(required=True,
                                  widget=FileInput(
                                      attrs={'id': 'uploadCertificate'}))

    uploadPrivateKey = FileField(required=True,
                                 widget=FileInput(
                                     attrs={'id': 'uploadPrivateKey'}))

    pinField = CharField(widget=PasswordInput(attrs={'id': 'pinField', 'name': 'pinField'}),
                         required=True,
                         error_messages={'required': 'Campo obbligatorio!'},
                         validators=[regex_dim_pin])

    cert = None

    def clean_uploadCertificate(self):
        uploadCertificate = self.cleaned_data.get('uploadCertificate')
        if not uploadCertificate:
            raise ValidationError("Il certificato selezionato non è valido!")
        self.cert = get_certificate(uploadCertificate)
        if "BEGIN RSA PRIVATE KEY" in self.cert:
            self.cert = None
            LOG.error("Chiave privata presente - Certificato non valido", extra=set_client_ip())
            raise ValidationError("Il certificato non deve contenere la chiave privata!")
        if not check_keylength_certificate(self.cert):
            LOG.error("Lunghezza chiave non conforme", extra=set_client_ip())
            raise ValidationError("Lunghezza chiave non conforme")
        if not check_expiration_certificate(self.cert):
            LOG.error("Certificato scaduto", extra=set_client_ip())
            raise ValidationError("Certificato scaduto")
        if not verify_policy_certificate(self.cert):
            LOG.error("Policy del certificato non valide", extra=set_client_ip())
            raise ValidationError("Policy del certificato non valide")
        result, message = verify_certificate_chain(self.cert)
        if result != StatusCode.OK.value:
            raise ValidationError(message)
        return

    def clean_uploadPrivateKey(self):
        uploadPrivateKey = self.cleaned_data.get('uploadPrivateKey')
        if not self.cert:
            raise ValidationError("Devi prima caricare il certificato!")
        if not uploadPrivateKey:
            raise ValidationError("La chiave privata selezionata non è valida!")
        pk = get_certificate(uploadPrivateKey)
        if "BEGIN CERTIFICATE" in pk:
            LOG.error("Certificato presente - Chiave privata non valida", extra=set_client_ip())
            raise ValidationError("La chiave privata non deve contenere il certificato!")
        cert = pk + "\n" + self.cert
        try:
            crypto.load_certificate(crypto.FILETYPE_PEM, cert.encode())
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
            raise ValidationError("La chiave privata selezionata non è valida!")
        try:
            crypto.load_privatekey(crypto.FILETYPE_PEM, cert.encode())
        except Exception as e:
            LOG.error("Exception: {}".format(str(e)), extra=set_client_ip())
            raise ValidationError("La chiave privata selezionata non è valida!")
        return

    def clean_pinField(self):
        pinField = self.cleaned_data.get('pinField')
        if pinField and re.match(regex_pin, pinField):
            raise ValidationError("Il pin non può avere cifre uguali o crescenti!")
        return


class EmailSetupForm(Form):
    """
    Upload SMTP
    """

    emailRAOField = CharField(
        widget=TextInput(attrs={'id': 'emailRAOField', 'name': 'emailRAOField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    smtpMailFromField = CharField(
        widget=TextInput(attrs={'id': 'smtpMailFromField', 'name': 'smtpMailFromField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    hostField = CharField(
        widget=TextInput(attrs={'id': 'hostField', 'name': 'hostField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
    )

    pwdRAOField = CharField(
        widget=TextInput(attrs={'id': 'pwdRAOField', 'name': 'pwdRAOField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_pwd_email])

    cryptoMailField = ChoiceField(
        widget=Select(attrs={'id': 'cryptoMailField', 'name': 'cryptoMailField', 'title': 'Crittografia'}),
        required=True,
        choices=get_choices_cryptotag(),
        initial=None,
        error_messages={'required': 'Campo obbligatorio!'})

    emailPortField = CharField(
        widget=TextInput(attrs={'id': 'emailPortField', 'name': 'emailPortField'}),
        required=True,
        error_messages={'required': 'Campo obbligatorio!'},
        validators=[regex_email_port])

    def clean_hostField(self):
        host = self.cleaned_data.get('hostField')
        validIP = RegexValidator(
            regex="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", )
        validHost = RegexValidator(
            regex="^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$",
            message="Host non valido")

        try:
            validIP(host)
            return host
        except:
            pass
        validHost(host)
        return host

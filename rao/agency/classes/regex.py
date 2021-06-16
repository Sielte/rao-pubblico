from django.core.validators import RegexValidator

passphrase_expression = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!$?#=*+-.:])"

regex_name = RegexValidator(regex=r"^[A-zÀ-ù'\-, ]{2,}$",
                            message="Il campo nome deve contenere almeno 2 caratteri e non può contenere alcuni caratteri speciali.")



regex_surname = RegexValidator(regex=r"^[A-zÀ-ù'\-, ]{2,}$",
                               message="Il campo cognome deve contenere almeno 2 caratteri e non può contenere alcuni caratteri speciali.")

regex_cf = RegexValidator(regex=r'^[a-zA-Z]{6}[0-9]{2}[a-zA-Z][0-9]{2}[a-zA-Z0-9]{5}$',
                          message="Codice fiscale non valido.")

regex_cap = RegexValidator(regex=r'^[0-9]{,10}$', message="CAP non valido.")

regex_dim_pin = RegexValidator(regex=r'^\d{6}$', message="Il PIN inserito deve essere formato da 6 cifre numeriche.")

regex_pin = r'^([0-9])\1{5}$|(^012345$|^123456$|^234567$|^345678$|^456789$|^567890$|^098765$|^987654$|^876543$|^765432$|^654321$|^543210$)'

regex_id_card_issuer = r'^[A-ZÀ-Ù]{1}[a-zà-ù\'\-, ]{1,}[A-zÀ-ù\'\-, ]{0,}$'

regex_number = RegexValidator(regex=r'^[0-9]{6,}$', message="Il numero inserito non è valido.")

regex_password = RegexValidator(regex=r'^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[*.#!@$%^&(){}[\]:;<>,.?/~_|]).{8,16}$',
                                message="La password deve contenere almeno 1 maiuscola, 1 minuscola, 1 numero, un "
                                        "carattere speciale ed essere lunga almeno 8 caratteri")

regex_email = RegexValidator(regex=r'^([a-zA-Z0-9_\-\.\+\'#\!&%\*\$/=\^\{\}\|\?]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$',
                             message="L'email inserita non è valida")
regex_date = RegexValidator(
    regex=r'(^(((0[1-9]|1[0-9]|2[0-8])[\/](0[1-9]|1[012]))|((29|30|31)[\/](0[13578]|1[02]))|((29|30)[\/](0[4,6,9]|11)))'
          r'[\/](19|[2-9][0-9])\d\d$)|(^29[\/]02[\/](19|[2-9][0-9])(00|04|08|12|16|20|24|28|32|36|40|44|48|52|56|60|64|'
          r'68|72|76|80|84|88|92|96)$)',
    message="Data non valida; prova con un formato dd/MM/yyyy")


regex_doc = RegexValidator(
    regex=r'^[a-zA-Z]{2}[ ]?[\d]{7}$',
    message="num. di documento non valido")

regex_patente = RegexValidator(
    regex=r'^[\w]{6,10}$',
    message="num. di documento non valido")

regex_cie = RegexValidator(
    regex=r'^([a-zA-Z]{2}[ ]?[\d]{5}[ ]?[a-zA-Z]{2}|[\d]{7}[ ]?[a-zA-Z]{2})$',
    message="num. di documento non valido")

regex_rao_name = RegexValidator(
    regex=r'^[A-Z]{1}[A-zÀ-ù ]{1,100}$',
    message="Il primo carattere deve essere maiuscolo.")

regex_issuercode = RegexValidator(
    regex=r'^[^*=%]{1,10}$',
    message="Il codice inserito non è valido.")

regex_host_email = RegexValidator(
    regex=r'^([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$',
    message="L'host inserito non è valido")

regex_pwd_email = RegexValidator(
    regex=r'^([0-9a-zA-Z*.#!@$%^&(){}[\]:;<>,.?\/~_|]).{3,50}$',
    message="La password inserita non è valida")

regex_email_port = RegexValidator(
    regex=r'^[0-9]{1,4}$',
    message="Il valore inserito non è valido")

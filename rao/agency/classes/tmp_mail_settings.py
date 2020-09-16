class TempMailSettings:

    def __init__(self, smtp_mail_from, rao_email, rao_host, password, email_port, email_crypto_type):
        self.email = smtp_mail_from
        self.username = rao_email
        self.host = rao_host
        self.password = password
        self.port = email_port
        self.crypto = email_crypto_type

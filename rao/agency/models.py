# -*- coding: utf-8 -*-
# Stdlib imports
from __future__ import unicode_literals

import datetime
import uuid

# Core Django imports
from django.db import models

# Imports from your apps
from agency.classes.choices import RoleTag, StatusCode, CryptoTag


class Role(models.Model):
    role = models.CharField(verbose_name='Nome', choices=[(tag, tag.value) for tag in RoleTag], max_length=30,
                            null=False)
    description = models.CharField(verbose_name='Descrizione', max_length=150, null=True)

    class Meta:
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'


class Operator(models.Model):
    email = models.CharField(verbose_name='Email', max_length=200, null=False, db_index=True, unique=True)
    password = models.CharField(verbose_name='Password', max_length=500)
    name = models.CharField(verbose_name='Nome', max_length=30, null=False, db_index=True)
    surname = models.CharField(verbose_name='Cognome', max_length=30, null=False, db_index=True)
    fiscalNumber = models.CharField(verbose_name='Codice Fiscale', max_length=16, null=False, db_index=True,
                                    unique=True)
    idRole = models.ForeignKey(Role, verbose_name='Ruolo', on_delete=None)
    status = models.BooleanField(verbose_name='Stato', default=False, db_index=True)
    signStatus = models.BooleanField(verbose_name='Stato', default=False, db_index=True)
    isActivated = models.BooleanField(verbose_name='Stato di attivazione', default=True, db_index=True)
    failureTimestamp = models.DateTimeField(verbose_name='Data tentativo errato', null=True)
    failureCounter = models.SmallIntegerField(verbose_name='Contatore tentativi errati', default=0)

    class Meta:
        verbose_name = 'Operator'
        verbose_name_plural = 'Operators'
        index_together = [
            ('fiscalNumber', 'name'),
            ('fiscalNumber', 'surname'),
            ('fiscalNumber', 'status'),
            ('fiscalNumber', 'idRole'),
            ('fiscalNumber', 'email'),
            ('name', 'surname'),
        ]


class AddressCity(models.Model):
    name = models.CharField(verbose_name='Provincia', max_length=150, null=False, db_index=True)
    code = models.CharField(verbose_name='Codice', max_length=20, null=False, db_index=True)


class AddressMunicipality(models.Model):
    name = models.CharField(verbose_name='Comune', max_length=150, null=False, db_index=True)
    code = models.CharField(verbose_name='Codice', max_length=20, null=False, db_index=True)
    city = models.ForeignKey(AddressCity, related_name='Città', verbose_name='Città', max_length=100, null=False,
                             on_delete=None)
    dateStart = models.DateField(verbose_name='Data Inizio', null=True)
    dateEnd = models.DateField(verbose_name='Data Fine', null=True)


class AddressNation(models.Model):
    name = models.CharField(verbose_name='Nazione', max_length=150, null=False, db_index=True)
    code = models.CharField(verbose_name='Codice', max_length=20, null=False, db_index=True)
    lettersCode = models.CharField(verbose_name='Sigla', max_length=5, null=False, db_index=True)
    prefix = models.CharField(verbose_name='Sigla', max_length=5, null=True)


class TokenUser(models.Model):
    uuid_token_user = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    token_user = models.TextField(verbose_name='Token Utente', null=True)
    timestamp_creation = models.DateTimeField(verbose_name='Data creazione', null=True)


class IdentityRequest(models.Model):
    uuid_identity = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fiscalNumberUser = models.CharField(verbose_name='Codice Fiscale', null=True, max_length=16, db_index=True)
    idOperator = models.ForeignKey(Operator, verbose_name='Operatore', on_delete=None)
    status = models.SmallIntegerField(verbose_name='Stato', default=0, db_index=True)
    timestamp_identification = models.DateTimeField(verbose_name='Data Identificazione', null=True)
    token = models.ForeignKey(TokenUser, verbose_name='Token Utente', on_delete=None)

    class Meta:
        verbose_name = 'Identity'
        verbose_name_plural = 'Identity'


class SettingsRAO(models.Model):
    name = models.CharField(verbose_name='Nome', max_length=150, null=False)

    email = models.CharField(verbose_name='Email', max_length=200, null=True)

    issuerCode = models.CharField(verbose_name='issuerCode', max_length=128, null=False)

    host = models.CharField(verbose_name='Host email', max_length=200, null=True)
    username = models.CharField(verbose_name='Configurazione email', max_length=200, null=True)
    password = models.CharField(verbose_name='Password email', max_length=500, null=True)
    port = models.CharField(verbose_name='Porta SMTP email', max_length=4, null=True)
    crypto = models.CharField(verbose_name='Crittografia', choices=[(tag, tag.value) for tag in CryptoTag],
                              max_length=10, null=True)

    class Meta:
        verbose_name = 'SettingsRAO'


class VerifyMail(models.Model):
    token = models.CharField(verbose_name='uuid', max_length=200, db_index=True)
    isVerified = models.BooleanField(verbose_name='Verificato', default=False)
    creationDate = models.DateTimeField(verbose_name='Data creazione UTC', null=True)
    expiredDate = models.DateTimeField(verbose_name='Data scadenza UTC', null=True)
    email = models.CharField(verbose_name='Email', max_length=200, db_index=True)

    def isValid(self, token):
        if token != self.token:
            return StatusCode.NOT_FOUND.value

        if self.expiredDate <= datetime.datetime.utcnow():
            return StatusCode.EXPIRED_TOKEN.value

        if self.isVerified:
            return StatusCode.ERROR.value
        return StatusCode.OK.value


class SetupTask(models.Model):
    """
    Modello utilizzato per effettuare l'esecuzione del setup in background
    """
    percentage = models.IntegerField(verbose_name='Percentuale')
    status = models.CharField(choices=(('in_progress', 'In Corso'),
                                       ('failed', 'Fallito'),
                                       ('completed', 'Completato')
                                       ), max_length=30
                              )
    error = models.CharField(max_length=200)

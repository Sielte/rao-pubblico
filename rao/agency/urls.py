# -*- coding: utf-8 -*-

# Core Django imports
from django.conf.urls import url
from django.urls import path

# Imports from your apps
from agency import views
from agency.utils import utils_setup, utils, utils_db

app_name = 'agency'
urlpatterns = [
    url(r'^$', views.login, name='login'),
    url(r'^logout/$', views.logout_agency, name='logout_agency'),
    url(r'^change_password/(?P<t>.+)/$', views.change_password, name='change_password'),
    url(r'^change_pin/(?P<t>.+)/$', views.change_pin, name='change_pin'),
    url(r'^list_identity/(?P<page>.+)/(?P<t>.+)/$', views.list_identity, name='list_identity'),
    url(r'^list_operator/(?P<page>.+)/(?P<t>.+)/$', views.list_operator, name='list_operator'),
    url(r'^add_identity/(?P<t>.+)/$', views.add_identity, name='add_identity'),
    url(r'^summary_identity/(?P<t>.+)/$', views.summary_identity, name='summary_identity'),
    url(r'^add_operator/(?P<t>.+)/$', views.add_operator, name='add_operator'),
    url(r'^dashboard/(?P<t>.+)/$', views.dashboard, name='dashboard'),
    url(r'^pdf/(?P<t>.+)/$', views.pdf_view, name='pdf'),
    url(r'^download_pdf/(?P<t>.+)/$', views.pdf_download, name='download_pdf'),
    url(r'^setup/$', views.initial_setup, name='setup'),
    url(r'^admin_setup/(?P<t>.+)/$', views.admin_setup, name='admin_setup'),
    url(r'^recovery_password/$', views.recovery_password, name='recovery_password'),

    url(r'^redirect/(?P<t>.+)/$', views.redirect_page, name='redirect'),
    url(r'^disable_operator/(?P<page>.+)/(?P<t>.+)/$', utils_db.disable_operator, name='disable_operator'),
    url(r'^reset_pin_operator/(?P<page>.+)/(?P<t>.+)/$', utils_db.reset_pin_operator, name='reset_pin_operator'),
    url(r'^send_mail_psw_operator/(?P<page>.+)/(?P<t>.+)/$', utils_db.send_mail_psw_operator,
        name='send_mail_psw_operator'),
    url(r'^resend_mail_activation/(?P<page>.+)/(?P<t>.+)/$', utils_db.resend_mail_activation,
        name='resend_mail_activation'),
    url(r'^change_setup_value/(?P<t>.+)/$', utils_db.change_setup_value, name='change_setup_value'),
    # ajax
    path('ajax_decode_fiscal_number/', utils.decode_fiscal_number, name='ajax_decode_fiscal_number'),
    path('ajax/load/', utils.load_select, name='ajax_load'),
    path('ajax/get_city/', utils.get_city_id, name='ajax_province_code'),
    url(r'^ajax_reports/$', utils_db.get_weekly_identification_report, name='ajax_reports'),
    path('ajax_delete_session_key/', utils.delete_session_key, name='ajax_delete_session_key'),

    # setup
    url(r'^checkImport/$', utils.check_import, name='check_import'),
    url(r'^startImport/$', utils.start_import, name='start_import'),

]

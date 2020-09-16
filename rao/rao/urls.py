# -*- coding: utf-8 -*-

# Core Django imports
from django.conf.urls import url, include

# Imports from your apps
from agency import views
from agency.views import handler404

urlpatterns = [
    url('agency/', include('agency.urls')),
    url(r'^$', views.login, name='login'),

]

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rao',
    'agency',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'rao.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')]
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'agency.classes.my_context_processor.version_context_processor'
            ],
        },
    },
]

WSGI_APPLICATION = 'rao.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.environ.get('DATABASE_NAME', './data/raodb.sqlite3')
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Rome'
USE_I18N = True
USE_L10N = True
USE_TZ = False

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = '/opt/rao/static'

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)

# File di LOG
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'SystemLogFilter': {
            '()': 'agency.classes.system_log_filter.SystemLogFilter'
        },

    },
    'formatters': {
        'standard': {
            'format': "[v. %(version)s] [%(client_ip)s] [%(rao_name)s] [%(asctime)s] %(levelname)s [%(funcName)s] [%(name)s:%(lineno)s] %(message)s",
            'datefmt': "%d/%b/%y %H:%M:%S"
        },
        'django.server': {
            '()': 'django.utils.log.ServerFormatter',
            'format': '[{server_time}] {levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'filters': ['SystemLogFilter'],
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': './data/debug.log',
            'formatter': 'standard'
        },
        'mail_admins': {
            'filters': ['SystemLogFilter'],
            'level': os.environ.get('MAIL_LOG_LEVEL', 'ERROR'),
            'class': 'django.utils.log.AdminEmailHandler',
            'include_html': True
        },
        'console': {
            'filters': ['SystemLogFilter'],
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'django.server': {
            'class': 'logging.StreamHandler',
            'formatter': 'django.server',
        },
    },
    'loggers': {
        'portal': {
            'handlers': ['console', 'mail_admins'],
            'level': os.environ.get('PORTAL_LOG_LEVEL', 'DEBUG'),
            'formatter': 'standard',
            'propagate': False
        },
        'agency': {
            'handlers': ['console', 'mail_admins'],
            'level': os.environ.get('AGENCY_LOG_LEVEL', 'DEBUG'),
            'formatter': 'standard',
            'propagate': False
        },
        'django.server': {
            'handlers': ['django.server'],
            'level': os.environ.get('WEBSERVER_LOG_LEVEL', 'WARNING'),
            'propagate': False,
        },
    },
}

# Sessione
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_MINUTES = 60
SESSION_COOKIE_AGE = 60 * SESSION_MINUTES

# URL

#BASE URL: endpoint del R.A.O.
BASE_URL = os.environ.get('BASE_URL', 'http://your-ip:port/')

#SIGN_URL: endpoint del Sistema di Firma
SIGN_URL = os.environ.get('SIGN_URL', 'http://your-ip:port/')
LOGIN_URL = BASE_URL + 'agency'
TEMPLATE_URL_MAIL = 'rao/mail/'
TEMPLATE_URL_AGENCY = 'rao/agency/'
TEMPLATE_URL_PDF = 'rao/pdf/'

# Impostazioni cartella temporanea per token
DATA_FILES_PATH = os.environ.get('DATA_FILES_PATH', '/rao/data/')
SIZE_FILE = 24000000

ENTRY_FOR_PAGE = 10

DAYS_TO_IDENTIFIED = 30



# Encrypting secret
SECRET_KEY_ENC = os.environ.get('SECRET_KEY_ENC', os.urandom(24))

CRL_PATH = os.environ.get('CRL_PATH', 'data/')

RAO_NAME = os.environ.get('RAO_NAME', '')

APP_VERSION = "1.0.11"

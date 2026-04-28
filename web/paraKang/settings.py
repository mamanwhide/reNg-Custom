import environ

env = environ.FileAwareEnv()

import mimetypes
import os

from paraKang.init import first_run
from paraKang.utilities import ParaKangTaskFormatter

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       PARAKANG CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, os.pardir, '.env'))

# Root env vars
PARAKANG_HOME = env('PARAKANG_HOME', default='/usr/src/app')
PARAKANG_RESULTS = env('PARAKANG_RESULTS', default=f'{PARAKANG_HOME}/scan_results')
PARAKANG_CACHE_ENABLED = env.bool('PARAKANG_CACHE_ENABLED', default=False)
PARAKANG_RECORD_ENABLED = env.bool('PARAKANG_RECORD_ENABLED', default=True)
PARAKANG_RAISE_ON_ERROR = env.bool('PARAKANG_RAISE_ON_ERROR', default=False)

# Common env vars
DEBUG = env.bool('DEBUG', default=False)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(PARAKANG_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=True)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=100) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=10)
DEFAULT_GET_GPT_REPORT = env.bool('DEFAULT_GET_GPT_REPORT', default=True)

# Globals
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[DOMAIN_NAME, 'localhost', '127.0.0.1', 'testserver'])
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# ParaKang version
# reads current version from a file called .version
VERSION_FILE = os.path.join(BASE_DIR, '.version')
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, 'r') as f:
        _version = f.read().strip()
else:
    _version = 'unknown'

# removes v from _version if exists
if _version.startswith('v'):
    _version = _version[1:]

PARAKANG_CURRENT_VERSION = _version

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        # CONN_MAX_AGE=0 closes DB connections after each request.
        # Required because gevent workers share greenlets that don't
        # release persistent connections, exhausting PostgreSQL's pool.
        'CONN_MAX_AGE': env.int('CONN_MAX_AGE', default=0),
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'recon_note.apps.ReconNoteConfig',
    'django_ace',
    'django_celery_beat',
    'mathfilters',
    'drf_yasg',
    'rolepermissions'
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'paraKang.middleware.UserPreferencesMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [(os.path.join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'paraKang.context_processors.projects',
                'paraKang.context_processors.version_context',
                'paraKang.context_processors.user_preferences',
            ],
    },
}]
ROOT_URLCONF = 'paraKang.urls'
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':(
        'rest_framework_datatables.pagination.DatatablesPageNumberPagination'
    ),
    'PAGE_SIZE': 500,
}
WSGI_APPLICATION = 'paraKang.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

MEDIA_URL = '/media/'
MEDIA_ROOT = '/usr/src/scan_results/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
    'logout',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'onboarding'
LOGOUT_REDIRECT_URL = 'login'

# Explicit authentication backend
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

# Tool Location
TOOL_LOCATION = '/usr/src/app/tools/'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

'''
CELERY settings
'''
CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BACKEND", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = True
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Silence Celery 5.4 deprecation warning for chord error callbacks.
# Setting True means error callbacks fire on chord header errors (new default).
CELERY_TASK_ALLOW_ERROR_CB_ON_CHORD_HEADER = True
# Fix: gevent + Redis backend causes BlockingSwitchOutError during AsyncResult
# garbage collection (__del__ calls unsubscribe which triggers blocking DNS).
# socket_timeout prevents the connection attempt from hanging inside gevent.
CELERY_RESULT_BACKEND_TRANSPORT_OPTIONS = {
    'retry_policy': {'timeout': 5.0},
    'socket_connect_timeout': 5,
    'socket_timeout': 5,
}
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'paraKang.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
PARAKANG_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': '/var/log/gunicorn/errors.log',
        },
        'null': {
            'class': 'logging.NullHandler'
        },
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'brief': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task'
        },
        'db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': '/var/log/gunicorn/db.log',
            'maxBytes': 1024 * 1024 * 10,  # SEC-12 fix: 10 MB (was 1 KB)
            'backupCount': 3
        },
        'celery': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': '/var/log/gunicorn/celery.log',
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
        },
    },
    'formatters': {
        'default': {
            'format': '%(message)s'
        },
        'brief': {
            'format': '%(name)-10s | %(message)s'
        },
        'task': {
            '()': lambda : ParaKangTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s')
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
            'datefmt': '%y %b %d, %H:%M:%S',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': env('DJANGO_LOG_LEVEL', default='ERROR' if DEBUG else 'CRITICAL'),
            'propagate': True,
        },
        '': {
            'handlers': ['brief'],
            'level': env('LOG_LEVEL', default='DEBUG' if DEBUG else 'INFO'),
            'propagate': False
        },
        'celery': {
            'handlers': ['celery'],
            'level': env('CELERY_LOG_LEVEL', default='DEBUG' if DEBUG else 'ERROR'),
        },
        'celery.app.trace': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['task'],
            'propagate': False
        },
        'celery.worker': {
            'handlers': ['null'],
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db'],
            'level': 'INFO',
            'propagate': False
        },
        'paraKang.tasks': {
            'handlers': ['task'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'api.views': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        }
    },
}

'''
File upload settings
'''
# SEC-07 fix: Set reasonable limit to prevent HashDoS attacks (was None)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10000

'''
    Caching Settings
'''
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('CELERY_BROKER', default='redis://redis:6379/0').rsplit('/', 1)[0] + '/1',
        'TIMEOUT': 60 * 30,  # 30 minutes caching will be used
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

'''
    Security Settings
'''
def _default_csrf_trusted_origins(domain_name):
    origins = {
        f'https://{domain_name}',
        f'http://{domain_name}',
        'https://localhost',
        'http://localhost',
        'https://127.0.0.1',
        'http://127.0.0.1',
        'https://[::1]',
        'http://[::1]',
    }

    host_only = domain_name.split(':', 1)[0].strip()
    if host_only:
        origins.add(f'https://{host_only}')
        origins.add(f'http://{host_only}')

    return sorted(origins)


CSRF_TRUSTED_ORIGINS = env.list(
    'CSRF_TRUSTED_ORIGINS',
    default=_default_csrf_trusted_origins(DOMAIN_NAME)
)
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG
# CSRF_COOKIE_HTTPONLY must be False so that JavaScript (getCookie('csrftoken'))
# can read the token and include it in the X-CSRFToken header for AJAX requests.
# Setting it to True blocks all JS-based POST/PUT/DELETE from the browser (403).
CSRF_COOKIE_HTTPONLY = False
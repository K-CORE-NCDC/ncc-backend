"""
Django settings for ncc project.

Generated by 'django-admin startproject' using Django 2.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

# Import statements
import os
from datetime import timedelta
from ckeditor.configs import DEFAULT_CONFIG
from django.utils.translation import gettext_lazy as _

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "n9qzn%pblm64cz)u#5l5twbo2pxu8agujv9b-9s2j@g(=3&&h0"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Application settings
AUTH_USER_MODEL = "app.User"
WSGI_APPLICATION = "ncc.wsgi.application"
FRONTEND_URL = ""
ROOT_URLCONF = "ncc.urls"

# CORS policy and session settings
ALLOWED_HOSTS = ["*"]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
SESSION_COOKIE_AGE = 36000
# SESSION_COOKIE_AGE = 300
# Installed apps and middleware
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "app",
    "admin_app",
    "user_data_visualization",
    "ckeditor",
    "ckeditor_uploader",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Sohel -LoggerMiddleware
    "user_data_visualization.middleware.MiddlewareUserData",


]

# Template settings
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Password validators, REST framework, and JWT settings
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=7),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=100),
    "USERNAME_FIELD": "email",
    "USER_ID_FIELD": "id",  # model property to attempt claims for
    "USER_ID_CLAIM": "user_id",  # actual keyword in token data
}

# CKEditor settings
CKEDITOR_UPLOAD_PATH = "uploads/"
CKEDITOR_IMAGE_BACKEND = "ckeditor_uploader.backends.PillowBackend"
CKEDITOR_THUMBNAIL_SIZE = (300, 300)
CKEDITOR_IMAGE_QUALITY = 40
CKEDITOR_BROWSE_SHOW_DIRS = True
CKEDITOR_ALLOW_NONIMAGE_FILES = True
CKEDITOR_CONFIGS = {
    "default": DEFAULT_CONFIG,
    "my-custom-toolbar": {
        "skin": "moono-lisa",
        "toolbar": "full",
        "toolbarGroups": None,
        "extraPlugins": ",".join(
            ["image2", "codesnippet", "embed", "html5video", "html5"]
        ),
        "removePlugins": ",".join(["image"]),
        "codeSnippet_theme": "xcode",
    },
    "removePlugins": "exportpdf",
}


# Database settings
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DATABASE_NAME"),
        "USER": os.environ.get("DATABASE_USER"),
        "PASSWORD": os.environ.get("DATABASE_PASSWORD"),
        "HOST": os.environ.get("DATABASE_HOST"),
        "PORT": os.environ.get("DATABASE_PORT"),
        "CONN_MAX_AGE":0
    }
}

# Other settings
DB = "default"
USE_X_FORWARDED_HOST = True
FORCE_SCRIPT_NAME = "/k-corev/" if os.environ.get("PRODUCTION") == "True" else "/k-corev/"

# Internationalization settings
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
LANGUAGES = (
    ("en", _("English")),
    ("ko", _("Korean")),
)
LOCALE_PATHS = (os.path.join(BASE_DIR, "locale/"),)

# Static and media files settings
MEDIA_ROOT = os.path.join(BASE_DIR, "media/")
MEDIA_URL = "/media/"
STATIC_URL = "/k-corev/static/"

if os.environ.get('PRODUCTION') != 'True':
    # FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"
    FRONTEND_DOMAIN = "http://3bigs.co.kr/k-core/"

else:
    # FRONTEND_DOMAIN = "http://3bigs.co.kr/k-core/"
    FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"



# FRONTEND_DOMAIN = "3bigs.co.kr/"


DOMAIN = "https://cancerdata.re.kr/k-corev/"
# DOMAIN = "https://www.3bigs.co.kr/k-corev/"



STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "staticfiles"),
    os.path.join(BASE_DIR, "media/"),
]

# ...

# Email settings
if os.environ.get("PRODUCTION") != "True":
    EMAIL_USE_TLS = True
    # EMAIL_USE_SSL = True
    EMAIL_PORT = 587
    EMAIL_HOST = "smtp.gmail.com"
    EMAIL_HOST_USER = "sameer@3bigs.com"
    EMAIL_HOST_PASSWORD = "oaprovnqouifpibr"
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    SENDER_EMAIL = "diva@3bigs.com"
else:
    EMAIL_USE_TLS = True
    EMAIL_PORT = 25
    EMAIL_HOST = "49.50.1.45"
    EMAIL_HOST_USER = "data@ncc.re.kr"
    EMAIL_HOST_PASSWORD = "ncdc!234"
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    SENDER_EMAIL = "data@ncc.re.kr"


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'level': 'ERROR',  # Show only ERROR messages
            'class': 'logging.StreamHandler',  # Output to console
            'formatter': 'simple',  # Use the 'simple' formatter
            'filters': ['require_debug_false'],  # Exclude debug messages
        },
        'error_file': {
            'level': 'ERROR',  # Show only ERROR messages
            'class': 'user_data_visualization.apps.DynamicLogFileHandler',
            # 'filename': 'user_data_visualization.apps.DynamicLogFileHandler',
            'when': 'midnight',  # Roll over at midnight
            'interval': 1,  # Create a new log file every day
            'backupCount': 14,  # Keep logs for 14 days
            'formatter': 'simple',  # Use the 'simple' formatter
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['error_file', 'console'],
            # Use 'error_file' and 'console' handlers for SQL queries
            'level': 'ERROR',
            # Show only ERROR messages for SQL queries
            'propagate': False,
        },
        'django': {
            'handlers': ['error_file', 'console'],
            # Use 'error_file' and 'console' handlers for Django errors and exceptions
            'level': 'ERROR',
            # Show only ERROR messages for Django errors and exceptions
        },
    },
    'root': {
        'handlers': ['error_file'],
        'level': 'ERROR',
        # Show only ERROR messages for the root logger
    },
}

# For Debug, Debugs, all
# 'formatters': {
#         'verbose': {
#             'format': '{levelname} {asctime} {module} {message}
# \n--------------------------------------------------',
#             'style': '{',
#         },
#     },

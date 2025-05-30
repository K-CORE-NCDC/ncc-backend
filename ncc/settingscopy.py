# """
# Django settings for ncc project.

# Generated by 'django-admin startproject' using Django 2.2.4.

# For more information on this file, see
# https://docs.djangoproject.com/en/2.2/topics/settings/

# For the full list of settings and their values, see
# https://docs.djangoproject.com/en/2.2/ref/settings/
# """

# from ckeditor.configs import DEFAULT_CONFIG
# from django.utils.translation import gettext_lazy as _
# import os
# from datetime import timedelta
# from logging.handlers import TimedRotatingFileHandler


# # Build paths inside the project like this: os.path.join(BASE_DIR, ...)
# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# # Quick-start development settings - unsuitable for production
# # See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# # SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = "n9qzn%pblm64cz)u#5l5twbo2pxu8agujv9b-9s2j@g(=3&&h0"

# # SECURITY WARNING: don't run with debug turned on in production!
# DEBUG = True



# AUTH_USER_MODEL = "app.User"
# WSGI_APPLICATION = "ncc.wsgi.application"
# FRONTEND_URL = ""
# ROOT_URLCONF = "ncc.urls"


# # CORS POLICY
# # CORS_ALLOW_ALL_ORIGINS = True
# ALLOWED_HOSTS = ["*"]
# CORS_ORIGIN_ALLOW_ALL = True
# CORS_ALLOW_CREDENTIALS = True
# SESSION_COOKIE_AGE = 36000
# # SESSION_COOKIE_AGE = 30

# # Application definition
# INSTALLED_APPS = [
#     "django.contrib.admin",
#     "django.contrib.auth",
#     "django.contrib.contenttypes",
#     "django.contrib.sessions",
#     "django.contrib.messages",
#     "django.contrib.staticfiles",
#     "corsheaders",
#     "rest_framework",
#     "app",
#     "admin_app",
#     "user_data_visualization",
#     "ckeditor",
#     "ckeditor_uploader",
# ]

# MIDDLEWARE = [
#     "corsheaders.middleware.CorsMiddleware",
#     "django.middleware.security.SecurityMiddleware",
#     "django.contrib.sessions.middleware.SessionMiddleware",
#     "django.middleware.locale.LocaleMiddleware",
#     "django.middleware.common.CommonMiddleware",
#     "django.middleware.csrf.CsrfViewMiddleware",
#     "django.contrib.auth.middleware.AuthenticationMiddleware",
#     "django.contrib.messages.middleware.MessageMiddleware",
#     "django.middleware.clickjacking.XFrameOptionsMiddleware",
#     # 'app.middelware.SessionVerificationMiddleware',
#     # 'app.middelware.CorsMiddleware',
#     "user_data_visualization.middleware.MiddlewareUserData",
#     # Custom Middleware
#     # 'app.middelware.MyMiddleware'
# ]

# TEMPLATES = [
#     {
#         "BACKEND": "django.template.backends.django.DjangoTemplates",
#         "DIRS": [os.path.join(BASE_DIR, "templates")],
#         "APP_DIRS": True,
#         "OPTIONS": {
#             "context_processors": [
#                 "django.template.context_processors.debug",
#                 "django.template.context_processors.request",
#                 "django.contrib.auth.context_processors.auth",
#                 "django.contrib.messages.context_processors.messages",
#             ],
#         },
#     },
# ]

# AUTH_PASSWORD_VALIDATORS = [
#     {
#         "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
#     },
#     {
#         "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
#     },
# ]

# REST_FRAMEWORK = {
#     # 'DEFAULT_AUTHENTICATION_CLASSES': [
#     #     'rest_framework_simplejwt.authentication.JWTAuthentication',
#     # ],
#     "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
#     # 'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
#     "DEFAULT_AUTHENTICATION_CLASSES": [
#         "rest_framework.authentication.SessionAuthentication",
#     ],
# }

# SIMPLE_JWT = {
#     "ACCESS_TOKEN_LIFETIME": timedelta(days=7),
#     "REFRESH_TOKEN_LIFETIME": timedelta(days=100),
#     "USERNAME_FIELD": "email",
#     "USER_ID_FIELD": "id",  # model property to attempt claims for
#     "USER_ID_CLAIM": "user_id",  # actual keyword in token data
# }

# # CKEDITOR CONFIGS
# CKEDITOR_IMAGE_BACKEND = "ckeditor_uploader.backends.PillowBackend"
# CKEDITOR_THUMBNAIL_SIZE = (300, 300)
# CKEDITOR_IMAGE_QUALITY = 40
# CKEDITOR_BROWSE_SHOW_DIRS = True
# CKEDITOR_ALLOW_NONIMAGE_FILES = True

# DATABASES = {
#     "default": {
#         "ENGINE": "django.db.backends.postgresql",
#         "NAME": os.environ.get("DATABASE_NAME"),
#         "USER": os.environ.get("DATABASE_USER"),
#         "PASSWORD": os.environ.get("DATABASE_PASSWORD"),
#         "HOST": os.environ.get("DATABASE_HOST"),
#         "PORT": os.environ.get("DATABASE_PORT"),
#         "CONN_MAX_AGE":0
#     }
# }


# DB = "default"
# USE_X_FORWARDED_HOST = True

# if os.environ.get("PRODUCION_MODE") != "True":
#     FORCE_SCRIPT_NAME = "/k-corev/"
# else:
#     FORCE_SCRIPT_NAME = "/k-corev/"

# # Password validation
# # https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators


# # Internationalization
# # https://docs.djangoproject.com/en/2.2/topics/i18n/


# LANGUAGE_CODE = "en-us"

# TIME_ZONE = "UTC"

# USE_I18N = True

# USE_L10N = True

# USE_TZ = True

# DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# LANGUAGES = (
#     ("en", _("English")),
#     ("ko", _("Korean")),
# )

# LOCALE_PATHS = (os.path.join(BASE_DIR, "locale/"),)
# # Static files (CSS, JavaScript, Images)
# # https://docs.djangoproject.com/en/2.2/howto/static-files/

# # STATIC_ROOT = os.path.join(BASE_DIR, 'static')
# MEDIA_ROOT = os.path.join(BASE_DIR, "media/")
# MEDIA_URL = "/media/"
# STATIC_URL = "/k-corev/static/"

# if os.environ.get('PRODUCION_MODE') != 'True':
#     FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"
# else:
#     FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"


# # FRONTEND_DOMAIN = "3bigs.co.kr/"


# # DOMAIN = "https://cancerdata.re.kr/k-corev/"
# DOMAIN = "https://www.cancerdata.re.kr/k-corev/"

# STATIC_ROOT = os.path.join(BASE_DIR, "static")
# STATICFILES_DIRS = [
#     os.path.join(BASE_DIR, "staticfiles"),
#     os.path.join(BASE_DIR, "media/"),
# ]
# CKEDITOR_UPLOAD_PATH = "uploads/"

# CKEDITOR_THUMBNAIL_SIZE = (300, 300)
# CKEDITOR_IMAGE_QUALITY = 40
# CKEDITOR_BROWSE_SHOW_DIRS = True
# CKEDITOR_ALLOW_NONIMAGE_FILES = True

# CKEDITOR_CONFIGS = {
#     "default": DEFAULT_CONFIG,
#     "my-custom-toolbar": {
#         "skin": "moono-lisa",
#         "toolbar": "full",
#         "toolbarGroups": None,
#         "extraPlugins": ",".join(
#             ["image2", "codesnippet", "embed", "html5video", "html5"]
#         ),
#         "removePlugins": ",".join(["image"]),
#         "codeSnippet_theme": "xcode",
#     },
#     "removePlugins": "exportpdf",
# }

# # Adding EMAIL Dependencies

# if os.environ.get("PRODUCION_MODE") != "True":
#     EMAIL_USE_TLS = True
#     # EMAIL_USE_SSL = True
#     EMAIL_PORT = 587
#     EMAIL_HOST = "smtp.gmail.com"
#     EMAIL_HOST_USER = "sameer@3bigs.com"
#     EMAIL_HOST_PASSWORD = "vxnqnsonpiizlzeu"
#     EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

#     SENDER_EMAIL = "dmsohel07@gmail.com"

# else:
#     EMAIL_USE_TLS = True
#     EMAIL_PORT = 25
#     EMAIL_HOST = "49.50.1.45"
#     EMAIL_HOST_USER = "data@ncc.re.kr"
#     EMAIL_HOST_PASSWORD = "ncdc!234"
#     EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
#     SENDER_EMAIL = "data@ncc.re.kr"

# # LOGGING = {
# #     'version': 1,
# #     'disable_existing_loggers': False,
# #     'handlers': {
# #         'file': {
# #             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
# #             'class': 'logging.FileHandler',
# #             'filename': 'sql_queries.log',  # Set the filename for the log file
# #         },
# #         'console': {
# #             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
# #             'class': 'logging.StreamHandler',  # Output to console
# #         },
# #     },
# #     'loggers': {
# #         'django.db.backends': {
# #             'handlers': ['file', 'console'],  # Use 'file' and 'console' handlers for SQL queries
# #             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
# #             'propagate': False,
# #         },
# #     },
# # }

# LOG_FOLDER = 'log_folder'  # Set the folder where log files will be stored
# LOG_FILE = os.path.join(LOG_FOLDER, 'Exceptions.log')
# if not os.path.exists(LOG_FOLDER):
#     os.makedirs(LOG_FOLDER)

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'file': {
#             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
#             'class': 'logging.FileHandler',
#             'filename': 'sql_queries.log',  # Set the filename for the log file
#         },
#         'console': {
#             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
#             'class': 'logging.StreamHandler',  # Output to console
#         },
#         'error_file': {
#             'level': 'ERROR',  # You can change the level as needed.
#             'class': 'logging.FileHandler',
#             'filename': 'Exceptions.log',
#         },
#     },
#     'loggers': {
#         'django.db.backends': {
#             'handlers': ['file', 'console'],  # Use 'file' and 'console' handlers for SQL queries
#             'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
#             'propagate': False,
#         },
#         'django': {
#             'handlers': ['error_file', 'console'],  # Use 'error_file' and 'console' handlers for Django errors and exceptions
#             'level': 'ERROR',  # Capture Django errors and exceptions at the ERROR level
#         },
#     },
#     'root': {
#         'handlers': ['error_file'],
#         'level': 'ERROR',  # You can change the level as needed.
#     },
# }












"""
Django settings for ncc project.

Generated by 'django-admin startproject' using Django 2.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

from ckeditor.configs import DEFAULT_CONFIG
from django.utils.translation import gettext_lazy as _
import os
from datetime import timedelta
from logging.handlers import TimedRotatingFileHandler


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "n9qzn%pblm64cz)u#5l5twbo2pxu8agujv9b-9s2j@g(=3&&h0"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True



AUTH_USER_MODEL = "app.User"
WSGI_APPLICATION = "ncc.wsgi.application"
FRONTEND_URL = ""
ROOT_URLCONF = "ncc.urls"


# CORS POLICY
ALLOWED_HOSTS = ["*"]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
SESSION_COOKIE_AGE = 36000

# Application definition
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
    "user_data_visualization.middleware.MiddlewareUserData",
]

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

# CKEDITOR CONFIGS
CKEDITOR_IMAGE_BACKEND = "ckeditor_uploader.backends.PillowBackend"
CKEDITOR_THUMBNAIL_SIZE = (300, 300)
CKEDITOR_IMAGE_QUALITY = 40
CKEDITOR_BROWSE_SHOW_DIRS = True
CKEDITOR_ALLOW_NONIMAGE_FILES = True

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


DB = "default"
USE_X_FORWARDED_HOST = True

if os.environ.get("PRODUCION_MODE") != "True":
    FORCE_SCRIPT_NAME = "/k-corev/"
else:
    FORCE_SCRIPT_NAME = "/k-corev/"

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/


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
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

# STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_ROOT = os.path.join(BASE_DIR, "media/")
MEDIA_URL = "/media/"
STATIC_URL = "/k-corev/static/"

if os.environ.get('PRODUCION_MODE') != 'True':
    FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"
else:
    FRONTEND_DOMAIN = "https://www.cancerdata.re.kr/k-core/"


# FRONTEND_DOMAIN = "3bigs.co.kr/"


# DOMAIN = "https://cancerdata.re.kr/k-corev/"
DOMAIN = "https://www.cancerdata.re.kr/k-corev/"

STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "staticfiles"),
    os.path.join(BASE_DIR, "media/"),
]
CKEDITOR_UPLOAD_PATH = "uploads/"

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

# Adding EMAIL Dependencies

if os.environ.get("PRODUCION_MODE") != "True":
    EMAIL_USE_TLS = True
    # EMAIL_USE_SSL = True
    EMAIL_PORT = 587
    EMAIL_HOST = "smtp.gmail.com"
    EMAIL_HOST_USER = "sameer@3bigs.com"
    EMAIL_HOST_PASSWORD = "vxnqnsonpiizlzeu"
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

    SENDER_EMAIL = "dmsohel07@gmail.com"

else:
    EMAIL_USE_TLS = True
    EMAIL_PORT = 25
    EMAIL_HOST = "49.50.1.45"
    EMAIL_HOST_USER = "data@ncc.re.kr"
    EMAIL_HOST_PASSWORD = "ncdc!234"
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    SENDER_EMAIL = "data@ncc.re.kr"

LOG_FOLDER = 'log_folder'  # Set the folder where log files will be stored
LOG_FILE = os.path.join(LOG_FOLDER, 'Exceptions.log')
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
            'class': 'logging.FileHandler',
            'filename': 'sql_queries.log',  # Set the filename for the log file
        },
        'console': {
            'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
            'class': 'logging.StreamHandler',  # Output to console
        },
        'error_file': {
            'level': 'ERROR',  # You can change the level as needed.
            'class': 'logging.FileHandler',
            'filename': 'Exceptions.log',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['file', 'console'],  # Use 'file' and 'console' handlers for SQL queries
            'level': 'DEBUG',  # Capture SQL queries at the DEBUG level
            'propagate': False,
        },
        'django': {
            'handlers': ['error_file', 'console'],  # Use 'error_file' and 'console' handlers for Django errors and exceptions
            'level': 'ERROR',  # Capture Django errors and exceptions at the ERROR level
        },
    },
    'root': {
        'handlers': ['error_file'],
        'level': 'ERROR',  # You can change the level as needed.
    },
}


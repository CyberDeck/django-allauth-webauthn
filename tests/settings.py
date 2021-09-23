from pathlib import Path
from typing import List

from django.urls.base import reverse_lazy

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "supersecr3tk3y"
ALLOWED_HOSTS: List[str] = []

# Application definition
INSTALLED_APPS = [
    # Required by allauth.
    "django.contrib.sites",
    # Configure some required Django packages.
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    # Enable allauth.
    "allauth",
    "allauth.account",
    # Required to render the default template for 'account_login'.
    "allauth.socialaccount",
    # Enable 2FA Webauthn
    "django_allauth_webauthn",
    # Test App
    "tests",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates", BASE_DIR / "tests" / "templates"],
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


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
)

SITE_ID = 1

ACCOUNT_ADAPTER = "django_allauth_webauthn.adapter.WebAuthnAdapter"

ACCOUNT_EMAIL_VERIFICATION = "none"

LOGIN_REDIRECT_URL = reverse_lazy("home")

DJANGO_ALLAUTH_WEBAUTHN_DOMAIN = "localhost"
DJANGO_ALLAUTH_WEBAUTHN_ORIGIN = "https://localhost:8000"
DJANGO_ALLAUTH_WEBAUTHN_NAME = "Webauthn Test"
DJANGO_ALLAUTH_WEBAUTHN_ICON_URL = "https://localhost:8000/favicon.ico"

DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_ERROR_URL = reverse_lazy("test-registration-error")
DJANGO_ALLAUTH_WEBAUTHN_LOGIN_ERROR_URL = reverse_lazy("test-login-error")
DJANGO_ALLAUTH_WEBAUTHN_REMOVE_RENAME_REDIRECT_URL = reverse_lazy("removed-renamed-success")

from django.conf import settings

ICON_URL = getattr(settings, "DJANGO_ALLAUTH_WEBAUTHN_ICON_URL", None)
DOMAIN = getattr(settings, "DJANGO_ALLAUTH_WEBAUTHN_DOMAIN", None)
NAME = getattr(settings, "DJANGO_ALLAUTH_WEBAUTHN_NAME", None)
ORIGIN = getattr(settings, "DJANGO_ALLAUTH_WEBAUTHN_ORIGIN", None)
# Where to redirect after successful key registration.
REGISTRATION_REDIRECT_URL = getattr(
    settings,
    "DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_REDIRECT_URL",
    settings.LOGIN_REDIRECT_URL,
)
# Where to redirect after key registration error.
REGISTRATION_ERROR_URL = getattr(
    settings,
    "DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_ERROR_URL",
    settings.LOGIN_REDIRECT_URL,
)
# Where to redirect after login errors.
LOGIN_ERROR_URL = getattr(settings, "DJANGO_ALLAUTH_WEBAUTHN_LOGIN_ERROR_URL", settings.LOGIN_URL)
# Where to redirect after remove or renaming a token?
REMOVE_RENAME_REDIRECT_URL = getattr(
    settings,
    "DJANGO_ALLAUTH_WEBAUTHN_REMOVE_RENAME_REDIRECT_URL",
    settings.LOGIN_REDIRECT_URL,
)

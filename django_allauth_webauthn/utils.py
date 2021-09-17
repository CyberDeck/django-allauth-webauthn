import base64
import random
import string

import webauthn
from django.contrib.sites.shortcuts import get_current_site

from . import app_settings
from .models import WebauthnData


def user_has_webauthn_enabled(user):
    if not user.is_authenticated:  # pragma: no cover
        return False
    return WebauthnData.objects.filter(user=user).exists()


def random_numbers_letters(count):  # pragma: no cover
    return "".join([random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(count)])


def get_icon_url(request):
    if app_settings.ICON_URL is None:  # pragma: no cover
        return f"https://{get_site_domain(request)}/favicon.ico"
    return app_settings.ICON_URL


def get_site_domain(request):
    if app_settings.DOMAIN is None:  # pragma: no cover
        site = get_current_site(request)
        return site.domain
    return app_settings.DOMAIN


def get_origin(request):
    if app_settings.ORIGIN is None:  # pragma: no cover
        return f"https://{get_site_domain(request)}"
    return app_settings.ORIGIN


def get_site_name(request):
    if app_settings.NAME is None:  # pragma: no cover
        site = get_current_site(request)
        return site.name
    return app_settings.NAME


def get_display_name(request):
    return (f"{get_site_name(request)} user: {request.user.get_username()}",)


def sanitize_session(request):
    """
    If present, remove artifact from previous aborted login, or successful login.
    """
    try:
        del request.session["allauth_webauthn_user_id"]
    except KeyError:
        pass
    try:
        del request.session["allauth_webauthn_challenge"]
    except KeyError:
        pass


def authenticate(request, user_id, credential_id, data):
    """Authenticate a dedicated user given a signed token."""
    if not user_id or not credential_id:  # pragma: no cover
        return None

    challenge = request.session.get("allauth_webauthn_challenge")
    if not challenge:  # pragma: no cover
        return None

    device = WebauthnData.objects.filter(user_id=user_id, credential_id=credential_id).first()
    if not device:
        return None

    webauthn_user = webauthn.WebAuthnUser(
        user_id=base64.b64encode(str(device.user.id).encode()).decode(),
        username=device.user.get_username(),
        display_name=get_display_name(request),
        icon_url=get_icon_url(request),
        credential_id=device.credential_id,
        public_key=device.public_key,
        sign_count=device.sign_counter,
        rp_id=get_site_domain(request),
    )

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user, data, challenge, get_origin(request), uv_required=False
    )

    try:
        sign_counter = webauthn_assertion_response.verify()
    except Exception:
        return None

    device.update_sign_counter(sign_counter)

    return device.user

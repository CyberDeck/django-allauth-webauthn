import base64

import webauthn
from allauth.account import signals
from allauth.account.adapter import get_adapter
from allauth.account.utils import get_login_redirect_url
from allauth.account.utils import get_next_redirect_url
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http.response import JsonResponse
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.views.generic.base import TemplateView

from . import app_settings
from .models import WebauthnData
from .utils import authenticate
from .utils import get_display_name
from .utils import get_icon_url
from .utils import get_origin
from .utils import get_site_domain
from .utils import get_site_name
from .utils import random_numbers_letters
from .utils import sanitize_session


class Register(LoginRequiredMixin, View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        site_name = get_site_name(request)
        challenge = random_numbers_letters(32)
        request.session["allauth_webauthn_challenge"] = challenge
        reg_data = webauthn.WebAuthnMakeCredentialOptions(
            challenge=challenge,
            rp_name=site_name,
            rp_id=get_site_domain(request),
            user_id=base64.b64encode(str(request.user.id).encode()).decode(),
            username=request.user.get_username(),
            display_name=get_display_name(request),
            icon_url=get_icon_url(request),
        ).registration_dict
        return JsonResponse(reg_data)

    def post(self, request, *args, **kwargs):
        site_domain = get_site_domain(request)
        challenge = request.session.get("allauth_webauthn_challenge")
        if not challenge:
            return HttpResponse("No challenge exists in your session.", status=422)
        registration_response = request.POST
        webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
            rp_id=site_domain,
            origin=get_origin(request),
            registration_response=registration_response,
            challenge=challenge,
            self_attestation_permitted=True,
            none_attestation_permitted=True,
            uv_required=False,
        )
        try:
            webauthn_credential = webauthn_registration_response.verify()
        except Exception as e:
            messages.error(request, _("Registration failed. Error: %(error)s") % {"error": e})
            return redirect(app_settings.REGISTRATION_ERROR_URL)

        credential_id = str(webauthn_credential.credential_id, "utf-8")
        public_key = str(webauthn_credential.public_key, "utf-8")
        sign_count = webauthn_credential.sign_count

        device = WebauthnData.objects.filter(credential_id=credential_id)
        if device.exists():
            messages.error(
                request,
                _("This token is already registered to an account. Try logging in with it."),
            )
            return redirect(app_settings.REGISTRATION_ERROR_URL)

        token_count = WebauthnData.objects.filter(user=request.user).count()
        device_name = _("Device #%(num)d") % {"num": token_count + 1}
        WebauthnData.objects.create(
            user=request.user,
            name=device_name,
            credential_id=credential_id,
            public_key=public_key,
            sign_counter=sign_count,
        )

        messages.success(request, _("Your security token has been successfully registered."))
        return redirect(app_settings.REGISTRATION_REDIRECT_URL)


class Login(TemplateView):
    template_name = "django_allauth_webauthn/login.html"

    def dispatch(self, request, *args, **kwargs):
        # Redirect the user to the login page if they does not come from there,
        # i.e. if "allauth_webauthn_user_id" is not included in the session.
        if "allauth_webauthn_user_id" not in request.session:
            return redirect("account_login")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        kwargs["login_redirect_url"] = get_next_redirect_url(self.request)
        return super().get(request, *args, **kwargs)


class Verify(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        site_domain = get_site_domain(request)
        challenge = random_numbers_letters(32)
        request.session["allauth_webauthn_challenge"] = challenge
        user_id = request.session.get("allauth_webauthn_user_id")
        user_credential_ids = (
            WebauthnData.objects.filter(user_id=user_id)
            .order_by("-last_used_on")
            .values_list("credential_id", flat=True)
        )
        login_data = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": site_domain,
            "allowCredentials": [{"id": credential_id, "type": "public-key"} for credential_id in user_credential_ids],
            "userVerification": "preferred",
        }
        return JsonResponse(login_data)

    def post(self, request, *args, **kwargs):
        user_id = request.session.get("allauth_webauthn_user_id")
        challenge = request.session.get("allauth_webauthn_challenge")
        if not challenge or not user_id:
            messages.error(request, "No challenge or user exists for your session.")
            return redirect(app_settings.LOGIN_ERROR_URL)

        user = authenticate(request, user_id, request.POST["id"], request.POST)
        if user is None:
            messages.error(request, "Your credentials could not be validated.")
            return redirect(app_settings.LOGIN_ERROR_URL)

        adapter = get_adapter(request)

        adapter.login_without_webauthn(request, user)

        # Perform the rest of allauth.account.utils.perform_login, this is
        # copied from commit cedad9f156a8c78bfbe43a0b3a723c1a0b840dbd.

        # TODO Support redirect_url.
        response = HttpResponseRedirect(get_login_redirect_url(self.request))

        # TODO Support signal_kwargs.
        signals.user_logged_in.send(sender=user.__class__, request=self.request, response=response, user=user)

        adapter.add_message(
            self.request,
            messages.SUCCESS,
            "account/messages/logged_in.txt",
            {"user": user},
        )

        sanitize_session(request)

        return response


class Remove(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        device = WebauthnData.objects.get(user=request.user, pk=kwargs["pk"])
        device.delete()
        return redirect(app_settings.REMOVE_RENAME_REDIRECT_URL)


class Rename(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        device = WebauthnData.objects.get(user=request.user, pk=kwargs["pk"])
        device.name = request.POST["name"]
        device.save()
        return redirect(app_settings.REMOVE_RENAME_REDIRECT_URL)

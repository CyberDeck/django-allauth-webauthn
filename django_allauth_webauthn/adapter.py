from urllib.parse import urlencode

from allauth.account.adapter import DefaultAccountAdapter
from allauth.exceptions import ImmediateHttpResponse
from django.http import HttpResponseRedirect
from django.urls import reverse

from .utils import sanitize_session
from .utils import user_has_webauthn_enabled


class WebAuthnAdapter(DefaultAccountAdapter):
    def has_webauthn_enabled(self, user):
        """Returns True if the user has to user webauthn as a 2nd login factor."""
        return user_has_webauthn_enabled(user)

    def login(self, request, user):
        # Clean previous logins or failed logins (e.g. aborted during webauth)
        sanitize_session(request)
        # Require two-factor authentication if it has been configured.
        if self.has_webauthn_enabled(user):
            # Cast to string for the case when this is not a JSON serializable
            # object, e.g. a UUID.
            request.session["allauth_webauthn_user_id"] = str(user.id)

            redirect_url = reverse("webauthn-login")
            # Add "next" parameter to the URL.
            view = request.resolver_match.func.view_class()
            view.request = request
            success_url = view.get_success_url()
            query_params = request.GET.copy()
            if success_url:
                query_params[view.redirect_field_name] = success_url
            if query_params:
                redirect_url += "?" + urlencode(query_params)

            raise ImmediateHttpResponse(response=HttpResponseRedirect(redirect_url))

        # Otherwise defer to the original allauth adapter.
        return self.login_without_webauthn(request, user)

    def login_without_webauthn(self, request, user):
        """Perform a login with the original allauth adapter"""
        return super().login(request, user)

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.urls import include
from django.urls import path


def blank_view(request):
    return HttpResponse("<h1>HELLO WORLD!</h1>")


@login_required
def protected_view(request):
    return HttpResponse("secret content")


urlpatterns = [
    path("accounts/", include("allauth.urls")),
    path("webauthn/", include("django_allauth_webauthn.urls")),
    path("reg-error", blank_view, name="test-registration-error"),
    path("login-error", blank_view, name="test-login-error"),
    path("removed-renamed-success", blank_view, name="removed-renamed-success"),
    path("protected", protected_view, name="protected"),
    path("", blank_view, name="home"),
]

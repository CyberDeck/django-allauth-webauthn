from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.views.generic import TemplateView

from django_allauth_webauthn.models import WebauthnData


class Home(TemplateView):
    template_name = "home.html"

    def get_context_data(self, **kwargs):
        if self.request.user.is_active:
            kwargs["tokens"] = WebauthnData.objects.filter(user=self.request.user)
        return super().get_context_data(**kwargs)


@login_required
def secret_view(request):
    return HttpResponse("Secret")

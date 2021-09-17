from django.conf import settings
from django.db import models
from django.utils.timezone import now


class WebauthnData(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=128, blank=True)
    credential_id = models.CharField(max_length=250, unique=True)
    public_key = models.CharField(max_length=65)
    sign_counter = models.IntegerField(default=0)
    last_used_on = models.DateTimeField(default=now)

    def update_sign_counter(self, sign_counter):
        """Updates the sign_counter and last_used_on."""
        self.sign_counter = sign_counter
        self.last_used_on = now()
        self.save()

    def __str__(self):
        return self.name or str(self.user)

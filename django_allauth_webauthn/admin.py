from django.contrib import admin

from .models import WebauthnData


@admin.register(WebauthnData)
class WebauthnDataAdmin(admin.ModelAdmin):
    search_fields = ["name", "credential_id"]
    list_display = ["user", "name", "last_used_on"]

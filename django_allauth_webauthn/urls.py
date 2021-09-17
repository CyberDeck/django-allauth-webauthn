from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.Login.as_view(), name="webauthn-login"),
    path("register/", views.Register.as_view(), name="webauthn-register"),
    path("verify/", views.Verify.as_view(), name="webauthn-verify"),
    path("remove/<int:pk>/", views.Remove.as_view(), name="webauthn-remove"),
    path("rename/<int:pk>/", views.Rename.as_view(), name="webauthn-rename"),
]

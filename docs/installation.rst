Installation
============

Install ``django-allauth-webauthn`` with with pip:

.. code-block:: bash

    $ pip install django-allauth-webauthn

Please note that this will pull in django-allauth as well as Django.

After all these pre-requisites are installed you need to configure those packages by itself.
Please consult at least the `django-allauth documentation`_ for a more detailed guide regarding their configuration and installation requirements.

.. _django-allauth documentation: https://django-allauth.readthedocs.io/en/latest/installation.html

To setup ``django-allauth-webauthn`` please make the following changes to your ``settings.py``:

.. code-block:: python

    ...

    INSTALLED_APPS = [
        # Required by allauth and by django-allauth-webauthn
        "django.contrib.sites",

        # Configure Django auth package
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",

        # Enable messages to give the user feedback about registered tokens
        "django.contrib.messages",

        # Enable allauth
        "allauth",
        "allauth.account",
        "allauth.socialaccount",

        # Enable webauthn-based two-factor authentication
        "django_allauth_webauthn",
        ...
    ]

    ...

    MIDDLEWARE = [
        ...
        # Enable auth and messages middleware
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ]

    ...

    # Configure your default site. See
    # https://docs.djangoproject.com/en/dev/ref/settings/#sites.
    SITE_ID = 1

    # Enable the django-allauth-webauthn adapter
    ACCOUNT_ADAPTER = "django_allauth_webauthn.adapter.WebAuthnAdapter"

    # Tune django-allauth-webauthn for your domain (if not configured
    # the domain is taken from the sites configuration)
    DJANGO_ALLAUTH_WEBAUTHN_DOMAIN = "localhost"
    # Webauthn-authenticator is quite piggy about the origin from
    # which the requests come in. At least set it manually for the
    # development environment (if not configured the origin is
    # constructed from the sites configuration as "https://your-domain/")
    DJANGO_ALLAUTH_WEBAUTHN_ORIGIN = "https://localhost:8000"
    # You may provide a manual name of your site (if not configured
    # the name is taken from the sites configuration)
    DJANGO_ALLAUTH_WEBAUTHN_NAME = "Webauthn Test"

After you modified the ``settings.py`` with aboves configuration, you shall run migrations:

.. code-block:: bash

    $ python manage.py migrate

Finally, you need to include the ``django-allauth-webauthn`` URLs in your ``urls.py``:

.. code-block:: python

    from django.conf.urls import include, path

    urlpatterns = [
        ...
        path("accounts/", include("allauth.urls")),
        path("webauthn/", include("django_allauth_webauthn.urls")),
        ...
    ]

.. warning::

    Any login view that is *not* provided by django-allauth will bypass the
    allauth workflow (**including our webauthn-based two-factor authentication**). The Django admin
    site includes such an additional login view (usually available at
    ``/admin/login``).

    To repeat if you overlooked it:
    If the user is able to login at an additional login view, such as ``/admin/login``, she will be able to use your app without an webauthn-based two-factor authentication at all!

    Please take a look at the `django-allauth-2fa documentation`_ about a possible solution and `pitfalls`_.

.. _django-allauth-2fa documentation: https://django-allauth-2fa.readthedocs.io/en/latest/installation/
.. _pitfalls: https://github.com/valohai/django-allauth-2fa/issues/102

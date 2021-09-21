Configuration
=============

The following configuration settings exists to fine-tune ``django-allauth-webauthn``:

``DJANGO_ALLAUTH_WEBAUTHN_NAME``
--------------------------------

The name of your site. Some authenticators may show this name to the user during token registration or authentication.

Default
    The name defaults to the name from your site settings (see `sites framework`_), i.e. set to the :attr:`~django.contrib.sites.models.Site.name` attribute from the :class:`~django.contrib.sites.models.Site` class instance returned from :func:`~django.contrib.sites.shortcuts.get_current_site`.

``DJANGO_ALLAUTH_WEBAUTHN_DOMAIN``
----------------------------------

The domain of your site. Relevant for the ``webauthn`` specification and how the relying party can communicate with the authenticator.

Default
    The domain defaults to the domain from your site settings (see `sites framework`_), i.e. set to the :attr:`~django.contrib.sites.models.Site.domain` attribute from the :class:`~django.contrib.sites.models.Site` class instance returned from :func:`~django.contrib.sites.shortcuts.get_current_site`.

``DJANGO_ALLAUTH_WEBAUTHN_ORIGIN``
----------------------------------

The origin of requests from your site (i.e. the relying party) to the authentication.

Default
    The origin is constructed from the domain of your site settings (see `sites framework`_) to be ``https://<domain>``.
    The domain itself is retrieved from ``DJANGO_ALLAUTH_WEBAUTHN_DOMAIN``.

.. warning::

    Within a development environment it is utterly important to include the *port* of your development server. Thus, for a standard Django development server set this setting manually to:

    .. code-block:: python

        DJANGO_ALLAUTH_WEBAUTHN_ORIGIN = "https://localhost:8000"

    Please ensure that you access the development server by browsing to https://localhost:8000/ (**not** to **127.0.0.1**).

``DJANGO_ALLAUTH_WEBAUTHN_ICON_URL``
------------------------------------

An URL pointing to an icon (e.g. the site's favicon). Some authenticator present this icon to the user.

Default
    The icon URL is constructed from the domain of your site settings (see `sites framework`_) to be ``https://<domain>/favicon.ico``.
    The domain itself is retrieved from ``DJANGO_ALLAUTH_WEBAUTHN_DOMAIN``.

``DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_REDIRECT_URL``
-----------------------------------------------------

Set this to an URL to redirect the user to after a successful registration of a security token.

Default
    :setting:`LOGIN_REDIRECT_URL`

``DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_ERROR_URL``
--------------------------------------------------

Set this to an URL to redirect the user to after a aborted or failed registration of a security token.

Default
    :setting:`LOGIN_REDIRECT_URL`

``DJANGO_ALLAUTH_WEBAUTHN_LOGIN_ERROR_URL``
-------------------------------------------

Set this to an URL to redirect the user to after a failed two-factor authentication.

Default
    :setting:`LOGIN_URL`


``DJANGO_ALLAUTH_WEBAUTHN_REMOVE_RENAME_REDIRECT_URL``
------------------------------------------------------

Set this to an URL to redirect the user to after a security token was renamed or deleted.

Default
    :setting:`LOGIN_REDIRECT_URL`

.. _sites framework: https://docs.djangoproject.com/en/dev/ref/contrib/sites/

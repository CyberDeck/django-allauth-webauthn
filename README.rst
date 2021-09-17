Welcome to django-allauth-webauthn!
===================================

``django-allauth-webauthn`` adds `two-factor authentication`_ by using the `webauthn`_ standard to `django-allauth`_.
django-allauth is a set of `Django`_ applications which help with authentication, registration, and other account management tasks.

Using the `webauthn`_ standard for the second authentication factor allows for a variety of authentication schemes on the client side.
The user may authenticate by using a roaming hardware token (e.g. a USB key or Bluetooth Low Energy device) or the operating system may provide the authentication functionality (e.g. Windows Hello).

``django-allauth-webauthn`` does not implement the `webauthn`_ standard to allow for *password-less* logins.
It allows to authenticate a user *after* the usual login scheme against a pre-registered security token.
The user may pre-register an arbitrary amount of tokens.

Source code
    http://github.com/cyberdeck/django-allauth-webauthn
Documentation
    https://django-allauth-webauthn.readthedocs.io/

Main Feature
------------

Adds `webauthn`_-based `two-factor authentication`_ views and workflow to `django-allauth`_.

Compatibility
-------------

``django-allauth-webauthn`` was actively developed against `django-allauth`_ 0.45 using `Django`_ 3.2 and Python 3.8.

However, it includes exceptional testing aiming for 100% coverage and thus, you may test it easily against your version requirements.
If you need to patch it due to compatibility reasons I would love to see you contributing a *pull request*.

Where does it come from?
------------------------

``django-allauth-webauthn`` was created from scratch but it borrows a lot of ingredients from `django-allauth-2fa`_ and `django-webauthin`_.
Both packages are exceptionally useful but does not included the feature to allow for a `webauthn`_-based `two-factor authentication`_ out of the box.

Contributing
------------

``django-allauth-webauthn`` was initially developed by H. Gregor Molter due to the lack of other suitable `webauthn`_-based `two-factor authentication`_ packages.
Please feel free to contribute if you find ``django-allauth-webauthn`` useful!

1. Check for open issues or open a new issue to start a discussion around a bug or your special feature request.
2. For the `repository`_ on GitHub and start to develop on the **master** branch or a custom branch derived from the master branch.
3. Write one or multiple test(s) to allow for validation that the bug was fixed or that your special feature works as expected without any negative impact on the behavior of the other functionality.
4. Before submitting your patch please thoroughly check your contribution by executing the pre-commit script.
5. Send a pull request to get your changes merged and published.

.. _repository: http://github.com/cyberdeck/django-allauth-webauthn/

Developing
**********

``django-allauth-webauthn`` make heavy use of the `poetry`_ Python packaging and dependency manager and the `pre-commit`_ framework.

After you forked (and branched) ``django-allauth-webauthn`` please install all development dependencies with `poetry`_:

.. code-block:: bash

    $ poetry install

`poetry`_ will install all needed development dependencies in a virtual environment for you.
Afterwards install the `pre-commit`_ hooks by running:

.. code-block:: bash

    $ poetry run pre-commit install

The pre-commit hooks will be executed automatically prior committing to the Git repository.
There are hooks for source code styling (e.g. import reordering) and it is ensured that all tests may be executed successfully and that no obvious type checking issues are included.

To execute these hooks manually (i.e. without performing a commit) execute the following:

.. code-block:: bash

    $ poetry run pre-commit run --all-files

.. _poetry: https://python-poetry.org/
.. _pre-commit: https://pre-commit.com/

Testing
*******

Tests can be run using the standard Django testing facility by executing:

.. code-block:: bash

    $ poetry run python manage.py test

Coverage
********

During test execution a coverage report can be created with:

.. code-block:: bash

    $ poetry run coverage run manage.py test

To view the coverage report on the command line you have to execute:

.. code-block:: bash

    $ poetry run coverage report -m

or you can generate an HTML report for more eye candy:

.. code-block:: bash

    $ poetry run coverage html

The resulting HTML report will be stored in the ``coverage_html`` folder.

Demo Project
************

A simple demo Django project is included within the *demo* folder and may be run by:

.. code-block:: bash

    $ cd demo
    # Migrate the demo database first (only needed once)
    $ poetry run python manage.py migrate
    # Run the SSL demo server (a self-signed certificate and private key is created during first run)
    $ poetry run python manage.py runserver_plus --cert test.crt

.. note::

    The `webauthn`_ technology requires you to run your test server over *https*.
    Otherwise the registration of security tokens or authentication cannot be executed successfully.
    Some browser are a little bit piggy about self-signed certificates on **127.0.0.1**.
    Please use at least https://localhost:8000/ to access the demo server and consult the web about your browser's behavior before submitting an issue!

The demo app allows you to register security tokens to a logged in user.
If a user has at least a single security token registered, she will be asked to authenticate with this token during sign in.
Security tokens may be renamed or deleted. All in one, it demonstrates the basic workflow for `webauthn`_-based `two-factor authentication`_.

.. note::

    If you do not have a security token at hand or if you hesitate to use your super-secret token during development, you may `emulate authenticators`_ with the Chrome browser.

.. _emulate authenticators: https://developer.chrome.com/docs/devtools/webauthn/

.. _two-factor authentication: https://en.wikipedia.org/wiki/Multi-factor_authentication
.. _webauthn: https://en.wikipedia.org/wiki/WebAuthn
.. _django-allauth: https://github.com/pennersr/django-allauth/
.. _django-allauth-2fa: https://github.com/valohai/django-allauth-2fa/
.. _django-webauthin: https://gitlab.com/stavros/django-webauthin/
.. _Django: https://www.djangoproject.com/

import json
from typing import Optional
from unittest.mock import patch

from allauth.account.signals import user_logged_in
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from django_allauth_webauthn.models import WebauthnData


class BaseTests:
    class TestWebauthn(TestCase):
        # Mocked random challenges during registration and login
        REGISTRATION_CHALLENGE: Optional[str] = None
        LOGIN_CHALLENGE: Optional[str] = None

        # Expected data to be read from get requests or written by post requests
        REGISTRATION_GET_DATA: Optional[dict] = None
        REGISTRATION_POST_DATA: Optional[dict] = None
        LOGIN_GET_DATA: Optional[dict] = None
        LOGIN_POST_DATA: Optional[dict] = None

        # The WebauthnData device which fits the aboves testdata
        DEVICE: Optional[dict] = None

        # Another unspecified WebauthnData device to test login failure with aboves data,
        # i.e. test if valid authentication data for the wrong device fails
        DEVICE_2 = {
            "credential_id": "yd3MdXVR-YYXXLvn8PthHCTNztwsJq41i_JDHo8Z3Ks",
            "public_key": "pQECAyYgASFYIAyjRD_Dgdb6odM44rDRlcrKIeR_X_HMr6mgp4xsjyuVIlggZDGtL3LWBx3TJrbs1y72FYaF4q-GapajZrx4faRdGTE",  # noqa
            "sign_counter": 5,
            "name": "Device #2",
        }

        def setUp(self):
            # Track the signals sent via allauth.
            self.user_logged_in_count = 0
            user_logged_in.connect(self._login_callback)

        def _login_callback(self, sender, **kwargs):
            self.user_logged_in_count += 1

        def setup_testcase(
            self,
            username="test",
            password="testpa$$w0rD",
            id=None,
            login=False,
            set_session_user_id=False,
            set_session_challenge=None,
            devices=None,
        ):
            createargs = {"username": username}
            if id:
                createargs["id"] = id

            user = get_user_model().objects.create(**createargs)
            user.set_password(password)
            user.save()

            if devices:
                for device in devices:
                    device = WebauthnData.objects.create(user=user, **device)

            if set_session_user_id or set_session_challenge:
                session = self.client.session
                if set_session_user_id:
                    session["allauth_webauthn_user_id"] = user.id
                if set_session_challenge:
                    session["allauth_webauthn_challenge"] = set_session_challenge
                session.save()

            if login:
                self.client.force_login(user)

            return user

        def test_account_login_without_webauthn_enabled(self):
            user = self.setup_testcase()
            # Manually login user
            response = self.client.post(
                reverse("account_login"),
                {"login": user.username, "password": "testpa$$w0rD"},
            )

            self.assertRedirects(
                response,
                settings.LOGIN_REDIRECT_URL,
                fetch_redirect_response=False,
            )
            self.assertEqual(self.user_logged_in_count, 1)
            # Try to access a protected page
            response = self.client.get(reverse("protected"))
            self.assertEqual(response.content, b"secret content")

        def test_account_login_with_webauthn_enabled(self):
            user = self.setup_testcase(devices=[self.DEVICE])
            # Manually login user
            response = self.client.post(
                reverse("account_login"),
                {"login": user.username, "password": "testpa$$w0rD"},
            )

            self.assertRedirects(response, reverse("webauthn-login"), fetch_redirect_response=False)
            self.assertEqual(self.user_logged_in_count, 0)

        def test_account_login_with_webauthn_enabled_and_next_page_(self):
            user = self.setup_testcase(devices=[self.DEVICE])
            # Manually login user
            redirect_next = "?next=" + reverse("protected")
            response = self.client.post(
                reverse("account_login") + redirect_next,
                {"login": user.username, "password": "testpa$$w0rD"},
            )

            self.assertRedirects(
                response,
                reverse("webauthn-login") + redirect_next,
                fetch_redirect_response=False,
            )
            self.assertEqual(self.user_logged_in_count, 0)

        def test_webauthn_register_get_without_valid_session(self):
            response = self.client.get(reverse("webauthn-register"))
            self.assertRedirects(
                response,
                reverse("account_login") + "?next=" + reverse("webauthn-register"),
                fetch_redirect_response=False,
            )

        @patch("django_allauth_webauthn.views.random_numbers_letters")
        def test_webauthn_register_get(self, mock_challenge):
            mock_challenge.return_value = self.REGISTRATION_CHALLENGE
            self.setup_testcase(id=2, login=True, set_session_user_id=True)
            response = self.client.get(reverse("webauthn-register"))
            self.assertEqual(response.status_code, 200)
            registration_data = json.loads(response.content)
            self.assertEqual(registration_data, self.REGISTRATION_GET_DATA)

        def test_webauthn_register_post_without_logged_in_user_fails(self):
            response = self.client.post(reverse("webauthn-register"))
            self.assertRedirects(
                response,
                reverse("account_login") + "?next=" + reverse("webauthn-register"),
                fetch_redirect_response=False,
            )

        def test_webauthn_register_post_without_session_challenge_fails(self):
            self.setup_testcase(id=2, login=True)
            response = self.client.post(reverse("webauthn-register"))
            self.assertEqual(response.status_code, 422)

        def test_webauthn_register_post_without_data_fails(self):
            user = self.setup_testcase(
                id=2,
                login=True,
                set_session_user_id=True,
                set_session_challenge=self.REGISTRATION_CHALLENGE,
            )
            response = self.client.post(reverse("webauthn-register"))
            self.assertRedirects(
                response,
                settings.DJANGO_ALLAUTH_WEBAUTHN_REGISTRATION_ERROR_URL,
                fetch_redirect_response=False,
            )
            self.assertFalse(WebauthnData.objects.filter(user=user).exists())

        def test_webauthn_register_post_with_token_from_some_account_fails(self):
            # Register the device to another account
            self.setup_testcase(username="other", devices=[self.DEVICE])
            user = self.setup_testcase(
                id=2,
                login=True,
                set_session_user_id=True,
                set_session_challenge=self.REGISTRATION_CHALLENGE,
            )
            self.assertFalse(WebauthnData.objects.filter(user=user).exists())
            response = self.client.post(reverse("webauthn-register"), self.REGISTRATION_POST_DATA)
            self.assertRedirects(
                response,
                reverse("test-registration-error"),
                fetch_redirect_response=False,
            )
            # Registering a known token did not work
            self.assertFalse(WebauthnData.objects.filter(user=user).exists())

        def test_webauthn_register_post(self):
            user = self.setup_testcase(
                id=2,
                login=True,
                set_session_user_id=True,
                set_session_challenge=self.REGISTRATION_CHALLENGE,
            )
            self.assertFalse(WebauthnData.objects.filter(user=user).exists())
            response = self.client.post(reverse("webauthn-register"), self.REGISTRATION_POST_DATA)
            self.assertTrue(WebauthnData.objects.filter(user=user).exists())
            device = WebauthnData.objects.filter(user=user).last()
            self.assertEqual(device.credential_id, self.DEVICE["credential_id"])
            self.assertEqual(device.public_key, self.DEVICE["public_key"])
            self.assertEqual(device.sign_counter, self.DEVICE["sign_counter"])
            self.assertRedirects(
                response,
                settings.LOGIN_REDIRECT_URL,
                fetch_redirect_response=False,
            )

        def test_login_view_without_session_user_id_fails(self):
            self.setup_testcase(id=2, devices=[self.DEVICE])
            response = self.client.get(reverse("webauthn-login"))
            self.assertRedirects(response, reverse("account_login"), fetch_redirect_response=False)

        def test_login_view(self):
            self.setup_testcase(id=2, devices=[self.DEVICE], set_session_user_id=True)
            self.client.get(reverse("webauthn-login"))
            self.assertTemplateUsed("django_allauth_webauthn/login.html")

        @patch("django_allauth_webauthn.views.random_numbers_letters")
        def test_verify_get(self, mock_challenge):
            mock_challenge.return_value = self.LOGIN_CHALLENGE
            self.setup_testcase(id=2, devices=[self.DEVICE], set_session_user_id=True)
            response = self.client.get(reverse("webauthn-verify"))
            self.assertEqual(response.status_code, 200)
            login_data = json.loads(response.content)
            self.assertEqual(login_data, self.LOGIN_GET_DATA)
            # Ensure that the challenge is set correctly to the session, too.
            session = self.client.session
            self.assertEqual(session["allauth_webauthn_challenge"], self.LOGIN_CHALLENGE)

        def test_verify_post_without_session_user_id_fails(self):
            self.setup_testcase(id=2, devices=[self.DEVICE], set_session_challenge=self.LOGIN_CHALLENGE)
            response = self.client.post(reverse("webauthn-verify"), self.LOGIN_POST_DATA)
            self.assertRedirects(response, reverse("test-login-error"))

        def test_verify_post_without_session_challenge_fails(self):
            self.setup_testcase(id=2, devices=[self.DEVICE], set_session_user_id=True)
            response = self.client.post(reverse("webauthn-verify"), self.LOGIN_POST_DATA)
            self.assertRedirects(response, reverse("test-login-error"))

        def test_verify_post_without_correct_device_fails(self):
            self.setup_testcase(
                id=2,
                devices=[self.DEVICE_2],
                set_session_user_id=True,
                set_session_challenge=self.LOGIN_CHALLENGE,
            )
            response = self.client.post(reverse("webauthn-verify"), self.LOGIN_POST_DATA)
            self.assertRedirects(response, reverse("test-login-error"))

        def test_verify_post_with_replayed_data_fails(self):
            """Do a basic test with a replay attack in terms of an invalid sign counter (less or equal the actual one)"""
            user = self.setup_testcase(
                id=2,
                devices=[self.DEVICE],
                set_session_user_id=True,
                set_session_challenge=self.LOGIN_CHALLENGE,
            )
            device = user.webauthndata_set.first()
            device.sign_counter = 2
            device.save()
            self.assertEqual(self.user_logged_in_count, 0)
            response = self.client.post(reverse("webauthn-verify"), self.LOGIN_POST_DATA)
            # User not logged in?
            self.assertEqual(self.user_logged_in_count, 0)
            self.assertRedirects(response, reverse("test-login-error"))

        def test_verify_post(self):
            user = self.setup_testcase(
                id=2,
                devices=[self.DEVICE_2, self.DEVICE],
                set_session_user_id=True,
                set_session_challenge=self.LOGIN_CHALLENGE,
            )
            device = user.webauthndata_set.get(credential_id=self.DEVICE["credential_id"])
            initial_sign_counter = device.sign_counter
            self.assertEqual(self.user_logged_in_count, 0)
            self.client.post(reverse("webauthn-verify"), self.LOGIN_POST_DATA)
            # User logged in?
            self.assertEqual(self.user_logged_in_count, 1)
            # Sign counter increased?
            device.refresh_from_db()
            self.assertGreater(device.sign_counter, initial_sign_counter)
            # Session variables removed / sanitized?
            session = self.client.session
            self.assertNotIn("allauth_webauthn_user_id", session)
            self.assertNotIn("allauth_webauthn_challenge", session)

        def test_verify_post_with_redirect(self):
            user = self.setup_testcase(
                id=2,
                devices=[self.DEVICE_2, self.DEVICE],
                set_session_user_id=True,
                set_session_challenge=self.LOGIN_CHALLENGE,
            )
            user.webauthndata_set.get(credential_id=self.DEVICE["credential_id"])
            response = self.client.post(
                reverse("webauthn-verify") + "?next=" + reverse("protected"),
                self.LOGIN_POST_DATA,
            )
            # User logged in?
            self.assertEqual(self.user_logged_in_count, 1)
            # Redirected to target page?
            self.assertRedirects(response, reverse("protected"))

        def test_account_login_with_webauthn_enabled_fails_without_token(self):
            user = self.setup_testcase(id=2, devices=[self.DEVICE])
            response = self.client.post(
                reverse("account_login"),
                {"login": user.username, "password": "testpa$$w0rD"},
            )
            self.assertRedirects(response, reverse("webauthn-login"), fetch_redirect_response=False)
            self.assertEqual(self.user_logged_in_count, 0)
            # Protected page should not render but redirect back to login
            response = self.client.get(reverse("protected"))
            self.assertRedirects(
                response,
                reverse("account_login") + "?next=/protected",
                fetch_redirect_response=False,
            )

        def test_rename_post_for_not_owned_devices_fails(self):
            other_user = self.setup_testcase(username="other", devices=[self.DEVICE_2])
            self.setup_testcase(devices=[self.DEVICE], login=True)
            other_user_device = other_user.webauthndata_set.get(credential_id=self.DEVICE_2["credential_id"])
            self.assertEqual(other_user_device.name, "Device #2")
            with self.assertRaises(WebauthnData.DoesNotExist):
                self.client.post(
                    reverse("webauthn-rename", kwargs={"pk": other_user_device.pk}),
                    {"name": "My new name"},
                )
            other_user_device.refresh_from_db()
            self.assertEqual(other_user_device.name, "Device #2")

        def test_rename_post(self):
            user = self.setup_testcase(devices=[self.DEVICE], login=True)
            device = user.webauthndata_set.get(credential_id=self.DEVICE["credential_id"])
            self.assertEqual(device.name, "Device #1")
            response = self.client.post(
                reverse("webauthn-rename", kwargs={"pk": device.pk}),
                {"name": "My new name"},
            )
            self.assertRedirects(
                response,
                reverse("removed-renamed-success"),
                fetch_redirect_response=False,
            )
            device.refresh_from_db()
            self.assertEqual(device.name, "My new name")

        def test_remove_post_for_not_owned_devices_fails(self):
            other_user = self.setup_testcase(username="other", devices=[self.DEVICE_2])
            self.setup_testcase(devices=[self.DEVICE], login=True)
            other_user_device = other_user.webauthndata_set.get(credential_id=self.DEVICE_2["credential_id"])
            self.assertTrue(other_user.webauthndata_set.filter(credential_id=self.DEVICE_2["credential_id"]).exists())
            with self.assertRaises(WebauthnData.DoesNotExist):
                self.client.post(reverse("webauthn-remove", kwargs={"pk": other_user_device.pk}))
            self.assertTrue(other_user.webauthndata_set.filter(credential_id=self.DEVICE_2["credential_id"]).exists())

        def test_remove_post(self):
            user = self.setup_testcase(devices=[self.DEVICE], login=True)
            device = user.webauthndata_set.get(credential_id=self.DEVICE["credential_id"])
            self.assertTrue(user.webauthndata_set.filter(credential_id=self.DEVICE["credential_id"]).exists())
            self.client.post(reverse("webauthn-remove", kwargs={"pk": device.pk}))
            self.assertFalse(user.webauthndata_set.filter(credential_id=self.DEVICE["credential_id"]).exists())


class TestWebauthnCTAP2(BaseTests.TestWebauthn):
    REGISTRATION_CHALLENGE = "gWr81DvWPCLkOPwBqyUOXDr7XnsMQcw1"
    LOGIN_CHALLENGE = "vXUgAJyIOdouNr3dACKs7NW4WMh6nMRJ"

    # The dicts are dumped and loaded with json to ensure equal json output with the test data.
    # Otherwise some single-value tuples are compared against single-value lists...
    REGISTRATION_GET_DATA = json.loads(
        json.dumps(
            {
                "challenge": REGISTRATION_CHALLENGE,
                "rp": {"name": "Webauthn Test", "id": "localhost"},
                "user": {
                    "id": "Mg==",
                    "name": "test",
                    "displayName": ("Webauthn Test user: test",),
                    "icon": "https://localhost:8000/favicon.ico",
                },
                "pubKeyCredParams": [
                    {"alg": -7, "type": "public-key"},
                    {"alg": -257, "type": "public-key"},
                    {"alg": -37, "type": "public-key"},
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "direct",
                "extensions": {"webauthn.loc": True},
            }
        )
    )

    REGISTRATION_POST_DATA = {
        "id": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
        "rawId": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
        "type": "public-key",
        "attObj": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAL21FJyx959Rs3nwo61SpNu8Gt3X1blxGnDnfjRRcKcNAiEA3M7PhbCUTChCRqNPIh1fbOA5Zto4RWdOY_OsTn81TlJjeDVjgVkB3jCCAdowggF9oAMCAQICAQEwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00MTA5MTAxOTU4NTZaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzATBgsrBgEEAYLlHAIBAQQEAwIFIDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA0gAMEUCIQC9SGLply8pw6QIsW67rLNSUeUXoPaHbsh7SpsPrPNYtwIgZKEWn1CpRIh4p7h460VMOxe8EQ1_FlBA_bIqIsTzWEBoYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAEBAgMEBQYHCAECAwQFBgcIACCwNJ56ojut7ZCKPat5m-AW1nxg6ldiOQNfbemC2OWVkKUBAgMmIAEhWCAs8n6Uv2IdoEdN3FqEmFhc22KRTR2vbjizTEi0zQgP2SJYIBOVdl7yJa_5GEENQMcAoXJvHav2qesgQQ6P3rTEJmsc",  # noqa
        "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ1dyODFEdldQQ0xrT1B3QnF5VU9YRHI3WG5zTVFjdzEiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",  # noqa
        "registrationClientExtensions": "{}",
    }

    LOGIN_GET_DATA = json.loads(
        json.dumps(
            {
                "challenge": LOGIN_CHALLENGE,
                "timeout": 60000,
                "rpId": "localhost",
                "allowCredentials": [
                    {
                        "id": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
                        "type": "public-key",
                    }
                ],
                "userVerification": "preferred",
            }
        )
    )

    LOGIN_POST_DATA = {
        "id": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
        "rawId": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
        "type": "public-key",
        "authData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg==",
        "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidlhVZ0FKeUlPZG91TnIzZEFDS3M3Tlc0V01oNm5NUkoiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",  # noqa
        "signature": "3045022100809f264357de167540f67f398bce9b23fc70269d9f4d6e45214723dfc051b22202204922922be6649bb01af1a96d794b03e652b74e1e8ff17fbedca9bdcc2e6853a4",  # noqa
        "assertionClientExtensions": "{}",
    }

    DEVICE = {
        "credential_id": "sDSeeqI7re2Qij2reZvgFtZ8YOpXYjkDX23pgtjllZA",
        "public_key": "pQECAyYgASFYICzyfpS_Yh2gR03cWoSYWFzbYpFNHa9uOLNMSLTNCA_ZIlggE5V2XvIlr_kYQQ1AxwChcm8dq_ap6yBBDo_etMQmaxw",
        "sign_counter": 1,
        "name": "Device #1",
    }


class TestWebauthnU2F(BaseTests.TestWebauthn):
    REGISTRATION_CHALLENGE = "W5TDQtAUGXS7TqwIMlI9TJLvc8Zixwfy"
    LOGIN_CHALLENGE = "9owV5Nr47k5ImAxNOEr1bGPosTiulIYO"

    # The dicts are dumped and loaded with json to ensure equal json output with the test data.
    # Otherwise some single-value tuples are compared against single-value lists...
    REGISTRATION_GET_DATA = json.loads(
        json.dumps(
            {
                "challenge": REGISTRATION_CHALLENGE,
                "rp": {"name": "Webauthn Test", "id": "localhost"},
                "user": {
                    "id": "Mg==",
                    "name": "test",
                    "displayName": ("Webauthn Test user: test",),
                    "icon": "https://localhost:8000/favicon.ico",
                },
                "pubKeyCredParams": [
                    {"alg": -7, "type": "public-key"},
                    {"alg": -257, "type": "public-key"},
                    {"alg": -37, "type": "public-key"},
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "direct",
                "extensions": {"webauthn.loc": True},
            }
        )
    )

    REGISTRATION_POST_DATA = {
        "id": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
        "rawId": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
        "type": "public-key",
        "attObj": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAPXJyJWQ4rMuJZMEyObKCQcrDkwGjLFqUzFZZpFwbx9NAiEAiIR4z-lcsXsaURPkF9rS5ePjDL3fZKfgonZOoWfjz-ZjeDVjgVkB3zCCAdswggF9oAMCAQICAQEwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00MTA5MTAyMDA0NDZaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzATBgsrBgEEAYLlHAIBAQQEAwIFIDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA0kAMEYCIQDCpbuX5xS4iJIsc3V9i_Vndw0OvEiPlfiOpuAoHGjZ-QIhAMhPya13X5hoWBKTUeAwE-Tfw9zc27JDCGOXGD4AQy6raGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAAAgaCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJalAQIDJiABIVggwtSQRUx62PwYiNH1-8UlZuW8dHff4F0Wap0MOHik2gciWCDrFo_4N_dlSXQ5t4s92VKxHDTzl1AzVH3P4PFLOtbr7g",  # noqa
        "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVzVURFF0QVVHWFM3VHF3SU1sSTlUSkx2YzhaaXh3ZnkiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",  # noqa
        "registrationClientExtensions": "{}",
    }

    LOGIN_GET_DATA = json.loads(
        json.dumps(
            {
                "challenge": LOGIN_CHALLENGE,
                "timeout": 60000,
                "rpId": "localhost",
                "allowCredentials": [
                    {
                        "id": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
                        "type": "public-key",
                    }
                ],
                "userVerification": "preferred",
            }
        )
    )

    LOGIN_POST_DATA = {
        "id": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
        "rawId": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
        "type": "public-key",
        "authData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAg==",
        "clientData": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOW93VjVOcjQ3azVJbUF4Tk9FcjFiR1Bvc1RpdWxJWU8iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",  # noqa
        "signature": "3045022100c015418be3da081df47d399b58a03d2745ebf7ecbd2cd7acbcc1da650ed8139802201e2b98f7ca27112970463abfbd56f1aab32ae8613df76aa6882a8cb816c49749",  # noqa
        "assertionClientExtensions": "{}",
    }

    DEVICE = {
        "credential_id": "aCh9CpDe1omGzbU_7zNebWWZtYrdgnchxQWKKFc6HJY",
        "public_key": "pQECAyYgASFYIMLUkEVMetj8GIjR9fvFJWblvHR33-BdFmqdDDh4pNoHIlgg6xaP-Df3ZUl0ObeLPdlSsRw085dQM1R9z-DxSzrW6-4",
        "sign_counter": 0,
        "name": "Device #1",
    }

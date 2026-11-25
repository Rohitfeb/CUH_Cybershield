import os
import re
import unittest
from urllib.parse import urlparse
from unittest.mock import MagicMock, patch

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "password-reset-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, User


class PasswordResetTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.app.config["PASSWORD_RESET_TOKEN_MAX_AGE"] = 1800
        self.app.config.update(
            MAIL_SERVER=None,
            MAIL_USERNAME=None,
            MAIL_PASSWORD=None,
            MAIL_DEFAULT_SENDER=None
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            user = User(name="Test User", email="test@example.com", role="student")
            user.set_password("original-password")
            db.session.add(user)
            db.session.commit()

    def _request_reset_link(self):
        response = self.client.post(
            "/forgot-password",
            data={"email": "test@example.com"}
        )
        self.assertEqual(response.status_code, 200)
        match = re.search(
            r'href="([^"]*reset-password/[^"]+)"',
            response.get_data(as_text=True)
        )
        self.assertIsNotNone(match)
        return urlparse(match.group(1)).path

    def test_reset_link_changes_password_and_cannot_be_reused(self):
        reset_path = self._request_reset_link()

        response = self.client.post(
            reset_path,
            data={
                "password": "replacement-password",
                "confirm_password": "replacement-password"
            }
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            user = User.query.filter_by(email="test@example.com").one()
            self.assertTrue(user.check_password("replacement-password"))
            self.assertFalse(user.check_password("original-password"))
            self.assertTrue(
                user.password_hash.startswith("pbkdf2:sha256:600000$")
            )

        response = self.client.get(reset_path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/forgot-password", response.location)

    def test_reset_rejects_mismatched_passwords(self):
        reset_path = self._request_reset_link()

        response = self.client.post(
            reset_path,
            data={
                "password": "replacement-password",
                "confirm_password": "different-password"
            }
        )
        self.assertEqual(response.status_code, 200)

        with self.app.app_context():
            user = User.query.filter_by(email="test@example.com").one()
            self.assertTrue(user.check_password("original-password"))

    def test_expired_reset_link_is_rejected(self):
        reset_path = self._request_reset_link()
        self.app.config["PASSWORD_RESET_TOKEN_MAX_AGE"] = -1

        response = self.client.get(reset_path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/forgot-password", response.location)

    def test_unknown_email_does_not_show_reset_link(self):
        response = self.client.post(
            "/forgot-password",
            data={"email": "unknown@example.com"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(
            "reset-password/",
            response.get_data(as_text=True)
        )

    def test_local_reset_link_is_available_when_debug_is_disabled(self):
        self.app.debug = False
        self.app.config["DEPLOYMENT_ENV"] = "development"
        self.app.config["RESET_BASE_URL"] = "http://127.0.0.1:5000"

        response = self.client.post(
            "/forgot-password",
            data={"email": "test@example.com"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "reset-password/",
            response.get_data(as_text=True)
        )
        self.assertIn(
            "Continue to set new password",
            response.get_data(as_text=True)
        )

    def test_configured_mail_route_attempts_delivery(self):
        config = {
            "MAIL_SERVER": "smtp.example.com",
            "MAIL_USERNAME": "sender@example.com",
            "MAIL_PASSWORD": "smtp-app-password",
            "MAIL_DEFAULT_SENDER": "sender@example.com",
            "RESET_BASE_URL": "https://cybershield.example"
        }
        with patch.dict(self.app.config, config), patch(
            "app._send_password_reset_email"
        ) as send_email:
            response = self.client.post(
                "/forgot-password",
                data={"email": "test@example.com"}
            )

        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once()
        self.assertTrue(
            send_email.call_args.args[1].startswith(
                "https://cybershield.example/reset-password/"
            )
        )

    def test_forgot_page_shows_when_email_delivery_is_unconfigured(self):
        response = self.client.get("/forgot-password")
        self.assertIn(
            "Email delivery is not configured",
            response.get_data(as_text=True)
        )

    def test_login_and_registration_have_password_visibility_controls(self):
        login_page = self.client.get("/login").get_data(as_text=True)
        register_page = self.client.get("/register").get_data(as_text=True)
        self.assertIn('data-toggle-password="login-password"', login_page)
        self.assertIn('data-toggle-password="register-password"', register_page)
        self.assertIn("/forgot-password", login_page)

    def test_smtp_delivery_uses_tls_and_sends_reset_message(self):
        user = User(name="Mail User", email="mail@example.com", role="student")
        smtp = MagicMock()
        smtp_context = smtp.__enter__.return_value
        config = {
            "MAIL_SERVER": "smtp.example.com",
            "MAIL_PORT": 587,
            "MAIL_USE_TLS": True,
            "MAIL_USE_SSL": False,
            "MAIL_USERNAME": "sender@example.com",
            "MAIL_PASSWORD": "smtp-app-password",
            "MAIL_DEFAULT_SENDER": "sender@example.com"
        }

        with patch.dict(self.app.config, config), self.app.app_context(), patch(
            "app.smtplib.SMTP",
            return_value=smtp
        ):
            application._send_password_reset_email(
                user,
                "https://cybershield.example/reset-password/test-token"
            )

        smtp_context.starttls.assert_called_once()
        smtp_context.login.assert_called_once_with(
            "sender@example.com",
            "smtp-app-password"
        )
        message = smtp_context.send_message.call_args.args[0]
        self.assertEqual(message["To"], "mail@example.com")
        self.assertIn("reset-password/test-token", message.get_content())


if __name__ == "__main__":
    unittest.main()

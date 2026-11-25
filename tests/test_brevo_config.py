import os
import unittest

from config import validate_deployment_config

BASE = {
    "SECRET_KEY": "x" * 48,
    "DEPLOYMENT_ENV": "production",
    "SQLALCHEMY_DATABASE_URI": "postgresql+psycopg://u:p@host/db?sslmode=require",
    "SESSION_COOKIE_SECURE": True,
    "RESET_BASE_URL": "https://example.onrender.com",
    "MAIL_DEFAULT_SENDER": "sender@example.com",
}


def mail_errors(config):
    return [e for e in validate_deployment_config(config) if "MAIL" in e or "BREVO" in e]


class BrevoConfigTests(unittest.TestCase):
    def test_brevo_key_satisfies_production_mail_requirement(self):
        config = dict(BASE, BREVO_API_KEY="key", MAIL_SERVER=None)
        self.assertEqual(mail_errors(config), [])

    def test_missing_mail_provider_is_reported(self):
        config = dict(BASE, BREVO_API_KEY=None, MAIL_SERVER=None)
        self.assertTrue(
            any("BREVO_API_KEY" in e for e in mail_errors(config))
        )


if __name__ == "__main__":
    unittest.main()

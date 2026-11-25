import io
import os
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "email-checker-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, User


class EmailCheckerTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            user = User(
                name="Student",
                email="student@example.com",
                role="student",
            )
            user.set_password("valid-password")
            db.session.add(user)
            db.session.commit()
        self.client.post(
            "/login",
            data={
                "email": "student@example.com",
                "password": "valid-password",
            },
        )

    def test_eml_upload_shows_headers_and_detected_links_as_text(self):
        message = (
            b"From: Security Team <sender@example.org>\r\n"
            b"Subject: Urgent password verification\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Click here to verify your password immediately: "
            b"https://example.test/account\r\n"
        )
        response = self.client.post(
            "/email-checker",
            data={
                "email_file": (io.BytesIO(message), "suspicious.eml"),
            },
            content_type="multipart/form-data",
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("High Risk", page)
        self.assertIn("Urgent password verification", page)
        self.assertIn("sender@example.org", page)
        self.assertIn("https://example.test/account", page)
        self.assertNotIn('href="https://example.test/account"', page)

    def test_pasted_email_still_analyzes(self):
        response = self.client.post(
            "/email-checker",
            data={"email": "Please verify your password immediately."},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("High Risk", response.get_data(as_text=True))

    def test_rejects_non_eml_and_multiple_input_sources(self):
        unsupported = self.client.post(
            "/email-checker",
            data={"email_file": (io.BytesIO(b"email"), "message.txt")},
            content_type="multipart/form-data",
        )
        self.assertIn(
            "Upload an email file in .eml format.",
            unsupported.get_data(as_text=True),
        )

        both_sources = self.client.post(
            "/email-checker",
            data={
                "email": "Pasted message",
                "email_file": (io.BytesIO(b"Subject: Test\r\n\r\nBody"), "message.eml"),
            },
            content_type="multipart/form-data",
        )
        self.assertIn(
            "Paste email text or upload an .eml file, not both.",
            both_sources.get_data(as_text=True),
        )

    def test_eml_upload_size_is_limited(self):
        oversized = b"x" * (
            self.app.config["EMAIL_CHECKER_MAX_FILE_BYTES"] + 1
        )
        response = self.client.post(
            "/email-checker",
            data={"email_file": (io.BytesIO(oversized), "large.eml")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Email files must be 2 MB or smaller.",
            response.get_data(as_text=True),
        )


if __name__ == "__main__":
    unittest.main()

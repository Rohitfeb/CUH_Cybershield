import os
import re
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "security-hardening-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, User


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def test_public_pages_include_security_headers(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn(
            "strict-origin-when-cross-origin",
            response.headers["Referrer-Policy"]
        )

    def test_post_forms_include_csrf_token(self):
        for path in (
            "/register",
            "/login",
            "/forgot-password",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                page = response.get_data(as_text=True)
                self.assertIn('name="csrf_token"', page)
                self.assertRegex(
                    page,
                    r'name="csrf_token" value="[A-Za-z0-9_-]+"'
                )

    def test_csrf_rejects_missing_token_outside_test_mode(self):
        self.app.config["TESTING"] = False
        response = self.client.post(
            "/register",
            data={
                "name": "Security Test",
                "email": "security@example.com",
                "password": "valid-password"
            }
        )

        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from models_db import User
            self.assertIsNone(User.query.filter_by(
                email="security@example.com"
            ).first())

    def test_csrf_accepts_matching_session_token(self):
        self.app.config["TESTING"] = False
        page = self.client.get("/register")
        match = re.search(
            r'name="csrf_token" value="([A-Za-z0-9_-]+)"',
            page.get_data(as_text=True)
        )
        self.assertIsNotNone(match)

        response = self.client.post(
            "/register",
            data={
                "name": "Security Test",
                "email": "security@example.com",
                "password": "valid-password",
                "csrf_token": match.group(1)
            }
        )

        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from models_db import User
            self.assertIsNotNone(User.query.filter_by(
                email="security@example.com"
            ).first())

    def test_privacy_page_is_public(self):
        response = self.client.get("/privacy")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Privacy and Data Use", response.get_data(as_text=True))

    def test_change_password_requires_authentication_and_verifies_current_password(self):
        unauthenticated = self.client.get("/change-password")
        self.assertEqual(unauthenticated.status_code, 302)
        self.assertIn("/login", unauthenticated.location)

        with self.app.app_context():
            user = User(
                name="Password User",
                email="password@example.com",
                role="student",
            )
            user.set_password("current-password")
            db.session.add(user)
            db.session.commit()

        self.client.post(
            "/login",
            data={
                "email": "password@example.com",
                "password": "current-password",
            },
        )
        page = self.client.get("/change-password")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Change Password", page.get_data(as_text=True))

        invalid_current = self.client.post(
            "/change-password",
            data={
                "current_password": "wrong-password",
                "password": "replacement-password",
                "confirm_password": "replacement-password",
            },
        )
        self.assertEqual(invalid_current.status_code, 200)

        mismatched = self.client.post(
            "/change-password",
            data={
                "current_password": "current-password",
                "password": "replacement-password",
                "confirm_password": "different-password",
            },
        )
        self.assertEqual(mismatched.status_code, 200)

        changed = self.client.post(
            "/change-password",
            data={
                "current_password": "current-password",
                "password": "replacement-password",
                "confirm_password": "replacement-password",
            },
        )
        self.assertEqual(changed.status_code, 302)
        self.assertTrue(changed.location.endswith("/login"))
        self.assertEqual(
            self.client.get("/student-dashboard").status_code,
            302
        )
        with self.app.app_context():
            user = User.query.filter_by(email="password@example.com").one()
            self.assertTrue(user.check_password("replacement-password"))
            self.assertFalse(user.check_password("current-password"))

    def test_account_deletion_requires_password_and_removes_account(self):
        with self.app.app_context():
            user = User(
                name="Delete Me",
                email="delete@example.com",
                role="student",
            )
            user.set_password("valid-password")
            db.session.add(user)
            db.session.commit()

        self.client.post(
            "/login",
            data={
                "email": "delete@example.com",
                "password": "valid-password",
            },
        )

        wrong_password = self.client.post(
            "/account/delete",
            data={"password": "wrong-password"},
        )
        self.assertEqual(wrong_password.status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(
                User.query.filter_by(email="delete@example.com").first()
            )

        deleted = self.client.post(
            "/account/delete",
            data={"password": "valid-password"},
        )
        self.assertEqual(deleted.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(
                User.query.filter_by(email="delete@example.com").first()
            )


if __name__ == "__main__":
    unittest.main()

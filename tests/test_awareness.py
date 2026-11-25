import os
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "awareness-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db


class AwarenessTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def test_awareness_page_is_public_and_contains_resources(self):
        response = self.client.get("/awareness")

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Stay Alert. Stay Secure.", page)
        self.assertIn("Strong Passwords", page)
        self.assertIn("Recognize Phishing", page)
        self.assertIn("Social Engineering", page)
        self.assertIn("Report Suspicious Activity", page)

    def test_home_and_student_dashboard_link_to_awareness(self):
        home = self.client.get("/")
        self.assertIn("/awareness", home.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

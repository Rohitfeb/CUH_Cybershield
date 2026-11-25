import csv
import io
import os
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "quiz-coordinator-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, QuizAttempt, User


class QuizCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.coordinator_client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

            coordinator = User(
                name="Quiz Coordinator",
                email="coordinator@example.com",
                role="quiz_coordinator",
            )
            coordinator.set_password("valid-password")
            alice = User(
                name="Alice Student",
                email="alice@example.com",
                role="student",
            )
            alice.set_password("valid-password")
            bob = User(
                name="Bob Student",
                email="bob@example.com",
                role="student",
            )
            bob.set_password("valid-password")
            db.session.add_all([coordinator, alice, bob])
            db.session.flush()
            db.session.add_all([
                QuizAttempt(
                    user_id=alice.id,
                    score=8,
                    total_questions=10,
                    percentage=80,
                    difficulty="Beginner",
                ),
                QuizAttempt(
                    user_id=alice.id,
                    score=6,
                    total_questions=10,
                    percentage=60,
                    difficulty="Advanced",
                ),
                QuizAttempt(
                    user_id=bob.id,
                    score=10,
                    total_questions=10,
                    percentage=100,
                    difficulty="Beginner",
                ),
            ])
            db.session.commit()

        self.coordinator_client.post(
            "/login",
            data={
                "email": "coordinator@example.com",
                "password": "valid-password",
            },
        )

    def test_dashboard_filters_attempts_and_updates_metrics(self):
        response = self.coordinator_client.get(
            "/quiz-coordinator-dashboard"
            "?difficulty=Beginner&student=alice%40example.com"
        )

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Matching Attempts", page)
        self.assertIn("80.00%", page)
        self.assertIn("Participants", page)
        self.assertIn("Alice Student", page)
        attempts_table = page.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        self.assertNotIn("Bob Student", attempts_table)
        self.assertNotIn("Advanced", attempts_table)

    def test_coordinator_can_export_the_filtered_attempts_as_csv(self):
        response = self.coordinator_client.get(
            "/export-quiz-report"
            "?difficulty=Beginner&student=alice%40example.com"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        rows = list(csv.reader(io.StringIO(
            response.get_data(as_text=True).lstrip("\ufeff")
        )))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], "Alice Student")
        self.assertEqual(rows[1][3], "Beginner")
        self.assertNotIn("Bob Student", str(rows))

    def test_non_coordinator_cannot_export_quiz_report(self):
        student_client = self.app.test_client()
        student_client.post(
            "/login",
            data={
                "email": "alice@example.com",
                "password": "valid-password",
            },
        )
        response = student_client.get("/export-quiz-report")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/"))


if __name__ == "__main__":
    unittest.main()

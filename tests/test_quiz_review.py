import os
import time
import html
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "quiz-review-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, QuizAttempt, QuizAttemptAnswer, User


class QuizReviewTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            student = User(
                name="Quiz Student",
                email="student@example.com",
                role="student",
            )
            student.set_password("valid-password")
            other_student = User(
                name="Other Student",
                email="other@example.com",
                role="student",
            )
            other_student.set_password("valid-password")
            db.session.add_all([student, other_student])
            db.session.commit()

        self.client.post(
            "/login",
            data={
                "email": "student@example.com",
                "password": "valid-password",
            },
        )

    def _submit_quiz_with_one_wrong_answer(self):
        start_response = self.client.post(
            "/start-quiz",
            data={"difficulty": "Beginner"},
        )
        self.assertEqual(start_response.status_code, 200)

        with self.client.session_transaction() as browser_session:
            question_ids = browser_session["quiz_question_ids"]
        questions_by_id = {
            question["id"]: question
            for question in application.quiz_questions
        }
        selected_questions = [
            questions_by_id[question_id]
            for question_id in question_ids
        ]
        question_to_miss = selected_questions[0]
        wrong_option = next(
            option
            for option in question_to_miss["options"]
            if option != question_to_miss["answer"]
        )

        answers = {}
        for question in selected_questions:
            answers[f"answer_{question['id']}"] = (
                wrong_option
                if question["id"] == question_to_miss["id"]
                else question["answer"]
            )

        return (
            self.client.post("/submit-quiz", data=answers),
            question_to_miss,
            wrong_option,
            start_response.get_data(as_text=True),
        )

    def test_result_shows_selected_answer_correct_answer_and_explanation(self):
        submission, missed_question, wrong_option, quiz_page = (
            self._submit_quiz_with_one_wrong_answer()
        )
        self.assertEqual(submission.status_code, 302)
        self.assertTrue(submission.location.endswith("/quiz-result"))
        self.assertNotIn(missed_question["explanation"], quiz_page)

        result_page = self.client.get("/quiz-result")
        self.assertEqual(result_page.status_code, 200)
        page = result_page.get_data(as_text=True)
        self.assertIn("Review Your Answers", page)
        self.assertIn("Incorrect", page)
        self.assertIn(wrong_option, page)
        self.assertIn(missed_question["answer"], page)
        self.assertIn(html.escape(missed_question["explanation"]), page)

        with self.app.app_context():
            attempt = QuizAttempt.query.one()
            self.assertEqual(attempt.score, 9)
            self.assertEqual(len(attempt.answers), 10)
            incorrect_answers = [
                answer for answer in attempt.answers
                if not answer.is_correct
            ]
            self.assertEqual(len(incorrect_answers), 1)
            self.assertEqual(
                incorrect_answers[0].selected_answer,
                wrong_option,
            )
            self.assertEqual(
                incorrect_answers[0].explanation,
                missed_question["explanation"],
            )
            self.assertEqual(QuizAttemptAnswer.query.count(), 10)

    def test_quiz_shows_countdown_and_auto_submits_at_timeout(self):
        start_response = self.client.post(
            "/start-quiz",
            data={"difficulty": "Beginner"},
        )
        self.assertIn(b'id="quiz-countdown"', start_response.data)
        self.assertIn(b'data-remaining-seconds="600"', start_response.data)
        self.assertIn(b"form.submit()", start_response.data)

        with self.client.session_transaction() as browser_session:
            question_ids = browser_session["quiz_question_ids"]
            browser_session["quiz_started_at"] = (
                time.time()
                - application.QUIZ_TIME_LIMIT_SECONDS
                - 2
            )
        questions_by_id = {
            question["id"]: question
            for question in application.quiz_questions
        }
        first_question = questions_by_id[question_ids[0]]
        response = self.client.post(
            "/submit-quiz",
            data={
                f"answer_{first_question['id']}": first_question["answer"],
                "timed_out": "1",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/quiz-result"))
        result_page = self.client.get("/quiz-result")
        page = result_page.get_data(as_text=True)
        self.assertIn("Not answered (time expired)", page)

        with self.app.app_context():
            attempt = QuizAttempt.query.one()
            self.assertEqual(attempt.score, 1)
            self.assertEqual(
                sum(not answer.selected_answer for answer in attempt.answers),
                9,
            )

    def test_timeout_submission_outside_server_grace_period_is_rejected(self):
        self.client.post(
            "/start-quiz",
            data={"difficulty": "Beginner"},
        )
        with self.client.session_transaction() as browser_session:
            browser_session["quiz_started_at"] = (
                time.time()
                - application.QUIZ_TIME_LIMIT_SECONDS
                - application.QUIZ_TIMEOUT_GRACE_SECONDS
                - 1
            )

        response = self.client.post(
            "/submit-quiz",
            data={"timed_out": "1"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/quiz"))
        with self.app.app_context():
            self.assertEqual(QuizAttempt.query.count(), 0)

    def test_review_is_not_visible_to_another_logged_in_user(self):
        submission, _, _, _ = self._submit_quiz_with_one_wrong_answer()
        self.assertEqual(submission.status_code, 302)
        self.client.get("/logout")
        self.client.post(
            "/login",
            data={
                "email": "other@example.com",
                "password": "valid-password",
            },
        )

        response = self.client.get("/quiz-result")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/quiz"))

    def test_account_deletion_removes_saved_answer_reviews(self):
        submission, _, _, _ = self._submit_quiz_with_one_wrong_answer()
        self.assertEqual(submission.status_code, 302)

        response = self.client.post(
            "/account/delete",
            data={"password": "valid-password"},
        )

        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(QuizAttempt.query.count(), 0)
            self.assertEqual(QuizAttemptAnswer.query.count(), 0)


if __name__ == "__main__":
    unittest.main()

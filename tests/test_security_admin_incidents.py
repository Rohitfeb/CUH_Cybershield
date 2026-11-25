import os
import unittest
from urllib.parse import parse_qs, urlsplit

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "security-admin-incidents-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, IncidentNote, IncidentReport, User


class SecurityAdminIncidentTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.security_client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            security_admin = User(
                name="Security Admin",
                email="security@example.com",
                role="security_admin",
            )
            security_admin.set_password("valid-password")
            student = User(
                name="Student Reporter",
                email="student@example.com",
                role="student",
            )
            student.set_password("valid-password")
            faculty = User(
                name="Faculty Reporter",
                email="faculty@example.com",
                role="faculty",
            )
            faculty.set_password("valid-password")
            db.session.add_all([security_admin, student, faculty])
            db.session.flush()
            student_report = IncidentReport(
                user_id=student.id,
                incident_type="Phishing Email",
                description="Student received a suspicious password reset email.",
                status="Pending",
                severity="Low",
            )
            faculty_report = IncidentReport(
                user_id=faculty.id,
                incident_type="Account Hacking",
                description="Faculty account access was unexpectedly lost.",
                status="Under Review",
                severity="High",
            )
            db.session.add_all([student_report, faculty_report])
            db.session.commit()
            self.faculty_report_id = faculty_report.id

        self.security_client.post(
            "/login",
            data={
                "email": "security@example.com",
                "password": "valid-password",
            },
        )

    def test_security_dashboard_filters_by_status_severity_and_reporter(self):
        response = self.security_client.get(
            "/security-admin-dashboard"
            "?status=Under+Review&severity=High&q=faculty"
        )

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Showing 1 of 2 reports.", page)
        self.assertIn("Faculty account access was unexpectedly lost.", page)
        self.assertNotIn(
            "Student received a suspicious password reset email.",
            page,
        )

    def test_security_admin_can_add_private_notes_and_keep_filters(self):
        response = self.security_client.post(
            f"/admin/incident/{self.faculty_report_id}/note",
            data={
                "note": "Contacted the reporter and began account recovery.",
                "filter_status": "Under Review",
                "filter_severity": "High",
                "filter_q": "faculty",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            parse_qs(urlsplit(response.location).query),
            {
                "status": ["Under Review"],
                "severity": ["High"],
                "q": ["faculty"],
            },
        )
        with self.app.app_context():
            note = IncidentNote.query.one()
            self.assertEqual(note.report_id, self.faculty_report_id)
            self.assertEqual(note.author_name, "Security Admin")

        dashboard = self.security_client.get(response.location)
        self.assertIn(
            "Contacted the reporter and began account recovery.",
            dashboard.get_data(as_text=True),
        )

        student_client = self.app.test_client()
        student_client.post(
            "/login",
            data={
                "email": "student@example.com",
                "password": "valid-password",
            },
        )
        report_form = student_client.get("/report-incident")
        denied = student_client.post(
            f"/admin/incident/{self.faculty_report_id}/note",
            data={"note": "Unauthorized note"},
        )
        self.assertNotIn("Contacted the reporter", report_form.get_data(as_text=True))
        self.assertEqual(denied.status_code, 302)
        self.assertTrue(denied.location.endswith("/"))
        with self.app.app_context():
            self.assertEqual(IncidentNote.query.count(), 1)

    def test_security_admin_can_update_status_and_severity(self):
        self.security_client.post(
            f"/admin/update-incident/{self.faculty_report_id}",
            data={
                "status": "Resolved",
                "filter_status": "Under Review",
                "filter_severity": "High",
                "filter_q": "faculty",
            },
        )
        self.security_client.post(
            f"/admin/update-incident-severity/{self.faculty_report_id}",
            data={"severity": "Critical"},
        )

        with self.app.app_context():
            report = db.session.get(IncidentReport, self.faculty_report_id)
            self.assertEqual(report.status, "Resolved")
            self.assertEqual(report.severity, "Critical")


if __name__ == "__main__":
    unittest.main()

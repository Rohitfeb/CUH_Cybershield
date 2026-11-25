import io
import os
import tempfile
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "incident-upload-test-secret"
os.environ["FLASK_DEBUG"] = "1"

import app as application
from models_db import db, IncidentAttachment, IncidentReport, User


class IncidentUploadTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.previous_upload_folder = self.app.config["INCIDENT_UPLOAD_FOLDER"]
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app.config["INCIDENT_UPLOAD_FOLDER"] = self.temp_dir.name
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            for email, role in (
                ("student@example.com", "student"),
                ("faculty@example.com", "faculty"),
                ("security@example.com", "security_admin"),
            ):
                user = User(name=role, email=email, role=role)
                user.set_password("valid-password")
                db.session.add(user)
            db.session.commit()

    def tearDown(self):
        self.app.config["INCIDENT_UPLOAD_FOLDER"] = self.previous_upload_folder
        self.temp_dir.cleanup()

    def _login(self, email):
        return self.client.post(
            "/login",
            data={"email": email, "password": "valid-password"},
        )

    def _report_data(self, attachments=None):
        data = {
            "incident_type": "Phishing Email",
            "description": "A suspicious email included a credential link.",
        }
        if attachments is not None:
            if isinstance(attachments, tuple):
                attachments = [attachments]
            data["attachments"] = attachments
        return data

    def test_student_can_submit_and_staff_can_download_private_evidence(self):
        self._login("student@example.com")
        response = self.client.post(
            "/report-incident",
            data=self._report_data(
                (io.BytesIO(b"\x89PNG\r\n\x1a\nimage evidence"), "screen shot.png")
            ),
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            report = IncidentReport.query.one()
            attachment = IncidentAttachment.query.one()
            self.assertEqual(attachment.report_id, report.id)
            self.assertEqual(attachment.original_filename, "screen_shot.png")
            self.assertEqual(
                attachment.size_bytes,
                len(b"\x89PNG\r\n\x1a\nimage evidence"),
            )
            self.assertTrue(
                os.path.isfile(
                    os.path.join(
                        self.temp_dir.name,
                        attachment.stored_filename,
                    )
                )
            )
            attachment_id = attachment.id

        denied = self.client.get(
            f"/admin/incident-attachment/{attachment_id}"
        )
        self.assertEqual(denied.status_code, 302)

        staff_client = self.app.test_client()
        staff_client.post(
            "/login",
            data={
                "email": "security@example.com",
                "password": "valid-password",
            },
        )
        downloaded = staff_client.get(
            f"/admin/incident-attachment/{attachment_id}"
        )
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, b"\x89PNG\r\n\x1a\nimage evidence")
        self.assertIn("attachment;", downloaded.headers["Content-Disposition"])
        self.assertEqual(
            downloaded.headers["X-Content-Type-Options"],
            "nosniff",
        )

    def test_faculty_can_upload_multiple_file_types_as_private_evidence(self):
        self._login("faculty@example.com")
        form = self.client.get("/report-incident")
        self.assertIn(b'name="attachments"', form.data)
        self.assertIn(b"multiple", form.data)

        response = self.client.post(
            "/report-incident",
            data=self._report_data([
                (io.BytesIO(b"email attachment evidence"), "forwarded-email.msg"),
                (io.BytesIO(b"email screenshot"), "screenshot.webp"),
            ]),
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            report = IncidentReport.query.one()
            attachments = IncidentAttachment.query.order_by(
                IncidentAttachment.id
            ).all()
            self.assertEqual(report.user.role, "faculty")
            self.assertEqual(len(attachments), 2)
            self.assertTrue(all(a.report_id == report.id for a in attachments))
            attachment = attachments[0]
            self.assertEqual(attachment.original_filename, "forwarded-email.msg")
            self.assertEqual(
                attachment.size_bytes,
                len(b"email attachment evidence"),
            )
            self.assertTrue(
                os.path.isfile(
                    os.path.join(self.temp_dir.name, attachment.stored_filename)
                )
            )
            attachment_ids = [attachment.id for attachment in attachments]

        staff_client = self.app.test_client()
        staff_client.post(
            "/login",
            data={
                "email": "security@example.com",
                "password": "valid-password",
            },
        )
        for attachment_id, expected_content in zip(
            attachment_ids,
            (b"email attachment evidence", b"email screenshot"),
        ):
            downloaded = staff_client.get(
                f"/admin/incident-attachment/{attachment_id}"
            )
            self.assertEqual(downloaded.status_code, 200)
            self.assertEqual(downloaded.data, expected_content)

    def test_attachment_size_is_limited_and_evidence_is_optional(self):
        self._login("student@example.com")
        too_large = b"\x89PNG\r\n\x1a\n" + (
            b"x" * self.app.config["INCIDENT_UPLOAD_MAX_BYTES"]
        )
        rejected = self.client.post(
            "/report-incident",
            data=self._report_data((io.BytesIO(too_large), "large.png")),
            content_type="multipart/form-data",
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn("5 MB or smaller", rejected.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(IncidentReport.query.count(), 0)

        previous_request_limit = self.app.config["MAX_CONTENT_LENGTH"]
        self.app.config["MAX_CONTENT_LENGTH"] = 7 * 1024 * 1024
        aggregate_too_large = self.client.post(
            "/report-incident",
            data=self._report_data([
                (io.BytesIO(b"1" * (3 * 1024 * 1024)), "first.dat"),
                (io.BytesIO(b"2" * (2 * 1024 * 1024 + 1)), "second.dat"),
            ]),
            content_type="multipart/form-data",
        )
        self.app.config["MAX_CONTENT_LENGTH"] = previous_request_limit
        self.assertEqual(aggregate_too_large.status_code, 200)
        self.assertIn(
            "All attachments must total 5 MB or smaller",
            aggregate_too_large.get_data(as_text=True),
        )
        with self.app.app_context():
            self.assertEqual(IncidentReport.query.count(), 0)

        too_many = [
            (io.BytesIO(b"evidence"), f"proof-{index}.dat")
            for index in range(self.app.config["INCIDENT_UPLOAD_MAX_FILES"] + 1)
        ]
        rejected = self.client.post(
            "/report-incident",
            data=self._report_data(too_many),
            content_type="multipart/form-data",
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn("no more than 5 evidence files", rejected.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(IncidentReport.query.count(), 0)

        submitted = self.client.post(
            "/report-incident",
            data=self._report_data(),
            content_type="multipart/form-data",
        )
        self.assertEqual(submitted.status_code, 302)
        with self.app.app_context():
            self.assertEqual(IncidentReport.query.count(), 1)
            self.assertEqual(IncidentAttachment.query.count(), 0)

    def test_deleting_reporter_account_removes_evidence_file(self):
        self._login("student@example.com")
        self.client.post(
            "/report-incident",
            data=self._report_data([
                (io.BytesIO(b"%PDF-evidence"), "evidence.pdf"),
                (io.BytesIO(b"email evidence"), "evidence.eml"),
            ]),
            content_type="multipart/form-data",
        )

        with self.app.app_context():
            attachments = IncidentAttachment.query.all()
            saved_paths = [
                os.path.join(self.temp_dir.name, attachment.stored_filename)
                for attachment in attachments
            ]
        deleted = self.client.post(
            "/account/delete",
            data={"password": "valid-password"},
        )
        self.assertEqual(deleted.status_code, 302)
        self.assertTrue(all(not os.path.exists(path) for path in saved_paths))
        with self.app.app_context():
            self.assertEqual(IncidentAttachment.query.count(), 0)
            self.assertEqual(IncidentReport.query.count(), 0)


if __name__ == "__main__":
    unittest.main()

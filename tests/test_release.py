import os
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "release-test-secret-with-at-least-32-characters"
os.environ["FLASK_DEBUG"] = "0"

import app as application
import release_check


class ReleaseTests(unittest.TestCase):
    def test_required_release_artifacts_exist(self):
        root = Path(application.app.root_path)
        required = (
            "wsgi.py",
            "gunicorn.conf.py",
            "Dockerfile",
            "Procfile",
            "release_check.py",
        )
        for filename in required:
            self.assertTrue((root / filename).is_file(), filename)

    def test_release_check_is_callable(self):
        self.assertTrue(callable(release_check.check_release))

    def test_release_check_requires_production_configuration(self):
        with patch.dict(
            os.environ,
            {
                "DEPLOYMENT_ENV": "development",
                "SECRET_KEY": "development-is-not-a-valid-release-secret",
                "RESET_BASE_URL": "http://127.0.0.1:5000",
                "SESSION_COOKIE_SECURE": "0",
                "FLASK_DEBUG": "1",
                "DATABASE_URL": "sqlite:///cybershield.db",
                "INCIDENT_UPLOAD_FOLDER": "",
                "MAIL_SERVER": "",
                "MAIL_USERNAME": "",
                "MAIL_DEFAULT_SENDER": "",
            },
            clear=True,
        ):
            errors = release_check.check_release()

        self.assertIn("DEPLOYMENT_ENV must be production.", errors)


if __name__ == "__main__":
    unittest.main()

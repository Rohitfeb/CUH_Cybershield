import os
import unittest

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "deployment-test-secret"
os.environ["FLASK_DEBUG"] = "0"

import app as application
from models_db import db


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.app = application.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def test_health_endpoint_reports_database_and_model(self):
        response = self.client.get("/health")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["database"], "ready")
        self.assertEqual(payload["model"], "ready")

    def test_wsgi_entrypoint_exposes_app(self):
        import wsgi

        self.assertIs(wsgi.app, application.app)

    def test_deployment_files_exist(self):
        import pathlib

        root = pathlib.Path(application.app.root_path)
        for filename in ("Dockerfile", "Procfile", "gunicorn.conf.py", "wsgi.py"):
            self.assertTrue((root / filename).is_file(), filename)


if __name__ == "__main__":
    unittest.main()

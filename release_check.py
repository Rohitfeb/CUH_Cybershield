import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def check_release():
    errors = []
    required_files = (
        "app.py",
        "wsgi.py",
        "gunicorn.conf.py",
        "requirements.txt",
        "Dockerfile",
        "Procfile",
        "models/url_detector.pkl",
        "models/email_detector.pkl",
    )
    for filename in required_files:
        if not (ROOT / filename).is_file():
            errors.append(f"Missing required file: {filename}")

    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < 32:
        errors.append("SECRET_KEY must contain at least 32 characters.")

    if os.environ.get("DEPLOYMENT_ENV", "").lower() != "production":
        errors.append("DEPLOYMENT_ENV must be production.")

    database_url = os.environ.get("DATABASE_URL", "")
    if database_url.startswith("sqlite"):
        errors.append("DATABASE_URL must use PostgreSQL for production.")

    if not os.environ.get("INCIDENT_UPLOAD_FOLDER", "").strip():
        errors.append("INCIDENT_UPLOAD_FOLDER must be configured.")

    reset_base_url = os.environ.get("RESET_BASE_URL", "")
    if not reset_base_url.startswith("https://"):
        errors.append("RESET_BASE_URL must use HTTPS.")

    if os.environ.get("FLASK_DEBUG", "0").lower() not in ("0", "false", "no"):
        errors.append("FLASK_DEBUG must be disabled.")

    if os.environ.get("SESSION_COOKIE_SECURE", "0").lower() not in (
        "1",
        "true",
        "yes",
    ):
        errors.append("SESSION_COOKIE_SECURE must be enabled.")

    if not os.environ.get("MAIL_SERVER", "").strip():
        errors.append("MAIL_SERVER must be configured.")
    if not (
        os.environ.get("MAIL_DEFAULT_SENDER", "").strip()
        or os.environ.get("MAIL_USERNAME", "").strip()
    ):
        errors.append("MAIL_DEFAULT_SENDER or MAIL_USERNAME must be configured.")

    return errors


if __name__ == "__main__":
    errors = check_release()
    if errors:
        print("Release check failed:")
        for error in errors:
            print(f"- {error}")
        sys.exit(1)

    test_environment = os.environ.copy()
    test_environment["DATABASE_URL"] = "sqlite://"
    test_environment["SECRET_KEY"] = (
        "release-check-test-secret-at-least-32-characters"
    )
    test_environment["FLASK_DEBUG"] = "0"
    test_environment["DEPLOYMENT_ENV"] = "development"
    test_environment["RESET_BASE_URL"] = "http://127.0.0.1:5000"
    test_environment["SESSION_COOKIE_SECURE"] = "0"
    for mail_setting in (
        "MAIL_SERVER",
        "MAIL_PORT",
        "MAIL_USE_TLS",
        "MAIL_USE_SSL",
        "MAIL_USERNAME",
        "MAIL_PASSWORD",
        "MAIL_DEFAULT_SENDER",
    ):
        test_environment.pop(mail_setting, None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(ROOT / "tests"),
            "-p",
            "test*.py",
            "-v",
        ],
        cwd=ROOT,
        env=test_environment,
    )
    if result.returncode != 0:
        sys.exit(1)

    print("Release check passed. All required files and tests are ready.")

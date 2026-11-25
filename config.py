import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32)
    DEPLOYMENT_ENV = os.environ.get("DEPLOYMENT_ENV", "development").lower()
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get(
        "SESSION_COOKIE_SECURE", "0"
    ).lower() in ("1", "true", "yes")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///cybershield.db"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in (
        "1",
        "true",
        "yes",
    )
    FLASK_HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
    FLASK_PORT = int(os.environ.get("FLASK_PORT", "5000"))
    PASSWORD_RESET_TOKEN_MAX_AGE = 1800
    RESET_BASE_URL = os.environ.get("RESET_BASE_URL", "").rstrip("/")
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1").lower() in (
        "1",
        "true",
        "yes",
    )
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "0").lower() in (
        "1",
        "true",
        "yes",
    )
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")
    # HTTPS email API (Brevo). Use this on hosts that block SMTP ports,
    # such as Render's free plan. When set, it is used instead of SMTP.
    BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
    # Number of reverse proxies in front of the app (Render = 1, local = 0).
    TRUST_PROXY_HOPS = int(os.environ.get("TRUST_PROXY_HOPS", "0"))
    MAX_CONTENT_LENGTH = 6 * 1024 * 1024
    EMAIL_CHECKER_MAX_FILE_BYTES = 2 * 1024 * 1024
    INCIDENT_UPLOAD_MAX_BYTES = 5 * 1024 * 1024
    INCIDENT_UPLOAD_MAX_FILES = 5
    INCIDENT_UPLOAD_FOLDER = os.environ.get(
        "INCIDENT_UPLOAD_FOLDER",
        os.path.join(os.path.dirname(__file__), "instance", "incident_uploads"),
    )
    RATE_LIMIT_STORAGE_URI = os.environ.get(
        "RATE_LIMIT_STORAGE_URI",
        "memory://"
    )


def validate_deployment_config(config):
    if config.get("DEPLOYMENT_ENV") != "production":
        return []

    errors = []
    secret = config.get("SECRET_KEY")
    if not secret or len(str(secret)) < 32:
        errors.append("SECRET_KEY must contain at least 32 characters.")
    if str(config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite"):
        errors.append("DATABASE_URL must use PostgreSQL in production.")
    if not str(config.get("INCIDENT_UPLOAD_FOLDER", "")).strip():
        errors.append("INCIDENT_UPLOAD_FOLDER must be configured.")
    if config.get("DEBUG"):
        errors.append("FLASK_DEBUG must be disabled in production.")
    if not config.get("SESSION_COOKIE_SECURE"):
        errors.append("SESSION_COOKIE_SECURE must be enabled in production.")
    if not str(config.get("RESET_BASE_URL", "")).startswith("https://"):
        errors.append("RESET_BASE_URL must be a public HTTPS URL.")
    if not (config.get("MAIL_SERVER") or config.get("BREVO_API_KEY")):
        errors.append(
            "MAIL_SERVER or BREVO_API_KEY must be configured in production."
        )
    if not (
        config.get("MAIL_DEFAULT_SENDER")
        or config.get("MAIL_USERNAME")
    ):
        errors.append("MAIL_DEFAULT_SENDER or MAIL_USERNAME must be configured.")
    return errors
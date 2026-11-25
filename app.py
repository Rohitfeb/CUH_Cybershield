
import os

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import re
import ipaddress
import random
import time
import csv
import io
import hashlib
import hmac
import smtplib
import ssl
import secrets
import json
import logging
import uuid
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from flask import make_response
from quiz_questions import quiz_questions
from urllib.parse import urlsplit
from dotenv import load_dotenv

load_dotenv()

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from flask import (
    Flask, current_app, render_template, request,
    redirect, url_for, flash, session, send_from_directory
)
from werkzeug.utils import secure_filename

from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, or_
from sqlalchemy.exc import SQLAlchemyError

import joblib
import pandas as pd
from sqlalchemy.exc import IntegrityError

from config import Config
from config import validate_deployment_config
from models_db import (
    db,
    User,
    IncidentReport,
    IncidentAttachment,
    IncidentNote,
    QuizAttempt,
    QuizAttemptAnswer,
)
from utils.url_detector import extract_url_features


app = Flask(__name__)

app.config.from_object(Config)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "ip"):
            payload["ip"] = record.ip
        if hasattr(record, "user_id"):
            payload["user_id"] = record.user_id
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


if not app.debug:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri=app.config["RATE_LIMIT_STORAGE_URI"],
)


def security_event(event, message, **fields):
    app.logger.info(
        message,
        extra={
            "event": event,
            "ip": request.remote_addr,
            "user_id": (
                current_user.id
                if current_user.is_authenticated
                else None
            ),
            **fields,
        },
    )

DEPLOYMENT_ERRORS = validate_deployment_config(app.config)
if DEPLOYMENT_ERRORS:
    app.logger.critical(
        "Production configuration is incomplete: %s",
        " ".join(DEPLOYMENT_ERRORS)
    )

# Initialize database
db.init_app(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

ROLE_DASHBOARD_ENDPOINTS = {
    "admin": "admin_dashboard",
    "super_admin": "admin_dashboard",
    "security_admin": "security_admin_dashboard",
    "quiz_coordinator": "quiz_coordinator_dashboard",
    "student": "student_dashboard",
    "faculty": "faculty_dashboard",
}

ROLE_CHANGE_TARGETS = (
    "student",
    "faculty",
    "security_admin",
    "quiz_coordinator",
)
ROLE_CHANGEABLE_SOURCE_ROLES = (*ROLE_CHANGE_TARGETS, "admin")
QUIZ_DIFFICULTIES = ("Beginner", "Intermediate", "Advanced", "Mixed")
QUIZ_TIME_LIMIT_SECONDS = 10 * 60
QUIZ_TIMEOUT_GRACE_SECONDS = 60
INCIDENT_STATUSES = ("Pending", "Under Review", "Resolved")
INCIDENT_SEVERITIES = ("Unassigned", "Low", "Medium", "High", "Critical")


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.before_request
def validate_csrf():
    limiter.enabled = not app.config.get("TESTING", False)
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if app.config.get("TESTING"):
        return None

    submitted_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    if (
        not submitted_token
        or not session_token
        or not hmac.compare_digest(submitted_token, session_token)
    ):
        flash("Your session is invalid. Please try again.", "danger")
        return redirect(request.referrer or url_for("home"))
    return None


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    if not app.debug:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _csrf_token()}


# Load trained URL detection model
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "url_detector.pkl"
)

saved_model = joblib.load(MODEL_PATH)

url_model = saved_model["model"]
url_features = saved_model["features"]
label_mapping = saved_model["label_mapping"]


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def dashboard_endpoint_for_role(role):
    return ROLE_DASHBOARD_ENDPOINTS.get(role)


@app.context_processor
def inject_dashboard_endpoint():
    endpoint = (
        dashboard_endpoint_for_role(current_user.role)
        if current_user.is_authenticated
        else None
    )
    return {"user_dashboard_endpoint": endpoint}


def _is_valid_email(email):
    return (
        len(email) <= 120
        and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None
    )


def _password_reset_serializer():
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"],
        salt="cuh-cybershield-password-reset-v1"
    )


def _password_hash_fingerprint(user):
    return hashlib.sha256(user.password_hash.encode("utf-8")).hexdigest()


def _send_password_reset_email(user, reset_url):
    mail_server = current_app.config.get("MAIL_SERVER")
    mail_sender = (
        current_app.config.get("MAIL_DEFAULT_SENDER")
        or current_app.config.get("MAIL_USERNAME")
    )
    if not mail_server or not mail_sender:
        raise RuntimeError("Password reset email is not configured.")

    message = EmailMessage()
    message["Subject"] = "Reset your CUH Cyber Shield password"
    message["From"] = mail_sender
    message["To"] = user.email
    message.set_content(
        "We received a request to reset your CUH Cyber Shield password.\n\n"
        f"Use this link within 30 minutes:\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    port = current_app.config["MAIL_PORT"]
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    if current_app.config.get("MAIL_USE_SSL"):
        with smtplib.SMTP_SSL(
            mail_server,
            port,
            context=ssl.create_default_context(),
            timeout=15
        ) as server:
            if username:
                server.login(username, password or "")
            server.send_message(message)
        return

    with smtplib.SMTP(mail_server, port, timeout=15) as server:
        if current_app.config.get("MAIL_USE_TLS"):
            server.starttls(context=ssl.create_default_context())
        if username:
            server.login(username, password or "")
        server.send_message(message)


# Create database tables
with app.app_context():
    db.create_all()

    attachment_constraints = inspect(db.engine).get_unique_constraints(
        "incident_attachment"
    )
    report_id_constraints = [
        constraint
        for constraint in attachment_constraints
        if constraint.get("column_names") == ["report_id"]
    ]
    if report_id_constraints:
        if db.engine.dialect.name == "sqlite":
            temporary_table = f"incident_attachment_{uuid.uuid4().hex}"
            with db.engine.begin() as connection:
                connection.exec_driver_sql(
                    f"""
                    CREATE TABLE {temporary_table} (
                        id INTEGER NOT NULL PRIMARY KEY,
                        report_id INTEGER NOT NULL
                            REFERENCES incident_report (id) ON DELETE CASCADE,
                        stored_filename VARCHAR(80) NOT NULL UNIQUE,
                        original_filename VARCHAR(255) NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        uploaded_at DATETIME NOT NULL
                    )
                    """
                )
                connection.exec_driver_sql(
                    f"""
                    INSERT INTO {temporary_table}
                        (id, report_id, stored_filename, original_filename,
                         size_bytes, uploaded_at)
                    SELECT id, report_id, stored_filename, original_filename,
                           size_bytes, uploaded_at
                    FROM incident_attachment
                    """
                )
                connection.exec_driver_sql("DROP TABLE incident_attachment")
                connection.exec_driver_sql(
                    f"ALTER TABLE {temporary_table} "
                    "RENAME TO incident_attachment"
                )
        elif db.engine.dialect.name == "postgresql":
            preparer = db.engine.dialect.identifier_preparer
            with db.engine.begin() as connection:
                for constraint in report_id_constraints:
                    name = constraint.get("name")
                    if not name:
                        raise RuntimeError(
                            "Cannot migrate unnamed incident attachment constraint."
                        )
                    connection.exec_driver_sql(
                        "ALTER TABLE incident_attachment DROP CONSTRAINT "
                        f"{preparer.quote(name)}"
                    )
        else:
            raise RuntimeError(
                "The database cannot migrate incident attachments to multiple files."
            )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/account/delete", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def delete_account():
    password = request.form.get("password", "")
    if not current_user.check_password(password):
        security_event(
            "account.delete_failed",
            "Account deletion password verification failed",
        )
        flash("Password is incorrect.", "danger")
        return redirect(
            url_for(dashboard_endpoint_for_role(current_user.role) or "home")
        )

    user_id = current_user.id
    security_event(
        "account.deleted",
        "User account deleted",
    )
    reports = IncidentReport.query.filter_by(user_id=user_id).all()
    attachment_paths = []
    for report in reports:
        for attachment in report.attachments:
            attachment_paths.append(os.path.join(
                current_app.config["INCIDENT_UPLOAD_FOLDER"],
                attachment.stored_filename,
            ))
        db.session.delete(report)
    attempt_ids = db.session.query(QuizAttempt.id).filter_by(user_id=user_id)
    QuizAttemptAnswer.query.filter(
        QuizAttemptAnswer.attempt_id.in_(attempt_ids)
    ).delete(synchronize_session=False)
    QuizAttempt.query.filter_by(user_id=user_id).delete()
    db.session.delete(db.session.get(User, user_id))
    db.session.commit()
    for attachment_path in attachment_paths:
        try:
            os.remove(attachment_path)
        except FileNotFoundError:
            continue
        except OSError:
            current_app.logger.exception(
                "Could not remove an attachment for a deleted account."
            )
    logout_user()
    flash("Your account and associated records were deleted.", "success")
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or len(name) > 100 or not email or len(password) < 8:
            flash(
                "Enter a name (up to 100 characters), email, and a password "
                "of at least 8 characters.",
                "warning"
            )
            return redirect(url_for("register"))

        if not _is_valid_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered.")
            return redirect(url_for("register"))

        user = User(
            name=name,
            email=email,
            role="student"
        )

        try:
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            security_event(
                "account.register",
                "New student account registered",
            )
        except IntegrityError:
            db.session.rollback()
            flash("Email already registered.", "warning")
            return redirect(url_for("register"))
        except Exception:
            db.session.rollback()
            app.logger.exception("User registration failed.")
            flash("Unable to create your account. Please try again.", "danger")
            return redirect(url_for("register"))

        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        try:
            password_matches = user is not None and user.check_password(password)
        except (ValueError, MemoryError):
            app.logger.exception(
                "Password hash verification failed; account recovery is required."
            )
            flash(
                "Unable to verify this password on this server. "
                "Use Forgot Password to set it again.",
                "danger"
            )
            return render_template("login.html")

        if not password_matches:
            security_event(
                "auth.login_failed",
                "Failed login attempt",
            )
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        dashboard_endpoint = dashboard_endpoint_for_role(user.role)
        if dashboard_endpoint is None:
            flash("Your account role is not authorised.", "danger")
            return render_template("login.html")

        login_user(user)
        security_event(
            "auth.login_succeeded",
            "User login succeeded",
        )
        return redirect(url_for(dashboard_endpoint))

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    reset_url = None
    local_reset_allowed = (
        current_app.config["DEPLOYMENT_ENV"] != "production"
        and str(current_app.config["RESET_BASE_URL"]).startswith(
            ("http://127.0.0.1", "http://localhost", "http://[::1]")
        )
    )
    mail_delivery_configured = bool(
        current_app.config.get("MAIL_SERVER")
        and (
            current_app.config.get("MAIL_DEFAULT_SENDER")
            or current_app.config.get("MAIL_USERNAME")
        )
        and (
            not current_app.config.get("MAIL_USERNAME")
            or current_app.config.get("MAIL_PASSWORD")
        )
    )

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first() if email else None

        if user:
            token = _password_reset_serializer().dumps({
                "user_id": user.id,
                "password_hash": _password_hash_fingerprint(user)
            })
            reset_path = url_for("reset_password", token=token)
            base_url = current_app.config.get("RESET_BASE_URL")
            if not base_url:
                configured_host = current_app.config["FLASK_HOST"]
                if configured_host in ("127.0.0.1", "localhost", "::1"):
                    if configured_host == "::1":
                        configured_host = "[::1]"
                    base_url = (
                        f"http://{configured_host}:"
                        f"{current_app.config['FLASK_PORT']}"
                    )
                else:
                    current_app.logger.error(
                        "RESET_BASE_URL must be configured when FLASK_HOST "
                        "is not a loopback address."
                    )

            if base_url:
                reset_url = f"{base_url}{reset_path}"
                try:
                    _send_password_reset_email(user, reset_url)
                except RuntimeError as error:
                    current_app.logger.warning("%s", error)
                    if not local_reset_allowed:
                        reset_url = None
                except (OSError, smtplib.SMTPException):
                    current_app.logger.exception(
                        "Password reset email could not be sent."
                    )
                    if not local_reset_allowed:
                        reset_url = None
            elif local_reset_allowed:
                reset_url = url_for(
                    "reset_password",
                    token=token,
                    _external=True
                )

            if not base_url and not current_app.debug:
                current_app.logger.error(
                    "No safe reset URL is available; configure RESET_BASE_URL."
                )

        flash(
            "If an account exists for that email, password reset instructions "
            "will be sent."
        )
        return render_template(
            "forgot_password.html",
            reset_url=reset_url if local_reset_allowed else None,
            mail_delivery_configured=mail_delivery_configured
        )

    return render_template(
        "forgot_password.html",
        mail_delivery_configured=mail_delivery_configured
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        payload = _password_reset_serializer().loads(
            token,
            max_age=current_app.config["PASSWORD_RESET_TOKEN_MAX_AGE"]
        )
    except SignatureExpired:
        flash("That password reset link has expired. Request a new one.", "warning")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("That password reset link is invalid. Request a new one.", "danger")
        return redirect(url_for("forgot_password"))

    user = db.session.get(User, payload.get("user_id"))
    token_fingerprint = payload.get("password_hash")
    if (
        user is None
        or not isinstance(token_fingerprint, str)
        or not hmac.compare_digest(
            token_fingerprint,
            _password_hash_fingerprint(user) if user else ""
        )
    ):
        flash("That password reset link is invalid or has already been used.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "warning")
        elif password != confirmation:
            flash("The passwords do not match.", "warning")
        else:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been reset. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour")
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        try:
            current_password_matches = current_user.check_password(
                current_password
            )
        except (ValueError, MemoryError):
            app.logger.exception(
                "Current password verification failed during password change."
            )
            flash(
                "Unable to verify your current password. Use Forgot Password "
                "to reset it.",
                "danger"
            )
            return render_template("change_password.html")

        if not current_password_matches:
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < 8:
            flash("New password must be at least 8 characters.", "warning")
        elif new_password != confirmation:
            flash("The new passwords do not match.", "warning")
        elif new_password == current_password:
            flash("Choose a password different from your current password.", "warning")
        else:
            current_user.set_password(new_password)
            try:
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
                app.logger.exception("Password change could not be saved.")
                flash("Unable to change your password. Please try again.", "danger")
                return render_template("change_password.html")

            security_event(
                "auth.password_changed",
                "User changed their password",
            )
            logout_user()
            flash("Password changed. Please sign in with your new password.", "success")
            return redirect(url_for("login"))

    return render_template("change_password.html")


# Cyber Awareness Quiz Page
@app.route("/quiz")
@login_required
def quiz():
    return render_template("quiz.html")


# Start Quiz
@app.route("/start-quiz", methods=["POST"])
@login_required
def start_quiz():

    difficulty = request.form.get("difficulty")

    # Validate difficulty
    allowed_difficulties = [
        "Beginner",
        "Intermediate",
        "Advanced",
        "Mixed"
    ]

    if difficulty not in allowed_difficulties:
        flash("Please select a valid difficulty level.", "warning")
        return redirect(url_for("quiz"))

    # Clear previous quiz result
    session.pop("quiz_result", None)

    # Filter questions according to difficulty
    if difficulty == "Mixed":
        available_questions = quiz_questions
    else:
        available_questions = [
            q for q in quiz_questions
            if q["difficulty"] == difficulty
        ]

    # Check whether at least 10 questions are available
    if len(available_questions) < 10:
        flash(
            "Not enough questions available for this difficulty. Please try another difficulty.",
            "warning"
        )
        return redirect(url_for("quiz"))

    # Select 10 random questions
    selected_questions = random.sample(available_questions, 10)

    # Store question IDs and difficulty in session
    session["quiz_question_ids"] = [
        q["id"] for q in selected_questions
    ]

    session["quiz_difficulty"] = difficulty
    session["quiz_started_at"] = time.time()

    # Hide correct answers from the browser
    safe_questions = [
        {
            "id": q["id"],
            "question": q["question"],
            "options": q["options"],
            "difficulty": q["difficulty"]
        }
        for q in selected_questions
    ]

    return render_template(
        "quiz_questions.html",
        questions=safe_questions,
        difficulty=difficulty,
        remaining_seconds=QUIZ_TIME_LIMIT_SECONDS,
    )


# Submit Quiz and Calculate Score
@app.route("/submit-quiz", methods=["POST"])
@login_required
def submit_quiz():

    question_ids = session.get("quiz_question_ids")

    if not question_ids:
        flash("Please start a new quiz.", "warning")
        return redirect(url_for("quiz"))

    started_at = session.get("quiz_started_at")

    if started_at is None:
        flash("Quiz time expired. Please try again.", "warning")
        return redirect(url_for("quiz"))

    elapsed = time.time() - started_at
    timed_out = request.form.get("timed_out") == "1"
    if elapsed > QUIZ_TIME_LIMIT_SECONDS and (
        not timed_out
        or elapsed > QUIZ_TIME_LIMIT_SECONDS + QUIZ_TIMEOUT_GRACE_SECONDS
    ):
        session.pop("quiz_question_ids", None)
        session.pop("quiz_difficulty", None)
        session.pop("quiz_started_at", None)

        flash("Quiz time expired. Please try again.", "warning")
        return redirect(url_for("quiz"))

    questions_by_id = {question["id"]: question for question in quiz_questions}
    selected_questions = [
        questions_by_id[question_id]
        for question_id in question_ids
        if question_id in questions_by_id
    ]

    if len(selected_questions) != 10:
        flash("Invalid quiz questions. Please restart.", "danger")
        return redirect(url_for("quiz"))

    # Check whether all questions are answered
    submitted_answers = {}
    for question in selected_questions:
        submitted_answer = request.form.get(f"answer_{question['id']}")
        if submitted_answer is None and not timed_out:
            flash("Please answer all questions.", "warning")
            return redirect(url_for("quiz"))
        submitted_answer = submitted_answer or ""
        if submitted_answer not in question["options"]:
            if timed_out and not submitted_answer:
                submitted_answers[question["id"]] = ""
                continue
            flash("An invalid answer was submitted. Please restart the quiz.", "danger")
            return redirect(url_for("quiz"))
        submitted_answers[question["id"]] = submitted_answer

    score = sum(
        submitted_answers[question["id"]] == question["answer"]
        for question in selected_questions
    )

    total_questions = len(selected_questions)
    percentage = (score / total_questions) * 100

    # Save result in database
    attempt = QuizAttempt(
        user_id=current_user.id,
        score=score,
        total_questions=total_questions,
        percentage=percentage,
        difficulty=session.get("quiz_difficulty", "Mixed"),
        answers=[
            QuizAttemptAnswer(
                question_id=question["id"],
                question_text=question["question"],
                difficulty=question["difficulty"],
                selected_answer=submitted_answers[question["id"]],
                correct_answer=question["answer"],
                explanation=question["explanation"],
                is_correct=(
                    submitted_answers[question["id"]] == question["answer"]
                ),
            )
            for question in selected_questions
        ],
    )

    db.session.add(attempt)
    db.session.commit()

    session["quiz_result"] = {
        "score": score,
        "total_questions": total_questions,
        "percentage": round(percentage, 2),
        "difficulty": session.get("quiz_difficulty"),
        "attempt_id": attempt.id,
    }

    # Clear active quiz
    session.pop("quiz_question_ids", None)
    session.pop("quiz_difficulty", None)
    session.pop("quiz_started_at", None)

    return redirect(url_for("quiz_result"))


# Display Quiz Result
@app.route("/quiz-result")
@login_required
def quiz_result():

    result = session.get("quiz_result")

    if not result:
        flash("No quiz result found.", "info")
        return redirect(url_for("quiz"))

    review_answers = []
    attempt_id = result.get("attempt_id")
    if attempt_id is not None:
        attempt = db.session.get(QuizAttempt, attempt_id)
        if attempt is None or attempt.user_id != current_user.id:
            session.pop("quiz_result", None)
            flash("Quiz result not found.", "info")
            return redirect(url_for("quiz"))
        review_answers = attempt.answers

    return render_template(
        "quiz_result.html",
        result=result,
        review_answers=review_answers,
    )


# Student Quiz History
@app.route("/quiz-history")
@login_required
def quiz_history():

    if current_user.role not in ["student", "faculty"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    attempts = QuizAttempt.query.filter_by(
        user_id=current_user.id
    ).order_by(
        QuizAttempt.attempted_at.desc()
    ).all()

    from datetime import timezone, timedelta

    for attempt in attempts:
        if attempt.attempted_at:
            utc_time = attempt.attempted_at.replace(
                tzinfo=timezone.utc
            )

            attempt.attempted_at_ist = utc_time.astimezone(
                timezone(timedelta(hours=5, minutes=30))
            )

    return render_template(
        "quiz_history.html",
        attempts=attempts
    )


@app.route("/student-dashboard")
@login_required
def student_dashboard():

    if current_user.role != "student":
        return redirect(
            url_for(dashboard_endpoint_for_role(current_user.role) or "home")
        )

    return render_template(
        "student_dashboard.html",
        user=current_user
    )


@app.route("/faculty-dashboard")
@login_required
def faculty_dashboard():
    if current_user.role != "faculty":
        return redirect(
            url_for(dashboard_endpoint_for_role(current_user.role) or "home")
        )

    return render_template("faculty_dashboard.html", user=current_user)


def convert_to_ist(dt):
    from datetime import timezone, timedelta

    if dt is None:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    ist_timezone = timezone(timedelta(hours=5, minutes=30))

    return dt.astimezone(ist_timezone)

def _paginate_role_accounts(query, page_parameter, per_page=10):
    total = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    requested_page = request.args.get(page_parameter, 1, type=int) or 1
    page = max(1, min(requested_page, total_pages))
    accounts = query.offset((page - 1) * per_page).limit(per_page).all()
    return accounts, page, total_pages, total


@app.route("/admin-dashboard")
@login_required
def admin_dashboard():

    if current_user.role not in ["admin", "super_admin"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    # Fetch administrator accounts
    admin_users = User.query.filter(
        User.role.in_(["security_admin", "quiz_coordinator"])
    ).order_by(User.id.desc()).all()
    if current_user.role == "super_admin":
        manageable_users, student_accounts_page, student_accounts_pages, student_accounts_total = (
            _paginate_role_accounts(
                User.query.filter(
                    User.role.in_(["student", "faculty", "admin"])
                )
                .order_by(User.name.asc(), User.id.asc()),
                "student_accounts_page",
            )
        )
        (
            manageable_staff_users,
            staff_accounts_page,
            staff_accounts_pages,
            staff_accounts_total,
        ) = _paginate_role_accounts(
            User.query.filter(
                User.role.in_(["security_admin", "quiz_coordinator"])
            ).order_by(User.name.asc(), User.id.asc()),
            "staff_accounts_page",
        )
    else:
        manageable_users = []
        manageable_staff_users = []
        student_accounts_page = student_accounts_pages = student_accounts_total = 1
        staff_accounts_page = staff_accounts_pages = staff_accounts_total = 1
    
    # Fetch all incident reports, newest first
    reports = IncidentReport.query.order_by(
        IncidentReport.created_at.desc()
    ).all()

    # Fetch all quiz attempts, newest first
    quiz_attempts = QuizAttempt.query.order_by(
        QuizAttempt.attempted_at.desc()
    ).all()

    # Convert quiz attempt timestamps to IST
    for attempt in quiz_attempts:
        attempt.attempted_at_ist = convert_to_ist(
           attempt.attempted_at
      )
    
    # Quiz difficulty filter
    allowed_difficulties = [
       "All",
       "Beginner",
       "Intermediate",
       "Advanced",
       "Mixed"
    ]

    selected_difficulty = request.args.get("difficulty", "All")

    if selected_difficulty not in allowed_difficulties:
       selected_difficulty = "All"

    if selected_difficulty == "All":
       filtered_quiz_attempts = quiz_attempts
    else:
       filtered_quiz_attempts = [
          attempt for attempt in quiz_attempts
          if attempt.difficulty == selected_difficulty
        ]

    # Pagination for quiz performance
    per_page = 10

    page = request.args.get("page", 1, type=int)

    total_filtered_attempts = len(filtered_quiz_attempts)

    total_pages = max(
            1,
            (total_filtered_attempts + per_page - 1) // per_page
    )

    # Keep page number within valid range
    page = max(1, min(page, total_pages))

    # Calculate records for the current page
    start = (page - 1) * per_page
    end = start + per_page

    paginated_quiz_attempts = filtered_quiz_attempts[start:end]

    # Total quiz attempts
    total_quiz_attempts = len(quiz_attempts)

    # Total unique students who attempted quizzes
    total_quiz_students = len(set(
        attempt.user_id for attempt in quiz_attempts
    ))

    # Average quiz percentage
    if total_quiz_attempts > 0:
        average_quiz_percentage = round(
            sum(attempt.percentage for attempt in quiz_attempts)
            / total_quiz_attempts, 2
        )
    else:
        average_quiz_percentage = 0

    # Difficulty-wise quiz attempts
    beginner_attempts = sum(
        1 for attempt in quiz_attempts
        if attempt.difficulty == "Beginner"
    )

    intermediate_attempts = sum(
        1 for attempt in quiz_attempts
        if attempt.difficulty == "Intermediate"
    )

    advanced_attempts = sum(
        1 for attempt in quiz_attempts
        if attempt.difficulty == "Advanced"
    )

    mixed_attempts = sum(
    1 for attempt in quiz_attempts
    if attempt.difficulty == "Mixed"
    )

    return render_template(
        "admin_dashboard.html",
        reports=reports,
        admin_users=admin_users,
        manageable_users=manageable_users,
        manageable_staff_users=manageable_staff_users,
        student_accounts_page=student_accounts_page,
        student_accounts_pages=student_accounts_pages,
        student_accounts_total=student_accounts_total,
        staff_accounts_page=staff_accounts_page,
        staff_accounts_pages=staff_accounts_pages,
        staff_accounts_total=staff_accounts_total,
        quiz_attempts=quiz_attempts,
        total_quiz_attempts=total_quiz_attempts,
        total_quiz_students=total_quiz_students,
        average_quiz_percentage=average_quiz_percentage,
        beginner_attempts=beginner_attempts,
        intermediate_attempts=intermediate_attempts,
        advanced_attempts=advanced_attempts,
        mixed_attempts=mixed_attempts,
        filtered_quiz_attempts=filtered_quiz_attempts,
        selected_difficulty=selected_difficulty,
        paginated_quiz_attempts=paginated_quiz_attempts,
        current_page=page,
        total_pages=total_pages,
        total_filtered_attempts=total_filtered_attempts,
        per_page=per_page
    )


# Create Administrator Account (Super Admin Only)
@app.route("/create-admin", methods=["POST"])
@login_required
def create_admin():

    if current_user.role != "super_admin":
        flash("Only Super Admin can create administrator accounts.", "danger")
        return redirect(url_for("home"))

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()

    allowed_roles = ["security_admin", "quiz_coordinator"]

    if not name or len(name) > 100 or not email or not password:
        flash("Please fill in all fields.", "warning")
        return redirect(url_for("admin_dashboard"))

    if not _is_valid_email(email):
        flash("Please enter a valid email address.", "warning")
        return redirect(url_for("admin_dashboard"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "warning")
        return redirect(url_for("admin_dashboard"))

    if role not in allowed_roles:
        flash("Invalid administrator role.", "danger")
        return redirect(url_for("admin_dashboard"))

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        flash("An account with this email already exists.", "warning")
        return redirect(url_for("admin_dashboard"))

    try:
        new_admin = User(
            name=name,
            email=email,
            role=role
        )
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        flash("Administrator account created successfully!", "success")
    except IntegrityError:
        db.session.rollback()
        flash("An account with this email already exists.", "warning")
    except Exception:
        db.session.rollback()
        app.logger.exception("Administrator account creation failed.")
        flash("Unable to create administrator account.", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/change-user-role/<int:user_id>", methods=["POST"])
@login_required
def change_user_role(user_id):
    if current_user.role != "super_admin":
        flash("Only Super Admin can change account roles.", "danger")
        return redirect(url_for("home"))

    user = db.session.get(User, user_id)
    if user is None:
        flash("Account not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    new_role = request.form.get("role", "").strip()
    if (
        user.role not in ROLE_CHANGEABLE_SOURCE_ROLES
        or new_role not in ROLE_CHANGE_TARGETS
        or new_role == user.role
    ):
        flash("This account cannot be changed to the selected role.", "warning")
        return redirect(url_for("admin_dashboard"))

    old_role = user.role
    try:
        user.role = new_role
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Account role change failed.")
        flash("Unable to change this account's role.", "danger")
        return redirect(url_for("admin_dashboard"))

    security_event(
        "account.role_changed",
        "Account role changed by super admin",
        target_user_id=user.id,
        old_role=old_role,
        new_role=new_role,
    )
    role_labels = {
        "student": "Student",
        "faculty": "Faculty",
        "admin": "Admin",
        "security_admin": "Security Admin",
        "quiz_coordinator": "Quiz Coordinator",
    }
    role_label = role_labels[new_role]
    flash(f"{user.name}'s role was changed to {role_label}.", "success")
    return redirect(url_for("admin_dashboard"))


# Security Admin Dashboard
@app.route("/security-admin-dashboard")
@login_required
def security_admin_dashboard():

    if current_user.role != "security_admin":
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    selected_status = request.args.get("status", "").strip()
    selected_severity = request.args.get("severity", "").strip()
    report_search = request.args.get("q", "").strip()
    if selected_status and selected_status not in INCIDENT_STATUSES:
        flash("Select a valid incident status filter.", "warning")
        return redirect(url_for("security_admin_dashboard"))
    if selected_severity and selected_severity not in INCIDENT_SEVERITIES:
        flash("Select a valid incident severity filter.", "warning")
        return redirect(url_for("security_admin_dashboard"))
    if len(report_search) > 120:
        flash("Incident search must be 120 characters or fewer.", "warning")
        return redirect(url_for("security_admin_dashboard"))

    all_reports = IncidentReport.query.order_by(
        IncidentReport.created_at.desc()
    ).all()

    total_reports = len(all_reports)

    pending_reports = sum(
        1 for report in all_reports
        if report.status == "Pending"
    )

    under_review_reports = sum(
        1 for report in all_reports
        if report.status == "Under Review"
    )

    resolved_reports = sum(
        1 for report in all_reports
        if report.status == "Resolved"
    )

    report_query = IncidentReport.query.join(User)
    if selected_status:
        report_query = report_query.filter(
            IncidentReport.status == selected_status
        )
    if selected_severity:
        report_query = report_query.filter(
            IncidentReport.severity == selected_severity
        )
    if report_search:
        search_pattern = f"%{report_search}%"
        search_conditions = [
            User.name.ilike(search_pattern),
            User.email.ilike(search_pattern),
            IncidentReport.incident_type.ilike(search_pattern),
            IncidentReport.description.ilike(search_pattern),
        ]
        if report_search.isdecimal():
            search_conditions.append(IncidentReport.id == int(report_search))
        report_query = report_query.filter(or_(*search_conditions))

    reports = report_query.order_by(
        IncidentReport.created_at.desc()
    ).all()

    return render_template(
        "security_admin_dashboard.html",
        reports=reports,
        total_reports=total_reports,
        pending_reports=pending_reports,
        under_review_reports=under_review_reports,
        resolved_reports=resolved_reports,
        matching_reports=len(reports),
        selected_status=selected_status,
        selected_severity=selected_severity,
        report_search=report_search,
    )


def _incident_management_redirect():
    if current_user.role == "security_admin":
        filter_args = {
            form_name: request.form.get(f"filter_{form_name}", "").strip()
            for form_name in ("status", "severity", "q")
        }
        return redirect(url_for(
            "security_admin_dashboard",
            **{
                key: value
                for key, value in filter_args.items()
                if value
            }
        ))
    return redirect(url_for("admin_dashboard"))


@app.route(
    "/admin/incident/<int:report_id>/note",
    methods=["POST"],
)
@login_required
@limiter.limit("30 per hour")
def add_incident_note(report_id):
    if current_user.role not in ("admin", "super_admin", "security_admin"):
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    report = db.session.get(IncidentReport, report_id)
    if report is None:
        flash("Incident report not found.", "danger")
        return _incident_management_redirect()

    note_text = request.form.get("note", "").strip()
    if not note_text or len(note_text) > 2000:
        flash(
            "Investigation notes must be between 1 and 2000 characters.",
            "warning",
        )
        return _incident_management_redirect()

    try:
        db.session.add(IncidentNote(
            report_id=report.id,
            author_name=current_user.name,
            note=note_text,
        ))
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Incident investigation note could not be saved.")
        flash("Unable to save the investigation note.", "danger")
        return _incident_management_redirect()

    security_event(
        "incident.note_added",
        "Internal incident investigation note added",
        report_id=report.id,
    )
    flash("Internal investigation note added.", "success")
    return _incident_management_redirect()


@app.route("/quiz-coordinator-dashboard")
@login_required
def quiz_coordinator_dashboard():

    if current_user.role != "quiz_coordinator":
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    filters = _quiz_attempt_filters()
    if filters is None:
        return redirect(url_for("quiz_coordinator_dashboard"))

    difficulty, student_search = filters
    attempts = _filtered_quiz_attempts(
        difficulty,
        student_search,
    ).all()

    for attempt in attempts:
        attempt.attempted_at_ist = convert_to_ist(attempt.attempted_at)

    return render_template(
        "quiz_coordinator_dashboard.html",
        attempts=attempts,
        total_attempts=len(attempts),
        average_percentage=(
            round(sum(a.percentage for a in attempts) / len(attempts), 2)
            if attempts else 0
        ),
        participant_count=len({attempt.user_id for attempt in attempts}),
        selected_difficulty=difficulty,
        student_search=student_search,
    )


def _quiz_attempt_filters():
    difficulty = request.args.get("difficulty", "").strip()
    student_search = request.args.get("student", "").strip()

    if difficulty and difficulty not in QUIZ_DIFFICULTIES:
        flash("Select a valid quiz difficulty.", "warning")
        return None
    if len(student_search) > 120:
        flash("Student search must be 120 characters or fewer.", "warning")
        return None

    return difficulty, student_search


def _filtered_quiz_attempts(difficulty, student_search):
    query = QuizAttempt.query.join(User)
    if difficulty:
        query = query.filter(QuizAttempt.difficulty == difficulty)
    if student_search:
        search_pattern = f"%{student_search}%"
        query = query.filter(
            or_(
                User.name.ilike(search_pattern),
                User.email.ilike(search_pattern),
            )
        )
    return query.order_by(QuizAttempt.attempted_at.desc())


# Export Quiz Performance Report
@app.route("/export-quiz-report")
@login_required
def export_quiz_report():

    if current_user.role not in ["admin", "super_admin", "quiz_coordinator"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    filters = _quiz_attempt_filters()
    if filters is None:
        endpoint = (
            "quiz_coordinator_dashboard"
            if current_user.role == "quiz_coordinator"
            else "admin_dashboard"
        )
        return redirect(url_for(endpoint))

    difficulty, student_search = filters
    attempts = _filtered_quiz_attempts(
        difficulty,
        student_search,
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # CSV headings
    writer.writerow([
        "Attempt ID",
        "Student Name",
        "Student Email",
        "Difficulty",
        "Score",
        "Total Questions",
        "Percentage",
        "Attempt Date"
    ])

    # CSV records
    for attempt in attempts:
        writer.writerow([
            attempt.id,
            attempt.user.name if attempt.user else "Unknown",
            attempt.user.email if attempt.user else "Unknown",
            attempt.difficulty,
            attempt.score,
            attempt.total_questions,
            attempt.percentage,
            attempt.attempted_at
        ])

    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Disposition"] = (
        "attachment; filename=CUH_Cyber_Shield_Quiz_Report.csv"
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"

    return response


# URL PHISHING CHECKER
@app.route("/url-checker", methods=["GET", "POST"])
@login_required
def url_checker():

    if current_user.role not in ["student", "faculty", "admin", "super_admin"]:
        flash("Access denied.")
        return redirect(url_for("home"))

    result = None
    submitted_url = ""

    if request.method == "POST":

        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            flash("Please enter a URL.")

        elif len(submitted_url) > 2048:
            flash("URL is too long.")

        else:
            try:
                candidate = submitted_url

                if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
                    candidate = "https://" + candidate

                parsed = urlsplit(candidate)

                if (
                    parsed.scheme not in ["http", "https"]
                    or not parsed.hostname
                    or any(char.isspace() for char in candidate)
                    or parsed.username is not None
                    or parsed.password is not None
                ):
                    raise ValueError("Invalid URL format.")

                # Validate IP addresses when hostname is an IP
                try:
                    ipaddress.ip_address(parsed.hostname)
                except ValueError:
                    if (
                        "." not in parsed.hostname
                        or parsed.hostname.startswith(".")
                        or parsed.hostname.endswith(".")
                    ):
                        raise ValueError("Invalid domain format.")

                # Extract features without visiting the URL
                extracted = extract_url_features(candidate)

                missing_features = [
                    feature for feature in url_features
                    if feature not in extracted
                ]

                if missing_features:
                    raise ValueError(
                        "URL feature extraction is incomplete."
                    )

                input_data = pd.DataFrame(
                    [[extracted[f] for f in url_features]],
                    columns=url_features
                )

                prediction = int(url_model.predict(input_data)[0])

                result = {
                    "label": label_mapping[prediction],
                    "is_phishing": prediction == 1
                }

                if hasattr(url_model, "predict_proba"):
                    probabilities = url_model.predict_proba(input_data)[0]

                    result["probabilities"] = {
                        label_mapping[int(cls)]: round(
                            float(prob) * 100, 2
                        )
                        for cls, prob in zip(
                            url_model.classes_, probabilities
                        )
                    }

            except ValueError as error:
                flash(str(error))

            except Exception:
                app.logger.exception("URL checker prediction failed.")
                flash("Unable to analyze this URL. Please try again.")

    return render_template(
        "url_checker.html",
        result=result,
        submitted_url=submitted_url
    )


def _extract_eml_content(content):
    message = BytesParser(policy=policy.default).parsebytes(content)
    headers = [
        f"{name}: {message[name]}"
        for name in ("From", "Reply-To", "Subject")
        if message[name]
    ]
    plain_text_parts = []
    html_parts = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            body = payload.decode("utf-8", errors="replace")
        if isinstance(body, str) and body.strip():
            body_parts = (
                plain_text_parts if content_type == "text/plain" else html_parts
            )
            body_parts.append(body)

    body_parts = plain_text_parts or html_parts
    return "\n".join(headers + [""] + body_parts), {
        "sender": str(message.get("From", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "subject": str(message.get("Subject", "")),
    }


@app.route("/email-checker", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per hour")
def email_checker():

    if current_user.role not in ["student", "faculty", "admin", "super_admin"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    result = None
    submitted_email = ""

    if request.method == "POST":
        submitted_email = request.form.get("email", "").strip()
        email_file = request.files.get("email_file")
        has_uploaded_file = bool(email_file and email_file.filename)
        analysis_content = submitted_email
        email_metadata = {}
        input_error = False

        if email_file is not None and email_file.filename:
            if submitted_email:
                flash(
                    "Paste email text or upload an .eml file, not both.",
                    "warning",
                )
                analysis_content = ""
                input_error = True
            elif os.path.splitext(email_file.filename)[1].lower() != ".eml":
                flash("Upload an email file in .eml format.", "warning")
                analysis_content = ""
                input_error = True
            else:
                email_bytes = email_file.stream.read(
                    current_app.config["EMAIL_CHECKER_MAX_FILE_BYTES"] + 1
                )
                if not email_bytes:
                    flash("The selected email file is empty.", "warning")
                    analysis_content = ""
                    input_error = True
                elif len(email_bytes) > current_app.config[
                    "EMAIL_CHECKER_MAX_FILE_BYTES"
                ]:
                    flash("Email files must be 2 MB or smaller.", "warning")
                    analysis_content = ""
                    input_error = True
                else:
                    analysis_content, email_metadata = _extract_eml_content(
                        email_bytes
                    )

        if not input_error and not analysis_content:
            flash("No readable email content was found to analyze.", "warning")
        elif (
            not input_error
            and not has_uploaded_file
            and len(analysis_content) > 50000
        ):
            flash("Email content is too long.", "warning")
        elif not input_error:
            text = analysis_content.lower()
            suspicious_words = [
                "verify", "password", "otp", "urgent", "immediately",
                "bank account", "payment", "gift card", "click here",
                "confirm your account", "suspended", "login"
            ]

            matched_words = [word for word in suspicious_words if word in text]
            suspicious_links = re.findall(
                r"https?://[^\s]+|www\.[^\s]+",
                analysis_content,
                flags=re.I
            )

            score = len(matched_words) * 10 + len(suspicious_links) * 15
            if re.search(r"[^\s]+@[^\s]+\.[^\s]+", text):
                score += 5
            if "urgent" in text or "immediately" in text:
                score += 15

            if score >= 45:
                risk = "High"
            elif score >= 20:
                risk = "Medium"
            else:
                risk = "Low"

            result = {
                "risk": risk,
                "score": min(score, 100),
                "matched_words": matched_words,
                "link_count": len(suspicious_links),
                "links": suspicious_links,
                **email_metadata,
            }

    return render_template(
        "email_checker.html",
        result=result,
        submitted_email=submitted_email
    )


def _read_incident_attachments(uploads):
    selected_uploads = [
        upload for upload in uploads if upload and upload.filename
    ]
    max_files = current_app.config["INCIDENT_UPLOAD_MAX_FILES"]
    if len(selected_uploads) > max_files:
        raise ValueError(f"Choose no more than {max_files} evidence files.")

    max_bytes = current_app.config["INCIDENT_UPLOAD_MAX_BYTES"]
    total_bytes = 0
    attachments = []
    for upload in selected_uploads:
        original_filename = secure_filename(upload.filename)
        if not original_filename or len(original_filename) > 255:
            raise ValueError("Choose a valid attachment filename.")

        content = upload.stream.read(max_bytes - total_bytes + 1)
        if not content:
            raise ValueError("Selected attachments cannot be empty.")
        total_bytes += len(content)
        if total_bytes > max_bytes:
            raise ValueError("All attachments must total 5 MB or smaller.")
        attachments.append((original_filename, content))

    return attachments


@app.route("/report-incident", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per hour")
def report_incident():

    if current_user.role not in ["student", "faculty"]:
        flash("You are not authorized to submit incident reports.", "danger")
        return redirect(url_for("home"))

    incident_type = ""
    description = ""
    if request.method == "POST":
        incident_type = request.form.get("incident_type", "").strip()
        description = request.form.get("description", "").strip()
        try:
            attachment_data = _read_incident_attachments(
                request.files.getlist("attachments")
            )
        except ValueError as error:
            flash(str(error), "warning")
            return render_template(
                "report_incident.html",
                incident_type=incident_type,
                description=description,
            )
        except OSError:
            current_app.logger.exception(
                "Incident attachment could not be read."
            )
            flash("Unable to read the selected attachment.", "danger")
            return render_template(
                "report_incident.html",
                incident_type=incident_type,
                description=description,
            )

        if not incident_type or not description:
            flash("Please fill in all required fields.", "warning")
            return render_template(
                "report_incident.html",
                incident_type=incident_type,
                description=description,
            )
        if (
            len(incident_type) > 100
            or len(description) < 10
            or len(description) > 3000
        ):
            flash(
                "Incident type must be 100 characters or fewer and "
                "description must be between 10 and 3000 characters.",
                "warning",
            )
            return render_template(
                "report_incident.html",
                incident_type=incident_type,
                description=description,
            )

        report = IncidentReport(
            user_id=current_user.id,
            incident_type=incident_type,
            description=description
        )

        saved_paths = []
        try:
            db.session.add(report)
            db.session.flush()
            if attachment_data:
                os.makedirs(
                    current_app.config["INCIDENT_UPLOAD_FOLDER"],
                    exist_ok=True,
                )
                for original_filename, content in attachment_data:
                    stored_filename = uuid.uuid4().hex
                    saved_path = os.path.join(
                        current_app.config["INCIDENT_UPLOAD_FOLDER"],
                        stored_filename,
                    )
                    saved_paths.append(saved_path)
                    with open(saved_path, "xb") as attachment_file:
                        attachment_file.write(content)
                    db.session.add(IncidentAttachment(
                        report_id=report.id,
                        stored_filename=stored_filename,
                        original_filename=original_filename,
                        size_bytes=len(content),
                    ))
            db.session.commit()
            security_event(
                "incident.report_submitted",
                "Cyber incident report submitted",
                report_id=report.id,
                attachment_count=len(attachment_data),
            )
            flash(
                "Your cyber incident report was submitted successfully!",
                "success",
            )
            return redirect(url_for("report_incident"))
        except (OSError, SQLAlchemyError):
            db.session.rollback()
            for saved_path in saved_paths:
                if not os.path.exists(saved_path):
                    continue
                try:
                    os.remove(saved_path)
                except OSError:
                    current_app.logger.exception(
                        "Could not remove an uncommitted incident attachment."
                    )
            current_app.logger.exception("Incident report submission failed.")
            flash("Unable to submit the report. Please try again.", "danger")

    return render_template(
        "report_incident.html",
        incident_type=incident_type,
        description=description,
    )


@app.route("/admin/incident-attachment/<int:attachment_id>")
@login_required
def download_incident_attachment(attachment_id):
    if current_user.role not in (
        "admin",
        "super_admin",
        "security_admin",
    ):
        flash("You are not authorized to download incident evidence.", "danger")
        return redirect(url_for("home"))

    attachment = db.session.get(IncidentAttachment, attachment_id)
    if attachment is None:
        return {"error": "Incident attachment not found."}, 404

    return send_from_directory(
        current_app.config["INCIDENT_UPLOAD_FOLDER"],
        attachment.stored_filename,
        as_attachment=True,
        download_name=attachment.original_filename,
        mimetype="application/octet-stream",
    )


@app.route("/admin/update-incident/<int:report_id>", methods=["POST"])
@login_required
def update_incident_status(report_id):
    allowed_roles = ["admin", "super_admin", "security_admin"]

    if current_user.role not in allowed_roles:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    report = db.session.get(IncidentReport, report_id)

    if report is None:
        flash("Incident report not found.", "danger")
        return _incident_management_redirect()

    new_status = request.form.get("status", "").strip()

    if new_status not in INCIDENT_STATUSES:
        flash("Invalid report status.", "danger")
        return _incident_management_redirect()

    try:
        report.status = new_status
        db.session.commit()

        flash("Incident status updated successfully!", "success")

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Incident status update failed.")
        flash("Unable to update incident status.", "danger")

    return _incident_management_redirect()


@app.route("/admin/update-incident-severity/<int:report_id>", methods=["POST"])
@login_required
def update_incident_severity(report_id):

    if current_user.role not in ["admin", "super_admin", "security_admin"]:
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    report = db.session.get(IncidentReport, report_id)
    if report is None:
        flash("Incident report not found.", "danger")
        return _incident_management_redirect()

    new_severity = request.form.get("severity", "").strip()

    if new_severity not in INCIDENT_SEVERITIES:
        flash("Invalid incident severity.", "danger")
        return _incident_management_redirect()

    try:
        report.severity = new_severity
        db.session.commit()
        flash("Incident severity updated successfully!", "success")
    except Exception:
        db.session.rollback()
        app.logger.exception("Incident severity update failed.")
        flash("Unable to update incident severity.", "danger")

    return _incident_management_redirect()

@app.route("/logout")
@login_required
def logout():
    security_event(
        "auth.logout",
        "User logged out",
    )
    logout_user()

    flash("You have logged out successfully.")

    return redirect(url_for("home"))


@app.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        database_ready = True
    except Exception:
        app.logger.exception("Health check database query failed.")
        database_ready = False

    response = {
        "status": "success" if database_ready else "unhealthy",
        "database": "ready" if database_ready else "unavailable",
        "model": "ready" if url_model is not None else "unavailable"
    }
    return response, 200 if database_ready else 503

if __name__ == "__main__":
    app.run(
        host=app.config["FLASK_HOST"],
        port=app.config["FLASK_PORT"],
        debug=app.config["DEBUG"],
        use_reloader=False
    )
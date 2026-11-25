from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()


class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    role = db.Column(
        db.String(30),
        nullable=False,
        default="student"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256:600000"
        )

    def check_password(self, password):
        return check_password_hash(
            self.password_hash,
            password
        )

# New Incident Report Model
class IncidentReport(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    incident_type = db.Column(
        db.String(100),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="Pending"
    )

    severity = db.Column(
        db.String(30),
        nullable=False,
        default="Unassigned",
        server_default="Unassigned"
    )
    
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )

    user = db.relationship(
        "User",
        backref=db.backref("incident_reports", lazy=True)
    )

    attachments = db.relationship(
        "IncidentAttachment",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    notes = db.relationship(
        "IncidentNote",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at",
    )


class IncidentNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer,
        db.ForeignKey("incident_report.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_name = db.Column(db.String(100), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )

    report = db.relationship("IncidentReport", back_populates="notes")


class IncidentAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer,
        db.ForeignKey("incident_report.id", ondelete="CASCADE"),
        nullable=False,
    )
    stored_filename = db.Column(db.String(80), nullable=False, unique=True)
    original_filename = db.Column(db.String(255), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )

    report = db.relationship("IncidentReport", back_populates="attachments")

# New Quiz Attempt Model

# Quiz Attempt Model
class QuizAttempt(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    total_questions = db.Column(
        db.Integer,
        nullable=False
    )

    percentage = db.Column(
        db.Float,
        nullable=False
    )

    # New difficulty column
    difficulty = db.Column(
        db.String(30),
        nullable=False,
        default="Mixed"
    )

    attempted_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
    )

    user = db.relationship(
        "User",
        backref=db.backref("quiz_attempts", lazy=True)
    )

    answers = db.relationship(
        "QuizAttemptAnswer",
        back_populates="attempt",
        cascade="all, delete-orphan",
        order_by="QuizAttemptAnswer.id",
    )


class QuizAttemptAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey("quiz_attempt.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    question_id = db.Column(db.Integer, nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(30), nullable=False)
    selected_answer = db.Column(db.Text, nullable=False)
    correct_answer = db.Column(db.Text, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)

    attempt = db.relationship("QuizAttempt", back_populates="answers")

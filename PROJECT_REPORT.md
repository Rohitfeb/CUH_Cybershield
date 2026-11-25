# CUH Cyber Shield

## Project Report

### 1. Project Overview

CUH Cyber Shield is a Flask-based campus cybersecurity awareness platform for
Central University of Haryana. It combines phishing detection, cybersecurity
education, quiz assessment, incident reporting, role-based administration,
private evidence handling, password recovery, and deployment support in one
application.

The project is designed for students and faculty, while providing dedicated
workflows for security administrators, quiz coordinators, administrators, and
super administrators.

### 2. Objectives

- Help users identify suspicious URLs and phishing indicators in email content.
- Provide cybersecurity awareness resources and knowledge assessment.
- Allow students and faculty to report suspicious cyber incidents.
- Provide incident management, severity, status, filters, and private notes.
- Separate operational responsibilities through role-based access control.
- Protect user accounts, reset credentials securely, and maintain privacy.
- Support local development, container deployment, and production configuration.

### 3. Technology Stack

| Area | Technology |
|---|---|
| Web framework | Flask 3 |
| Authentication | Flask-Login |
| Database | SQLite for development, PostgreSQL-compatible SQLAlchemy for production |
| ORM | Flask-SQLAlchemy / SQLAlchemy |
| Password security | Werkzeug PBKDF2-SHA256 password hashing |
| ML and data | scikit-learn, pandas, joblib |
| Front end | Jinja templates, Bootstrap 5, custom CSS |
| Security controls | CSRF validation, secure session cookies, security headers, rate limiting |
| Deployment | Gunicorn, Docker, WSGI, health endpoint |
| Testing | Python unittest |

### 4. System Modules

#### 4.1 Authentication and Accounts

- Public student registration and normalized email addresses.
- Login and role-specific dashboard routing.
- Password change after current-password verification.
- Signed, 30-minute password reset links.
- SMTP password-reset delivery with a development fallback.
- Authenticated account deletion with password verification and record cleanup.
- Public pages for awareness and privacy information.

#### 4.2 Role-Based Access

The application supports:

- Student
- Faculty
- Administrator
- Super administrator
- Security administrator
- Quiz coordinator

The super administrator alone can create staff accounts and manage eligible
roles. Super administrator accounts are protected from role changes.

#### 4.3 URL Phishing Analysis

The URL checker accepts a user-entered URL and extracts practical indicators,
then uses the trained `url_detector.pkl` model to classify the result and
display a risk-oriented explanation.

#### 4.4 Email Phishing Analysis

The email checker accepts pasted email content or an uploaded `.eml` file.
It extracts headers and message text, identifies suspicious links and
phishing indicators, and limits uploaded file size. The model artifact is
stored at `models/email_detector.pkl`.

#### 4.5 Cyber Awareness Quiz

- Quiz selection by difficulty: Beginner, Intermediate, Advanced, and Mixed.
- A visible 10-minute countdown with automatic timeout submission.
- Server-side timeout grace-period validation.
- Saved attempt score, percentage, difficulty, and answer history.
- Post-submission review of the selected answer, correct answer, and explanation.
- Quiz history restricted to the signed-in student or faculty member.
- Account deletion removes saved attempts and answer reviews.

#### 4.6 Incident Reporting

- Authenticated student and faculty incident submission.
- Optional private evidence attachments, up to five files per report.
- Combined evidence size limit of 5 MB.
- Supported by a private, non-public upload directory.
- Incident status: Pending, Under Review, or Resolved.
- Severity: Unassigned, Low, Medium, High, or Critical.
- Private investigation notes for security staff.
- Search and filtering for incident management.
- Staff-only evidence downloads.

#### 4.7 Dashboards and Reporting

- Student and faculty dashboards with the appropriate tools.
- Super-administrator account and role management.
- Security-administrator incident management.
- Quiz-coordinator participant filters, metrics, and CSV export.
- Independent pagination for role-management tables.

### 5. Database Structure

The primary data models are:

| Model | Purpose |
|---|---|
| `User` | Accounts, password hashes, and roles |
| `IncidentReport` | Report details, status, severity, and reporter |
| `IncidentAttachment` | Private evidence metadata and stored filename |
| `IncidentNote` | Internal security investigation notes |
| `QuizAttempt` | Aggregate score and quiz metadata |
| `QuizAttemptAnswer` | Per-question result and answer review |

Foreign-key relationships and cascade deletion preserve consistency when accounts
are deleted or reports are removed.

### 6. Security Measures

- Passwords are hashed and never stored as plain text.
- Login and registration forms include password visibility controls.
- CSRF tokens protect state-changing POST, PUT, PATCH, and DELETE requests.
- Session cookies are HTTP-only and can use Secure and SameSite settings.
- Security headers include:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy`
- Password reset tokens are signed and expire after 30 minutes.
- Sensitive evidence files remain outside public static directories.
- Route access is enforced using authentication and role checks.
- Production configuration validation rejects insecure deployment settings.
- Rate limits protect login, registration, reset, role, upload, and account operations.
- A JSON log formatter provides structured application and security-event logs.

### 7. Project Structure

```text
CUH_Cybershield/
|-- app.py                  Flask application and route implementation
|-- config.py               Environment and deployment configuration
|-- models_db.py            SQLAlchemy models
|-- quiz_questions.py       Quiz question bank
|-- release_check.py        Production and test release validation
|-- wsgi.py                 WSGI entry point
|-- gunicorn.conf.py        Gunicorn configuration
|-- Dockerfile              Container build
|-- requirements.txt        Python dependencies
|-- dataset/                Training and reference datasets
|-- ml/                     Training or supporting ML scripts
|-- models/                Trained joblib model artifacts
|-- static/                 CSS and browser JavaScript
|-- templates/              Jinja HTML templates
|-- tests/                  Automated unittest suite
|-- instance/               Local database and private upload storage
`-- utils/                  URL feature extraction utilities
```

### 8. Setup and Execution

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000/`.

Set `SECRET_KEY` and all environment-specific values before starting a shared
or production environment.

### 9. Testing

The automated suite can be run with:

```powershell
.\\.venv\\Scripts\\python.exe -m unittest discover -s tests -p "test*.py" -v
```

The test coverage includes:

- Authentication and role routing
- Super-administrator role management
- Password reset and password change
- Account deletion
- CSRF and security headers
- URL and email checker behavior
- Private incident evidence and staff downloads
- Incident status, severity, filters, and notes
- Quiz countdown, timeout, result review, history, and privacy
- Quiz coordinator filters and CSV exports
- Deployment files and health checks
- Release validation

The validated baseline suite passes 53 tests.

### 10. Deployment

For container deployment:

```powershell
docker build -t cuh-cybershield .
docker run --env-file .env -p 8080:8080 cuh-cybershield
```

For production, configure:

- A stable random `SECRET_KEY` of at least 32 characters
- `DEPLOYMENT_ENV=production`
- `FLASK_DEBUG=0`
- `SESSION_COOKIE_SECURE=1`
- Public HTTPS `RESET_BASE_URL`
- SMTP reset-email settings
- A persistent database, preferably PostgreSQL
- Persistent private incident-evidence storage

The application exposes `/health`. It returns HTTP 200 only when the database
is available and HTTP 503 with an unhealthy response when it is unavailable.

### 11. Limitations and Future Enhancements

- ML predictions are decision-support indicators and require professional review.
- URL checks should be integrated with an external reputation or DNS service for live threat intelligence.
- Email attachment analysis can be expanded beyond `.eml` text extraction.
- Incident evidence antivirus scanning can be added before storage.
- A production audit trail can record administrator and security actions.
- PostgreSQL migration and cloud object storage can improve horizontal deployment.
- Automated accessibility, browser, and load tests can supplement unittest coverage.

### 12. Conclusion

CUH Cyber Shield provides a complete campus cybersecurity awareness and
response workflow. It combines usable public-facing awareness tools with
role-specific operational dashboards, private incident evidence, ML-assisted
phishing indicators, account protection, automated tests, and deployment
configuration. The project is ready for local demonstration and subject to
production secret, SMTP, database, and persistent-storage configuration before
public deployment.

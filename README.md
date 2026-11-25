# CUH Cyber Shield


A Flask-based campus cybersecurity awareness application.

## Features

- Student and faculty accounts
- Separate student and faculty dashboards with cybersecurity tools and resources
- Super admin, security admin, and quiz coordinator roles
- Cyber awareness quizzes with difficulty levels
- Visible 10-minute quiz timer with automatic submission at timeout
- Post-quiz answer review with correct answers and explanations
- URL phishing analysis
- Email phishing indicator analysis from pasted text or `.eml` files
- Cyber incident reporting and status/severity management
- Security-admin incident search, filters, and private investigation notes
- Optional private evidence attachments for incident reports
- Quiz coordinator attempt filters, participation metrics, and CSV export

## Accounts and roles

Public registration creates student accounts. The sign-in flow supports the
`student`, `faculty`, `admin`, `super_admin`, `security_admin`, and
`quiz_coordinator` roles, each routed to its corresponding dashboard.
Only a super admin can create security admin and quiz coordinator accounts.
From the administrator dashboard, super admins can assign student, faculty,
security admin, and quiz coordinator roles to accounts. Existing admin accounts
can be changed to one of those roles, but admin and super admin cannot be
assigned as new roles. Super admin accounts cannot be changed.
Authenticated users can change their password after verifying the current one.
Passwords are stored as hashes, not plaintext.
Student and faculty incident reports accept up to five evidence files of any
type, with a combined size limit of 5 MB per report. Files are stored outside
the public static directory and only incident-management staff can download
them.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000/`.

Set `SECRET_KEY` and other options in `.env` before running in a shared or production environment.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | Random per process | Stable Flask session and reset-token signing key |
| `DATABASE_URL` | `sqlite:///cybershield.db` | SQLAlchemy database connection |
| `INCIDENT_UPLOAD_FOLDER` | `instance/incident_uploads` | Private directory for incident evidence; use persistent storage in production |
| `FLASK_DEBUG` | `0` | Enables debug mode (`1`, `true`, or `yes`) |
| `FLASK_HOST` | `127.0.0.1` | Application bind address |
| `FLASK_PORT` | `5000` | Application port |
| `RESET_BASE_URL` | Localhost when bound to loopback | Public base URL used in reset links; set the deployed HTTPS URL when hosted remotely |
| `MAIL_SERVER` | Unset | SMTP host for reset email delivery |
| `MAIL_PORT` | `587` | SMTP port |
| `MAIL_USE_TLS` | `1` | Use STARTTLS for SMTP |
| `MAIL_USE_SSL` | `0` | Use implicit SMTP SSL instead of STARTTLS |
| `MAIL_USERNAME` | Unset | SMTP login |
| `MAIL_PASSWORD` | Unset | SMTP password or provider app password |
| `MAIL_DEFAULT_SENDER` | SMTP username | Sender address for reset emails |

Password reset links are signed, expire after 30 minutes, and become invalid after
the password is changed. Configure SMTP before using resets outside development.
In debug mode only, a local reset link is shown on screen when email delivery is
not configured. Passwords remain hashed; the login and registration password
controls only temporarily show the text entered into that form.
Set a stable, random `SECRET_KEY` and the externally reachable `RESET_BASE_URL`
before deployment.
For Gmail SMTP, use an app password (with 2-Step Verification enabled) as
`MAIL_PASSWORD`; do not use or commit your normal account password.

To enter the Neon PostgreSQL URL and Gmail app password without exposing them in
the terminal or source code, run:

```powershell
.\set_local_secrets.ps1
```

## Deployment preparation

For a production deployment:

1. Set a long, stable `SECRET_KEY`.
2. Set `DEPLOYMENT_ENV=production`, `FLASK_DEBUG=0`, and
   `SESSION_COOKIE_SECURE=1`.
3. Set `RESET_BASE_URL` to the public HTTPS URL.
4. Configure SMTP values and a persistent external database.
5. Run with Gunicorn:

```bash
gunicorn --config gunicorn.conf.py wsgi:app
```

The containerized deployment can be built and run with:

```powershell
docker build -t cuh-cybershield .
docker run --env-file .env -p 8080:8080 cuh-cybershield
```

Because container filesystems and SQLite databases are ephemeral, mount persistent
PostgreSQL storage and the incident evidence directory when using Docker:

```powershell
docker volume create cuh-cybershield-evidence
docker run --env-file .env -p 8080:8080 `
  -v cuh-cybershield-evidence:/var/lib/cuh-cybershield/incidents `
  cuh-cybershield
```

Use `/health` for platform health checks. It returns HTTP 503 when the database
is unavailable.

## Phase 5 release validation

Before deployment, set all production environment variables and run:

```powershell
python release_check.py
```

The release check verifies required artifacts, HTTPS configuration, secure
cookies, debug mode, and the complete test suite.

## Testing

Run the complete automated test suite from the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test*.py" -v
```

The suite covers authentication and role access, password reset, CSRF and
security headers, phishing checkers, incident evidence, quiz review and timeout
behavior, quiz reporting, deployment artifacts, and the health endpoint.

For the full system analysis, architecture, features, testing evidence, and
deployment guidance, see [PROJECT_REPORT.md](PROJECT_REPORT.md).

## Production database

Set `DATABASE_URL` to a PostgreSQL connection string, for example:

```text
postgresql+psycopg://username:password@host:5432/cybershield
```

SQLite remains available for local development. Back up the production database
through the database provider and use persistent storage or an external database
service.
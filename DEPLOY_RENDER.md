# Deploying CUH Cyber Shield on Render (free) with Neon + Brevo

## What you need (all free)
- GitHub repo with this project (`.env`, `instance/`, `.venv/` are git-ignored)
- Neon PostgreSQL project (neon.tech) -> copy the connection string
- Brevo account (brevo.com) -> verified sender + API key

## 1. Neon database
Create a project and copy the connection string. Convert it to:
`postgresql+psycopg://USER:PASSWORD@HOST/DBNAME?sslmode=require`

## 2. Brevo email
1. Sign up (new accounts are reviewed, do this a day early).
2. Add and verify your sender address (Senders section).
3. SMTP & API -> API keys -> create key -> **Restricted**,
   **Transactional email = All**, everything else None.
   Use the API key, not the SMTP key. Copy it once.

## 3. Render
1. Push the project to GitHub.
2. Render -> New -> Blueprint -> pick the repo (uses `render.yaml`).
3. When prompted, set:
   - `DATABASE_URL` = Neon URL from step 1
   - `BREVO_API_KEY` = key from step 2
   - `MAIL_DEFAULT_SENDER` = the verified Brevo sender
   - `RESET_BASE_URL` = leave blank, set after first deploy
4. After the first deploy copy the service URL
   (e.g. `https://cuh-cybershield.onrender.com`), set `RESET_BASE_URL` to it
   (no trailing slash) and let Render redeploy.

## 4. Create the super admin (once, from your own computer)
PowerShell, in the project folder with the venv active:

    $env:DATABASE_URL = "postgresql+psycopg://USER:PASS@HOST/DB?sslmode=require"
    $env:DEPLOYMENT_ENV = "development"
    python create_super_admin.py

## 5. Verify
- `https://YOUR-URL/health` should report the database as ready.
- Log in, then use Forgot Password and confirm the email arrives (check spam).
- Fail a login once and check Render logs: the `ip` field should be your real IP.

## Free-plan limitations (tell evaluators)
- Service sleeps after ~15 min idle; first request takes about a minute.
- Uploaded incident evidence is erased on every restart/redeploy.
- SMTP is blocked on free Render, so email goes through Brevo's HTTPS API.
- Memory is 512 MB: keep `WEB_CONCURRENCY=1`.

## Local development
Copy `.env` settings from the provided local `.env` (SQLite, development mode).
Forgot Password shows the reset link on the page when no email provider is set.
If you lose access, run `python recover_account.py`.

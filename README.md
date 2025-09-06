# WebVitals360 (Website Security & Performance Audit)
 
WebVitals360 is a Flask app that audits a website for security headers, performance, SEO, and accessibility. It aggregates results from PageSpeed Insights and other online checkers, generates PDF reports (Issues and Remedies), and can email them to the user.
 
## Features
 
- __User accounts__: sign up and sign in (username or email) using `users` table in MySQL.
- __Scan endpoint__: POST a URL and receive scores and categorized issues.
- __PDF reports__: Issues and Remedies PDFs generated per scan.
- __Email delivery__: send PDFs via SMTP or providers (SendGrid/Mailgun/Brevo). You can disable email and just download in the UI.
- __Modern UI__: `templates/index.html` and `static/` assets.
 
## Project structure
 
- `hk/app.py` — Flask application (routes, scanning logic, email).
- `hk/templates/` — HTML templates (`index.html`, `index_login.html`).
- `hk/static/` — CSS/JS assets (e.g., `style.css`, `style_login.css`, `script.js`).
- `hk/.env` — Environment configuration (create this locally; do not commit secrets).
- `hk/reports/` — Generated reports directory (created at runtime if needed).
- `hk/reports/*.pdf` — Generated PDF files per scan (temporary or saved depending on config).
 
## Requirements
 
- Python 3.10+
- MySQL 8.x (or compatible) reachable from your machine
- PowerShell (Windows) or any shell
 
Python packages (install via pip):
 
- Flask, python-dotenv, requests, pymysql, reportlab
- Optional: playwright (headless fetch) — if installed, run `playwright install` once
 
Quick install:
 
```powershell
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install --upgrade pip
pip install Flask python-dotenv requests pymysql reportlab
# Optional headless HTML fetch
pip install playwright
python -m playwright install
```
 
## MySQL setup
 
Create a database and user, then set credentials in `.env`. Tables are auto-created on app start.
 
Example SQL (adjust as needed):
 
```sql
CREATE DATABASE webvitals360 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'wv360'@'%' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON webvitals360.* TO 'wv360'@'%';
FLUSH PRIVILEGES;
```
 
## Environment variables (.env)
 
Create `hk/.env` with at least the following:
 
```env
# Flask
FLASK_SECRET_KEY=change_me
FLASK_ENV=development
PORT=8080
 
# MySQL
MYSQL_HOST=127.0.0.1
MYSQL_DATABASE=webvitals360
MYSQL_USER=wv360
MYSQL_PASSWORD=strong_password_here
 
# Email (choose one provider or plain SMTP)
# --- SendGrid (recommended) ---
SENDGRID_API_KEY=your_sendgrid_api_key
FROM_EMAIL=you@yourdomain.com  # must be verified in SendGrid
 
# --- OR SMTP ---
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=you@gmail.com
# SMTP_PASS=app_specific_password
# MAIL_USE_TLS=true
 
# Fallback recipient when user is not signed in
REPORT_RECIPIENT=you@yourdomain.com
 
# Optional: disable SMTP fallback if using only SendGrid
# SMTP_DISABLE=true
 
# Optional: API keys for external services (PageSpeed, etc.)
# GOOGLE_PSI_KEY=your_google_api_key
```
 
Notes:
 
- Verify `FROM_EMAIL` in your provider (SendGrid Single Sender or domain). Unverified senders are often dropped.
- If using Gmail SMTP, you must use an App Password with 2FA enabled.
 
## Run locally (Windows PowerShell)
 
```powershell
# From repo root
cd hk
. ..\.venv\Scripts\Activate.ps1  # if not already activated
python app.py
# App will start at http://127.0.0.1:8080
```
 
Visit:
 
- `http://127.0.0.1:8080/` — main UI
- `http://127.0.0.1:8080/login` — login/register UI (if routed)
- `http://127.0.0.1:8080/test_email` — sends a tiny test email with a PDF to confirm email setup
 
## Usage
 
1) Sign up or sign in.
 
2) Enter a website URL and start a scan from the UI. Alternatively, use the API:
 
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/scan -ContentType "application/json" -Body '{"url":"example.com"}'
```
 
3) The response includes category scores and an `email_status` string. If email is configured, you’ll receive Issues and Remedies PDFs as attachments.
 
## Common issues
 
- __Email not arriving__:
  - Check `email_status` in the `/scan` or `/test_email` response.
  - Verify `FROM_EMAIL` is authorized by your provider.
  - Check SendGrid Activity for drops/bounces or spam folder.
  - Firewall may block outbound ports (587/465).
 
- __MySQL connection errors__:
  - Confirm `.env` values and database privileges.
  - Ensure MySQL is listening on the host/port you set.
 
- __Playwright install issues__:
  - Skip Playwright; app will fall back to simple HTTP fetch.
 
## Deploying
 
- You can deploy behind any WSGI server (e.g., gunicorn) and reverse proxy (nginx). For Windows/IIS, use `wfastcgi`.
- Set environment variables on the target host and ensure MySQL/network access.
 
## License
 
Proprietary — for internal or educational use unless you add a license. Update this section as needed.
"# 24_Stephen" 
"# 24_Stephen" 

from flask import Flask, render_template, request, jsonify, send_file
import time
import random
from flask import Flask, render_template, request, redirect, url_for, session
import numpy as np
import pickle
import mysql.connector
from mysql.connector import Error
from os import getenv
import os
from dotenv import load_dotenv
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import base64
import mimetypes
import smtplib
from email.message import EmailMessage
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile

load_dotenv()

# Optional headless browser (Playwright) for fetching HTML when sites block bots
try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

def _fetch_html_headless(target_url: str, timeout_ms: int = 20000) -> str:
    """Fetch page HTML using a real browser context to bypass basic bot protections.
    Returns HTML string or raises Exception. Requires Playwright and Chromium installed.
    """
    if sync_playwright is None:
        raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")
    # Normalize URL
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 850},
                java_script_enabled=True,
                bypass_csp=False,
            )
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            # Route to add extra headers similar to a real browser
            page.goto(target_url, wait_until="domcontentloaded")
            # Some sites need network idle for late content
            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                pass
            content = page.content()
            return content
        finally:
            browser.close()

app = Flask(__name__)
app.secret_key = "0adb576b12e513f62b42875fa4a96f711e4c9b3c0ca6f07e"
# app.secret_key = os.getenv("FLASK_SECRET_KEY")

# ---------------- MYSQL CONNECTION ----------------
import pymysql


def get_db_connection():
    return pymysql.connect(
        host="localhost",
        user="root",             # replace with your MySQL username
        password="Prak@2004", # replace with your MySQL password
        database="stephen_db",
        cursorclass=pymysql.cursors.DictCursor
    )


def init_db():
    """Create required tables if not present."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Users table (for signup/login email storage)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE,
                    email VARCHAR(255),
                    password VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255),
                    url TEXT,
                    overall_score INT,
                    security_score INT,
                    performance_score INT,
                    seo_score INT,
                    accessibility_score INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            # (reverted) no separate reports table; PDFs are attached and not tokenized
        conn.commit()
        conn.close()
    except Exception:
        # fail soft; app should still run
        pass

init_db()

# ---------------- External API helpers ----------------
PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
OBS_ANALYZE = "https://http-observatory.security.mozilla.org/api/v1/analyze"
OBS_RESULTS = "https://http-observatory.security.mozilla.org/api/v1/getScanResults"
SECHEADERS_ENDPOINT = "https://securityheaders.com/"
SSLLABS_ANALYZE = "https://api.ssllabs.com/api/v3/analyze"

# ---------------- Email helpers (multi-provider) ----------------
def _smtp_send(from_addr: str, to_list, subject: str, text: str, attachments_paths):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_list)
    msg.set_content(text)
    for p in attachments_paths:
        if p and os.path.exists(p):
            ctype, encoding = mimetypes.guess_type(p)
            maintype, subtype = (ctype or "application/pdf").split("/", 1)
            with open(p, "rb") as f:
                msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(p))
    with smtplib.SMTP(host, port) as smtp:
        # Optional verbose SMTP logs
        if (os.getenv("SMTP_DEBUG", "0").lower() in ("1", "true", "yes", "on")):
            smtp.set_debuglevel(1)
        smtp.ehlo()
        # Optional TLS toggle
        use_tls = (os.getenv("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes"))
        if use_tls:
            smtp.starttls(); smtp.ehlo()
        if user and pwd:
            smtp.login(user, pwd)
        smtp.send_message(msg)
    return f"smtp:{to_list}"

def _mailgun_send(from_addr: str, to_list, subject: str, text: str, attachments_paths):
    api_key = os.getenv("MAILGUN_API_KEY")
    domain = os.getenv("MAILGUN_DOMAIN")
    if not api_key or not domain:
        raise RuntimeError("Mailgun not configured")
    url = f"https://api.mailgun.net/v3/{domain}/messages"
    data = {
        "from": from_addr,
        "to": to_list,
        "subject": subject,
        "text": text,
    }
    files = []
    for p in attachments_paths:
        if p and os.path.exists(p):
            files.append(("attachment", (os.path.basename(p), open(p, "rb"), "application/pdf")))
    r = requests.post(url, auth=("api", api_key), data=data, files=files, timeout=20)
    if r.status_code >= 300:
        raise RuntimeError(f"Mailgun failed: {r.status_code} {r.text[:200]}")
    return f"mailgun:{to_list}"

def _sendgrid_send(from_addr: str, to_list, subject: str, text: str, attachments_paths):
    # support common typo var name as fallback
    api_key = os.getenv("SENDGRID_API_KEY") or os.getenv("SENDGRID_API_KEYSG")
    if not api_key:
        raise RuntimeError("SendGrid not configured")
    url = "https://api.sendgrid.com/v3/mail/send"
    atts = []
    for p in attachments_paths:
        if p and os.path.exists(p):
            with open(p, "rb") as f:
                atts.append({
                    "content": base64.b64encode(f.read()).decode("ascii"),
                    "type": "application/pdf",
                    "filename": os.path.basename(p),
                    "disposition": "attachment",
                })
    payload = {
        "personalizations": [{"to": [{"email": addr} for addr in to_list]}],
        "from": {"email": from_addr},
        "subject": subject,
        "content": [{"type": "text/plain", "value": text}],
    }
    if atts:
        payload["attachments"] = atts
    r = requests.post(url, headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}, json=payload, timeout=20)
    if r.status_code >= 300:
        raise RuntimeError(f"SendGrid failed: {r.status_code} {r.text[:200]}")
    return f"sendgrid:{to_list}"

def _brevo_send(from_addr: str, to_list, subject: str, text: str, attachments_paths):
    api_key = os.getenv("BREVO_API_KEY")
    if not api_key:
        raise RuntimeError("Brevo not configured")
    url = "https://api.brevo.com/v3/smtp/email"
    atts = []
    for p in attachments_paths:
        if p and os.path.exists(p):
            with open(p, "rb") as f:
                atts.append({
                    "name": os.path.basename(p),
                    "content": base64.b64encode(f.read()).decode("ascii"),
                })
    payload = {
        "sender": {"email": from_addr},
        "to": [{"email": addr} for addr in to_list],
        "subject": subject,
        "textContent": text,
    }
    if atts:
        payload["attachment"] = atts
    r = requests.post(url, headers={"api-key": api_key, "Content-Type": "application/json"}, json=payload, timeout=20)
    if r.status_code >= 300:
        raise RuntimeError(f"Brevo failed: {r.status_code} {r.text[:200]}")
    return f"brevo:{to_list}"

def send_email_any(from_addr: str, to_list, subject: str, text: str, attachments_paths):
    """Send email using available providers in smart order.
    Order: SendGrid, Brevo, Mailgun, then SMTP (unless SMTP_DISABLE=1).
    Returns provider string on success; raises on complete failure.
    """
    errors = []
    providers = []
    # Prefer APIs first if keys present
    if os.getenv("SENDGRID_API_KEY") or os.getenv("SENDGRID_API_KEYSG"):
        providers.append(_sendgrid_send)
    if os.getenv("BREVO_API_KEY"):
        providers.append(_brevo_send)
    if os.getenv("MAILGUN_API_KEY") and os.getenv("MAILGUN_DOMAIN"):
        providers.append(_mailgun_send)
    # Append SMTP last unless disabled
    if not (os.getenv("SMTP_DISABLE", "0").lower() in ("1", "true", "yes", "on")):
        providers.append(_smtp_send)

    # If no providers configured, still try SMTP as last resort
    if not providers:
        providers = [_smtp_send]

    for fn in providers:
        try:
            return fn(from_addr, to_list, subject, text, attachments_paths)
        except Exception as e:
            name = getattr(fn, "__name__", "provider")
            errors.append(f"{name}:{e}")
            continue
    raise RuntimeError("; ".join(errors))

def call_pagespeed(page_url: str, categories=("performance", "seo", "accessibility", "best-practices"), strategy="mobile", timeout=15):
    """Call Google PageSpeed Insights. Returns dict with selected fields or None on failure."""
    try:
        params = {
            "url": page_url,
            "strategy": strategy,
        }
        # add categories explicitly
        for c in categories:
            # PSI uses repeated category params
            pass
        api_key = os.getenv("PAGESPEED_API_KEY")
        if api_key:
            params["key"] = api_key
        # Manually build with repeated category params
        cat_qs = "&".join([f"category={c}" for c in categories])
        base_qs = "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()])
        url = f"{PSI_ENDPOINT}?{base_qs}&{cat_qs}"
        r = requests.get(url, timeout=timeout)
        data = r.json()
        lr = (data.get("lighthouseResult") or {})
        cats = (lr.get("categories") or {})
        audits = (lr.get("audits") or {})
        perf_score = cats.get("performance", {}).get("score")
        seo_score = cats.get("seo", {}).get("score")
        acc_score = cats.get("accessibility", {}).get("score")
        bp_score = cats.get("best-practices", {}).get("score")
        # key audits
        def audit(num):
            a = audits.get(num, {})
            return {
                "id": num,
                "title": a.get("title"),
                "score": a.get("score"),
                "numericValue": a.get("numericValue"),
                "displayValue": a.get("displayValue"),
            }
        return {
            "perf_score": int(round((perf_score or 0) * 100)),
            "seo_score": int(round((seo_score or 0) * 100)),
            "acc_score": int(round((acc_score or 0) * 100)),
            "bp_score": int(round((bp_score or 0) * 100)),
            "audits": {
                "lcp": audit("largest-contentful-paint"),
                "fcp": audit("first-contentful-paint"),
                "tbt": audit("total-blocking-time"),
                "cls": audit("cumulative-layout-shift"),
                "color-contrast": audit("color-contrast"),
                "image-alt": audit("image-alt"),
            }
        }
    except Exception:
        return None

def call_ssllabs(host: str, timeout=10):
    """Fetch cached SSL Labs grade quickly (no long polling). Returns dict or None.
    Uses fromCache to avoid slow scans and keeps overall analysis fast.
    """
    try:
        params = {
            "host": host,
            "publish": "off",
            "fromCache": "on",
            "all": "done",
        }
        r = requests.get(SSLLABS_ANALYZE, params=params, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        endpoints = data.get("endpoints") or []
        # Pick first available grade
        for ep in endpoints:
            if ep.get("grade"):
                return {"grade": ep.get("grade")}
        return None
    except Exception:
        return None

def call_securityheaders(page_url: str, timeout=15):
    """Call SecurityHeaders.com and return grade and details or None. No API key required.
    Uses JSON mode: https://securityheaders.com/?q=<url>&hide=on&followRedirects=on&json=on
    """
    try:
        params = {
            "q": page_url,
            "hide": "on",
            "followRedirects": "on",
            "json": "on",
        }
        r = requests.get(SECHEADERS_ENDPOINT, params=params, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return None
        data = r.json()
        # Typical fields include: grade, score, directives / missing headers list
        return {
            "grade": data.get("grade"),
            "score": data.get("score"),
            "missing": data.get("missing", []),
            "present": data.get("present", []),
        }
    except Exception:
        return None

def call_observatory(host: str, timeout=15):
    """Call Mozilla Observatory and return grade/score or None. host must be just domain."""
    try:
        # Trigger (or reuse) scan
        requests.get(OBS_ANALYZE, params={"host": host, "hidden": "true", "rescan": "true"}, timeout=timeout)
        # Poll results a few times
        for _ in range(6):
            res = requests.get(OBS_RESULTS, params={"host": host}, timeout=timeout)
            if res.status_code != 200:
                time.sleep(1)
                continue
            data = res.json()
            # Data typically contains 'grade' and 'score'
            grade = data.get("grade") or data.get("overall_grade")
            score = data.get("score") or data.get("overall_score")
            if grade is not None or score is not None:
                return {"grade": grade, "score": score}
            time.sleep(1)
        return None
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('index_login.html')

@app.route("/home")
def home():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("index.html", user=session["user"])

# ---- Minimal CORS for extension to call /ai_fix ----
@app.after_request
def add_cors_headers(resp):
    try:
        # Allow CORS for extension and local calls
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    except Exception:
        pass
    return resp

@app.route('/ai_fix', methods=['OPTIONS'], endpoint='ai_fix_preflight')
def ai_fix_preflight():
    # Empty 200 with CORS headers set by after_request
    return ('', 200)


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            return "Passwords do not match! <a href='/'>Go back</a>"

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if user already exists
            cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
            existing = cursor.fetchone()
            if existing:
                return "User already exists! <a href='/'>Go back</a>"

            # Insert new user
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, password))
            conn.commit()
            cursor.close()
            conn.close()

            session["user"] = username
            return redirect(url_for("home"))

        except Error as e:
            return f"Database error: {e}"

    return redirect(url_for("index"))


# ---------------- SIGNIN ----------------
@app.route("/signin", methods=["POST"])
def signin():
    # Accept username or email in the username field
    identifier = request.form["username"]
    password = request.form["password"]

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Match by username or email
        cursor.execute("SELECT * FROM users WHERE (username=%s OR email=%s) AND password=%s", (identifier, identifier, password))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            session["user"] = user.get("username") or identifier
            return redirect(url_for("home"))
        else:
            return "Invalid login! <a href='/'>Try again</a>"

    except Error as e:
        return f"Database error: {e}"


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "Missing url"}), 400

    # Normalize URL
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    api_timeout = int(os.getenv("API_TIMEOUT_SECONDS", "12"))
    # Fast mode via request or env
    fast = False
    try:
        fast = bool(data.get('fast'))
    except Exception:
        fast = False
    if not fast:
        fast = (os.getenv("FAST_MODE", "false").lower() in ("1", "true", "yes", "on"))
    if fast:
        api_timeout = min(api_timeout, 6)
    start = time.time()
    try:
        resp = requests.get(url, timeout=api_timeout, headers={"User-Agent": "Mozilla/5.0"})
        load_time = time.time() - start
        status_ok = 200 <= resp.status_code < 400
        html = resp.text if status_ok else ""
        headers = resp.headers
    except Exception as e:
        return jsonify({"error": f"Failed to fetch URL: {e}"}), 502

    soup = BeautifulSoup(html, "lxml") if html else BeautifulSoup("", "lxml")

    # Security checks (heuristics)
    parsed = urlparse(url)
    security_issues = []
    if parsed.scheme != "https":
        security_issues.append({"title": "Site not using HTTPS", "severity": "high", "desc": "Upgrade to HTTPS."})
    # Security headers
    sec_headers = {
        "Content-Security-Policy": "Define a CSP to mitigate XSS.",
        "Strict-Transport-Security": "Enable HSTS for HTTPS sites.",
        "X-Content-Type-Options": "Set to nosniff to prevent MIME sniffing.",
        "X-Frame-Options": "Prevent clickjacking (SAMEORIGIN/deny).",
        "Referrer-Policy": "Control referrer leakage.",
        "Permissions-Policy": "Restrict powerful features."
    }
    for h, tip in sec_headers.items():
        if h not in headers:
            severity = "high" if h in ["Content-Security-Policy", "Strict-Transport-Security"] else "medium"
            security_issues.append({"title": f"Missing header: {h}", "severity": severity, "desc": tip})

    # Known libraries
    libs = [t.get("src") or t.get("href") for t in soup.find_all(["script", "link"]) if t.get("src") or t.get("href")]
    for lib in libs:
        if not lib:
            continue
        if re.search(r"jquery[-.]?1\\.", lib, re.I):
            security_issues.append({"title": "Outdated jQuery 1.x detected", "severity": "medium", "desc": "Upgrade to jQuery 3.x"})
        if re.search(r"bootstrap(.|%2E)*3\\.3\\.7", lib, re.I):
            security_issues.append({"title": "Outdated Bootstrap 3.3.7 detected", "severity": "low", "desc": "Upgrade to Bootstrap 5.x"})

    # Performance checks (simple heuristics)
    perf_issues = []
    scripts = soup.find_all("script")
    images = soup.find_all("img")
    links = soup.find_all("link")
    if load_time > 3.0:
        perf_issues.append({"title": "Slow initial response", "severity": "medium", "desc": f"TTFB ~{load_time:.1f}s"})
    if len(scripts) > 20:
        perf_issues.append({"title": "Too many JS files", "severity": "medium", "desc": f"{len(scripts)} scripts"})
    large_imgs = []
    if not fast:
        # Only probe a few images in normal mode
        for img in images[:3]:  # limit requests
            src = (img.get("src") or "").strip()
            if not src or src.startswith("data:"):
                continue
            try:
                img_url = src if src.startswith("http") else f"{parsed.scheme}://{parsed.netloc}/{src.lstrip('/')}"
                head = requests.head(img_url, timeout=min(5, api_timeout))
                size = int(head.headers.get('Content-Length', '0'))
                if size > 500_000:
                    large_imgs.append({"src": src, "size_kb": round(size/1024)})
            except Exception:
                pass
    if large_imgs:
        perf_issues.append({"title": "Large images detected", "severity": "medium", "desc": f"{len(large_imgs)} images >500KB"})

    # SEO checks
    seo_issues = []
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    if not title:
        seo_issues.append({"title": "Missing <title>", "impact": "high", "desc": "Add a descriptive title"})
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if not meta_desc or not meta_desc.get("content", "").strip():
        seo_issues.append({"title": "Missing meta description", "impact": "high", "desc": "Add a concise summary"})
    viewport = soup.find("meta", attrs={"name": "viewport"})
    if not viewport:
        seo_issues.append({"title": "Missing viewport", "impact": "high", "desc": "Add responsive viewport"})
    # canonical URL
    canonical = soup.find("link", rel=lambda v: v and "canonical" in v)
    if not canonical or not (canonical.get("href") or "").strip():
        seo_issues.append({"title": "Missing rel=canonical", "impact": "medium", "desc": "Add canonical to avoid duplicate content"})
    # hreflang for multilingual sites
    hreflangs = soup.find_all("link", attrs={"rel": "alternate", "hreflang": True})
    # Not strictly required, but if multiple languages are detected by heuristic tags
    if len(hreflangs) == 0 and soup.find(attrs={"lang": True}):
        seo_issues.append({"title": "No hreflang annotations", "impact": "low", "desc": "Add hreflang for multilingual pages"})
    # OpenGraph / Twitter cards for rich sharing
    if not soup.find("meta", property="og:title"):
        seo_issues.append({"title": "Missing OpenGraph tags", "impact": "low", "desc": "Add og:title/description/image for social previews"})
    if not soup.find("meta", attrs={"name": "twitter:card"}):
        seo_issues.append({"title": "Missing Twitter Card", "impact": "low", "desc": "Add twitter:card and related tags"})
    # H1 usage
    h1s = soup.find_all("h1")
    if len(h1s) == 0:
        seo_issues.append({"title": "Missing <h1>", "impact": "medium", "desc": "Add a single descriptive H1"})
    elif len(h1s) > 1:
        seo_issues.append({"title": "Multiple <h1> tags", "impact": "low", "desc": "Prefer a single H1 for clarity"})
    # robots.txt and sitemap.xml (skip in fast mode)
    if not fast:
        try:
            with ThreadPoolExecutor(max_workers=2) as ex:
                fut_robots = ex.submit(requests.get, f"{parsed.scheme}://{parsed.netloc}/robots.txt", timeout=min(5, api_timeout))
                fut_sitemap = ex.submit(requests.get, f"{parsed.scheme}://{parsed.netloc}/sitemap.xml", timeout=min(5, api_timeout))
                try:
                    robots = fut_robots.result()
                    if robots.status_code >= 400:
                        seo_issues.append({"title": "robots.txt not accessible", "impact": "medium", "desc": "Add robots.txt"})
                except Exception:
                    seo_issues.append({"title": "robots.txt not accessible", "impact": "medium", "desc": "Add robots.txt"})
                try:
                    sitemap = fut_sitemap.result()
                    if sitemap.status_code >= 400:
                        seo_issues.append({"title": "sitemap.xml not accessible", "impact": "medium", "desc": "Add sitemap.xml"})
                except Exception:
                    seo_issues.append({"title": "sitemap.xml not accessible", "impact": "medium", "desc": "Add sitemap.xml"})
        except Exception:
            # if executor fails, skip silently
            pass

    # Accessibility checks
    acc_issues = []
    missing_alts = sum(1 for img in images if not (img.get("alt") or "").strip())
    if missing_alts:
        acc_issues.append({"title": "Images missing alt text", "wcag": "A", "desc": f"{missing_alts} images lack alt"})
    for tag_name in ["header", "main", "footer", "nav"]:
        el = soup.find(tag_name)
        if el and not el.get("role"):
            acc_issues.append({"title": f"<{tag_name}> missing ARIA role", "wcag": "AA", "desc": f"Add role to {tag_name}"})
    # Form controls with no labels
    form_controls = soup.find_all(["input", "select", "textarea"])
    unlabeled = 0
    for fc in form_controls:
        if fc.get("type") in ("hidden",):
            continue
        id_attr = fc.get("id")
        has_label = False
        if id_attr and soup.find("label", attrs={"for": id_attr}):
            has_label = True
        if fc.find_parent("label"):
            has_label = True
        if not has_label:
            unlabeled += 1
    if unlabeled:
        acc_issues.append({"title": "Form controls missing labels", "wcag": "A", "desc": f"{unlabeled} inputs without accessible label"})

    # External API integrations
    psi = obs = sech = ssll = None
    if fast:
        # Fast: only a lightweight PSI call (desktop, fewer categories)
        psi = call_pagespeed(url, categories=("performance", "seo"), strategy="desktop", timeout=api_timeout)
    else:
        # Normal: run providers in parallel
        try:
            with ThreadPoolExecutor(max_workers=4) as ex:
                futs = {
                    "psi": ex.submit(call_pagespeed, url, ("performance", "seo", "accessibility"), "mobile", api_timeout),
                    "obs": ex.submit(call_observatory, parsed.netloc, api_timeout),
                    "sech": ex.submit(call_securityheaders, url, api_timeout),
                    "ssll": ex.submit(call_ssllabs, parsed.netloc, api_timeout),
                }
                for k, f in futs.items():
                    try:
                        res = f.result(timeout=api_timeout)
                    except Exception:
                        res = None
                    if k == "psi":
                        psi = res
                    elif k == "obs":
                        obs = res
                    elif k == "sech":
                        sech = res
                    elif k == "ssll":
                        ssll = res
        except Exception:
            pass

    # Build API-derived issues and scores
    api_perf_score = None
    api_seo_score = None
    api_acc_score = None
    if psi:
        api_perf_score = psi.get("perf_score")
        api_seo_score = psi.get("seo_score")
        api_acc_score = psi.get("acc_score")
        audits = psi.get("audits", {})
        # Enrich perf issues with key audits
        if audits.get("lcp") and audits["lcp"].get("displayValue"):
            perf_issues.append({"title": "Largest Contentful Paint", "severity": "medium", "desc": audits["lcp"]["displayValue"]})
        if audits.get("tbt") and audits["tbt"].get("displayValue"):
            perf_issues.append({"title": "Total Blocking Time", "severity": "medium", "desc": audits["tbt"]["displayValue"]})
        if audits.get("cls") and audits["cls"].get("displayValue"):
            perf_issues.append({"title": "Cumulative Layout Shift", "severity": "medium", "desc": audits["cls"]["displayValue"]})
        if audits.get("color-contrast") and audits["color-contrast"].get("score") == 0:
            acc_issues.append({"title": "Insufficient color contrast", "wcag": "AA", "desc": "Improve text/background contrast"})
        if audits.get("image-alt") and audits["image-alt"].get("score") == 0:
            acc_issues.append({"title": "Images missing alt (from PSI)", "wcag": "A", "desc": "Provide descriptive alt text"})

    if obs:
        grade = obs.get("grade")
        score = obs.get("score")
        if grade:
            security_issues.append({"title": f"Mozilla Observatory grade: {grade}", "severity": "low", "desc": f"Observatory score {score if score is not None else 'N/A'}"})
    if sech:
        sh_grade = sech.get("grade")
        sh_missing = sech.get("missing") or []
        if sh_grade:
            security_issues.append({"title": f"SecurityHeaders grade: {sh_grade}", "severity": "low", "desc": f"Missing {len(sh_missing)} headers"})
        # add missing headers as individual actionable items
        for h in sh_missing:
            security_issues.append({"title": f"Missing header from SecurityHeaders: {h}", "severity": "medium", "desc": "Implement this header as recommended."})
    if ssll:
        if ssll.get("grade"):
            security_issues.append({"title": f"SSL Labs grade: {ssll['grade']}", "severity": "low", "desc": "TLS configuration and certificate evaluation"})

    # Scores (blend API scores with heuristics when available)
    def score_from(num_issues, base=100, penalty=7):
        return max(40, base - num_issues * penalty)

    security_score = score_from(len(security_issues))
    performance_score = score_from(len(perf_issues))
    seo_score = score_from(len(seo_issues))
    # If API scores exist, blend 60% API, 40% heuristic
    if isinstance(api_perf_score, int) and api_perf_score > 0:
        performance_score = int(round(0.6 * api_perf_score + 0.4 * performance_score))
    if isinstance(api_seo_score, int) and api_seo_score > 0:
        seo_score = int(round(0.6 * api_seo_score + 0.4 * seo_score))
    accessibility_score = score_from(len(acc_issues))
    if isinstance(api_acc_score, int) and api_acc_score > 0:
        accessibility_score = int(round(0.6 * api_acc_score + 0.4 * accessibility_score))
    overall_score = round((security_score + performance_score + seo_score + accessibility_score) / 4)

    # Save scan to DB (soft-fail)
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (username, url, overall_score, security_score, performance_score, seo_score, accessibility_score) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (session.get("user"), url, overall_score, security_score, performance_score, seo_score, accessibility_score),
            )
        conn.commit(); conn.close()
    except Exception:
        pass

    # Build issues/remedies content for PDF (both HTML and plain text)
    severity_rank = {"high": 3, "medium": 2, "low": 1}

    def _sort_issues(items):
        return sorted(items, key=lambda i: (-severity_rank.get(str(i.get("severity") or i.get("impact") or "low").lower(), 1), i.get("title") or ""))

    def _exec_summary_text():
        return (
            f"Executive Summary for {url}\n"
            f"Overall Score: {overall_score}\n"
            f"Security: {security_score}  Performance: {performance_score}  SEO: {seo_score}  Accessibility: {accessibility_score}\n"
            "\nTop Priorities:\n"
            "  - Address missing critical security headers (CSP, HSTS) if flagged.\n"
            "  - Improve Core Web Vitals (LCP/TBT/CLS) where indicated.\n"
            "  - Provide essential SEO metas (title, description, canonical).\n"
            "  - Fix accessibility basics (alt text, ARIA roles, color contrast).\n"
        )

    def issues_text():
        lines = [ _exec_summary_text(), "\nDetailed Issues:\n" ]
        sections = [
            ("Security", _sort_issues(security_issues)),
            ("Performance", _sort_issues(perf_issues)),
            ("SEO", _sort_issues(seo_issues)),
            ("Accessibility", _sort_issues(acc_issues)),
        ]
        for name, items in sections:
            lines.append(f"\n{name} Issues:")
            if not items:
                lines.append("  - None detected")
            else:
                for i in items:
                    sev = i.get("severity") or i.get("impact") or "low"
                    title = i.get("title") or "Issue"
                    desc = i.get("desc") or i.get("description") or ""
                    lines.append(f"  - [{sev.upper()}] {title}: {desc}")
        return "\n".join(lines)

    def remedies_text():
        # Simple rule-based remediation suggestion
        tips = []
        def add(t):
            if t not in tips:
                tips.append(t)
        for i in security_issues:
            t = (i.get("title") or "").lower()
            if "content-security-policy" in t or "csp" in t:
                add("Define a strict Content-Security-Policy; disallow inline scripts; use nonces/hashes.")
            if "strict-transport-security" in t or "hsts" in t or "https" in t:
                add("Enforce HTTPS and add HSTS header with an appropriate max-age and preload if eligible.")
            if "x-content-type-options" in t:
                add("Set X-Content-Type-Options: nosniff to prevent MIME sniffing.")
            if "x-frame-options" in t:
                add("Set X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors).")
            if "referrer-policy" in t:
                add("Set Referrer-Policy to 'strict-origin-when-cross-origin' or stricter.")
            if "permissions-policy" in t:
                add("Use Permissions-Policy to restrict powerful APIs (camera, geolocation, etc.).")
        for i in perf_issues:
            ti = (i.get("title") or "").lower()
            if "large images" in ti:
                add("Compress/resize images, serve WebP/AVIF, and use responsive srcset sizes.")
            if "too many js" in ti or "blocking" in ti:
                add("Bundle/minify JS, defer non-critical scripts, enable HTTP/2 multiplexing and caching.")
            if "lcp" in ti:
                add("Optimize above-the-fold content and hero image; preconnect/preload critical resources.")
            if "tbt" in ti:
                add("Reduce main-thread work, split long tasks, and code-split to lower TBT.")
            if "cls" in ti or "layout shift" in ti:
                add("Reserve space for images/ads with width/height; avoid inserting content above existing.")
        for i in seo_issues:
            ti = (i.get("title") or "").lower()
            if "title" in ti:
                add("Add a unique, descriptive <title> (50–60 chars).")
            if "meta description" in ti:
                add("Add a compelling meta description (120–160 chars).")
            if "viewport" in ti:
                add("Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.")
            if "canonical" in ti:
                add("Add a canonical link to the preferred URL to avoid duplicates.")
            if "robots.txt" in ti:
                add("Provide robots.txt and ensure it permits important pages.")
            if "sitemap.xml" in ti:
                add("Provide sitemap.xml and submit in Search Console.")
        for i in acc_issues:
            ti = (i.get("title") or "").lower()
            if "alt" in ti:
                add("Provide descriptive alt text for informative images; use empty alt for decorative ones.")
            if "aria" in ti or "role" in ti:
                add("Add appropriate ARIA roles/landmarks to structure the page for assistive tech.")
            if "contrast" in ti:
                add("Ensure text/background contrast meets WCAG AA ratios (4.5:1 normal, 3:1 large).")
        # Always include general governance items once
        add("Set up performance budgets and monitor Core Web Vitals in production.")
        add("Automate security headers and TLS checks in CI/CD.")
        add("Run accessibility audits (e.g., axe, Lighthouse) on key templates.")
        header = f"Remedies for {url}\n"
        body = "\n".join([f"  - {t}" for t in tips]) if tips else "  - No remedial actions required."
        return header + body

    def issues_html():
        # Minimal HTML version (used only if PDF_ENGINE=weasyprint)
        def ul(items):
            return "".join([f"<li><b>[{(i.get('severity') or i.get('impact') or 'low').upper()}]</b> {i.get('title')}: {i.get('desc') or ''}</li>" for i in _sort_issues(items)])
        return f"""
        <h2>Executive Summary</h2>
        <p>Overall: {overall_score} | Security: {security_score} | Performance: {performance_score} | SEO: {seo_score} | Accessibility: {accessibility_score}</p>
        <h2>Issues for {url}</h2>
        <h3>Security</h3><ul>{ul(security_issues)}</ul>
        <h3>Performance</h3><ul>{ul(perf_issues)}</ul>
        <h3>SEO</h3><ul>{ul(seo_issues)}</ul>
        <h3>Accessibility</h3><ul>{ul(acc_issues)}</ul>
        """

    def remedies_html():
        # Convert text bullets to simple HTML list
        items = remedies_text().splitlines()[1:]  # skip header line
        lis = "".join([f"<li>{x.strip('- ').strip()}</li>" for x in items if x.strip()])
        return f"""
        <h2>Recommended Remedies for {url}</h2>
        <ul>{lis}</ul>
        """

    # Generate PDFs (soft-fail)
    issues_pdf_path = os.path.join(os.getcwd(), f"issues_{int(time.time())}.pdf")
    remedies_pdf_path = os.path.join(os.getcwd(), f"remedies_{int(time.time())}.pdf")
    try:
        pdf_engine = (os.getenv("PDF_ENGINE", "reportlab") or "").lower()
        use_weasy = (pdf_engine == "weasyprint")

        if use_weasy:
            try:
                from weasyprint import HTML
                HTML(string=issues_html()).write_pdf(issues_pdf_path)
                HTML(string=remedies_html()).write_pdf(remedies_pdf_path)
            except Exception:
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas
                from reportlab.lib.utils import simpleSplit

                def write_pdf(path, title, body):
                    c = canvas.Canvas(path, pagesize=letter)
                    width, height = letter
                    y = height - 72
                    c.setFont("Helvetica-Bold", 14)
                    c.drawString(72, y, title)
                    y -= 24
                    c.setFont("Helvetica", 10)
                    lines = simpleSplit(body, "Helvetica", 10, width - 144)
                    for line in lines:
                        if y < 72:
                            c.showPage()
                            y = height - 72
                            c.setFont("Helvetica", 10)
                        c.drawString(72, y, line)
                        y -= 14
                    c.showPage()
                    c.save()

                write_pdf(issues_pdf_path, f"Issues for {url}", issues_text())
                write_pdf(remedies_pdf_path, f"Remedies for {url}", remedies_text())
        else:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.utils import simpleSplit

            def write_pdf(path, title, body):
                c = canvas.Canvas(path, pagesize=letter)
                width, height = letter
                y = height - 72
                c.setFont("Helvetica-Bold", 14)
                c.drawString(72, y, title)
                y -= 24
                c.setFont("Helvetica", 10)
                lines = simpleSplit(body, "Helvetica", 10, width - 144)
                for line in lines:
                    if y < 72:
                        c.showPage()
                        y = height - 72
                        c.setFont("Helvetica", 10)
                    c.drawString(72, y, line)
                    y -= 14
                c.showPage()
                c.save()

            write_pdf(issues_pdf_path, f"Issues for {url}", issues_text())
            write_pdf(remedies_pdf_path, f"Remedies for {url}", remedies_text())
    except Exception:
        issues_pdf_path = remedies_pdf_path = None

    results = {
        "overall_score": overall_score,
        "categories": {
            "security": {
                "score": security_score,
                "issues": len(security_issues),
                "issues_list": security_issues,
                "description": "Vulnerability assessment and security headers analysis",
                "observatory": obs or {},
                "securityheaders": sech or {},
                "ssllabs": ssll or {}
            },
            "performance": {
                "score": performance_score,
                "issues": len(perf_issues),
                "issues_list": perf_issues,
                "description": "Core Web Vitals and speed optimization",
                "load_time": f"{load_time:.1f}s",
                "pagespeed": {"score": api_perf_score} if api_perf_score is not None else {}
            },
            "seo": {
                "score": seo_score,
                "issues": len(seo_issues),
                "issues_list": seo_issues,
                "description": "Search engine optimization and meta data analysis",
                "pagespeed": {"score": api_seo_score} if api_seo_score is not None else {}
            },
            "accessibility": {
                "score": accessibility_score,
                "issues": len(acc_issues),
                "issues_list": acc_issues,
                "description": "Accessibility best practices",
                "pagespeed": {"score": api_acc_score} if api_acc_score is not None else {}
            }
        }
    }
    return jsonify(results)

@app.route('/generate_report_pdf', methods=['POST'])
def generate_report_pdf():
    data = request.get_json()
    url = data.get('url')
    # Retrieve scan data from DB or session to regenerate report
    # For simplicity, we'll assume the client sends necessary data to regenerate
    # In a real app, you might fetch from DB using a scan_id

    # Placeholder for report data. This would ideally come from the /scan endpoint's results
    # or be re-generated with the necessary inputs.
    overall_score = data.get('overall_score', 0)
    security_score = data.get('security_score', 0)
    performance_score = data.get('performance_score', 0)
    seo_score = data.get('seo_score', 0)
    accessibility_score = data.get('accessibility_score', 0)

    security_issues = data.get('security_issues_list', [])
    perf_issues = data.get('performance_issues_list', [])
    seo_issues = data.get('seo_issues_list', [])
    acc_issues = data.get('accessibility_issues_list', [])

    severity_rank = {"high": 3, "medium": 2, "low": 1}

    def _sort_issues(items):
        return sorted(items, key=lambda i: (-severity_rank.get(str(i.get("severity") or i.get("impact") or "low").lower(), 1), i.get("title") or ""))

    def _exec_summary_text():
        return (
            f"Executive Summary for {url}\n"
            f"Overall Score: {overall_score}\n"
            f"Security: {security_score}  Performance: {performance_score}  SEO: {seo_score}  Accessibility: {accessibility_score}\n"
            "\nTop Priorities:\n"
            "  - Address missing critical security headers (CSP, HSTS) if flagged.\n"
            "  - Improve Core Web Vitals (LCP/TBT/CLS) where indicated.\n"
            "  - Provide essential SEO metas (title, description, canonical).\n"
            "  - Fix accessibility basics (alt text, ARIA roles, color contrast).\n"
        )

    def issues_text():
        lines = [ _exec_summary_text(), "\nDetailed Issues:\n" ]
        sections = [
            ("Security", _sort_issues(security_issues)),
            ("Performance", _sort_issues(perf_issues)),
            ("SEO", _sort_issues(seo_issues)),
            ("Accessibility", _sort_issues(acc_issues)),
        ]
        for name, items in sections:
            lines.append(f"\n{name} Issues:")
            if not items:
                lines.append("  - None detected")
            else:
                for i in items:
                    sev = i.get("severity") or i.get("impact") or "low"
                    title = i.get("title") or "Issue"
                    desc = i.get("desc") or i.get("description") or ""
                    lines.append(f"  - [{sev.upper()}] {title}: {desc}")
        return "\n".join(lines)

    def remedies_text():
        tips = []
        def add(t):
            if t not in tips:
                tips.append(t)
        for i in security_issues:
            t = (i.get("title") or "").lower()
            if "content-security-policy" in t or "csp" in t:
                add("Define a strict Content-Security-Policy; disallow inline scripts; use nonces/hashes.")
            if "strict-transport-security" in t or "hsts" in t or "https" in t:
                add("Enforce HTTPS and add HSTS header with an appropriate max-age and preload if eligible.")
            if "x-content-type-options" in t:
                add("Set X-Content-Type-Options: nosniff to prevent MIME sniffing.")
            if "x-frame-options" in t:
                add("Set X-Frame-Options: SAMEORIGIN (or use CSP frame-ancestors).")
            if "referrer-policy" in t:
                add("Set Referrer-Policy to 'strict-origin-when-cross-origin' or stricter.")
            if "permissions-policy" in t:
                add("Use Permissions-Policy to restrict powerful APIs (camera, geolocation, etc.).")
        for i in perf_issues:
            ti = (i.get("title") or "").lower()
            if "large images" in ti:
                add("Compress/resize images, serve WebP/AVIF, and use responsive srcset sizes.")
            if "too many js" in ti or "blocking" in ti:
                add("Bundle/minify JS, defer non-critical scripts, enable HTTP/2 multiplexing and caching.")
            if "lcp" in ti:
                add("Optimize above-the-fold content and hero image; preconnect/preload critical resources.")
            if "tbt" in ti:
                add("Reduce main-thread work, split long tasks, and code-split to lower TBT.")
            if "cls" in ti or "layout shift" in ti:
                add("Reserve space for images/ads with width/height; avoid inserting content above existing.")
        for i in seo_issues:
            ti = (i.get("title") or "").lower()
            if "title" in ti:
                add("Add a unique, descriptive <title> (50–60 chars).")
            if "meta description" in ti:
                add("Add a compelling meta description (120–160 chars).")
            if "viewport" in ti:
                add("Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.")
            if "canonical" in ti:
                add("Add a canonical link to the preferred URL to avoid duplicates.")
            if "robots.txt" in ti:
                add("Provide robots.txt and ensure it permits important pages.")
            if "sitemap.xml" in ti:
                add("Provide sitemap.xml and submit in Search Console.")
        for i in acc_issues:
            ti = (i.get("title") or "").lower()
            if "alt" in ti:
                add("Provide descriptive alt text for informative images; use empty alt for decorative ones.")
            if "aria" in ti or "role" in ti:
                add("Add appropriate ARIA roles/landmarks to structure the page for assistive tech.")
            if "contrast" in ti:
                add("Ensure text/background contrast meets WCAG AA ratios (4.5:1 normal, 3:1 large).")
        # Always include general governance items once
        add("Set up performance budgets and monitor Core Web Vitals in production.")
        add("Automate security headers and TLS checks in CI/CD.")
        add("Run accessibility audits (e.g., axe, Lighthouse) on key templates.")
        header = f"Remedies for {url}\n"
        body = "\n".join([f"  - {t}" for t in tips]) if tips else "  - No remedial actions required."
        return header + body

    def issues_html():
        # Minimal HTML version (used only if PDF_ENGINE=weasyprint)
        def ul(items):
            return "".join([f"<li><b>[{(i.get('severity') or i.get('impact') or 'low').upper()}]</b> {i.get('title')}: {i.get('desc') or ''}</li>" for i in _sort_issues(items)])
        return f"""
        <h2>Executive Summary</h2>
        <p>Overall: {overall_score} | Security: {security_score} | Performance: {performance_score} | SEO: {seo_score} | Accessibility: {accessibility_score}</p>
        <h2>Issues for {url}</h2>
        <h3>Security</h3><ul>{ul(security_issues)}</ul>
        <h3>Performance</h3><ul>{ul(perf_issues)}</ul>
        <h3>SEO</h3><ul>{ul(seo_issues)}</ul>
        <h3>Accessibility</h3><ul>{ul(acc_issues)}</ul>
        """

    def remedies_html():
        # Convert text bullets to simple HTML list
        items = remedies_text().splitlines()[1:]  # skip header line
        lis = "".join([f"<li>{x.strip('- ').strip()}</li>" for x in items if x.strip()])
        return f"""
        <h2>Recommended Remedies for {url}</h2>
        <ul>{lis}</ul>
        """

    # Generate PDFs (soft-fail)
    issues_pdf_path = os.path.join(os.getcwd(), f"issues_{int(time.time())}.pdf")
    remedies_pdf_path = os.path.join(os.getcwd(), f"remedies_{int(time.time())}.pdf")
    try:
        pdf_engine = (os.getenv("PDF_ENGINE", "reportlab") or "").lower()
        use_weasy = (pdf_engine == "weasyprint")

        if use_weasy:
            try:
                from weasyprint import HTML
                HTML(string=issues_html()).write_pdf(issues_pdf_path)
                HTML(string=remedies_html()).write_pdf(remedies_pdf_path)
            except Exception as e:
                print(f"DEBUG: WeasyPrint failed: {e}")
                # Fallback to reportlab if WeasyPrint fails
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas
                from reportlab.lib.utils import simpleSplit

                def write_pdf(path, title, body):
                    c = canvas.Canvas(path, pagesize=letter)
                    width, height = letter
                    y = height - 72
                    c.setFont("Helvetica-Bold", 14)
                    c.drawString(72, y, title)
                    y -= 24
                    c.setFont("Helvetica", 10)
                    lines = simpleSplit(body, "Helvetica", 10, width - 144)
                    for line in lines:
                        if y < 72:
                            c.showPage()
                            y = height - 72
                            c.setFont("Helvetica", 10)
                        c.drawString(72, y, line)
                        y -= 14
                    c.showPage()
                    c.save()

                write_pdf(issues_pdf_path, f"Issues for {url}", issues_text())
                write_pdf(remedies_pdf_path, f"Remedies for {url}", remedies_text())
        else:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.utils import simpleSplit

            def write_pdf(path, title, body):
                c = canvas.Canvas(path, pagesize=letter)
                width, height = letter
                y = height - 72
                c.setFont("Helvetica-Bold", 14)
                c.drawString(72, y, title)
                y -= 24
                c.setFont("Helvetica", 10)
                lines = simpleSplit(body, "Helvetica", 10, width - 144)
                for line in lines:
                    if y < 72:
                        c.showPage()
                        y = height - 72
                        c.setFont("Helvetica", 10)
                    c.drawString(72, y, line)
                    y -= 14
                c.showPage()
                c.save()

            write_pdf(issues_pdf_path, f"Issues for {url}", issues_text())
            write_pdf(remedies_pdf_path, f"Remedies for {url}", remedies_text())
    except Exception as e:
        print(f"DEBUG: PDF generation failed: {e}")
        issues_pdf_path = remedies_pdf_path = None

    # Send the generated PDF as a response
    if issues_pdf_path and remedies_pdf_path:
        # For simplicity, we'll return the issues PDF. You can extend this to combine or choose.
        # Or, ideally, serve them as downloads.
        return send_file(issues_pdf_path, as_attachment=True, download_name=f"report_issues_{int(time.time())}.pdf", mimetype='application/pdf')
    else:
        return jsonify({"error": "Failed to generate PDF reports"}), 500


# ---------------- Test email endpoint ----------------
@app.route("/test_email", methods=["GET"])
def test_email():
    """Sends a simple test email with a tiny PDF attachment.
    Priority recipient: signed-in user's email. If absent or force requested, use SMTP_USER.
    Use query ?force_smtp_user=1 to force sending to SMTP_USER.
    """
    try:
        # Determine recipient
        force_smtp = request.args.get("force_smtp_user", "0").lower() in ("1", "true", "yes", "on")
        user_email = None
        if ("user" in session) and not force_smtp:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE username=%s", (session["user"],))
                row = cur.fetchone()
                user_email = row.get("email") if row else None
            conn.close()
        to_list = []
        if user_email and not force_smtp:
            to_list = [user_email]
        else:
            fallback = os.getenv("SMTP_USER") or os.getenv("REPORT_RECIPIENT")
            if fallback:
                to_list = [fallback]

        if not to_list:
            return jsonify({"ok": False, "error": "No recipient found. Sign in or set SMTP_USER/REPORT_RECIPIENT."}), 400

        # Create a tiny PDF in a temp file
        pdf_path = None
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf_path = tf.name
            tf.close()
            c = canvas.Canvas(pdf_path, pagesize=letter)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(72, 720, "Test PDF Attachment")
            c.setFont("Helvetica", 11)
            c.drawString(72, 700, f"Generated at {datetime.utcnow().isoformat()}Z")
            c.showPage(); c.save()
        except Exception as e:
            return jsonify({"ok": False, "error": f"Failed to generate test PDF: {e}"}), 500

        # Send email
        from_addr = os.getenv("FROM_EMAIL") or os.getenv("SMTP_USER") or "no-reply@example.com"
        subject = "Test email from Website Audit App"
        text = "Hello! This is a test email with a tiny PDF attachment."
        try:
            sent_via = send_email_any(from_addr, to_list, subject, text, [pdf_path])
            status = f"sent via {sent_via}"
            print("[test_email]", status)
            return jsonify({"ok": True, "status": status, "to": to_list})
        except Exception as e:
            err = f"failed: {e}"
            print("[test_email]", err)
            return jsonify({"ok": False, "status": err, "to": to_list}), 500
        finally:
            try:
                if pdf_path and os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route('/ai_fix', methods=['POST'])
def ai_fix():
    """Generate corrected HTML code using two modes:
    - Option 1 (URL): fetches HTML from the provided URL.
    - Option 2 (Snippet): uses provided HTML snippet directly.

    High-accuracy correction is attempted via OpenAI if OPENAI_API_KEY is set.
    Falls back to lightweight rule-based cleanup if the API is unavailable or fails.
    Accepts optional 'notes' to steer corrections.
    """
    data = request.get_json() or {}
    url = data.get('url')
    html = data.get('html')
    notes = (data.get('notes') or '').strip()

    if not url and not html:
        return jsonify({"error": "Provide 'url' or 'html'"}), 400

    # Option 1: fetch from URL when html not provided
    if url and not html:
        try:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "https://" + url
            sess = requests.Session()
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Upgrade-Insecure-Requests": "1",
            }
            resp = sess.get(url, timeout=20, headers=headers, allow_redirects=True)
            if resp.status_code == 403 and url.startswith("https://") and not url.split("//",1)[1].startswith("www."):
                # Retry with www-prefixed host (some sites block apex)
                parsed = urlparse(url)
                www_url = f"{parsed.scheme}://www.{parsed.netloc}{parsed.path or ''}"
                resp = sess.get(www_url, timeout=20, headers=headers, allow_redirects=True)
            if resp.status_code == 403:
                # Try headless browser fallback
                try:
                    html = _fetch_html_headless(url)
                except Exception as he:
                    return jsonify({"error": "Fetch blocked by remote site (403) and headless fallback failed. Switch to Snippet mode.", "status": 403, "detail": str(he)[:200]}), 502
            else:
                resp.raise_for_status()
                html = resp.text
        except Exception as e:
            # Network/other error: try headless once before failing
            try:
                html = _fetch_html_headless(url)
            except Exception as he:
                return jsonify({"error": f"Failed to fetch URL: {e}", "fallback_error": str(he)[:200]}), 502

    html = html or ""

    # Try OpenAI for high-accuracy correction
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and html.strip():
        try:
            # Use Chat Completions API for broad compatibility
            payload = {
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "temperature": 0.2,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are an expert web auditor and refactoring assistant. "
                            "Given raw HTML, produce a corrected, secure, SEO- and accessibility-friendly HTML document. "
                            "Follow best practices: enforce HTTPS links, add/keep a single <title>, meta description, viewport, canonical when appropriate, "
                            "avoid inline events where possible, add alt text for images, preserve original content and functionality, fix obvious structural issues, "
                            "and do not include explanations—respond with ONLY the corrected HTML."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            (f"Notes: {notes}\n" if notes else "") +
                            "Input HTML begins below. Return ONLY corrected HTML.\n\n" + html
                        ),
                    },
                ],
            }
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=60,
            )
            if r.status_code < 300:
                out = (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "")
                if out.strip():
                    return jsonify({"corrected_html": out})
                # fall through to rule-based if empty
            else:
                # Soft-fail to rule-based
                pass
        except Exception:
            # Soft-fail to rule-based
            pass

    # Fallback: simple rule-based cleanup
    soup = BeautifulSoup(html or "", "lxml")
    # Force https in src/href
    for tag in soup.find_all(["script", "link", "img", "a"]):
        for attr in ["src", "href"]:
            if tag.has_attr(attr):
                v = (tag.get(attr) or "").strip()
                if v.startswith("http://"):
                    tag[attr] = v.replace("http://", "https://", 1)
    # Ensure SEO basics
    if not soup.head:
        soup.html.insert(0, soup.new_tag("head")) if soup.html else soup.insert(0, soup.new_tag("head"))
    head = soup.head
    if not soup.title or not (soup.title.string and soup.title.string.strip()):
        t = soup.new_tag("title"); t.string = "Auto-generated Title"; head.append(t)
    if not head.find("meta", attrs={"name": "description"}):
        page_text = soup.get_text(" ", strip=True)
        desc = (page_text[:160] + ("..." if len(page_text) > 160 else "")) if page_text else "Auto-generated description"
        m = soup.new_tag("meta", attrs={"name": "description", "content": desc}); head.append(m)
    if not head.find("meta", attrs={"name": "viewport"}):
        head.append(soup.new_tag("meta", attrs={"name": "viewport", "content": "width=device-width, initial-scale=1.0"}))
    # Accessibility: lazy loading and alt text placeholders
    for img in soup.find_all("img"):
        if not img.get("alt"):
            img["alt"] = "Decorative image"
        if not img.get("loading"):
            img["loading"] = "lazy"

    corrected_html = str(soup)
    return jsonify({"corrected_html": corrected_html, "fallback": True})


@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    """Top 10 secured websites based on highest recorded security_score."""
    rows = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT url, MAX(security_score) AS security_score, MAX(overall_score) AS overall_score
                FROM scans
                GROUP BY url
                ORDER BY security_score DESC, overall_score DESC
                LIMIT 10
                """
            )
            rows = cur.fetchall()
        conn.close()
    except Exception:
        rows = []
    return jsonify({"top": rows})


if __name__ == '__main__':
    app.run(debug=True, port=8080)

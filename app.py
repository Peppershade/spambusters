"""
Spambuster - Email spam protection web application.
Scans incoming emails for suspicious content using PyTorch ML model.
"""
import hmac
import logging
import secrets
import shutil
import threading
import time
from functools import wraps
from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, session, send_file, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import pyotp
import qrcode
import io
import base64

from config import Config, OperationMode
from services.logging_config import setup_logging
setup_logging()
logger = logging.getLogger(__name__)

from database import (
    init_db, get_flagged_emails, get_recent_emails, label_email,
    get_stats, get_scan_history, add_training_data, get_training_data,
    get_sender_stats, get_all_sender_stats, cleanup_all,
    add_to_list, remove_from_list, get_all_listed_senders, get_spam_stats_by_day,
    get_deleted_emails_log, get_deleted_email_log_entry, mark_email_restored,
    get_deleted_stats, cleanup_expired_deleted_logs,
    get_spam_keywords, add_spam_keyword, remove_spam_keyword,
    has_users, create_user, get_user, get_user_by_id,
    get_user_setting, set_user_setting, run_saas_migrations,
    update_user_password, regenerate_totp_secret, update_last_login, run_migrations,
    get_all_users_with_stats, get_system_stats, create_user_full,
    update_user_role, update_user_active, delete_user, delete_user_data, count_admins,
    is_account_locked, record_failed_login, reset_failed_login_attempts,
    validate_discord_action_token, invalidate_discord_action_token,
    cleanup_expired_discord_tokens, log_deleted_email,
    create_user_session, get_user_sessions, validate_user_session,
    revoke_session, revoke_all_other_sessions, extend_session, cleanup_expired_sessions,
    get_system_setting, set_system_setting, log_audit_event, get_audit_log
)
from services.discord_bot import get_discord_notifier
from services.scanner import get_scanner
from models.classifier import get_classifier
from services.context import UserContext, set_current_user, get_current_user, clear_current_user


# --- Password validation ---
def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.

    Requirements:
    - At least 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    # Special characters
    special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"

    return True, ""


# --- SECRET_KEY enforcement ---
if not Config.SECRET_KEY:
    _generated = secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY is not set! A random key has been generated for this session. "
        "Sessions will NOT survive restarts. Set SECRET_KEY=\"%s\" permanently.",
        _generated
    )
    Config.SECRET_KEY = _generated


app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Session security configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SECURE=Config.USE_HTTPS,  # Only send over HTTPS (set USE_HTTPS=true in production)
    SESSION_COOKIE_SAMESITE='Lax',     # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800,   # 30 minutes session timeout
)

# Warn if running without HTTPS in production-like setup
if not Config.USE_HTTPS and Config.SECRET_KEY and len(Config.SECRET_KEY) == 64:
    logger.warning(
        "USE_HTTPS is disabled but SECRET_KEY is set. "
        "Set USE_HTTPS=true when running behind HTTPS reverse proxy. See SECURITY.md."
    )

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# CSRF protection
csrf = CSRFProtect(app)


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "Too many requests", "retry_after": e.description}), 429
    flash("Too many attempts. Please wait a moment and try again.", "error")
    return redirect(request.url)


@app.context_processor
def inject_config():
    """Make config available in all templates."""
    return {"config": Config}


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Unhandled server error", exc_info=True)
    return render_template("errors/500.html"), 500


@app.after_request
def set_security_headers(response):
    """Add security headers and request ID to all responses."""
    # Propagate request ID for tracing
    if hasattr(g, "request_id"):
        response.headers["X-Request-ID"] = g.request_id
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Content Security Policy
    # All <script> blocks extracted to external files in static/js/
    # 'unsafe-inline' still needed for inline event handlers (onclick, oninput, etc.)
    # Allow CDN resources: Font Awesome (cdnjs), Chart.js (jsdelivr)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    # Permissions Policy - disable unnecessary features
    response.headers['Permissions-Policy'] = (
        "geolocation=(), "
        "camera=(), "
        "microphone=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )

    return response


# --- Authentication ---

def login_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_current_user_id() -> int:
    """Get the current user ID from session. Must be called from within a request."""
    user_id = session.get("user_id")
    if not user_id:
        raise RuntimeError("No user_id in session")
    return user_id


def admin_required(f):
    """Decorator to require admin privileges for routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        user = get_current_user()
        if not user or not user.is_admin:
            flash("Admin access required", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


@app.before_request
def ensure_db():
    """Ensure database is initialized, run migrations, and set up user context."""
    global _db_initialized
    g.request_id = request.headers.get("X-Request-ID") or secrets.token_hex(8)

    # /health does its own DB probe — skip migrations so a DB unavailability
    # during startup (e.g. volume not yet mounted) returns a degraded status
    # rather than a 500 that masks the real problem.
    if request.endpoint == "health_check":
        return

    if not _db_initialized:
        init_db()
        run_migrations()
        run_saas_migrations()
        _db_initialized = True
        # Start the report scheduler here so it runs in Gunicorn worker
        # processes (post-fork). The is_alive() check prevents double-starting
        # when running via `python app.py` where start_app() already fired it.
        if not (_scheduler_thread and _scheduler_thread.is_alive()):
            _start_scheduler_thread()

    # Clear any existing user context
    clear_current_user()

    # Allow static files, login, setup, landing, service worker, health check without auth
    # api_discord_label uses its own token auth, not session auth
    allowed = {"login", "setup", "landing", "static", "service_worker", "health_check",
               "api_discord_label", "offline", "login_2fa_required"}
    if request.endpoint in allowed:
        return

    # If no users exist, redirect to setup
    if not has_users():
        if request.endpoint != "setup":
            return redirect(url_for("setup"))
        return

    # Check authentication for all other routes
    if not session.get("authenticated") and request.endpoint not in allowed:
        return redirect(url_for("login"))

    # Validate session token against database
    if session.get("authenticated") and session.get("session_token"):
        db_session_row = validate_user_session(session["session_token"])
        if db_session_row is None:
            # Session was revoked or expired
            session.clear()
            return redirect(url_for("login"))

        # Sliding window: extend session if less than 50% TTL remaining
        from datetime import datetime, timedelta
        expires_at = db_session_row["expires_at"]
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                expires_at = datetime.now() + timedelta(minutes=30)
        remaining = (expires_at - datetime.now()).total_seconds()
        if remaining < 900:  # Less than 15 min (50% of 30 min TTL)
            extend_session(session["session_token"])

    # Set up user context for authenticated users
    if session.get("authenticated") and session.get("user_id"):
        user = get_user_by_id(session["user_id"])
        if user:
            set_current_user(UserContext(
                user_id=user["id"],
                username=user["username"],
                is_admin=bool(user.get("is_admin", False)),
                session_id=session.get("session_id")
            ))

    # Periodic cleanup (roughly every 100 requests, non-blocking)
    import random
    if random.randint(1, 100) == 1:
        try:
            cleanup_expired_sessions()
            cleanup_expired_discord_tokens()
            cleanup_expired_deleted_logs()
        except Exception:
            pass


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Login page with two-step authentication."""
    if not has_users():
        return redirect(url_for("setup"))

    if session.get("authenticated"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        step = request.form.get("step", "1")

        if step == "1":
            # Step 1: Verify username and password
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            # Check if account is locked
            is_locked, seconds_remaining = is_account_locked(username)
            if is_locked:
                minutes = (seconds_remaining + 59) // 60  # Round up
                flash(f"Account locked due to multiple failed login attempts. Try again in {minutes} minute(s).", "error")
                return render_template("login.html", step="1")

            user = get_user(username)
            if not user or not check_password_hash(user["password_hash"], password):
                # Record failed login attempt
                if username:  # Only record if username was provided
                    record_failed_login(username)
                    log_audit_event(None, "login_failed", details=username, ip=request.remote_addr)
                    # Log account lockout if threshold just reached
                    locked, _ = is_account_locked(username)
                    if locked:
                        log_audit_event(None, "account_locked", details=username, ip=request.remote_addr)
                flash("Invalid username or password", "error")
                return render_template("login.html", step="1")

            # Check if user has 2FA enabled
            if user.get("totp_enabled", 0) == 1:
                # Go to step 2 for 2FA verification
                session["temp_username"] = username
                return render_template("login.html", step="2", username=username)
            else:
                # No 2FA — check if global 2FA enforcement requires setup first
                if get_system_setting("require_2fa_all", "0") == "1":
                    session["pending_2fa_user_id"] = user["id"]
                    session["pending_2fa_username"] = username
                    return redirect(url_for("login_2fa_required"))

                # No 2FA, log in directly
                # Reset failed login attempts on successful login
                reset_failed_login_attempts(user["id"])
                # Clear session to prevent session fixation
                session.clear()
                session["authenticated"] = True
                session["username"] = username
                session["user_id"] = user["id"]
                session["is_admin"] = bool(user.get("is_admin", False))
                session.permanent = True
                # Create tracked session
                session_token = secrets.token_urlsafe(32)
                create_user_session(user["id"], session_token,
                                    request.remote_addr, request.user_agent.string)
                session["session_token"] = session_token
                update_last_login(user["id"])
                return redirect(url_for("dashboard"))

        elif step == "2":
            # Step 2: Verify 2FA code
            username = session.get("temp_username")
            totp_code = request.form.get("totp_code", "").strip()

            if not username:
                flash("Session expired. Please login again.", "error")
                return redirect(url_for("login"))

            # Check if account is locked
            is_locked, seconds_remaining = is_account_locked(username)
            if is_locked:
                minutes = (seconds_remaining + 59) // 60  # Round up
                flash(f"Account locked due to multiple failed login attempts. Try again in {minutes} minute(s).", "error")
                return redirect(url_for("login"))

            user = get_user(username)
            if not user:
                flash("Invalid session. Please login again.", "error")
                return redirect(url_for("login"))

            # Verify TOTP
            totp = pyotp.TOTP(user["totp_secret"])
            if not totp.verify(totp_code, valid_window=1):
                # Record failed 2FA attempt
                record_failed_login(username)
                flash("Invalid 2FA code", "error")
                return render_template("login.html", step="2", username=username)

            # Reset failed login attempts on successful login
            reset_failed_login_attempts(user["id"])
            # Clear session to prevent session fixation
            session.clear()
            session["authenticated"] = True
            session["username"] = username
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user.get("is_admin", False))
            session.permanent = True
            # Create tracked session
            session_token = secrets.token_urlsafe(32)
            create_user_session(user["id"], session_token,
                                request.remote_addr, request.user_agent.string)
            session["session_token"] = session_token
            update_last_login(user["id"])
            return redirect(url_for("dashboard"))

    return render_template("login.html", step="1")


@app.route("/setup", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])
def setup():
    """First-time setup page."""
    if has_users():
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        enable_2fa = request.form.get("enable_2fa") == "on"
        totp_secret = request.form.get("totp_secret", "")
        totp_code = request.form.get("totp_code", "").strip()

        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
        elif password != password_confirm:
            flash("Passwords do not match", "error")
        else:
            # Validate password strength
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, "error")
                qr_data = _generate_qr_data(totp_secret, username)
                return render_template("setup.html", totp_secret=totp_secret, qr_data=qr_data)

            # Password is valid, proceed with account creation
            if enable_2fa:
                # Verify the TOTP code
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(totp_code, valid_window=1):
                    flash("Invalid 2FA code. Make sure your authenticator app is synced.", "error")
                    qr_data = _generate_qr_data(totp_secret, username)
                    return render_template("setup.html", totp_secret=totp_secret, qr_data=qr_data)

                # First user is always an admin
                create_user_full(
                    username=username,
                    password_hash=generate_password_hash(password),
                    totp_secret=totp_secret,
                    totp_enabled=True,
                    is_admin=True
                )
            else:
                # Create user without 2FA
                create_user_full(
                    username=username,
                    password_hash=generate_password_hash(password),
                    totp_secret=None,
                    totp_enabled=False,
                    is_admin=True
                )

            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))

        # Re-render with same secret on error
        qr_data = _generate_qr_data(totp_secret, username)
        return render_template("setup.html", totp_secret=totp_secret, qr_data=qr_data)

    # Generate new TOTP secret
    totp_secret = pyotp.random_base32()
    qr_data = _generate_qr_data(totp_secret, "admin")
    return render_template("setup.html", totp_secret=totp_secret, qr_data=qr_data)


def _generate_qr_data(secret: str, username: str) -> str:
    """Generate base64-encoded QR code image for TOTP setup."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Spambusters")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.read()).decode()


@app.route("/logout")
def logout():
    """Log out the current user."""
    # Revoke session in database before clearing
    token = session.get("session_token")
    uid = session.get("user_id")
    if token and uid:
        # Find and revoke the session by token
        db_sess = validate_user_session(token)
        if db_sess:
            revoke_session(uid, db_sess["id"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/login/2fa-required", methods=["GET", "POST"])
def login_2fa_required():
    """2FA setup enforcement: redirect here when require_2fa_all is on and user has no 2FA."""
    user_id = session.get("pending_2fa_user_id")
    username = session.get("pending_2fa_username")
    if not user_id or not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        new_secret = request.form.get("totp_secret", "")
        totp_code = request.form.get("totp_code", "").strip()

        if not new_secret or not totp_code:
            flash("Please scan the QR code and enter the verification code.", "error")
            qr_data = _generate_qr_data(new_secret or pyotp.random_base32(), username)
            return render_template("login_2fa_required.html", totp_secret=new_secret, qr_data=qr_data)

        totp = pyotp.TOTP(new_secret)
        if not totp.verify(totp_code, valid_window=1):
            flash("Invalid verification code. Please try again.", "error")
            qr_data = _generate_qr_data(new_secret, username)
            return render_template("login_2fa_required.html", totp_secret=new_secret, qr_data=qr_data)

        # Save 2FA secret and complete login
        regenerate_totp_secret(user_id, new_secret)
        reset_failed_login_attempts(user_id)
        session.clear()
        session["authenticated"] = True
        session["username"] = username
        session["user_id"] = user_id
        user = get_user_by_id(user_id)
        session["is_admin"] = bool(user.get("is_admin", False)) if user else False
        session.permanent = True
        session_token = secrets.token_urlsafe(32)
        create_user_session(user_id, session_token, request.remote_addr, request.user_agent.string)
        session["session_token"] = session_token
        update_last_login(user_id)
        flash("2FA has been set up successfully. Welcome!", "success")
        return redirect(url_for("dashboard"))

    # GET: generate fresh secret and show QR
    totp_secret = pyotp.random_base32()
    qr_data = _generate_qr_data(totp_secret, username)
    return render_template("login_2fa_required.html", totp_secret=totp_secret, qr_data=qr_data)


# --- PWA Service Worker ---

@app.route("/service-worker.js")
def service_worker():
    """Serve service worker from root scope."""
    return send_file("static/service-worker.js", mimetype="application/javascript")


@app.route("/offline")
def offline():
    """Offline fallback page for PWA."""
    return render_template("offline.html")


@app.route("/health")
def health_check():
    """Health check endpoint (no auth required). Returns system status."""
    checks = {}

    # DB connectivity
    try:
        from database import get_db_connection
        get_db_connection().execute("SELECT 1")
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    # Encryption key
    checks["encryption_key"] = "ok" if Config.ENCRYPTION_MASTER_KEY else "missing"

    # Disk space (warn < 100 MB)
    try:
        disk_path = "data" if Path("data").exists() else "."
        free_mb = shutil.disk_usage(disk_path).free // (1024 * 1024)
    except Exception:
        free_mb = -1
    checks["disk_free_mb"] = free_mb

    # Model files
    try:
        checks["model_files"] = len(list(Path(Config.MODELS_DIR).rglob("*.pt")))
    except Exception:
        checks["model_files"] = 0

    # Scheduler thread
    checks["scheduler_alive"] = bool(_scheduler_thread and _scheduler_thread.is_alive())

    # Overall status
    degraded = (
        checks["database"] != "ok"
        or checks["encryption_key"] != "ok"
        or free_mb < 100
    )
    checks["status"] = "degraded" if degraded else "ok"

    return jsonify(checks), 503 if degraded else 200


# --- Main Routes ---

@app.route("/")
def landing():
    """Public landing page."""
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard showing overview and recent activity."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)
    stats = get_stats(user_id)
    recent_scans = get_scan_history(user_id, limit=5)
    flagged = get_flagged_emails(user_id, limit=10)

    return render_template(
        "index.html",
        stats=stats,
        recent_scans=recent_scans,
        flagged_emails=flagged,
        mode=scanner.mode,
        is_scanning=scanner.is_scanning,
        classifier_trained=get_classifier(user_id).is_trained
    )


@app.route("/emails")
@login_required
def emails():
    """View all scanned emails."""
    user_id = get_current_user_id()
    page = request.args.get("page", 1, type=int)
    filter_type = request.args.get("filter", "all")

    if filter_type == "flagged":
        all_emails = get_flagged_emails(user_id, limit=200)
    else:
        all_emails = get_recent_emails(user_id, limit=200)

        if filter_type == "spam":
            all_emails = [e for e in all_emails if e["is_spam"] == 1]
        elif filter_type == "safe":
            all_emails = [e for e in all_emails if e["is_spam"] == 0]

    return render_template(
        "emails.html",
        emails=all_emails,
        filter_type=filter_type
    )


@app.route("/email/<int:email_id>/label", methods=["POST"])
@login_required
def label_email_view(email_id):
    """Label an email as spam or not spam (AJAX or regular POST)."""
    user_id = get_current_user_id()
    if request.is_json:
        data = request.get_json()
        is_spam = data.get("is_spam", False)
        label_email(user_id, email_id, is_spam)
        return jsonify({"success": True, "is_spam": is_spam})

    is_spam = request.form.get("is_spam") == "1"
    label_email(user_id, email_id, is_spam)
    flash(f"Email labeled as {'spam' if is_spam else 'not spam'}", "success")
    return redirect(request.referrer or url_for("emails"))


@app.route("/training")
@login_required
def training():
    """Training data management page."""
    user_id = get_current_user_id()
    training_data = get_training_data(user_id)
    stats = get_stats(user_id)

    spam_count = sum(1 for d in training_data if d["label"] == 1)
    ham_count = len(training_data) - spam_count

    return render_template(
        "training.html",
        training_count=len(training_data),
        spam_count=spam_count,
        ham_count=ham_count,
        classifier_trained=get_classifier(user_id).is_trained
    )


@app.route("/training/add", methods=["POST"])
@login_required
def add_training():
    """Add manual training data."""
    user_id = get_current_user_id()
    content = request.form.get("content", "").strip()
    label = int(request.form.get("label", 0))
    language = request.form.get("language", "unknown")

    if not content:
        flash("Content is required", "error")
        return redirect(url_for("training"))

    add_training_data(user_id, content, label, language)
    flash("Training sample added", "success")
    return redirect(url_for("training"))


@app.route("/training/train", methods=["POST"])
@login_required
@limiter.limit("3 per minute")
def train_model():
    """Train the classifier model."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)
    result = scanner.train_classifier()

    if result.get("success"):
        flash(f"Model trained successfully! Accuracy: {result['final_accuracy']:.2%}", "success")
    else:
        flash(f"Training failed: {result.get('error', 'Unknown error')}", "error")

    return redirect(url_for("training"))


@app.route("/training/recalculate", methods=["POST"])
@login_required
def recalculate_scores():
    """Recalculate spam scores for all existing emails."""
    from database import get_db_connection

    user_id = get_current_user_id()
    classifier = get_classifier(user_id)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, subject, sender, content, spam_score, is_spam FROM emails WHERE user_id = ?",
        (user_id,)
    )
    emails_list = cursor.fetchall()

    updated = 0
    changes = []

    for email in emails_list:
        full_content = f"{email['subject']}\n{email['sender']}\n{email['content']}"
        new_score, new_is_spam = classifier.predict(full_content)

        old_score = email['spam_score']
        score_diff = new_score - old_score

        if abs(score_diff) > 0.1:
            changes.append({
                'id': email['id'],
                'subject': email['subject'][:50],
                'old_score': old_score,
                'new_score': new_score,
                'diff': score_diff
            })

        cursor.execute("""
            UPDATE emails SET spam_score = ?, is_spam = ? WHERE id = ? AND user_id = ?
        """, (new_score, 1 if new_is_spam else 0, email['id'], user_id))
        updated += 1

    conn.commit()
    conn.close()

    session['recalc_changes'] = changes[:20]
    session['recalc_total'] = updated

    flash(f"Recalculated {updated} emails. {len(changes)} had significant score changes.", "success")
    return redirect(url_for("recalculate_results"))


@app.route("/training/recalculate-results")
@login_required
def recalculate_results():
    """Show results of recalculation."""
    changes = session.pop('recalc_changes', [])
    total = session.pop('recalc_total', 0)

    changes.sort(key=lambda x: abs(x['diff']), reverse=True)

    return render_template(
        "recalculate_results.html",
        changes=changes,
        total=total,
        threshold=Config.SPAM_THRESHOLD
    )


@app.route("/settings")
@login_required
def settings():
    """Redirect to general settings for backwards compatibility."""
    return redirect(url_for("settings_general"))


@app.route("/settings/general")
@login_required
def settings_general():
    """General settings page - Operation mode and email configuration."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    return render_template(
        "settings/general.html",
        mode=scanner.mode,
        modes=OperationMode,
        config=Config
    )


@app.route("/settings/scanning")
@login_required
def settings_scanning():
    """Scanning settings page - Weights, thresholds, keywords, background scanning."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)
    keywords = get_spam_keywords(user_id)

    # Scoring weights
    weight_urls = float(get_user_setting(user_id, "weight_urls", "0.3"))
    weight_model = float(get_user_setting(user_id, "weight_model", "0.7"))
    weight_keywords = float(get_user_setting(user_id, "weight_keywords", "0.3"))

    # Action thresholds
    threshold_delete = float(get_user_setting(user_id, "threshold_delete", "0.9"))
    threshold_move = float(get_user_setting(user_id, "threshold_move", "0.7"))
    threshold_warn = float(get_user_setting(user_id, "threshold_warn", "0.5"))

    return render_template(
        "settings/scanning.html",
        mode=scanner.mode,
        is_scanning=scanner.is_scanning,
        spam_keywords=keywords,
        weight_urls=weight_urls,
        weight_model=weight_model,
        weight_keywords=weight_keywords,
        threshold_delete=threshold_delete,
        threshold_move=threshold_move,
        threshold_warn=threshold_warn
    )


@app.route("/settings/notifications")
@login_required
def settings_notifications():
    """Notifications settings page - Discord and email warnings."""
    user_id = get_current_user_id()

    # Warning settings
    warning_prefix = get_user_setting(user_id, "warning_prefix", "[SPAM WARNING]")

    default_warning_html = (
        '<div style="background:#dc2626;color:white;padding:16px;margin:0 0 16px 0;'
        'border-radius:8px;font-family:Arial,sans-serif;font-size:14px;">'
        '<strong>Spambuster Warning:</strong> This email has been flagged as '
        'potentially dangerous (score: {score}%). Be careful with links and attachments.'
        '</div>'
    )
    default_warning_text = (
        "========================================\n"
        "SPAMBUSTER WARNING: This email has been flagged as potentially dangerous "
        "(score: {score}%).\n"
        "Be careful with links and attachments.\n"
        "========================================\n\n"
    )
    warning_html = get_user_setting(user_id, "warning_html", default_warning_html)
    warning_text = get_user_setting(user_id, "warning_text", default_warning_text)

    return render_template(
        "settings/notifications.html",
        config=Config,
        warning_prefix=warning_prefix,
        warning_html=warning_html,
        warning_text=warning_text
    )


@app.route("/settings/security")
@login_required
def settings_security():
    """Security settings page - Password change, 2FA regeneration."""
    user_id = session.get("user_id")
    user = get_user_by_id(user_id) if user_id else None

    return render_template(
        "settings/security.html",
        user=user
    )


@app.route("/settings/security/change-password", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def change_password():
    """Change the user's password."""
    user_id = session.get("user_id")
    if not user_id:
        flash("Session error. Please log in again.", "error")
        return redirect(url_for("logout"))

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("logout"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Verify current password
    if not check_password_hash(user["password_hash"], current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("settings_security"))

    # Validate new password
    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("settings_security"))

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for("settings_security"))

    # Update password
    new_hash = generate_password_hash(new_password)
    if update_user_password(user_id, new_hash):
        # Revoke all other sessions for security
        token = session.get("session_token")
        if token:
            revoke_all_other_sessions(user_id, token)
        flash("Password changed successfully. All other sessions have been revoked.", "success")
    else:
        flash("Failed to update password.", "error")

    return redirect(url_for("settings_security"))


@app.route("/settings/security/regenerate-2fa", methods=["POST"])
@login_required
@limiter.limit("3 per minute")
def regenerate_2fa():
    """Start the 2FA regeneration process."""
    user_id = session.get("user_id")
    if not user_id:
        flash("Session error. Please log in again.", "error")
        return redirect(url_for("logout"))

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("logout"))

    password = request.form.get("password", "")

    # Verify password
    if not check_password_hash(user["password_hash"], password):
        flash("Password is incorrect.", "error")
        return redirect(url_for("settings_security"))

    # Generate new TOTP secret
    new_secret = pyotp.random_base32()
    qr_data = _generate_qr_data(new_secret, session.get("username", "user"))

    return render_template(
        "settings/security.html",
        user=user,
        new_totp_secret=new_secret,
        qr_data=qr_data
    )


@app.route("/settings/security/confirm-2fa", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def confirm_2fa():
    """Confirm and save the new 2FA secret."""
    user_id = session.get("user_id")
    if not user_id:
        flash("Session error. Please log in again.", "error")
        return redirect(url_for("logout"))

    new_secret = request.form.get("totp_secret", "")
    totp_code = request.form.get("totp_code", "").strip()

    if not new_secret or not totp_code:
        flash("Missing required fields.", "error")
        return redirect(url_for("settings_security"))

    # Verify the TOTP code with the new secret
    totp = pyotp.TOTP(new_secret)
    if not totp.verify(totp_code, valid_window=1):
        flash("Invalid verification code. Please try again.", "error")
        # Re-show the QR code
        user = get_user_by_id(user_id)
        qr_data = _generate_qr_data(new_secret, session.get("username", "user"))
        return render_template(
            "settings/security.html",
            user=user,
            new_totp_secret=new_secret,
            qr_data=qr_data
        )

    # Save the new secret
    if regenerate_totp_secret(user_id, new_secret):
        # Revoke all other sessions for security
        token = session.get("session_token")
        if token:
            revoke_all_other_sessions(user_id, token)
        log_audit_event(user_id, "2fa_changed", target_user_id=user_id, ip=request.remote_addr)
        flash("2FA has been successfully updated. All other sessions have been revoked.", "success")
    else:
        flash("Failed to update 2FA secret.", "error")

    return redirect(url_for("settings_security"))


@app.route("/settings/advanced")
@login_required
def settings_advanced():
    """Advanced settings page - Data management, API documentation."""
    return render_template(
        "settings/advanced.html",
        config=Config
    )


@app.route("/settings/mode", methods=["POST"])
@login_required
def set_mode():
    """Change operation mode."""
    user_id = get_current_user_id()
    mode_value = request.form.get("mode")
    try:
        mode = OperationMode(mode_value)
        scanner = get_scanner(user_id)
        scanner.set_mode(mode)
        flash(f"Mode changed to {mode.value}", "success")
    except ValueError:
        flash("Invalid mode", "error")

    return redirect(url_for("settings_general"))


@app.route("/settings/keywords/add", methods=["POST"])
@login_required
def add_keyword():
    """Add a spam keyword."""
    user_id = get_current_user_id()
    keyword = request.form.get("keyword", "").strip()

    if not keyword:
        flash("Keyword is required", "error")
        return redirect(url_for("settings_scanning"))

    if add_spam_keyword(user_id, keyword):
        flash(f"Added keyword: {keyword}", "success")
    else:
        flash(f"Keyword already exists: {keyword}", "warning")

    return redirect(url_for("settings_scanning"))


@app.route("/settings/keywords/remove", methods=["POST"])
@login_required
def remove_keyword():
    """Remove a spam keyword."""
    user_id = get_current_user_id()
    keyword = request.form.get("keyword", "").strip()

    if keyword and remove_spam_keyword(user_id, keyword):
        flash(f"Removed keyword: {keyword}", "success")
    else:
        flash("Keyword not found", "error")

    return redirect(url_for("settings_scanning"))


@app.route("/settings/weights", methods=["POST"])
@login_required
def set_weights():
    """Save scoring weight settings."""
    user_id = get_current_user_id()
    weight_urls = request.form.get("weight_urls", "0.3")
    weight_model = request.form.get("weight_model", "0.7")
    weight_keywords = request.form.get("weight_keywords", "0.3")

    for key, val in [("weight_urls", weight_urls), ("weight_model", weight_model),
                     ("weight_keywords", weight_keywords)]:
        try:
            v = float(val)
            if 0.0 <= v <= 1.0:
                set_user_setting(user_id, key, str(v))
        except ValueError:
            pass

    flash("Scoring weights updated", "success")
    return redirect(url_for("settings_scanning"))


@app.route("/settings/thresholds", methods=["POST"])
@login_required
def set_thresholds():
    """Save action threshold settings."""
    user_id = get_current_user_id()
    threshold_delete = request.form.get("threshold_delete", "0.9")
    threshold_move = request.form.get("threshold_move", "0.7")
    threshold_warn = request.form.get("threshold_warn", "0.5")

    try:
        td = float(threshold_delete)
        tm = float(threshold_move)
        tw = float(threshold_warn)
        if 0.0 <= tw <= tm <= td <= 1.0:
            set_user_setting(user_id, "threshold_delete", str(td))
            set_user_setting(user_id, "threshold_move", str(tm))
            set_user_setting(user_id, "threshold_warn", str(tw))
            flash("Action thresholds updated", "success")
        else:
            flash("Thresholds must be: warn <= move <= delete", "error")
    except ValueError:
        flash("Invalid threshold values", "error")

    return redirect(url_for("settings_scanning"))


@app.route("/settings/warnings", methods=["POST"])
@login_required
def set_warnings():
    """Save email warning settings."""
    user_id = get_current_user_id()
    warning_prefix = request.form.get("warning_prefix", "[SPAM WARNING]").strip()
    warning_html = request.form.get("warning_html", "").strip()
    warning_text = request.form.get("warning_text", "").strip()

    if not warning_prefix:
        warning_prefix = "[SPAM WARNING]"

    set_user_setting(user_id, "warning_prefix", warning_prefix)

    # Only save custom templates if non-empty; clearing them resets to defaults
    if warning_html:
        set_user_setting(user_id, "warning_html", warning_html)
    if warning_text:
        set_user_setting(user_id, "warning_text", warning_text)

    flash("Email warning settings updated", "success")
    return redirect(url_for("settings_notifications"))


@app.route("/scan", methods=["POST"])
@login_required
def manual_scan():
    """Trigger a manual email scan."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    # Check if credentials are configured (either from database or env)
    from services.credentials import get_credentials_manager
    creds = get_credentials_manager().get_imap_credentials(user_id)
    if not creds.is_configured():
        flash("Email settings not configured. Configure IMAP settings in Email Settings.", "error")
        return redirect(url_for("settings_general"))

    try:
        results = scanner.scan_emails()
        spam_count = sum(1 for r in results if r.is_spam)
        flash(f"Scanned {len(results)} emails, found {spam_count} suspicious", "success")
    except Exception as e:
        flash(f"Scan failed: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/scan/start", methods=["POST"])
@login_required
def start_scanning():
    """Start background scanning."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    # Check if credentials are configured
    from services.credentials import get_credentials_manager
    creds = get_credentials_manager().get_imap_credentials(user_id)
    if not creds.is_configured():
        flash("Email settings not configured", "error")
        return redirect(url_for("settings_general"))

    if scanner.start_background_scanning():
        flash("Background scanning started", "success")
    else:
        flash("Scanning already running", "warning")

    return redirect(url_for("dashboard"))


@app.route("/scan/stop", methods=["POST"])
@login_required
def stop_scanning():
    """Stop background scanning."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    if scanner.stop_background_scanning():
        flash("Background scanning stopped", "success")
    else:
        flash("Scanning not running", "warning")

    return redirect(url_for("dashboard"))


@app.route("/import-deleted", methods=["POST"])
@login_required
def import_deleted():
    """Import emails from deleted/trash folder for review."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    # Check if credentials are configured
    from services.credentials import get_credentials_manager
    creds = get_credentials_manager().get_imap_credentials(user_id)
    if not creds.is_configured():
        flash("Email settings not configured", "error")
        return redirect(url_for("training"))

    try:
        results = scanner.import_from_deleted(limit=100)
        spam_count = sum(1 for r in results if r.is_spam)
        flash(f"Imported {len(results)} emails from deleted folder ({spam_count} detected as spam). Review and label them on the Emails page.", "success")
    except Exception as e:
        flash(f"Import failed: {str(e)}", "error")

    return redirect(url_for("training"))


@app.route("/senders")
@login_required
def senders():
    """Sender whitelist/blacklist management."""
    user_id = get_current_user_id()
    listed = get_all_listed_senders(user_id)
    sender_stats = get_all_sender_stats(user_id, limit=50)

    whitelist = [s for s in listed if s["list_type"] == "whitelist"]
    blacklist = [s for s in listed if s["list_type"] == "blacklist"]

    return render_template(
        "senders.html",
        whitelist=whitelist,
        blacklist=blacklist,
        sender_stats=sender_stats
    )


@app.route("/senders/add", methods=["POST"])
@login_required
def add_sender_to_list():
    """Add a sender to whitelist or blacklist."""
    user_id = get_current_user_id()
    email = request.form.get("email", "").strip()
    list_type = request.form.get("list_type", "whitelist")
    reason = request.form.get("reason", "")

    if not email:
        flash("Email address is required", "error")
        return redirect(url_for("senders"))

    if list_type not in ("whitelist", "blacklist"):
        flash("Invalid list type", "error")
        return redirect(url_for("senders"))

    add_to_list(user_id, email, list_type, reason)
    flash(f"Added {email} to {list_type}", "success")
    return redirect(url_for("senders"))


@app.route("/senders/remove", methods=["POST"])
@login_required
def remove_sender_from_list():
    """Remove a sender from whitelist/blacklist."""
    user_id = get_current_user_id()
    email = request.form.get("email", "").strip()

    if email:
        remove_from_list(user_id, email)
        flash(f"Removed {email} from list", "success")

    return redirect(url_for("senders"))


@app.route("/senders/quick-add/<int:email_id>/<list_type>", methods=["POST"])
@login_required
def quick_add_sender(email_id, list_type):
    """Quick add sender from email list to whitelist/blacklist."""
    from database import get_db_connection

    user_id = get_current_user_id()

    if list_type not in ("whitelist", "blacklist"):
        return jsonify({"success": False, "error": "Invalid list type"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT sender FROM emails WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Email not found"}), 404

    add_to_list(user_id, row["sender"], list_type)
    return jsonify({"success": True, "list_type": list_type})


@app.route("/deleted-log")
@login_required
def deleted_log():
    """View log of deleted emails with rollback option."""
    user_id = get_current_user_id()
    deleted_emails = get_deleted_emails_log(user_id, limit=100)
    stats = get_deleted_stats(user_id)

    return render_template(
        "deleted_log.html",
        deleted_emails=deleted_emails,
        stats=stats
    )


@app.route("/deleted-log/restore/<int:log_id>", methods=["POST"])
@login_required
def restore_deleted_email(log_id):
    """Restore a deleted email (mark as restored and provide .eml file)."""
    import os

    user_id = get_current_user_id()
    entry = get_deleted_email_log_entry(user_id, log_id)
    if not entry:
        flash("Deleted email entry not found", "error")
        return redirect(url_for("deleted_log"))

    if entry["restored"]:
        flash("This email has already been restored", "warning")
        return redirect(url_for("deleted_log"))

    if entry["eml_file_path"] and os.path.exists(entry["eml_file_path"]):
        mark_email_restored(user_id, log_id)
        flash(f"Email marked as restored. The .eml backup file is available at: {entry['eml_file_path']}", "success")
    else:
        mark_email_restored(user_id, log_id)
        flash("Email marked as restored (backup file not found)", "warning")

    return redirect(url_for("deleted_log"))


@app.route("/deleted-log/download/<int:log_id>")
@login_required
def download_eml(log_id):
    """Download the .eml backup file."""
    import os

    user_id = get_current_user_id()
    entry = get_deleted_email_log_entry(user_id, log_id)
    if not entry:
        flash("Entry not found", "error")
        return redirect(url_for("deleted_log"))

    if not entry["eml_file_path"] or not os.path.exists(entry["eml_file_path"]):
        flash("Backup file not found", "error")
        return redirect(url_for("deleted_log"))

    return send_file(
        entry["eml_file_path"],
        as_attachment=True,
        download_name=f"email_{log_id}.eml"
    )


@app.route("/deleted-log/cleanup", methods=["POST"])
@login_required
def cleanup_deleted_logs():
    """Clean up expired deleted email logs."""
    user_id = get_current_user_id()
    count = cleanup_expired_deleted_logs(user_id)
    flash(f"Cleaned up {count} expired entries", "success")
    return redirect(url_for("deleted_log"))


@app.route("/cleanup", methods=["POST"])
@login_required
def cleanup():
    """Delete all data from database and model files for the current user."""
    import os
    import shutil

    user_id = get_current_user_id()

    try:
        cleanup_all(user_id)

        # Remove user's model directory
        classifier = get_classifier(user_id)
        model_dir = classifier.model_dir
        if os.path.exists(model_dir):
            shutil.rmtree(model_dir)

        classifier.model = None
        classifier.vectorizer = None
        classifier.is_trained = False

        flash("All data cleared successfully. Database and model have been reset.", "success")
    except Exception as e:
        flash(f"Cleanup failed: {str(e)}", "error")

    return redirect(url_for("settings_advanced"))


# --- API endpoints ---

@app.route("/api/stats")
@login_required
def api_stats():
    """Get statistics as JSON."""
    user_id = get_current_user_id()
    return jsonify(get_stats(user_id))


@app.route("/api/scan", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def api_scan():
    """Trigger a scan and return results as JSON."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    try:
        results = scanner.scan_emails()
        return jsonify({
            "success": True,
            "scanned": len(results),
            "spam": sum(1 for r in results if r.is_spam),
            "results": [
                {
                    "message_id": r.email.message_id,
                    "subject": r.email.subject,
                    "sender": r.email.sender,
                    "spam_score": r.spam_score,
                    "is_spam": r.is_spam,
                    "action": r.action
                }
                for r in results
            ]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/predict", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_predict():
    """Predict if text is spam."""
    user_id = get_current_user_id()
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field"}), 400

    classifier = get_classifier(user_id)
    score, is_spam = classifier.predict(data["text"])

    return jsonify({
        "spam_score": score,
        "is_spam": is_spam,
        "threshold": Config.SPAM_THRESHOLD
    })


@app.route("/api/mode", methods=["GET", "POST"])
@login_required
def api_mode():
    """Get or set operation mode."""
    user_id = get_current_user_id()
    scanner = get_scanner(user_id)

    if request.method == "POST":
        data = request.get_json()
        if not data or "mode" not in data:
            return jsonify({"error": "Missing 'mode' field"}), 400

        try:
            mode = OperationMode(data["mode"])
            scanner.set_mode(mode)
            return jsonify({"success": True, "mode": mode.value})
        except ValueError:
            return jsonify({"error": "Invalid mode"}), 400

    return jsonify({"mode": scanner.mode.value})


@app.route("/api/chart-data")
@login_required
def api_chart_data():
    """Get spam statistics for charts."""
    user_id = get_current_user_id()
    days = request.args.get("days", 30, type=int)
    data = get_spam_stats_by_day(user_id, days)
    return jsonify(data)


@app.route("/api/explain/<int:email_id>")
@login_required
def api_explain(email_id):
    """Get explanation for why an email was classified as spam/safe."""
    from database import get_db_connection

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT subject, content, spam_score, is_spam FROM emails WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Email not found"}), 404

    classifier = get_classifier(user_id)
    full_content = f"{row['subject']}\n{row['content']}"
    explanation = classifier.explain_prediction(full_content)

    return jsonify({
        "spam_score": row["spam_score"],
        "is_spam": bool(row["is_spam"]),
        "explanation": explanation
    })


@app.route("/api/email/<int:email_id>/preview")
@login_required
def api_email_preview(email_id):
    """Get email content for preview modal."""
    from database import get_db_connection

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, sender, subject, content, received_at, spam_score, is_spam FROM emails WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Email not found"}), 404

    return jsonify({
        "id": row["id"],
        "sender": row["sender"],
        "subject": row["subject"],
        "content": row["content"][:5000],
        "truncated": len(row["content"]) > 5000,
        "received_at": row["received_at"],
        "spam_score": row["spam_score"],
        "is_spam": bool(row["is_spam"])
    })


@app.route("/api/email/<int:email_id>/test-warning", methods=["POST"])
@login_required
def api_test_warning(email_id):
    """Test warning injection on a specific email."""
    from database import get_db_connection
    from services.email_service import get_email_service

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT message_id, subject, spam_score FROM emails WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "Email not found"}), 404

    email_service = get_email_service(user_id)
    if not email_service.connection:
        if not email_service.connect():
            return jsonify({"success": False, "error": "Cannot connect to IMAP server"}), 500

    # We need the IMAP UID - search by message ID
    if not email_service.select_folder("INBOX"):
        return jsonify({"success": False, "error": "Cannot select INBOX"}), 500

    try:
        status, messages = email_service.connection.search(None, "ALL")
        if status != "OK":
            return jsonify({"success": False, "error": "Cannot search INBOX"}), 500

        # Find the UID for this message
        target_uid = None
        for uid in messages[0].split():
            status, msg_data = email_service.connection.fetch(uid, "(BODY[HEADER.FIELDS (MESSAGE-ID)])")
            if status == "OK" and msg_data[0] is not None:
                header = msg_data[0][1].decode("utf-8", errors="ignore")
                if row["message_id"] in header:
                    target_uid = uid
                    break

        if not target_uid:
            return jsonify({"success": False, "error": "Email not found on IMAP server (may have been moved or deleted)"}), 404

        score = row["spam_score"] if row["spam_score"] else 0.85
        success = email_service.warn_email(target_uid, row["subject"], score)

        if success:
            return jsonify({"success": True, "message": "Warning injected"})
        else:
            return jsonify({"success": False, "error": "Failed to inject warning"}), 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/email/<int:email_id>/restore", methods=["POST"])
@login_required
def api_restore_email(email_id):
    """Restore an email (mark as safe and attempt to move back to inbox)."""
    from database import get_db_connection

    user_id = get_current_user_id()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT action_taken, message_id FROM emails WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Email not found"}), 404

    action = row["action_taken"]

    label_email(user_id, email_id, False)

    cursor.execute(
        "UPDATE emails SET action_taken = 'restored' WHERE id = ? AND user_id = ?",
        (email_id, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Email restored (was: {action})"
    })


@app.route("/api/discord/label", methods=["POST"])
@limiter.limit("30 per minute")
def api_discord_label():
    """
    Handle Discord button/dropdown interactions.
    Requires DISCORD_WEBHOOK_SECRET to be configured and provided
    via Authorization header or ?secret= query parameter.
    """
    from database import get_db_connection

    # --- Token authentication ---
    webhook_secret = Config.DISCORD_WEBHOOK_SECRET
    if not webhook_secret:
        abort(404)  # Endpoint disabled when secret not configured

    # Accept token from Authorization: Bearer <token> or ?secret=<token>
    provided = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided = auth_header[7:]
    else:
        provided = request.args.get("secret", "")

    if not provided or not hmac.compare_digest(provided, webhook_secret):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    if not data:
        return jsonify({"error": "No data"}), 400

    if data.get("type") != 3:
        return jsonify({"type": 1})

    custom_id = data.get("data", {}).get("custom_id", "")
    values = data.get("data", {}).get("values", [])

    if values:
        custom_id = values[0]

    # Parse custom_id format: {action}_{email_id}_{token}
    parts = custom_id.split("_", 2)
    if len(parts) != 3:
        return jsonify({
            "type": 4,
            "data": {"content": "Invalid action format", "flags": 64}
        })

    action, email_id_str, token = parts
    try:
        email_id = int(email_id_str)
    except ValueError:
        return jsonify({
            "type": 4,
            "data": {"content": "Invalid email ID", "flags": 64}
        })

    # Validate token and get user_id
    user_id = validate_discord_action_token(token, email_id)
    if user_id is None:
        return jsonify({
            "type": 4,
            "data": {"content": "This action has expired or is invalid.", "flags": 64}
        })

    def get_email_info(eid, uid):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT sender, message_id, subject, spam_score, action_taken FROM emails WHERE id = ? AND user_id = ?",
            (eid, uid)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    result_msg = "Unknown action"

    if action == "spam":
        label_email(user_id, email_id, True)
        result_msg = "Marked as spam"

    elif action == "safe":
        label_email(user_id, email_id, False)
        result_msg = "Marked as safe"

    elif action == "delete":
        email_info = get_email_info(email_id, user_id)
        if email_info:
            # Attempt actual IMAP delete
            try:
                from services.email_service import get_email_service
                email_service = get_email_service(user_id)
                if not email_service.connection:
                    email_service.connect()

                imap_uid = email_service.find_uid_by_message_id(email_info["message_id"])
                if imap_uid:
                    # Save EML backup
                    eml_path = ""
                    try:
                        import os
                        user_eml_path = os.path.join(Config.EML_STORAGE_PATH, str(user_id))
                        os.makedirs(user_eml_path, exist_ok=True)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        safe_id = email_info["message_id"].replace("<", "").replace(">", "").replace("/", "_")[:50]
                        filename = f"{timestamp}_{safe_id}.eml"
                        filepath = os.path.join(user_eml_path, filename)
                        status, msg_data = email_service.connection.fetch(imap_uid, "(RFC822)")
                        if status == "OK" and msg_data[0][1]:
                            with open(filepath, "wb") as f:
                                f.write(msg_data[0][1])
                            eml_path = filepath
                    except Exception:
                        pass

                    if email_service.delete_email(imap_uid):
                        log_deleted_email(
                            user_id=user_id, email_id=email_id,
                            message_id=email_info["message_id"],
                            sender=email_info["sender"],
                            subject=email_info["subject"],
                            spam_score=email_info["spam_score"] or 0.0,
                            eml_file_path=eml_path
                        )
                        label_email(user_id, email_id, True)
                        result_msg = "Email deleted from server"
                    else:
                        label_email(user_id, email_id, True)
                        result_msg = "Failed to delete from IMAP, marked as spam"
                else:
                    label_email(user_id, email_id, True)
                    result_msg = "Email not found on IMAP server, marked as spam"
            except Exception as e:
                label_email(user_id, email_id, True)
                result_msg = f"Delete error, marked as spam"
        else:
            result_msg = "Email not found"

    elif action == "movetospam":
        label_email(user_id, email_id, True)
        result_msg = "Marked as spam"

    elif action == "whitelist":
        email_info = get_email_info(email_id, user_id)
        if email_info:
            add_to_list(user_id, email_info["sender"], "whitelist", "Added via Discord")
            label_email(user_id, email_id, False)
            result_msg = f"Sender whitelisted: {email_info['sender'][:50]}"
        else:
            result_msg = "Email not found"

    elif action == "blacklist":
        email_info = get_email_info(email_id, user_id)
        if email_info:
            add_to_list(user_id, email_info["sender"], "blacklist", "Added via Discord")
            label_email(user_id, email_id, True)
            result_msg = f"Sender blacklisted: {email_info['sender'][:50]}"
        else:
            result_msg = "Email not found"

    elif action == "restore":
        label_email(user_id, email_id, False)
        result_msg = "Marked as safe"

    # Invalidate the token after use
    invalidate_discord_action_token(token)

    return jsonify({
        "type": 4,
        "data": {"content": result_msg, "flags": 64}
    })


@app.route("/api/discord/status")
@login_required
def api_discord_status():
    """Get Discord bot status and activity."""
    user_id = get_current_user_id()
    discord = get_discord_notifier(user_id)
    activity = discord.get_activity()

    return jsonify({
        "configured": discord.is_configured,
        "online": discord.is_online,
        "activity_type": activity["type"],
        "activity_name": activity["name"]
    })


@app.route("/api/discord/activity", methods=["POST"])
@login_required
def api_discord_activity():
    """Set Discord bot activity/presence."""
    user_id = get_current_user_id()
    discord = get_discord_notifier(user_id)

    if not discord.is_online:
        return jsonify({"error": "Bot is not online"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    activity_type = data.get("type", "watching")
    activity_name = data.get("name", "for spam emails")

    valid_types = ["playing", "streaming", "listening", "watching", "competing"]
    if activity_type.lower() not in valid_types:
        return jsonify({"error": f"Invalid activity type. Must be one of: {', '.join(valid_types)}"}), 400

    if discord.set_activity(activity_type, activity_name):
        return jsonify({"success": True, "type": activity_type, "name": activity_name})
    else:
        return jsonify({"error": "Failed to set activity"}), 500


@app.route("/api/discord/start", methods=["POST"])
@login_required
def api_discord_start():
    """Start the Discord bot."""
    user_id = get_current_user_id()
    discord = get_discord_notifier(user_id)

    if discord.is_online:
        return jsonify({"success": True, "message": "Bot already running"})

    if not discord.bot_token:
        return jsonify({"error": "Discord bot not configured"}), 400

    if discord.start_bot():
        return jsonify({"success": True, "message": "Bot starting..."})
    else:
        return jsonify({"error": "Failed to start bot"}), 500


@app.route("/api/discord/stop", methods=["POST"])
@login_required
def api_discord_stop():
    """Stop the Discord bot."""
    user_id = get_current_user_id()
    discord = get_discord_notifier(user_id)

    if not discord.is_online:
        return jsonify({"success": True, "message": "Bot already stopped"})

    discord.stop_bot()
    return jsonify({"success": True, "message": "Bot stopped"})


# --- Session Management API ---

@app.route("/api/sessions")
@login_required
def api_sessions():
    """Get all active sessions for the current user."""
    user_id = get_current_user_id()
    sessions = get_user_sessions(user_id)

    current_token = session.get("session_token", "")

    result = []
    for s in sessions:
        result.append({
            "id": s["id"],
            "ip_address": s["ip_address"] or "Unknown",
            "user_agent": s["user_agent"] or "Unknown",
            "created_at": s["created_at"],
            "expires_at": s["expires_at"],
            "is_current": s["session_token"] == current_token
        })

    return jsonify(result)


@app.route("/api/sessions/<int:session_id>/revoke", methods=["POST"])
@login_required
def api_revoke_session(session_id):
    """Revoke a specific session."""
    user_id = get_current_user_id()
    if revoke_session(user_id, session_id):
        log_audit_event(user_id, "session_revoked",
                        details=f"session_id={session_id}", ip=request.remote_addr)
        return jsonify({"success": True, "message": "Session revoked"})
    return jsonify({"success": False, "error": "Session not found"}), 404


@app.route("/api/sessions/revoke-all", methods=["POST"])
@login_required
def api_revoke_all_sessions():
    """Revoke all other sessions."""
    user_id = get_current_user_id()
    current_token = session.get("session_token", "")
    count = revoke_all_other_sessions(user_id, current_token)
    if count:
        log_audit_event(user_id, "session_revoked",
                        details=f"all_other ({count})", ip=request.remote_addr)
    return jsonify({"success": True, "message": f"Revoked {count} session(s)"})


# --- Admin Routes ---

@app.route("/admin")
@admin_required
def admin_dashboard():
    """Admin dashboard showing system overview."""
    stats = get_system_stats()
    users = get_all_users_with_stats()
    require_2fa_all = get_system_setting("require_2fa_all", "0") == "1"

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_users=users[:10],  # Show 10 most recent users
        config=Config,
        require_2fa_all=require_2fa_all
    )


@app.route("/admin/system-settings", methods=["POST"])
@admin_required
def admin_system_settings():
    """Update system-wide settings."""
    require_2fa = "1" if request.form.get("require_2fa_all") == "1" else "0"
    set_system_setting("require_2fa_all", require_2fa)
    flash("System settings updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/audit-log")
@admin_required
def admin_audit_log():
    """View security audit log."""
    entries = get_audit_log(limit=200)
    return render_template("admin/audit_log.html", entries=entries)


@app.route("/admin/users")
@admin_required
def admin_users():
    """User management page."""
    users = get_all_users_with_stats()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user():
    """Create a new user."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip() or None
        display_name = request.form.get("display_name", "").strip() or None
        is_admin = request.form.get("is_admin") == "1"
        require_2fa = request.form.get("require_2fa") == "1"

        # Validation
        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
        elif not validate_password(password)[0]:
            flash(validate_password(password)[1], "error")
        elif get_user(username):
            flash("Username already exists", "error")
        else:
            # If 2FA required, generate a secret the user will set up on first login
            totp_secret = pyotp.random_base32() if require_2fa else ""

            # Create user
            admin_id = get_current_user_id()
            new_user_id = create_user_full(
                username=username,
                password_hash=generate_password_hash(password),
                totp_secret=totp_secret,
                totp_enabled=False,
                email=email,
                is_admin=is_admin,
                created_by=admin_id,
                display_name=display_name
            )
            log_audit_event(admin_id, "user_created", target_user_id=new_user_id,
                            details=username, ip=request.remote_addr)
            flash(f"User '{username}' created successfully", "success")
            return redirect(url_for("admin_users"))

        return render_template(
            "admin/create_user.html",
            username=username,
            email=email,
            display_name=display_name,
            is_admin=is_admin
        )

    # GET
    return render_template("admin/create_user.html")


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    """Edit a user."""
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip() or None
        is_admin = request.form.get("is_admin") == "1"
        current_user_id = get_current_user_id()

        # Prevent removing own admin
        if user_id == current_user_id and not is_admin:
            flash("Cannot remove your own admin privileges", "error")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        # Check username uniqueness (only if changed)
        if username != user["username"]:
            existing = get_user(username)
            if existing:
                flash("Username already taken", "error")
                return redirect(url_for("admin_edit_user", user_id=user_id))

        # Update user
        from database import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE auth_users
            SET username = ?, display_name = ?, is_admin = ?
            WHERE id = ?
        """, (username, display_name, 1 if is_admin else 0, user_id))
        conn.commit()
        conn.close()

        # Log role change if admin status changed
        if bool(is_admin) != bool(user.get("is_admin")):
            log_audit_event(current_user_id, "role_changed", target_user_id=user_id,
                            details=f"{username}: admin={is_admin}", ip=request.remote_addr)
        flash("User updated successfully", "success")
        return redirect(url_for("admin_users"))

    # GET - get user stats
    from database import get_db_connection
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM emails WHERE user_id = ?", (user_id,))
    email_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM training_data WHERE user_id = ?", (user_id,))
    training_count = cursor.fetchone()["count"]

    # Get created_by username
    created_by_username = None
    if user.get("created_by"):
        cursor.execute("SELECT username FROM auth_users WHERE id = ?", (user["created_by"],))
        row = cursor.fetchone()
        if row:
            created_by_username = row["username"]

    conn.close()

    user["email_count"] = email_count
    user["training_count"] = training_count
    user["created_by_username"] = created_by_username
    user["totp_enabled"] = bool(user.get("totp_secret"))

    return render_template("admin/edit_user.html", user=user)


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    """Reset a user's password."""
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    new_password = request.form.get("new_password", "")
    is_valid, error_msg = validate_password(new_password)
    if not is_valid:
        flash(error_msg, "error")
        return redirect(url_for("admin_edit_user", user_id=user_id))

    update_user_password(user_id, generate_password_hash(new_password))
    log_audit_event(get_current_user_id(), "password_reset", target_user_id=user_id,
                    details=user["username"], ip=request.remote_addr)
    flash(f"Password reset for {user['username']}", "success")
    return redirect(url_for("admin_edit_user", user_id=user_id))


@app.route("/admin/users/<int:user_id>/reset-2fa", methods=["POST"])
@admin_required
def admin_reset_2fa(user_id):
    """Reset a user's 2FA."""
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    # Generate new TOTP secret - user will need to set it up again
    new_secret = pyotp.random_base32()
    regenerate_totp_secret(user_id, new_secret)
    # Revoke all sessions for the target user so they must re-authenticate
    revoke_all_other_sessions(user_id, current_session_token="")
    actor_id = get_current_user_id()
    log_audit_event(actor_id, "2fa_reset", target_user_id=user_id,
                    details=user["username"], ip=request.remote_addr)
    flash(f"2FA reset for {user['username']}. They will need to set up 2FA on next login.", "success")
    return redirect(url_for("admin_edit_user", user_id=user_id))


@app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    """Toggle admin status for a user."""
    current_user_id = get_current_user_id()

    if user_id == current_user_id:
        flash("Cannot modify your own admin status", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    new_status = not user.get("is_admin", False)

    # Prevent removing last admin
    if not new_status and count_admins() <= 1:
        flash("Cannot remove the last admin", "error")
        return redirect(url_for("admin_users"))

    update_user_role(user_id, new_status)
    flash(f"{'Granted' if new_status else 'Revoked'} admin for {user['username']}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def admin_toggle_active(user_id):
    """Toggle active status for a user."""
    current_user_id = get_current_user_id()

    if user_id == current_user_id:
        flash("Cannot deactivate yourself", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    new_status = not user.get("is_active", True)
    update_user_active(user_id, new_status)
    flash(f"{'Activated' if new_status else 'Deactivated'} {user['username']}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Delete a user and all their data."""
    current_user_id = get_current_user_id()

    if user_id == current_user_id:
        flash("Cannot delete yourself", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for("admin_users"))

    # Prevent deleting last admin
    if user.get("is_admin") and count_admins() <= 1:
        flash("Cannot delete the last admin", "error")
        return redirect(url_for("admin_users"))

    username = user["username"]
    log_audit_event(current_user_id, "user_deleted", target_user_id=user_id,
                    details=username, ip=request.remote_addr)
    delete_user_data(user_id)
    delete_user(user_id)
    flash(f"Deleted user '{username}' and all their data", "success")
    return redirect(url_for("admin_users"))


# --- Settings: Email Configuration ---

@app.route("/settings/email")
@login_required
def settings_email():
    """IMAP email configuration page."""
    user_id = get_current_user_id()
    from services.credentials import get_credentials_manager

    manager = get_credentials_manager()
    credentials = manager.get_imap_credentials(user_id)

    return render_template(
        "settings/email.html",
        credentials=credentials
    )


@app.route("/settings/email/save", methods=["POST"])
@login_required
def settings_email_save():
    """Save IMAP email configuration."""
    user_id = get_current_user_id()
    from services.credentials import get_credentials_manager, IMAPCredentials

    server = request.form.get("imap_server", "").strip()
    port = int(request.form.get("imap_port", 993))
    email_address = request.form.get("email_address", "").strip()
    password = request.form.get("email_password", "")

    if not server or not email_address:
        flash("Server and email address are required", "error")
        return redirect(url_for("settings_email"))

    manager = get_credentials_manager()

    # If no new password provided, keep the existing one
    if not password:
        existing = manager.get_imap_credentials(user_id)
        password = existing.password

    try:
        creds = IMAPCredentials(
            server=server,
            port=port,
            email_address=email_address,
            password=password
        )
        manager.save_imap_credentials(user_id, creds)
        flash("Email settings saved successfully", "success")
    except Exception as e:
        flash(f"Failed to save settings: {e}", "error")

    return redirect(url_for("settings_email"))


@app.route("/settings/email/test", methods=["POST"])
@login_required
def settings_email_test():
    """Test IMAP connection."""
    user_id = get_current_user_id()
    from services.email_service import get_email_service, clear_email_service_cache

    # Clear cache to use fresh credentials
    clear_email_service_cache(user_id)

    email_service = get_email_service(user_id)
    if email_service.connect():
        email_service.disconnect()
        return jsonify({"success": True, "message": "Connection successful!"})
    else:
        return jsonify({"success": False, "error": "Connection failed. Check your settings."})


# --- Settings: Discord Configuration ---

@app.route("/settings/discord")
@login_required
def settings_discord():
    """Discord configuration page."""
    user_id = get_current_user_id()
    from services.credentials import get_credentials_manager
    from services.discord_bot import get_discord_notifier

    manager = get_credentials_manager()
    credentials = manager.get_discord_credentials(user_id)
    notifier = get_discord_notifier(user_id)

    return render_template(
        "settings/discord.html",
        credentials=credentials,
        bot_online=notifier.is_online,
        bot_configured=bool(credentials.bot_token)
    )


@app.route("/settings/discord/save", methods=["POST"])
@login_required
def settings_discord_save():
    """Save Discord configuration."""
    user_id = get_current_user_id()
    from services.credentials import get_credentials_manager, DiscordCredentials

    webhook_url = request.form.get("webhook_url", "").strip()
    bot_token = request.form.get("bot_token", "")
    channel_id = request.form.get("channel_id", "").strip()
    webhook_secret = request.form.get("webhook_secret", "").strip()
    notify_threshold = float(request.form.get("notify_threshold", 0.7))

    manager = get_credentials_manager()

    # If no new bot token provided, keep the existing one
    if not bot_token:
        existing = manager.get_discord_credentials(user_id)
        bot_token = existing.bot_token

    try:
        creds = DiscordCredentials(
            webhook_url=webhook_url,
            bot_token=bot_token,
            channel_id=channel_id,
            webhook_secret=webhook_secret,
            notify_threshold=notify_threshold
        )
        manager.save_discord_credentials(user_id, creds)
        flash("Discord settings saved successfully", "success")
    except Exception as e:
        flash(f"Failed to save settings: {e}", "error")

    return redirect(url_for("settings_discord"))


@app.route("/settings/discord/test", methods=["POST"])
@login_required
def settings_discord_test():
    """Send test Discord notification."""
    user_id = get_current_user_id()
    from services.discord_bot import get_discord_notifier

    # DON'T clear cache here - we want to test the actual running bot instance
    notifier = get_discord_notifier(user_id)
    if not notifier.is_configured:
        flash("Discord is not configured. Please set up a webhook URL or bot token.", "error")
        return redirect(url_for("settings_discord"))

    try:
        success, error_msg = notifier.send_test_notification()
        if success:
            flash("Test notification sent successfully! Check your Discord channel.", "success")
        else:
            flash(f"Failed to send test notification: {error_msg}", "error")
    except Exception as e:
        flash(f"Error sending notification: {str(e)}", "error")

    return redirect(url_for("settings_discord"))


# =============================================================================
# SMTP Settings Routes (admin-only, global SMTP config)
# =============================================================================

@app.route("/settings/smtp")
@login_required
@admin_required
def settings_smtp():
    """SMTP configuration page (admin only)."""
    from services.credentials import get_credentials_manager
    from services.email_sender import _get_admin_user_id

    admin_id = _get_admin_user_id()
    manager = get_credentials_manager()
    credentials = manager.get_smtp_credentials(admin_id)

    return render_template(
        "settings/smtp.html",
        credentials=credentials
    )


@app.route("/settings/smtp/save", methods=["POST"])
@login_required
@admin_required
def settings_smtp_save():
    """Save SMTP configuration."""
    from services.credentials import get_credentials_manager, SMTPCredentials
    from services.email_sender import _get_admin_user_id

    admin_id = _get_admin_user_id()
    manager = get_credentials_manager()

    server = request.form.get("smtp_server", "").strip()
    port = int(request.form.get("smtp_port", 587))
    username = request.form.get("smtp_username", "").strip()
    password = request.form.get("smtp_password", "")
    use_tls = request.form.get("smtp_use_tls") == "1"
    from_address = request.form.get("smtp_from_address", "").strip()

    # Keep existing password if placeholder was submitted
    if password == "********" or not password:
        existing = manager.get_smtp_credentials(admin_id)
        password = existing.password

    try:
        creds = SMTPCredentials(
            server=server,
            port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            from_address=from_address
        )
        manager.save_smtp_credentials(admin_id, creds)
        flash("SMTP settings saved successfully", "success")
    except Exception as e:
        flash(f"Failed to save settings: {e}", "error")

    return redirect(url_for("settings_smtp"))


@app.route("/settings/smtp/test", methods=["POST"])
@login_required
@admin_required
def settings_smtp_test():
    """Send test email via SMTP."""
    from services.email_sender import get_email_sender

    sender = get_email_sender()
    if not sender.is_configured:
        flash("SMTP is not configured. Please set up your SMTP settings first.", "error")
        return redirect(url_for("settings_smtp"))

    test_to = request.form.get("test_email", "").strip()
    if not test_to:
        test_to = sender.credentials.from_address

    try:
        success, error_msg = sender.send_test_email(test_to)
        if success:
            flash(f"Test email sent successfully to {test_to}!", "success")
        else:
            flash(f"Failed to send test email: {error_msg}", "error")
    except Exception as e:
        flash(f"Error sending test email: {str(e)}", "error")

    return redirect(url_for("settings_smtp"))


@app.route("/settings/smtp/report-settings", methods=["POST"])
@login_required
def settings_report_save():
    """Save weekly report settings."""
    user_id = get_current_user_id()

    report_enabled = "1" if request.form.get("report_enabled") == "1" else "0"
    report_day = request.form.get("report_day", "monday")
    report_email = request.form.get("report_email", "").strip()

    set_user_setting(user_id, "report_enabled", report_enabled)
    set_user_setting(user_id, "report_day", report_day)
    set_user_setting(user_id, "report_email", report_email)

    flash("Report settings saved successfully", "success")
    return redirect(url_for("settings_reports"))


@app.route("/settings/smtp/report-test", methods=["POST"])
@login_required
def settings_report_test():
    """Send a test weekly report immediately."""
    user_id = get_current_user_id()

    try:
        from services.report_scheduler import send_report_now
        success, msg = send_report_now(user_id)
        if success:
            flash("Test report sent! Check your email.", "success")
        else:
            flash(f"Failed to send report: {msg}", "error")
    except Exception as e:
        flash(f"Error sending report: {str(e)}", "error")

    return redirect(url_for("settings_reports"))


@app.route("/settings/reports")
@login_required
def settings_reports():
    """Email reports settings page (available to all users)."""
    from services.email_sender import get_email_sender

    user_id = get_current_user_id()
    sender = get_email_sender()

    report_enabled = get_user_setting(user_id, "report_enabled", "0") == "1"
    report_day = get_user_setting(user_id, "report_day", "monday")
    report_email = get_user_setting(user_id, "report_email", "")

    return render_template(
        "settings/reports.html",
        smtp_configured=sender.is_configured,
        report_enabled=report_enabled,
        report_day=report_day,
        report_email=report_email
    )


# Global reference to scheduler thread (checked by /health)
_scheduler_thread: threading.Thread = None

# Guard so migrations only run once per worker process, not on every request
_db_initialized: bool = False


def _start_scheduler_thread() -> threading.Thread:
    """Start the report scheduler as a watchdog daemon thread."""
    global _scheduler_thread

    def loop():
        while True:
            try:
                from services.report_scheduler import check_and_send_reports
                check_and_send_reports()
            except Exception as e:
                logger.error("Report scheduler error: %s", e, exc_info=True)
            time.sleep(3600)  # Check every hour

    _scheduler_thread = threading.Thread(target=loop, daemon=True, name="report-scheduler")
    _scheduler_thread.start()
    return _scheduler_thread


def start_app():
    """Initialize and start the application."""
    global _db_initialized
    init_db()
    run_migrations()
    run_saas_migrations()
    _db_initialized = True

    logger.info(
        "SPAMBUSTER starting — mode=%s threshold=%.2f encryption=%s",
        Config.OPERATION_MODE.value,
        Config.SPAM_THRESHOLD,
        "configured" if Config.ENCRYPTION_MASTER_KEY else "fallback"
    )

    # Note: In multi-user mode, scanning is started per-user when they log in
    # or explicitly via the dashboard. Global auto-start is not supported.

    # Start weekly report scheduler (checks every hour)
    _start_scheduler_thread()


if __name__ == "__main__":
    start_app()
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)

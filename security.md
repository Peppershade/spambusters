# Security Documentation

**Last Updated:** 2026-04-15
**Version:** 0.7.1
**Scope:** Complete security architecture review and threat analysis

## Security Update History

| Version | Date | Changes |
|---------|------|---------|
| 0.7.1 | 2026-04-15 | Fix XSS in explain modal — email-derived content (keywords, reason details) now escaped before innerHTML injection; fix EML expiry not enforced (cleanup_expired_deleted_logs added to periodic sweep); fix /health 500s on startup (migrations skipped for health endpoint); fix report scheduler not starting under Gunicorn |
| 0.6.1 | 2026-03-05 | Audit log (all admin/security events); admin-enforced 2FA; rate limits on scan/predict/train; session revoke on admin 2FA reset; structured logging; request ID middleware; custom error pages (no stack trace exposure); IMAP retry backoff; expanded /health endpoint |
| 0.6.0 | 2026-03-05 | DB-tracked sessions (sliding expiry, revoke UI, auto-revoke); per-action Discord tokens |
| 0.4.4 | 2026-02-07 | CSRF protection, security headers, session fixation fix, account lockout, strong password policy, session cookie flags |

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Credential Encryption](#credential-encryption)
4. [Database Security](#database-security)
5. [API Security](#api-security)
6. [Session Management](#session-management)
7. [Rate Limiting](#rate-limiting)
8. [Audit Logging](#audit-logging)
9. [Observability](#observability)
10. [Deployment Security](#deployment-security)
11. [Known Limitations](#known-limitations)
12. [Security Roadmap](#security-roadmap)
13. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Security Overview

### Threat Model

Spambusters is designed for **self-hosted deployment** in trusted environments. Primary security goals:

- **Confidentiality**: Protect IMAP credentials, Discord tokens, SMTP credentials, and email content
- **Integrity**: Prevent unauthorized modification of spam filters and user data
- **Availability**: Protect against brute-force and resource exhaustion
- **Privacy**: Ensure per-user data isolation in multi-tenant deployments

**Assumptions**:
- You control the deployment server
- Physical access is restricted
- OS and dependencies are kept updated
- Administrators are trusted (can access database and config)

**Out of Scope**:
- Protection against server compromise or malicious administrators
- Large-scale DDoS mitigation
- Public SaaS deployment (requires additional hardening)

---

## Authentication & Authorization

### Password Storage
**Implementation:** `database.py`

✅ **Secure Implementation**:
```python
from werkzeug.security import generate_password_hash, check_password_hash

# Storage
password_hash = generate_password_hash(password)  # PBKDF2-HMAC-SHA256

# Verification (constant-time comparison)
if not check_password_hash(user["password_hash"], password):
    flash("Invalid username or password", "error")
```

**Password Requirements** (`app.py:49-78`):
- Minimum length: **12 characters**
- Must contain uppercase, lowercase, digit, and special character (`!@#$%^&*()_+-=[]{}|;:,.<>?`)
- Enforced at registration and password change

✅ **Admin password reset** (`/admin/edit-user`) now calls the same `validate_password()` function — full 12-char + complexity policy enforced on all paths.

### Two-Factor Authentication (2FA)
**Implementation:** `app.py`

✅ **TOTP-based 2FA** (RFC 6238):
- Compatible with Google Authenticator, Authy, 1Password, etc.
- Optional during setup (admin can require it system-wide — planned)
- QR code provisioning for easy enrollment
- Verification window: ±30 seconds (`valid_window=1`)

**Security Considerations**:
- ✅ Constant-time verification (`pyotp.TOTP.verify`)
- ✅ Rate limited (5 attempts/min on login endpoint)
- ✅ All sessions auto-revoked on 2FA reset (including admin-triggered resets)
- ✅ Admin can enforce 2FA system-wide (`require_2fa_all` setting) — users without 2FA are redirected to setup on next login
- ⚠️ No backup codes provided
- ⚠️ TOTP secrets stored in database (encrypted at rest with SQLite, not with per-user DEK)

### Multi-User Authorization
**Implementation:** `app.py`

**Roles**:
- **Admin**: Full access, user management, system settings
- **Standard User**: Own data only

**Access Control Decorators**:
```python
@login_required       # Requires valid session
@admin_required       # Requires is_admin=True
```

**Per-User Data Isolation**:
```python
# All database functions scoped by user_id
def get_flagged_emails(user_id: int, limit: int = 50):
def save_email(user_id: int, message_id: str, ...):
```

---

## Credential Encryption

### Encryption Architecture
**Implementation:** `services/encryption.py`, `services/credentials.py`

Spambusters uses **hierarchical key management** with Fernet (AES-128-CBC + HMAC-SHA256):

```
ENCRYPTION_MASTER_KEY (environment variable)
    ↓ PBKDF2-HMAC-SHA256 (480,000 iterations, 256-bit salt)
    └─→ User KEK (Key Encryption Key)
            ↓ Fernet encryption
            └─→ User DEK (Data Encryption Key) - stored wrapped in DB
                    ↓ Fernet encryption (authenticated)
                    └─→ IMAP credentials, Discord tokens, SMTP credentials
```

### Key Derivation
**Implementation:** `services/encryption.py`

```python
ITERATIONS = 480000  # OWASP recommendation for PBKDF2-SHA256
SALT_LENGTH = 32     # 256 bits

def _derive_kek(self, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=self.ITERATIONS,
    )
    key = kdf.derive(self._master_key.encode())
    return base64.urlsafe_b64encode(key)
```

### What Gets Encrypted

**Per-User Encrypted Credentials**:
- IMAP server address, email address, and password
- IMAP port (plaintext — not sensitive)
- Discord webhook URL, bot token, webhook secret
- Discord channel ID (plaintext — not sensitive)
- SMTP server, username, password, from address
- SMTP port (plaintext — not sensitive)

**Database Storage**:
```sql
CREATE TABLE user_credentials (
    imap_server_enc BLOB,            -- Encrypted
    email_address_enc BLOB,          -- Encrypted
    email_password_enc BLOB,         -- Encrypted
    imap_port INTEGER,               -- Plaintext
    discord_webhook_url_enc BLOB,    -- Encrypted
    discord_bot_token_enc BLOB,      -- Encrypted
    discord_webhook_secret_enc BLOB, -- Encrypted
    discord_channel_id TEXT,         -- Plaintext
    smtp_server_enc BLOB,            -- Encrypted
    smtp_username_enc BLOB,          -- Encrypted
    smtp_password_enc BLOB,          -- Encrypted
    smtp_from_address_enc BLOB       -- Encrypted
)
```

### Key Rotation
**Implementation:** `services/credentials.py`

Automated key rotation process:
1. Decrypt all credentials with old key
2. Generate new DEK and KEK with fresh salt
3. Re-encrypt all credentials with new key
4. Update database atomically
5. Clear cached keys

### Fallback Behavior

⚠️ **If ENCRYPTION_MASTER_KEY not set**:
- A temporary key is generated per session (credentials lost on restart)
- A warning is emitted to the structured log (`logger.warning`)

**Production deployments MUST set**:
```bash
ENCRYPTION_MASTER_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

---

## Database Security

### SQL Injection Protection
**Implementation:** `database.py` (all functions)

✅ **All queries use parameterized statements**:

```python
# ✅ SAFE - Parameterized query
cursor.execute(
    "SELECT * FROM emails WHERE user_id = ? AND message_id = ?",
    (user_id, message_id)
)
```

All 50+ database functions use parameterized queries. No string interpolation in SQL.

### Multi-Tenant Isolation

✅ **User ID Scoping**:
- All data access requires `user_id` parameter
- Foreign key constraints enforce referential integrity

```sql
CREATE TABLE emails (
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
)
```

### Secure Deletion

**Implementation:** `database.py:delete_user_data`

User deletion cascades through:
- Emails & training data
- Scan history & sender stats
- Whitelist/blacklist entries
- User settings and sessions
- **Encrypted credentials** (securely erased)
- **Encryption keys** (securely erased)

---

## API Security

### Discord Webhook Endpoint
**Implementation:** `app.py:1565`

**Endpoint**: `POST /api/discord/label`

✅ **Two-Layer Authentication**:

**Layer 1 — Webhook Secret (request authentication)**:
```python
webhook_secret = Config.DISCORD_WEBHOOK_SECRET
if not webhook_secret:
    abort(404)  # Endpoint disabled if secret not configured

provided = request.headers.get("Authorization", "")[7:]  # Strip "Bearer "
if not provided:
    provided = request.args.get("secret", "")

# Constant-time comparison prevents timing attacks
if not hmac.compare_digest(provided, webhook_secret):
    return jsonify({"error": "Unauthorized"}), 401
```

**Layer 2 — Per-Action Token (operation authorization)**:
```python
# custom_id format: {action}_{email_id}_{token}
action, email_id_str, token = custom_id.split("_", 2)

# Token is scoped to specific email_id and user_id
user_id = validate_discord_action_token(token, email_id)
if user_id is None:
    return {"content": "This action has expired or is invalid.", "flags": 64}

# Token is invalidated after single use
invalidate_discord_action_token(token)
```

**Action Token Properties** (`database.py:1409`):
- Scoped to specific `email_id` + `user_id` (cannot be replayed on other emails)
- 72-hour TTL
- Single-use (invalidated immediately after action)
- Stored in `discord_action_tokens` table with `expires_at` and `used` flag

✅ **Additional Security Features**:
- Rate limited: 30 req/min per IP
- Endpoint returns 404 (not 401) if secret not configured — prevents enumeration

**Generate Secret**:
```bash
DISCORD_WEBHOOK_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
```

---

## Session Management

### Session Architecture (v0.6.0+)
**Implementation:** `app.py`, `database.py:1468+`

Spambusters uses **dual-layer session tracking**:

1. **Flask signed cookie** — identifies the session on the client side (HMAC-signed, tamper-proof)
2. **Database session record** (`user_sessions` table) — server-side validation, enables revocation

```sql
CREATE TABLE user_sessions (
    session_token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    is_valid INTEGER DEFAULT 1
)
```

### Session Creation

✅ **Two-Step Login Flow**:

**Step 1**: Username + Password → rate-limited, account lockout enforced
**Step 2**: TOTP verification (if enabled)

On successful login:
```python
session.clear()         # Prevent session fixation
session["authenticated"] = True
session["username"] = username
session["user_id"] = user["id"]
session["is_admin"] = bool(user.get("is_admin", False))
session.permanent = True
# DB session record created with IP, user-agent, 30-min TTL
```

### Session Security

✅ **Cookie Flags** (`app.py:100-106`):
```python
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SECURE=Config.USE_HTTPS,   # Set USE_HTTPS=true in production
SESSION_COOKIE_SAMESITE='Lax',
PERMANENT_SESSION_LIFETIME=1800,          # 30-minute expiry
```

✅ **Sliding Expiry**: Each authenticated request extends the session TTL 30 minutes (`extend_session`)

✅ **Revocation**:
- Users can view and revoke individual sessions from the UI
- `revoke_all_other_sessions()` called on password change and 2FA reset
- Admin can revoke any user's sessions

⚠️ **Note**: `SESSION_COOKIE_SECURE` is conditional on `USE_HTTPS=true`. Set this env var when running behind HTTPS.

---

## Rate Limiting

**Implementation:** `app.py`, Flask-Limiter (in-memory)

| Endpoint | Limit | Purpose |
|----------|-------|---------|
| `POST /login` | 5 per minute | Prevent brute-force password attacks |
| `POST /setup` | 3 per minute | Prevent account creation spam |
| `POST /api/discord/label` | 30 per minute | Prevent Discord webhook abuse |
| `POST /api/scan` | 5 per minute | Prevent resource exhaustion |
| `POST /api/predict` | 10 per minute | Prevent model abuse |
| `POST /training/train` | 3 per minute | Prevent training abuse |

✅ **Account Lockout**: 5 failed login attempts → 15-minute lockout (independent of rate limiting)

⚠️ **Limitations**:
- IP-based only (can be bypassed with proxies/VPNs)
- In-memory storage (resets on restart)

---

## Audit Logging

**Implementation:** `database.py`, `app.py`

All admin and security-significant events are written to an `audit_log` table:

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_user_id INTEGER,    -- Who performed the action
    target_user_id INTEGER,   -- Who it was performed on
    action TEXT NOT NULL,     -- Event type
    details TEXT,             -- JSON or text context
    ip_address TEXT
)
```

**Events logged**:

| Action | Trigger |
|--------|---------|
| `user_created` | Admin creates a new user |
| `user_deleted` | Admin deletes a user |
| `role_changed` | Admin changes is_admin flag |
| `password_reset` | Admin resets a user's password |
| `2fa_reset` | Admin resets a user's 2FA secret |
| `login_failed` | Invalid password attempt |
| `account_locked` | 5th failed attempt triggers lockout |
| `2fa_changed` | User enables/disables their own 2FA |
| `session_revoked` | User or admin revokes a session |

✅ Audit failures are silently caught — a logging error will never crash a request.

**Admin UI**: `/admin/audit-log` — displays last 200 events (admin-only).

---

## Observability

### Structured Logging

**Implementation:** `services/logging_config.py`

All modules use Python's `logging` module with a consistent format:
```
[2026-03-05 12:00:00,000] INFO [services.scanner] Processed 12 new emails (3 spam detected) for user 1
```

Configured via environment variables:
```bash
LOG_LEVEL=INFO    # DEBUG, INFO, WARNING, ERROR (default: INFO)
LOG_FILE=         # Path to log file; empty = stdout (default: stdout)
```

### Request ID Middleware

Every request is assigned a unique `X-Request-ID` header (taken from the incoming header if provided, otherwise generated as `secrets.token_hex(8)`). The same ID is echoed in the response header, enabling end-to-end request tracing across proxy logs and application logs.

### Health Endpoint

`GET /health` — returns JSON with system status checks:

```json
{
  "status": "ok",
  "database": "ok",
  "encryption_key": "ok",
  "disk_free_mb": 4200,
  "model_files": 1,
  "scheduler_alive": true
}
```

Returns HTTP 503 if database is unreachable, encryption key is missing, or disk free space < 100 MB.

### Error Pages

Custom error handlers for 404 and 500 — no stack traces or internal paths are exposed to the client. 500 errors are logged server-side with `exc_info=True` for full tracebacks in logs.

---

## Deployment Security

### Critical Environment Variables

```bash
# REQUIRED - Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY="<64-char-hex>"
ENCRYPTION_MASTER_KEY="<64-char-hex>"

# REQUIRED for HTTPS cookie security
USE_HTTPS=true

# Discord security (if using webhooks)
DISCORD_WEBHOOK_SECRET="<64-char-hex>"
```

⚠️ **Startup Behavior**:
```python
# If SECRET_KEY not set, generates temporary key (sessions lost on restart)
if not Config.SECRET_KEY:
    _generated = secrets.token_hex(32)
    print("WARNING: SECRET_KEY is not set!")
    Config.SECRET_KEY = _generated
```

### HTTPS/TLS Requirement

⚠️ **Spambusters does NOT implement HTTPS directly.**

Deploy behind a reverse proxy (Nginx, Caddy, Apache):

**Nginx Example**:
```nginx
server {
    listen 443 ssl http2;
    server_name spam.example.com;

    ssl_certificate /etc/letsencrypt/live/spam.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/spam.example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### File Permissions

```bash
chmod 600 spambuster.db
chown spambusters:spambusters spambuster.db

chmod 700 data/deleted_emails
chown -R spambusters:spambusters data/

chmod 755 models
chmod 644 models/*.pt models/*.pkl
```

### Backup Security

```bash
sqlite3 spambuster.db ".backup /secure/backups/spambuster-$(date +%Y%m%d).db"
gpg --symmetric --cipher-algo AES256 spambuster-$(date +%Y%m%d).db
rm spambuster-$(date +%Y%m%d).db
```

⚠️ **CRITICAL**: If you lose `ENCRYPTION_MASTER_KEY`, encrypted credentials cannot be recovered. Back it up securely and **separately** from database backups.

---

## Known Limitations

### Medium Priority

**2. EML Files Stored Unencrypted**
- **Risk**: Deleted email content readable from disk
- **Impact**: MEDIUM — requires filesystem access
- **Location**: `data/deleted_emails/{user_id}/*.eml`
- **Mitigation**: Encrypt EML files with user's DEK

**3. Rate Limiting is In-Memory Only**
- **Risk**: Limits reset on app restart; no protection across multiple workers/instances
- **Impact**: MEDIUM — in multi-process deployments (Gunicorn 2+ workers), limits are per-worker
- **Mitigation**: Configure Flask-Limiter with a Redis backend for persistent, distributed limiting

### Low Priority

**4. Service Worker Caches Authenticated Pages**
- **Risk**: Cached pages accessible offline after logout
- **Impact**: LOW — requires physical device access
- **Mitigation**: Clear caches on logout

**5. No 2FA Backup Codes**
- **Risk**: Users locked out if TOTP device is lost
- **Impact**: LOW — admin can reset 2FA
- **Mitigation**: Generate and display single-use recovery codes at enrollment

---

## Security Roadmap

### Completed

- [x] Parameterized SQL (no SQL injection)
- [x] PBKDF2-HMAC-SHA256 password hashing
- [x] TOTP 2FA (optional per user)
- [x] Per-user data isolation
- [x] Hierarchical credential encryption (Fernet + PBKDF2, 480k iterations)
- [x] Flask-WTF CSRF protection on all forms
- [x] Security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] Session fixation protection (`session.clear()` on login)
- [x] Session cookie security flags (HttpOnly, Secure conditional, SameSite=Lax)
- [x] 30-minute session timeout with sliding expiry
- [x] Account lockout (5 failed attempts → 15-min lock)
- [x] Strong password policy (12+ chars, complexity) — enforced on all paths including admin reset
- [x] Discord webhook HMAC authentication
- [x] Discord per-action tokens (scoped, single-use, 72-hour TTL)
- [x] DB-tracked sessions with revoke UI and auto-revoke on credential change
- [x] Rate limits on `/api/scan`, `/api/predict`, `/training/train`
- [x] Audit log table for all admin and security events
- [x] Structured logging (module-level loggers, LOG_LEVEL env var)
- [x] Security events logged (failed logins, lockouts, 2FA changes, session revocations)
- [x] Session revoke on admin-triggered 2FA reset
- [x] Admin setting to enforce 2FA for all users
- [x] `debug` mode controlled by `DEBUG` env var (off by default)
- [x] Custom error pages — no stack traces exposed on 500
- [x] Request ID middleware (X-Request-ID header, end-to-end tracing)
- [x] Expanded /health endpoint (DB, encryption key, disk, models, scheduler)
- [x] IMAP retry with backoff (auth errors don't retry)

### Planned

- [x] **HIGH**: XSS in explain modal — email-derived content (keywords, reason detail) now escaped before innerHTML injection (`emails.js`)
- [ ] **MED**: Encrypt EML backup files with user DEK
- [ ] **MED**: Redis backend for persistent/distributed rate limiting
- [ ] **LOW**: Add backup codes for 2FA recovery
- [ ] **LOW**: WebAuthn/FIDO2 as 2FA option
- [ ] **LOW**: OpenAPI/Swagger documentation for all API endpoints
- [ ] **LOW**: GDPR data export (user data portability)

---

## Security Best Practices Summary

**✅ What's Implemented**:
- Parameterized SQL queries (no SQL injection)
- PBKDF2-HMAC-SHA256 password hashing
- 12+ char password policy with complexity requirements (all paths)
- Optional TOTP 2FA with auto-revoke on reset; admin-enforceable system-wide
- Per-user data isolation with foreign key enforcement
- Hierarchical encrypted credential storage (IMAP, Discord, SMTP)
- CSRF protection on all POST forms (Flask-WTF)
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- Session fixation protection, sliding 30-min expiry, DB-tracked revocation
- Account lockout after 5 failed attempts
- Discord webhook HMAC auth + per-action token validation
- Jinja2 auto-escaping (XSS protection on server-rendered HTML)
- Rate limiting on authentication, Discord, scan, predict, and training endpoints
- Audit logging for all admin actions and security events
- Structured logging with configurable level; no sensitive data in logs
- Custom 404/500 error pages (no stack trace exposure)
- Request ID tracing (X-Request-ID header)

**⚠️ Known Gaps (see Known Limitations)**:
- EML backup files stored unencrypted on disk
- Rate limiting is in-memory (per-worker, resets on restart)

**🔒 Deployment Essentials**:
1. Set `SECRET_KEY` and `ENCRYPTION_MASTER_KEY`
2. Set `USE_HTTPS=true` when behind a TLS reverse proxy
3. Deploy behind HTTPS reverse proxy (Nginx, Caddy)
4. Configure firewall (allow only 443/tcp + 22/tcp)
5. Set secure file permissions (600 for DB, 700 for EML backups)
6. Back up `ENCRYPTION_MASTER_KEY` separately from database backups

---

**Security Audit**: 2026-04-15 by Claude Code
**Version**: 0.7.1

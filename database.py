"""
Database operations for Spambuster.
Stores emails, labels, and scan history.
"""
import sqlite3
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

from config import Config


def get_db_connection():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session():
    """Context manager for database sessions."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize the database schema."""
    with db_session() as conn:
        cursor = conn.cursor()

        # Emails table - stores email content and metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                content TEXT,
                received_at TIMESTAMP,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                spam_score REAL,
                is_spam INTEGER,
                user_label INTEGER,
                action_taken TEXT,
                flagged INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, message_id)
            )
        """)

        # Training data table - for manually labeled emails
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT,
                label INTEGER,
                language TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id)
            )
        """)

        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                emails_scanned INTEGER,
                spam_detected INTEGER,
                mode TEXT,
                FOREIGN KEY (user_id) REFERENCES auth_users(id)
            )
        """)

        # Sender statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sender_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                email_address TEXT,
                display_name TEXT,
                total_emails INTEGER DEFAULT 0,
                spam_count INTEGER DEFAULT 0,
                safe_count INTEGER DEFAULT 0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, email_address)
            )
        """)

        # Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Whitelist/Blacklist table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sender_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                email_address TEXT,
                list_type TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reason TEXT,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, email_address)
            )
        """)

        # Deleted emails log (for rollback capability)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deleted_emails_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                email_id INTEGER,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                spam_score REAL,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                eml_file_path TEXT,
                expires_at TIMESTAMP,
                restored INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES auth_users(id)
            )
        """)

        # Spam keywords table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS spam_keywords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                keyword TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, keyword)
            )
        """)

        # Auth users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                email TEXT,
                role TEXT DEFAULT 'admin',
                is_active INTEGER DEFAULT 1,
                is_admin INTEGER DEFAULT 0,
                last_login TIMESTAMP,
                preferences TEXT,
                display_name TEXT,
                created_by INTEGER,
                password_changed_at TIMESTAMP,
                failed_login_count INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES auth_users(id)
            )
        """)

        # User sessions table (for session tracking)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_valid INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES auth_users(id)
            )
        """)

        # User settings table (for per-user preferences)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                setting_key TEXT NOT NULL,
                setting_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, setting_key)
            )
        """)

        # User credentials table (encrypted IMAP/Discord settings)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                imap_server_enc BLOB,
                imap_port INTEGER DEFAULT 993,
                email_address_enc BLOB,
                email_password_enc BLOB,
                discord_webhook_url_enc BLOB,
                discord_bot_token_enc BLOB,
                discord_channel_id TEXT,
                discord_webhook_secret_enc BLOB,
                discord_notify_threshold REAL DEFAULT 0.7,
                smtp_server_enc BLOB,
                smtp_port INTEGER DEFAULT 587,
                smtp_username_enc BLOB,
                smtp_password_enc BLOB,
                smtp_use_tls INTEGER DEFAULT 1,
                smtp_from_address_enc BLOB,
                encryption_version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
        """)

        # Encryption keys table (per-user key material)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                wrapped_key BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                key_version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rotated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
        """)

        # Discord action tokens (for securing Discord button interactions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discord_action_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        """)

        # System-wide settings (admin-controlled)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Audit log for security-relevant admin/user actions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                actor_user_id INTEGER,
                target_user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT
            )
        """)

        # Note: user_id indexes are created in run_migrations() after columns are added


def get_system_setting(key: str, default: str = None) -> Optional[str]:
    """Get a system-wide setting by key."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default


def set_system_setting(key: str, value: str):
    """Set a system-wide setting."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)",
            (key, value)
        )


def log_audit_event(actor_id: Optional[int], action: str,
                    target_user_id: Optional[int] = None,
                    details: Optional[str] = None,
                    ip: Optional[str] = None):
    """Log a security-relevant event to the audit log."""
    try:
        with db_session() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (actor_user_id, target_user_id, action, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """, (actor_id, target_user_id, action, details, ip))
    except Exception:
        pass  # Audit log failures must never crash the app


def get_audit_log(limit: int = 200) -> list:
    """Get the most recent audit log entries."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT al.*, u.username as actor_username, t.username as target_username
            FROM audit_log al
            LEFT JOIN auth_users u ON al.actor_user_id = u.id
            LEFT JOIN auth_users t ON al.target_user_id = t.id
            ORDER BY al.timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def save_email(user_id: int, message_id: str, sender: str, subject: str, content: str,
               received_at: datetime, spam_score: float, is_spam: bool,
               action_taken: str = None) -> int:
    """Save an email to the database for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO emails
            (user_id, message_id, sender, subject, content, received_at, spam_score, is_spam, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, message_id, sender, subject, content, received_at, spam_score,
              1 if is_spam else 0, action_taken))
        return cursor.lastrowid


def get_email_by_message_id(user_id: int, message_id: str) -> Optional[dict]:
    """Get an email by its message ID for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM emails WHERE user_id = ? AND message_id = ?",
            (user_id, message_id)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def email_exists(user_id: int, message_id: str) -> bool:
    """Check if an email already exists in the database for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM emails WHERE user_id = ? AND message_id = ?",
            (user_id, message_id)
        )
        return cursor.fetchone() is not None


def get_flagged_emails(user_id: int, limit: int = 100):
    """Get emails flagged for review for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM emails
            WHERE user_id = ? AND (flagged = 1 OR (is_spam = 1 AND user_label IS NULL))
            ORDER BY scanned_at DESC
            LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_recent_emails(user_id: int, limit: int = 100):
    """Get recently scanned emails for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM emails
            WHERE user_id = ?
            ORDER BY scanned_at DESC
            LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def label_email(user_id: int, email_id: int, is_spam: bool):
    """Label an email as spam or not spam for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE emails
            SET user_label = ?, flagged = 0
            WHERE id = ? AND user_id = ?
        """, (1 if is_spam else 0, email_id, user_id))


def get_training_data(user_id: int):
    """Get all training data including user-labeled emails for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()

        # Get explicitly added training data
        cursor.execute(
            "SELECT content, label FROM training_data WHERE user_id = ?",
            (user_id,)
        )
        training = [dict(row) for row in cursor.fetchall()]

        # Get user-labeled emails
        cursor.execute("""
            SELECT content, user_label as label
            FROM emails
            WHERE user_id = ? AND user_label IS NOT NULL
        """, (user_id,))
        labeled = [dict(row) for row in cursor.fetchall()]

        return training + labeled


def add_training_data(user_id: int, content: str, label: int, language: str = "unknown"):
    """Add training data manually for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO training_data (user_id, content, label, language)
            VALUES (?, ?, ?, ?)
        """, (user_id, content, label, language))


def save_scan_history(user_id: int, started_at: datetime, completed_at: datetime,
                      emails_scanned: int, spam_detected: int, mode: str):
    """Save scan history for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history
            (user_id, started_at, completed_at, emails_scanned, spam_detected, mode)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, started_at, completed_at, emails_scanned, spam_detected, mode))


def get_scan_history(user_id: int, limit: int = 20):
    """Get recent scan history for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_history
            WHERE user_id = ?
            ORDER BY started_at DESC
            LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_stats(user_id: int):
    """Get overall statistics for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()

        # Core email counts
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END) as spam,
                SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END) as safe,
                SUM(CASE WHEN user_label IS NOT NULL THEN 1 ELSE 0 END) as labeled,
                SUM(CASE WHEN action_taken IS NOT NULL AND action_taken != 'none' THEN 1 ELSE 0 END) as actions_taken,
                SUM(CASE WHEN user_label IS NOT NULL AND user_label = is_spam THEN 1 ELSE 0 END) as correct_predictions
            FROM emails WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        total_emails = row["total"]
        spam_count = row["spam"] or 0
        safe_count = row["safe"] or 0
        labeled_count = row["labeled"] or 0
        actions_taken = row["actions_taken"] or 0
        correct_predictions = row["correct_predictions"] or 0

        # Action breakdown for pie chart
        cursor.execute("""
            SELECT action_taken, COUNT(*) as count
            FROM emails
            WHERE user_id = ? AND action_taken IS NOT NULL AND action_taken != 'none'
            GROUP BY action_taken
        """, (user_id,))
        action_breakdown = {r["action_taken"]: r["count"] for r in cursor.fetchall()}

        cursor.execute(
            "SELECT COUNT(*) as training FROM training_data WHERE user_id = ?",
            (user_id,)
        )
        training_count = cursor.fetchone()["training"]

        # Total training samples = manual training data + user-labeled emails
        total_training = training_count + labeled_count

        # Model accuracy: % of user labels that match classifier prediction
        model_accuracy = round(correct_predictions / labeled_count * 100, 1) if labeled_count > 0 else 0
        # Protection rate
        protection_rate = round(spam_count / total_emails * 100, 1) if total_emails > 0 else 0

        return {
            "total_emails": total_emails,
            "spam_detected": spam_count,
            "safe_count": safe_count,
            "user_labeled": labeled_count,
            "training_samples": total_training,
            "protection_rate": protection_rate,
            "model_accuracy": model_accuracy,
            "actions_taken": actions_taken,
            "action_breakdown": action_breakdown,
        }


def update_sender_stats(user_id: int, sender: str, is_spam: bool):
    """Update statistics for a sender for a specific user."""
    import re
    from datetime import datetime

    # Extract email address from sender string
    email_match = re.search(r'<([^>]+)>', sender)
    if email_match:
        email_address = email_match.group(1).lower()
        display_name = sender.split('<')[0].strip().strip('"')
    else:
        email_address = sender.lower().strip()
        display_name = ""

    now = datetime.now()

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM sender_stats WHERE user_id = ? AND email_address = ?",
            (user_id, email_address)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE sender_stats SET
                    total_emails = total_emails + 1,
                    spam_count = spam_count + ?,
                    safe_count = safe_count + ?,
                    last_seen = ?
                WHERE user_id = ? AND email_address = ?
            """, (1 if is_spam else 0, 0 if is_spam else 1, now, user_id, email_address))
        else:
            cursor.execute("""
                INSERT INTO sender_stats
                (user_id, email_address, display_name, total_emails, spam_count, safe_count, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """, (user_id, email_address, display_name, 1 if is_spam else 0, 0 if is_spam else 1, now, now))


def get_sender_stats(user_id: int, email_address: str) -> Optional[dict]:
    """Get statistics for a specific sender for a user."""
    import re
    # Extract just the email if it's in format "Name <email>"
    email_match = re.search(r'<([^>]+)>', email_address)
    if email_match:
        email_address = email_match.group(1).lower()
    else:
        email_address = email_address.lower().strip()

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM sender_stats WHERE user_id = ? AND email_address = ?",
            (user_id, email_address)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_sender_stats(user_id: int, limit: int = 100):
    """Get all sender statistics ordered by spam count for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM sender_stats
            WHERE user_id = ?
            ORDER BY spam_count DESC, total_emails DESC
            LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_setting(key: str, default: str = None) -> Optional[str]:
    """Get a setting value."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str):
    """Set a setting value."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?)
        """, (key, value))


def cleanup_all(user_id: int):
    """Delete all data from the database for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM emails WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM training_data WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM sender_stats WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM sender_lists WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM deleted_emails_log WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM spam_keywords WHERE user_id = ?", (user_id,))
        # Keep settings
    return True


def add_to_list(user_id: int, email_address: str, list_type: str, reason: str = None):
    """Add a sender to whitelist or blacklist for a specific user."""
    import re
    # Extract email if in format "Name <email>"
    match = re.search(r'<([^>]+)>', email_address)
    if match:
        email_address = match.group(1).lower()
    else:
        email_address = email_address.lower().strip()

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO sender_lists (user_id, email_address, list_type, reason)
            VALUES (?, ?, ?, ?)
        """, (user_id, email_address, list_type, reason))


def remove_from_list(user_id: int, email_address: str):
    """Remove a sender from whitelist/blacklist for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM sender_lists WHERE user_id = ? AND email_address = ?",
            (user_id, email_address.lower())
        )


def get_sender_list_status(user_id: int, email_address: str) -> Optional[str]:
    """Check if sender is on whitelist or blacklist for a user."""
    import re
    match = re.search(r'<([^>]+)>', email_address)
    if match:
        email_address = match.group(1).lower()
    else:
        email_address = email_address.lower().strip()

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT list_type FROM sender_lists WHERE user_id = ? AND email_address = ?",
            (user_id, email_address)
        )
        row = cursor.fetchone()
        return row["list_type"] if row else None


def get_all_listed_senders(user_id: int):
    """Get all whitelisted and blacklisted senders for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM sender_lists WHERE user_id = ? ORDER BY list_type, email_address",
            (user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_spam_stats_by_day(user_id: int, days: int = 30):
    """Get spam statistics grouped by day for charts for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                DATE(scanned_at) as date,
                COUNT(*) as total,
                SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END) as spam,
                SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END) as safe
            FROM emails
            WHERE user_id = ? AND scanned_at >= DATE('now', ?)
            GROUP BY DATE(scanned_at)
            ORDER BY date
        """, (user_id, f'-{days} days'))
        return [dict(row) for row in cursor.fetchall()]


def log_deleted_email(user_id: int, email_id: int, message_id: str, sender: str, subject: str,
                      spam_score: float, eml_file_path: str, retention_days: int = 30):
    """Log a deleted email for potential rollback for a user."""
    from datetime import datetime, timedelta

    expires_at = datetime.now() + timedelta(days=retention_days)

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO deleted_emails_log
            (user_id, email_id, message_id, sender, subject, spam_score, eml_file_path, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, email_id, message_id, sender, subject, spam_score, eml_file_path, expires_at))
        return cursor.lastrowid


def get_deleted_emails_log(user_id: int, limit: int = 100, include_restored: bool = False):
    """Get log of deleted emails for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        if include_restored:
            cursor.execute("""
                SELECT * FROM deleted_emails_log
                WHERE user_id = ?
                ORDER BY deleted_at DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM deleted_emails_log
                WHERE user_id = ? AND restored = 0
                ORDER BY deleted_at DESC
                LIMIT ?
            """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def mark_email_restored(user_id: int, log_id: int):
    """Mark a deleted email as restored for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE deleted_emails_log
            SET restored = 1
            WHERE id = ? AND user_id = ?
        """, (log_id, user_id))


def get_deleted_email_log_entry(user_id: int, log_id: int) -> Optional[dict]:
    """Get a specific deleted email log entry for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM deleted_emails_log WHERE id = ? AND user_id = ?",
            (log_id, user_id)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def cleanup_expired_deleted_logs(user_id: int = None):
    """Remove expired deleted email logs and their .eml files.

    If user_id is provided, only clean up that user's logs.
    Otherwise, clean up all expired logs (for system maintenance).
    """
    import os
    from datetime import datetime

    with db_session() as conn:
        cursor = conn.cursor()
        # Get expired entries
        if user_id is not None:
            cursor.execute("""
                SELECT id, eml_file_path FROM deleted_emails_log
                WHERE user_id = ? AND expires_at < ? AND restored = 0
            """, (user_id, datetime.now()))
        else:
            cursor.execute("""
                SELECT id, eml_file_path FROM deleted_emails_log
                WHERE expires_at < ? AND restored = 0
            """, (datetime.now(),))
        expired = cursor.fetchall()

        deleted_count = 0
        for entry in expired:
            # Delete .eml file
            if entry["eml_file_path"] and os.path.exists(entry["eml_file_path"]):
                try:
                    os.remove(entry["eml_file_path"])
                except Exception:
                    pass

            # Delete log entry
            cursor.execute("DELETE FROM deleted_emails_log WHERE id = ?", (entry["id"],))
            deleted_count += 1

        return deleted_count


def get_deleted_stats(user_id: int):
    """Get statistics about deleted emails for a user."""
    with db_session() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) as total FROM deleted_emails_log WHERE user_id = ? AND restored = 0",
            (user_id,)
        )
        pending = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) as total FROM deleted_emails_log WHERE user_id = ? AND restored = 1",
            (user_id,)
        )
        restored = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT COUNT(*) as total FROM deleted_emails_log
            WHERE user_id = ? AND expires_at < datetime('now') AND restored = 0
        """, (user_id,))
        expired = cursor.fetchone()["total"]

        return {
            "pending_rollback": pending,
            "restored": restored,
            "expired": expired
        }


def get_spam_keywords(user_id: int):
    """Get all spam keywords from database for a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT keyword FROM spam_keywords WHERE user_id = ? ORDER BY keyword",
            (user_id,)
        )
        return [row["keyword"] for row in cursor.fetchall()]


def add_spam_keyword(user_id: int, keyword: str) -> bool:
    """Add a spam keyword for a user. Returns True if added, False if already exists."""
    keyword = keyword.lower().strip()
    if not keyword:
        return False

    with db_session() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO spam_keywords (user_id, keyword) VALUES (?, ?)",
                (user_id, keyword)
            )
            return True
        except sqlite3.IntegrityError:
            return False


def remove_spam_keyword(user_id: int, keyword: str) -> bool:
    """Remove a spam keyword for a user. Returns True if removed."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM spam_keywords WHERE user_id = ? AND keyword = ?",
            (user_id, keyword.lower().strip())
        )
        return cursor.rowcount > 0


def init_default_spam_keywords(user_id: int, keywords: set):
    """Initialize default spam keywords if user has none."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as count FROM spam_keywords WHERE user_id = ?",
            (user_id,)
        )
        if cursor.fetchone()["count"] == 0:
            for keyword in keywords:
                try:
                    cursor.execute(
                        "INSERT INTO spam_keywords (user_id, keyword) VALUES (?, ?)",
                        (user_id, keyword.lower())
                    )
                except sqlite3.IntegrityError:
                    pass


def has_users() -> bool:
    """Check if any auth users exist."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM auth_users")
        return cursor.fetchone()["count"] > 0


def create_user(username: str, password_hash: str, totp_secret: str = None, totp_enabled: bool = False):
    """Create a new auth user."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auth_users (username, password_hash, totp_secret, totp_enabled) VALUES (?, ?, ?, ?)",
            (username, password_hash, totp_secret, 1 if totp_enabled else 0)
        )


def get_user(username: str) -> Optional[dict]:
    """Get a user by username."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auth_users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get a user by their ID."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auth_users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_user_password(user_id: int, password_hash: str) -> bool:
    """Update a user's password hash."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE auth_users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id)
        )
        return cursor.rowcount > 0


def regenerate_totp_secret(user_id: int, new_secret: str) -> bool:
    """Regenerate a user's TOTP secret."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE auth_users SET totp_secret = ? WHERE id = ?",
            (new_secret, user_id)
        )
        return cursor.rowcount > 0


def update_last_login(user_id: int):
    """Update the last login timestamp for a user."""
    from datetime import datetime
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE auth_users SET last_login = ? WHERE id = ?",
            (datetime.now(), user_id)
        )


def is_account_locked(username: str) -> tuple[bool, int]:
    """
    Check if an account is locked due to failed login attempts.

    Args:
        username: Username to check

    Returns:
        Tuple of (is_locked, seconds_until_unlock)
    """
    from datetime import datetime
    user = get_user(username)
    if not user:
        return False, 0

    locked_until = user.get("locked_until")
    if not locked_until:
        return False, 0

    # Parse timestamp
    if isinstance(locked_until, str):
        try:
            locked_until = datetime.fromisoformat(locked_until)
        except ValueError:
            return False, 0
    elif not isinstance(locked_until, datetime):
        return False, 0

    now = datetime.now()
    if now < locked_until:
        # Account is still locked
        seconds_remaining = int((locked_until - now).total_seconds())
        return True, seconds_remaining
    else:
        # Lock has expired, clear it
        reset_failed_login_attempts(user["id"])
        return False, 0


def record_failed_login(username: str):
    """
    Record a failed login attempt and lock account if threshold exceeded.

    Locks account for 15 minutes after 5 failed attempts.

    Args:
        username: Username that failed login
    """
    from datetime import datetime, timedelta

    user = get_user(username)
    if not user:
        return  # Don't leak whether username exists

    failed_count = user.get("failed_login_count", 0) + 1

    with db_session() as conn:
        cursor = conn.cursor()

        if failed_count >= 5:
            # Lock account for 15 minutes
            locked_until = datetime.now() + timedelta(minutes=15)
            cursor.execute(
                """UPDATE auth_users
                   SET failed_login_count = ?, locked_until = ?
                   WHERE id = ?""",
                (failed_count, locked_until, user["id"])
            )
        else:
            cursor.execute(
                """UPDATE auth_users
                   SET failed_login_count = ?
                   WHERE id = ?""",
                (failed_count, user["id"])
            )


def reset_failed_login_attempts(user_id: int):
    """
    Reset failed login attempts after successful login.

    Args:
        user_id: User ID
    """
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE auth_users
               SET failed_login_count = 0, locked_until = NULL
               WHERE id = ?""",
            (user_id,)
        )


def run_migrations():
    """Run database migrations to add new columns to existing tables."""
    with db_session() as conn:
        cursor = conn.cursor()

        # Check and add new columns to auth_users table
        cursor.execute("PRAGMA table_info(auth_users)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        auth_user_columns = [
            ("email", "TEXT"),
            ("role", "TEXT DEFAULT 'admin'"),
            ("is_active", "INTEGER DEFAULT 1"),
            ("is_admin", "INTEGER DEFAULT 0"),
            ("last_login", "TIMESTAMP"),
            ("preferences", "TEXT"),
            ("display_name", "TEXT"),
            ("created_by", "INTEGER"),
            ("password_changed_at", "TIMESTAMP"),
            ("failed_login_count", "INTEGER DEFAULT 0"),
            ("locked_until", "TIMESTAMP"),
        ]

        for col_name, col_type in auth_user_columns:
            if col_name not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE auth_users ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

        # Add user_id column to data tables for multi-tenancy
        tables_needing_user_id = [
            'emails', 'training_data', 'scan_history', 'sender_lists',
            'deleted_emails_log', 'spam_keywords', 'sender_stats'
        ]

        for table in tables_needing_user_id:
            cursor.execute(f"PRAGMA table_info({table})")
            cols = {row[1] for row in cursor.fetchall()}
            if 'user_id' not in cols:
                try:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER")
                except sqlite3.OperationalError:
                    pass

        # Create user_sessions table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                is_valid INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES auth_users(id)
            )
        """)

        # Create user_settings table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                setting_key TEXT NOT NULL,
                setting_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                UNIQUE(user_id, setting_key)
            )
        """)

        # Create user_credentials table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                imap_server_enc BLOB,
                imap_port INTEGER DEFAULT 993,
                email_address_enc BLOB,
                email_password_enc BLOB,
                discord_webhook_url_enc BLOB,
                discord_bot_token_enc BLOB,
                discord_channel_id TEXT,
                discord_webhook_secret_enc BLOB,
                discord_notify_threshold REAL DEFAULT 0.7,
                encryption_version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
        """)

        # Create encryption_keys table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                wrapped_key BLOB NOT NULL,
                key_salt BLOB NOT NULL,
                key_version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rotated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
        """)

        # Add SMTP columns to user_credentials if missing
        cursor.execute("PRAGMA table_info(user_credentials)")
        cred_columns = {row[1] for row in cursor.fetchall()}
        smtp_columns = [
            ("smtp_server_enc", "BLOB"),
            ("smtp_port", "INTEGER DEFAULT 587"),
            ("smtp_username_enc", "BLOB"),
            ("smtp_password_enc", "BLOB"),
            ("smtp_use_tls", "INTEGER DEFAULT 1"),
            ("smtp_from_address_enc", "BLOB"),
        ]
        for col_name, col_type in smtp_columns:
            if col_name not in cred_columns:
                try:
                    cursor.execute(f"ALTER TABLE user_credentials ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass

        # Create discord_action_tokens table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discord_action_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES auth_users(id),
                FOREIGN KEY (email_id) REFERENCES emails(id)
            )
        """)

        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_training_data_user_id ON training_data(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sender_lists_user_id ON sender_lists(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_spam_keywords_user_id ON spam_keywords(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sender_stats_user_id ON sender_stats(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deleted_emails_log_user_id ON deleted_emails_log(user_id)")


def run_saas_migrations():
    """
    Run SaaS conversion migrations.
    - Mark first user as admin
    - Assign orphaned data to admin user
    - Migrate global settings to user_settings
    - Add totp_enabled column for optional 2FA
    """
    with db_session() as conn:
        cursor = conn.cursor()

        # Migration: Add totp_enabled column if missing
        cursor.execute("PRAGMA table_info(auth_users)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'totp_enabled' not in columns:
            cursor.execute("ALTER TABLE auth_users ADD COLUMN totp_enabled INTEGER DEFAULT 1")
            # Set totp_enabled=1 for existing users who have totp_secret
            cursor.execute("UPDATE auth_users SET totp_enabled = 1 WHERE totp_secret IS NOT NULL")

        # Find first user and mark as admin
        cursor.execute("SELECT id FROM auth_users ORDER BY id LIMIT 1")
        admin = cursor.fetchone()
        if not admin:
            return  # No users yet, nothing to migrate

        admin_id = admin[0]

        # Mark first user as admin if not already
        cursor.execute(
            "UPDATE auth_users SET is_admin = 1 WHERE id = ? AND is_admin = 0",
            (admin_id,)
        )

        # Assign orphaned data to admin user
        tables = [
            'emails', 'training_data', 'scan_history', 'sender_lists',
            'deleted_emails_log', 'spam_keywords', 'sender_stats'
        ]
        for table in tables:
            cursor.execute(
                f"UPDATE {table} SET user_id = ? WHERE user_id IS NULL",
                (admin_id,)
            )

        # Migrate global settings to user_settings for admin
        settings_to_migrate = [
            'operation_mode', 'weight_urls', 'weight_model', 'weight_keywords',
            'threshold_delete', 'threshold_move', 'threshold_warn',
            'warning_prefix', 'warning_html', 'warning_text'
        ]

        for key in settings_to_migrate:
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                cursor.execute("""
                    INSERT OR IGNORE INTO user_settings (user_id, setting_key, setting_value)
                    VALUES (?, ?, ?)
                """, (admin_id, key, row[0]))


# ============================================================================
# User Settings Functions (per-user settings)
# ============================================================================

def get_user_setting(user_id: int, key: str, default: str = None) -> Optional[str]:
    """Get a user-specific setting value."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT setting_value FROM user_settings WHERE user_id = ? AND setting_key = ?",
            (user_id, key)
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        # Fallback to global settings
        return get_setting(key, default)


def set_user_setting(user_id: int, key: str, value: str):
    """Set a user-specific setting value."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO user_settings (user_id, setting_key, setting_value, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (user_id, key, value))


# ============================================================================
# Admin Functions
# ============================================================================

def get_all_users() -> list:
    """Get all users."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, role, is_active, is_admin,
                   created_at, last_login, display_name
            FROM auth_users
            ORDER BY id
        """)
        return [dict(row) for row in cursor.fetchall()]


def get_all_users_with_stats() -> list:
    """Get all users with their statistics."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                u.id, u.username, u.email, u.role, u.is_active, u.is_admin,
                u.created_at, u.last_login, u.display_name,
                CASE WHEN u.totp_secret IS NOT NULL AND u.totp_secret != '' THEN 1 ELSE 0 END as totp_enabled,
                (SELECT COUNT(*) FROM emails WHERE user_id = u.id) as email_count,
                (SELECT COUNT(*) FROM emails WHERE user_id = u.id AND is_spam = 1) as spam_count,
                (SELECT COUNT(*) FROM training_data WHERE user_id = u.id) as training_count
            FROM auth_users u
            ORDER BY u.id
        """)
        return [dict(row) for row in cursor.fetchall()]


def create_user_full(username: str, password_hash: str, totp_secret: str = None,
                     email: str = None, is_admin: bool = False, totp_enabled: bool = False,
                     created_by: int = None, display_name: str = None) -> int:
    """Create a new user with all optional fields."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auth_users
            (username, password_hash, totp_secret, totp_enabled, email, is_admin, created_by, display_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, password_hash, totp_secret, 1 if totp_enabled else 0, email,
              1 if is_admin else 0, created_by, display_name))
        return cursor.lastrowid


def update_user_role(user_id: int, is_admin: bool) -> bool:
    """Update a user's admin status."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE auth_users SET is_admin = ? WHERE id = ?",
            (1 if is_admin else 0, user_id)
        )
        return cursor.rowcount > 0


def update_user_active(user_id: int, is_active: bool) -> bool:
    """Update a user's active status."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE auth_users SET is_active = ? WHERE id = ?",
            (1 if is_active else 0, user_id)
        )
        return cursor.rowcount > 0


def delete_user(user_id: int) -> bool:
    """Delete a user account."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM auth_users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0


def delete_user_data(user_id: int):
    """Delete all data associated with a user."""
    with db_session() as conn:
        cursor = conn.cursor()
        tables = [
            'emails', 'training_data', 'scan_history', 'sender_lists',
            'deleted_emails_log', 'spam_keywords', 'sender_stats',
            'user_settings', 'user_sessions', 'user_credentials', 'encryption_keys'
        ]
        for table in tables:
            cursor.execute(f"DELETE FROM {table} WHERE user_id = ?", (user_id,))


def get_user_stats(user_id: int) -> dict:
    """Get statistics for a specific user."""
    with db_session() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total FROM emails WHERE user_id = ?", (user_id,))
        total_emails = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as spam FROM emails WHERE user_id = ? AND is_spam = 1", (user_id,))
        spam_count = cursor.fetchone()["spam"]

        cursor.execute("SELECT COUNT(*) as labeled FROM emails WHERE user_id = ? AND user_label IS NOT NULL", (user_id,))
        labeled_count = cursor.fetchone()["labeled"]

        cursor.execute("SELECT COUNT(*) as training FROM training_data WHERE user_id = ?", (user_id,))
        training_count = cursor.fetchone()["training"]

        cursor.execute("SELECT COUNT(*) as scans FROM scan_history WHERE user_id = ?", (user_id,))
        scan_count = cursor.fetchone()["scans"]

        return {
            "total_emails": total_emails,
            "spam_detected": spam_count,
            "user_labeled": labeled_count,
            "training_samples": training_count + labeled_count,
            "scan_count": scan_count
        }


def get_system_stats() -> dict:
    """Get system-wide statistics (for admin dashboard)."""
    with db_session() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total FROM auth_users")
        total_users = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM auth_users WHERE is_admin = 1")
        admin_users = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM emails")
        total_emails = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM emails WHERE is_spam = 1")
        total_spam = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM training_data")
        total_training = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM scan_history")
        total_scans = cursor.fetchone()["total"]

        # Calculate spam rate
        spam_rate = (total_spam / total_emails * 100) if total_emails > 0 else 0.0

        return {
            "total_users": total_users,
            "admin_users": admin_users,
            "total_emails": total_emails,
            "total_spam": total_spam,
            "total_training": total_training,
            "total_scans": total_scans,
            "spam_rate": spam_rate
        }


def count_admins() -> int:
    """Count the number of admin users."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM auth_users WHERE is_admin = 1")
        return cursor.fetchone()["count"]


# ============================================================================
# Discord Action Token Functions
# ============================================================================

def create_discord_action_token(user_id: int, email_id: int, ttl_hours: int = 72) -> str:
    """Create a token for securing Discord button actions."""
    import secrets
    from datetime import datetime, timedelta

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=ttl_hours)

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO discord_action_tokens (user_id, email_id, token, expires_at)
            VALUES (?, ?, ?, ?)
        """, (user_id, email_id, token, expires_at))

    return token


def validate_discord_action_token(token: str, email_id: int) -> Optional[int]:
    """Validate a Discord action token. Returns user_id if valid, None otherwise."""
    from datetime import datetime

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id FROM discord_action_tokens
            WHERE token = ? AND email_id = ? AND used = 0 AND expires_at > ?
        """, (token, email_id, datetime.now()))
        row = cursor.fetchone()
        return row["user_id"] if row else None


def invalidate_discord_action_token(token: str):
    """Mark a Discord action token as used."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE discord_action_tokens SET used = 1 WHERE token = ?",
            (token,)
        )


def cleanup_expired_discord_tokens():
    """Delete expired Discord action tokens."""
    from datetime import datetime

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM discord_action_tokens WHERE expires_at < ? OR used = 1",
            (datetime.now(),)
        )
        return cursor.rowcount


# ============================================================================
# Session Management Functions
# ============================================================================

def create_user_session(user_id: int, session_token: str, ip_address: str,
                        user_agent: str, ttl_minutes: int = 30) -> int:
    """Create a new user session record."""
    from datetime import datetime, timedelta

    expires_at = datetime.now() + timedelta(minutes=ttl_minutes)

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, session_token, expires_at, ip_address, user_agent))
        return cursor.lastrowid


def get_user_sessions(user_id: int) -> list:
    """Get all valid sessions for a user."""
    from datetime import datetime

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, session_token, created_at, expires_at, ip_address, user_agent, is_valid
            FROM user_sessions
            WHERE user_id = ? AND is_valid = 1 AND expires_at > ?
            ORDER BY created_at DESC
        """, (user_id, datetime.now()))
        return [dict(row) for row in cursor.fetchall()]


def validate_user_session(session_token: str) -> Optional[dict]:
    """Validate a session token. Returns session row if valid, None otherwise."""
    from datetime import datetime

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, session_token, expires_at
            FROM user_sessions
            WHERE session_token = ? AND is_valid = 1 AND expires_at > ?
        """, (session_token, datetime.now()))
        row = cursor.fetchone()
        return dict(row) if row else None


def revoke_session(user_id: int, session_id: int) -> bool:
    """Revoke a specific session."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET is_valid = 0 WHERE id = ? AND user_id = ?",
            (session_id, user_id)
        )
        return cursor.rowcount > 0


def revoke_all_other_sessions(user_id: int, current_session_token: str) -> int:
    """Revoke all sessions except the current one."""
    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET is_valid = 0 WHERE user_id = ? AND session_token != ?",
            (user_id, current_session_token)
        )
        return cursor.rowcount


def extend_session(session_token: str, ttl_minutes: int = 30):
    """Extend a session's expiration time."""
    from datetime import datetime, timedelta

    new_expires = datetime.now() + timedelta(minutes=ttl_minutes)

    with db_session() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE user_sessions SET expires_at = ? WHERE session_token = ? AND is_valid = 1",
            (new_expires, session_token)
        )


def cleanup_expired_sessions():
    """Delete expired and invalidated sessions."""
    from datetime import datetime, timedelta

    with db_session() as conn:
        cursor = conn.cursor()
        # Delete expired sessions and sessions invalidated more than 24h ago
        cursor.execute("""
            DELETE FROM user_sessions
            WHERE expires_at < ? OR (is_valid = 0 AND expires_at < ?)
        """, (datetime.now(), datetime.now() - timedelta(hours=24)))
        return cursor.rowcount

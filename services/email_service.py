"""
Email service for connecting to IMAP servers and fetching emails.
Per-user credential support for multi-tenant SaaS.
"""
import logging
import imaplib
import email
import time
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass
import re as _re

logger = logging.getLogger(__name__)

_IMAP_MAX_RETRIES = 3
_IMAP_RETRY_DELAYS = [1, 3, 7]

from config import Config


@dataclass
class EmailMessage:
    """Represents an email message."""
    message_id: str
    sender: str
    subject: str
    content: str
    received_at: datetime
    raw_email: bytes
    uid: bytes


class EmailService:
    """Service for interacting with email via IMAP. Per-user credential support."""

    def __init__(self, user_id: int):
        """
        Initialize email service for a specific user.

        Args:
            user_id: User ID for credential lookup
        """
        self.user_id = user_id
        self.connection: Optional[imaplib.IMAP4_SSL] = None
        self._credentials = None

    def _get_credentials(self):
        """Get IMAP credentials for this user."""
        if self._credentials is None:
            from services.credentials import get_credentials_manager
            manager = get_credentials_manager()
            self._credentials = manager.get_imap_credentials(self.user_id)
        return self._credentials

    def connect(self) -> bool:
        """Connect to the IMAP server using user's credentials, with retry backoff."""
        creds = self._get_credentials()

        if not creds.is_configured():
            logger.warning("IMAP credentials not configured for user %s", self.user_id)
            return False

        for attempt in range(_IMAP_MAX_RETRIES):
            try:
                self.connection = imaplib.IMAP4_SSL(creds.server, creds.port)
                self.connection.login(creds.email_address, creds.password)
                logger.info("Connected to %s for user %s", creds.server, self.user_id)
                return True
            except imaplib.IMAP4.error as e:
                # Auth failure — no point retrying
                logger.error("IMAP auth error for user %s: %s", self.user_id, e)
                return False
            except Exception as e:
                if attempt < _IMAP_MAX_RETRIES - 1:
                    delay = _IMAP_RETRY_DELAYS[attempt]
                    logger.warning(
                        "IMAP connect attempt %d/%d failed for user %s, retrying in %ds: %s",
                        attempt + 1, _IMAP_MAX_RETRIES, self.user_id, delay, e
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        "IMAP connect failed after %d attempts for user %s: %s",
                        _IMAP_MAX_RETRIES, self.user_id, e
                    )
                    return False
        return False

    def disconnect(self):
        """Disconnect from the IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except Exception:
                pass
            self.connection = None

    def select_folder(self, folder: str = "INBOX") -> bool:
        """Select a mailbox folder."""
        if not self.connection:
            return False
        try:
            status, _ = self.connection.select(folder)
            return status == "OK"
        except Exception as e:
            logger.error("Failed to select folder %s: %s", folder, e)
            return False

    def _decode_header(self, header: str) -> str:
        """Decode an email header."""
        if header is None:
            return ""
        decoded_parts = decode_header(header)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    result.append(part.decode(encoding or "utf-8", errors="ignore"))
                except Exception:
                    result.append(part.decode("utf-8", errors="ignore"))
            else:
                result.append(part)
        return " ".join(result)

    def _extract_content(self, msg: email.message.Message) -> str:
        """Extract text content from an email message."""
        content_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            content_parts.append(payload.decode(charset, errors="ignore"))
                        except Exception:
                            content_parts.append(payload.decode("utf-8", errors="ignore"))
                elif content_type == "text/html" and not content_parts:
                    # Fallback to HTML if no plain text
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            content_parts.append(payload.decode(charset, errors="ignore"))
                        except Exception:
                            content_parts.append(payload.decode("utf-8", errors="ignore"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    content_parts.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    content_parts.append(payload.decode("utf-8", errors="ignore"))

        return "\n".join(content_parts)

    def _parse_date(self, date_str: str) -> datetime:
        """Parse email date string."""
        if not date_str:
            return datetime.now()
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except Exception:
            return datetime.now()

    def fetch_emails(self, folder: str = "INBOX", limit: int = None,
                     unseen_only: bool = False) -> List[EmailMessage]:
        """
        Fetch emails from the specified folder.

        Args:
            folder: Mailbox folder to fetch from
            limit: Maximum number of emails to fetch
            unseen_only: Only fetch unseen emails

        Returns:
            List of EmailMessage objects
        """
        if not self.connection:
            if not self.connect():
                return []

        if not self.select_folder(folder):
            return []

        limit = limit or Config.MAX_EMAILS_PER_SCAN

        try:
            # Search for emails
            search_criteria = "UNSEEN" if unseen_only else "ALL"
            status, messages = self.connection.search(None, search_criteria)

            if status != "OK":
                return []

            email_ids = messages[0].split()

            # Get most recent emails (last N)
            email_ids = email_ids[-limit:]

            emails = []
            for uid in email_ids:
                try:
                    status, msg_data = self.connection.fetch(uid, "(RFC822)")
                    if status != "OK":
                        continue

                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)

                    message_id = msg.get("Message-ID", f"unknown-{uid.decode()}")
                    sender = self._decode_header(msg.get("From", ""))
                    subject = self._decode_header(msg.get("Subject", "(No Subject)"))
                    content = self._extract_content(msg)
                    received_at = self._parse_date(msg.get("Date"))

                    emails.append(EmailMessage(
                        message_id=message_id,
                        sender=sender,
                        subject=subject,
                        content=content,
                        received_at=received_at,
                        raw_email=raw_email,
                        uid=uid
                    ))
                except Exception as e:
                    logger.warning("Error parsing email %s: %s", uid, e)
                    continue

            return emails

        except Exception as e:
            logger.error("Error fetching emails: %s", e)
            return []

    def flag_email(self, uid: bytes, flag: str = "\\Flagged") -> bool:
        """Add a flag to an email."""
        if not self.connection:
            return False
        try:
            status, _ = self.connection.store(uid, "+FLAGS", flag)
            return status == "OK"
        except Exception as e:
            logger.error("Error flagging email: %s", e)
            return False

    def move_to_spam(self, uid: bytes, spam_folder: str = "Spam") -> bool:
        """Move an email to the spam folder."""
        if not self.connection:
            return False
        try:
            # Try common spam folder names
            spam_folders = [spam_folder, "Junk", "Junk E-mail", "[Gmail]/Spam", "INBOX.Spam"]

            for folder in spam_folders:
                try:
                    status, _ = self.connection.copy(uid, folder)
                    if status == "OK":
                        # Mark original as deleted
                        self.connection.store(uid, "+FLAGS", "\\Deleted")
                        self.connection.expunge()
                        return True
                except Exception:
                    continue

            # If no spam folder found, just flag it
            return self.flag_email(uid)

        except Exception as e:
            logger.error("Error moving email to spam: %s", e)
            return False

    def delete_email(self, uid: bytes) -> bool:
        """Delete an email."""
        if not self.connection:
            return False
        try:
            status, _ = self.connection.store(uid, "+FLAGS", "\\Deleted")
            if status == "OK":
                self.connection.expunge()
                return True
            return False
        except Exception as e:
            logger.error("Error deleting email: %s", e)
            return False

    def move_to_inbox(self, uid: bytes, from_folder: str = "Spam") -> bool:
        """Move an email back to inbox (restore from spam/junk)."""
        if not self.connection:
            if not self.connect():
                return False

        try:
            # Select the source folder
            if not self.select_folder(from_folder):
                # Try common spam folder names
                spam_folders = ["Spam", "Junk", "Junk E-mail", "[Gmail]/Spam", "INBOX.Spam"]
                selected = False
                for folder in spam_folders:
                    if self.select_folder(folder):
                        selected = True
                        break
                if not selected:
                    return False

            # Copy to inbox
            status, _ = self.connection.copy(uid, "INBOX")
            if status == "OK":
                # Mark original as deleted
                self.connection.store(uid, "+FLAGS", "\\Deleted")
                self.connection.expunge()
                return True
            return False

        except Exception as e:
            logger.error("Error moving email to inbox: %s", e)
            return False

    def restore_from_trash(self, uid: bytes) -> bool:
        """Move an email from trash back to inbox."""
        if not self.connection:
            if not self.connect():
                return False

        try:
            deleted_folder = self.get_deleted_folder_name()
            if not deleted_folder:
                return False

            if not self.select_folder(deleted_folder):
                return False

            # Copy to inbox
            status, _ = self.connection.copy(uid, "INBOX")
            if status == "OK":
                # Mark original as deleted
                self.connection.store(uid, "+FLAGS", "\\Deleted")
                self.connection.expunge()
                return True
            return False

        except Exception as e:
            logger.error("Error restoring email from trash: %s", e)
            return False

    def get_spam_folder_name(self) -> Optional[str]:
        """Find the spam/junk folder name."""
        folders = self.list_folders()
        spam_names = ["Spam", "Junk", "Junk E-mail", "[Gmail]/Spam",
                      "INBOX.Spam", "Ongewenste e-mail"]

        for name in spam_names:
            if name in folders:
                return name
            for folder in folders:
                if folder.lower() == name.lower():
                    return folder
        return None

    def fetch_from_spam(self, limit: int = None) -> List[EmailMessage]:
        """Fetch emails from the spam/junk folder."""
        spam_folder = self.get_spam_folder_name()
        if not spam_folder:
            logger.warning("Could not find spam/junk folder for user %s", self.user_id)
            return []

        return self.fetch_emails(folder=spam_folder, limit=limit)

    def list_folders(self) -> List[str]:
        """List all available mailbox folders."""
        if not self.connection:
            if not self.connect():
                return []

        try:
            status, folders = self.connection.list()
            if status != "OK":
                return []

            folder_names = []
            for folder in folders:
                # Parse folder name from response
                if isinstance(folder, bytes):
                    folder = folder.decode("utf-8", errors="ignore")
                # Extract folder name (last part after delimiter)
                parts = folder.split(' "/" ')
                if len(parts) >= 2:
                    name = parts[-1].strip('"')
                    folder_names.append(name)
            return folder_names
        except Exception as e:
            logger.error("Error listing folders: %s", e)
            return []

    def get_deleted_folder_name(self) -> Optional[str]:
        """Find the deleted/trash folder name."""
        folders = self.list_folders()
        deleted_names = ["Trash", "Deleted", "Deleted Items", "Verwijderd",
                        "Prullenbak", "[Gmail]/Trash", "INBOX.Trash"]

        for name in deleted_names:
            if name in folders:
                return name
            # Case-insensitive check
            for folder in folders:
                if folder.lower() == name.lower():
                    return folder
        return None

    def fetch_from_deleted(self, limit: int = None) -> List[EmailMessage]:
        """Fetch emails from the deleted/trash folder."""
        deleted_folder = self.get_deleted_folder_name()
        if not deleted_folder:
            logger.warning("Could not find deleted/trash folder for user %s", self.user_id)
            return []

        return self.fetch_emails(folder=deleted_folder, limit=limit)

    def find_uid_by_message_id(self, message_id: str, folder: str = "INBOX") -> Optional[bytes]:
        """
        Find an email's IMAP UID by its Message-ID header.

        Args:
            message_id: The Message-ID header value
            folder: Folder to search in

        Returns:
            UID bytes if found, None otherwise
        """
        if not self.connection:
            if not self.connect():
                return None

        if not self.select_folder(folder):
            return None

        try:
            # Clean message_id for IMAP search
            clean_id = message_id.strip().strip("<>")
            status, messages = self.connection.search(
                None, f'(HEADER Message-ID "<{clean_id}>")'
            )
            if status == "OK" and messages[0]:
                uids = messages[0].split()
                if uids:
                    return uids[0]
            return None
        except Exception as e:
            logger.error("Error finding UID by message_id: %s", e)
            return None

    def warn_email(self, uid: bytes, subject: str, spam_score: float,
                   folder: str = "INBOX") -> bool:
        """
        Modify an email in-place via IMAP to add spam warnings.
        Adds flagged flag, prepends warning to subject, and injects banner into body.

        Args:
            uid: IMAP UID of the email
            subject: Original subject line
            spam_score: Spam score (0.0-1.0)
            folder: Folder the email is in

        Returns:
            True if successful
        """
        from database import get_user_setting

        if not self.connection:
            if not self.connect():
                return False

        warning_prefix = get_user_setting(self.user_id, "warning_prefix", "[SPAM WARNING]")
        score_pct = int(spam_score * 100)

        # Default warning templates
        default_html = (
            '<div style="background:#dc2626;color:white;padding:16px;margin:0 0 16px 0;'
            'border-radius:8px;font-family:Arial,sans-serif;font-size:14px;">'
            '<strong>Spambuster Warning:</strong> This email has been flagged as '
            'potentially dangerous (score: {score}%). Be careful with links and attachments.'
            '</div>'
        )
        default_text = (
            "========================================\n"
            "SPAMBUSTER WARNING: This email has been flagged as potentially dangerous "
            "(score: {score}%).\n"
            "Be careful with links and attachments.\n"
            "========================================\n\n"
        )

        warning_html_tpl = get_user_setting(self.user_id, "warning_html", default_html)
        warning_text_tpl = get_user_setting(self.user_id, "warning_text", default_text)

        # Replace {score} placeholder with actual score
        warning_html = warning_html_tpl.replace("{score}", str(score_pct))
        warning_text = warning_text_tpl.replace("{score}", str(score_pct))

        try:
            # Ensure we're in the right folder
            if not self.select_folder(folder):
                return False

            # 1. Add flagged flag
            self.connection.store(uid, "+FLAGS", "\\Flagged")

            # 2. Fetch the full RFC822 message
            status, msg_data = self.connection.fetch(uid, "(RFC822 FLAGS)")
            if status != "OK":
                return False

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Get original flags (preserve them)
            flags_data = msg_data[0][0].decode("utf-8", errors="ignore")
            # Extract flags from response like b'1 (FLAGS (\\Seen \\Flagged) RFC822 {size})'
            flags_match = _re.search(r'FLAGS \(([^)]*)\)', flags_data)
            original_flags = flags_match.group(1) if flags_match else "\\Seen \\Flagged"
            if "\\Flagged" not in original_flags:
                original_flags += " \\Flagged"

            # 3. Modify subject - prepend warning prefix
            if warning_prefix not in (msg.get("Subject", "") or ""):
                if "Subject" in msg:
                    del msg["Subject"]
                msg["Subject"] = f"{warning_prefix} {subject}"

            self._inject_warning_into_body(msg, warning_html, warning_text)

            # 5. APPEND modified message back to same folder
            modified_raw = msg.as_bytes()
            # Get the internal date from original message
            date_str = msg.get("Date")
            internal_date = None
            if date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(date_str)
                    internal_date = imaplib.Time2Internaldate(dt)
                except Exception:
                    pass

            append_result = self.connection.append(
                folder,
                f"({original_flags})",
                internal_date,
                modified_raw
            )

            if append_result[0] != "OK":
                return False

            # 6. Delete the original message
            self.connection.store(uid, "+FLAGS", "\\Deleted")
            self.connection.expunge()

            return True

        except Exception as e:
            logger.error("Error injecting warning into email: %s", e)
            return False

    def _inject_warning_into_body(self, msg: email.message.Message,
                                   warning_html: str, warning_text: str):
        """Inject warning banner into email body parts."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html = payload.decode(charset, errors="ignore")
                        # Inject after <body> tag if present, else at start
                        body_match = _re.search(r'(<body[^>]*>)', html, _re.IGNORECASE)
                        if body_match:
                            insert_pos = body_match.end()
                            html = html[:insert_pos] + warning_html + html[insert_pos:]
                        else:
                            html = warning_html + html
                        part.set_payload(html, charset)
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text = payload.decode(charset, errors="ignore")
                        text = warning_text + text
                        part.set_payload(text, charset)
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                if content_type == "text/html":
                    html = payload.decode(charset, errors="ignore")
                    body_match = _re.search(r'(<body[^>]*>)', html, _re.IGNORECASE)
                    if body_match:
                        insert_pos = body_match.end()
                        html = html[:insert_pos] + warning_html + html[insert_pos:]
                    else:
                        html = warning_html + html
                    msg.set_payload(html, charset)
                else:
                    text = payload.decode(charset, errors="ignore")
                    text = warning_text + text
                    msg.set_payload(text, charset)


# Per-user email service instances cache
_email_service_instances: Dict[int, EmailService] = {}


def get_email_service(user_id: int) -> EmailService:
    """
    Get the email service instance for a specific user.

    Args:
        user_id: User ID

    Returns:
        EmailService instance for the user
    """
    global _email_service_instances
    if user_id not in _email_service_instances:
        _email_service_instances[user_id] = EmailService(user_id)
    return _email_service_instances[user_id]


def clear_email_service_cache(user_id: int = None):
    """
    Clear cached email service instances.

    Args:
        user_id: Specific user to clear, or None for all users
    """
    global _email_service_instances
    if user_id is not None:
        service = _email_service_instances.pop(user_id, None)
        if service:
            service.disconnect()
    else:
        for service in _email_service_instances.values():
            service.disconnect()
        _email_service_instances.clear()

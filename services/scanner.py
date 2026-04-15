"""
Email scanner service - orchestrates email fetching, classification, and actions.
Per-user support for multi-tenant SaaS.
"""
import logging
import os
from datetime import datetime
from typing import List, Dict, Any
import threading
import time

logger = logging.getLogger(__name__)

from config import Config, OperationMode
from database import (
    save_email, email_exists, save_scan_history,
    get_training_data, get_user_setting, set_user_setting, update_sender_stats,
    get_sender_list_status, log_deleted_email, get_email_by_message_id,
    create_discord_action_token
)
from services.discord_bot import get_discord_notifier
from models.classifier import get_classifier
from services.email_service import get_email_service, EmailMessage


class ScanResult:
    """Result of scanning a single email."""
    def __init__(self, email: EmailMessage, spam_score: float, is_spam: bool, action: str):
        self.email = email
        self.spam_score = spam_score
        self.is_spam = is_spam
        self.action = action


class EmailScanner:
    """
    Email scanner that fetches and classifies emails.
    Operates in two modes:
    - LEARNING: Flags suspicious emails for review, no automatic actions
    - ENFORCEMENT: Automatically moves/deletes spam
    Per-user support for multi-tenant SaaS.
    """

    def __init__(self, user_id: int):
        """
        Initialize scanner for a specific user.

        Args:
            user_id: User ID for per-user operations
        """
        self.user_id = user_id
        self.classifier = get_classifier(user_id)
        self.email_service = get_email_service(user_id)
        self.discord = get_discord_notifier(user_id)
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._is_running = False

    @property
    def mode(self) -> OperationMode:
        """Get current operation mode from user settings or config."""
        mode_str = get_user_setting(self.user_id, "operation_mode")
        if mode_str:
            try:
                return OperationMode(mode_str)
            except ValueError:
                pass
        return Config.OPERATION_MODE

    def set_mode(self, mode: OperationMode):
        """Set the operation mode for this user."""
        set_user_setting(self.user_id, "operation_mode", mode.value)

    def scan_emails(self, folder: str = "INBOX", limit: int = None) -> List[ScanResult]:
        """
        Scan emails in the specified folder.

        Args:
            folder: Mailbox folder to scan
            limit: Maximum number of emails to scan

        Returns:
            List of ScanResult objects
        """
        started_at = datetime.now()
        results = []
        spam_count = 0

        # Fetch emails
        emails = self.email_service.fetch_emails(folder, limit)

        for email_msg in emails:
            # Skip if already processed
            if email_exists(self.user_id, email_msg.message_id):
                continue

            # Check whitelist/blacklist first
            list_status = get_sender_list_status(self.user_id, email_msg.sender)
            if list_status == "whitelist":
                spam_score = 0.0
                is_spam = False
            elif list_status == "blacklist":
                spam_score = 1.0
                is_spam = True
            else:
                # Classify email normally
                full_content = f"{email_msg.subject}\n{email_msg.sender}\n{email_msg.content}"
                spam_score, is_spam = self.classifier.predict(full_content)

            # Determine action based on mode
            action = self._determine_action(email_msg, spam_score, is_spam)

            # Save to database
            email_id = save_email(
                user_id=self.user_id,
                message_id=email_msg.message_id,
                sender=email_msg.sender,
                subject=email_msg.subject,
                content=email_msg.content[:10000],  # Limit content size
                received_at=email_msg.received_at,
                spam_score=spam_score,
                is_spam=is_spam,
                action_taken=action
            )

            # Update sender statistics
            update_sender_stats(self.user_id, email_msg.sender, is_spam)

            results.append(ScanResult(email_msg, spam_score, is_spam, action))

            if is_spam:
                spam_count += 1

                # Send Discord notification for high-confidence spam
                notify_threshold = float(get_user_setting(
                    self.user_id, "discord_notify_threshold",
                    str(Config.DISCORD_NOTIFY_THRESHOLD)
                ))
                if spam_score >= notify_threshold and self.discord.is_configured:
                    try:
                        # Generate a secure token for Discord button actions
                        action_token = create_discord_action_token(self.user_id, email_id)
                        self.discord.send_spam_alert(
                            email_id=email_id,
                            sender=email_msg.sender,
                            subject=email_msg.subject,
                            spam_score=spam_score,
                            prediction="spam" if is_spam else "safe",
                            content_preview=email_msg.content[:200],
                            token=action_token
                        )
                    except Exception as e:
                        logger.warning("Discord notification failed: %s", e)

        completed_at = datetime.now()

        # Only log when new emails were processed
        if results:
            logger.info("Processed %d new emails (%d spam detected) for user %s", len(results), spam_count, self.user_id)

        # Save scan history
        if results:
            save_scan_history(
                user_id=self.user_id,
                started_at=started_at,
                completed_at=completed_at,
                emails_scanned=len(results),
                spam_detected=spam_count,
                mode=self.mode.value
            )

        return results

    def _save_email_as_eml(self, email_msg: EmailMessage) -> str:
        """
        Save email content as .eml file for potential rollback.

        Returns:
            Path to saved .eml file, or empty string if failed
        """
        try:
            # Ensure user-specific storage directory exists
            user_eml_path = os.path.join(Config.EML_STORAGE_PATH, str(self.user_id))
            os.makedirs(user_eml_path, exist_ok=True)

            # Create filename from timestamp and message id hash
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_id = email_msg.message_id.replace("<", "").replace(">", "").replace("/", "_")[:50]
            filename = f"{timestamp}_{safe_id}.eml"
            filepath = os.path.join(user_eml_path, filename)

            # Get user's email address from credentials
            from services.credentials import get_credentials_manager
            creds = get_credentials_manager().get_imap_credentials(self.user_id)
            to_address = creds.email_address if creds.is_configured() else "user@example.com"

            # Create .eml content
            eml_content = f"""From: {email_msg.sender}
To: {to_address}
Subject: {email_msg.subject}
Date: {email_msg.received_at}
Message-ID: {email_msg.message_id}
Content-Type: text/plain; charset="utf-8"

{email_msg.content}
"""
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(eml_content)

            return filepath
        except Exception as e:
            logger.error("Failed to save .eml file: %s", e)
            return ""

    def _get_thresholds(self) -> dict:
        """Get configurable action thresholds from user settings."""
        return {
            "delete": float(get_user_setting(self.user_id, "threshold_delete", "0.9")),
            "move": float(get_user_setting(self.user_id, "threshold_move", "0.7")),
            "warn": float(get_user_setting(self.user_id, "threshold_warn", "0.5")),
        }

    def _determine_action(self, email_msg: EmailMessage, spam_score: float, is_spam: bool) -> str:
        """
        Determine and execute the appropriate action for an email.
        Three escalating stages: Add banner > Move to spam > Delete
        """
        if not is_spam:
            return "none"

        thresholds = self._get_thresholds()

        if self.mode == OperationMode.LEARNING:
            # In learning mode, apply warning banner if above warn threshold
            if spam_score >= thresholds["warn"]:
                self.email_service.warn_email(
                    email_msg.uid, email_msg.subject, spam_score
                )
                return "warned"
            else:
                self.email_service.flag_email(email_msg.uid)
                return "flagged"

        elif self.mode == OperationMode.ENFORCEMENT:
            if spam_score >= thresholds["delete"]:
                # Stage 3: High confidence - save backup and delete
                eml_path = self._save_email_as_eml(email_msg)

                if self.email_service.delete_email(email_msg.uid):
                    saved_email = get_email_by_message_id(self.user_id, email_msg.message_id)
                    log_deleted_email(
                        user_id=self.user_id,
                        email_id=saved_email["id"] if saved_email else None,
                        message_id=email_msg.message_id,
                        sender=email_msg.sender,
                        subject=email_msg.subject,
                        spam_score=spam_score,
                        eml_file_path=eml_path,
                        retention_days=Config.EML_RETENTION_DAYS
                    )
                    return "deleted"
                return "delete_failed"
            elif spam_score >= thresholds["move"]:
                # Stage 2: Medium confidence - warn then move to spam
                self.email_service.warn_email(
                    email_msg.uid, email_msg.subject, spam_score
                )
                if self.email_service.move_to_spam(email_msg.uid):
                    return "moved_to_spam"
                return "move_failed"
            elif spam_score >= thresholds["warn"]:
                # Stage 1: Low-medium confidence - add warning banner only
                self.email_service.warn_email(
                    email_msg.uid, email_msg.subject, spam_score
                )
                return "warned"
            else:
                # Below all thresholds - do nothing
                return "none"

        return "none"

    def import_from_deleted(self, limit: int = None) -> List[ScanResult]:
        """
        Import emails from deleted/trash folder for review.
        Uses the classifier to predict spam score, user can then label them.
        """
        started_at = datetime.now()
        results = []
        spam_count = 0

        # Fetch from deleted folder
        emails = self.email_service.fetch_from_deleted(limit)

        for email_msg in emails:
            # Skip if already processed
            if email_exists(self.user_id, email_msg.message_id):
                continue

            # Classify using the model
            full_content = f"{email_msg.subject}\n{email_msg.sender}\n{email_msg.content}"
            spam_score, is_spam = self.classifier.predict(full_content)

            # Save to database - flag for review, don't auto-label
            save_email(
                user_id=self.user_id,
                message_id=email_msg.message_id,
                sender=email_msg.sender,
                subject=email_msg.subject,
                content=email_msg.content[:10000],
                received_at=email_msg.received_at,
                spam_score=spam_score,
                is_spam=is_spam,
                action_taken="imported_from_deleted"
            )

            # Update sender statistics
            update_sender_stats(self.user_id, email_msg.sender, is_spam)

            results.append(ScanResult(email_msg, spam_score, is_spam, "imported"))
            if is_spam:
                spam_count += 1

        completed_at = datetime.now()

        # Only log when emails were imported
        if results:
            logger.info("Imported %d emails from deleted folder (%d spam detected) for user %s", len(results), spam_count, self.user_id)

        if results:
            save_scan_history(
                user_id=self.user_id,
                started_at=started_at,
                completed_at=completed_at,
                emails_scanned=len(results),
                spam_detected=spam_count,
                mode="import_deleted"
            )

        return results

    def train_classifier(self) -> Dict[str, Any]:
        """Train the classifier using accumulated training data for this user."""
        training_data = get_training_data(self.user_id)

        if len(training_data) < 5:
            return {
                "success": False,
                "error": f"Need at least 5 training samples, have {len(training_data)}"
            }

        texts = [d["content"] for d in training_data]
        labels = [d["label"] for d in training_data]

        return self.classifier.train(texts, labels)

    def start_background_scanning(self, interval: int = None):
        """Start background email scanning."""
        if self._is_running:
            return False

        interval = interval or Config.SCAN_INTERVAL
        self._stop_event.clear()
        self._is_running = True

        def scan_loop():
            while not self._stop_event.is_set():
                try:
                    self.scan_emails()
                except Exception as e:
                    logger.error("Scan error for user %s: %s", self.user_id, e)

                # Wait for interval or stop event
                self._stop_event.wait(interval)

            self._is_running = False

        self._scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self._scan_thread.start()
        return True

    def stop_background_scanning(self):
        """Stop background email scanning."""
        if not self._is_running:
            return False

        self._stop_event.set()
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
        self._is_running = False
        return True

    @property
    def is_scanning(self) -> bool:
        """Check if background scanning is active."""
        return self._is_running


# Per-user scanner instances cache
_scanner_instances: Dict[int, EmailScanner] = {}


def get_scanner(user_id: int) -> EmailScanner:
    """
    Get the scanner instance for a specific user.

    Args:
        user_id: User ID

    Returns:
        EmailScanner instance for the user
    """
    global _scanner_instances
    if user_id not in _scanner_instances:
        _scanner_instances[user_id] = EmailScanner(user_id)
    return _scanner_instances[user_id]


def clear_scanner_cache(user_id: int = None):
    """
    Clear cached scanner instances.

    Args:
        user_id: Specific user to clear, or None for all users
    """
    global _scanner_instances
    if user_id is not None:
        scanner = _scanner_instances.pop(user_id, None)
        if scanner and scanner.is_scanning:
            scanner.stop_background_scanning()
    else:
        for scanner in _scanner_instances.values():
            if scanner.is_scanning:
                scanner.stop_background_scanning()
        _scanner_instances.clear()

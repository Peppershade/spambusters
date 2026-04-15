"""
User credentials management for Spambuster multi-user mode.
Handles encrypted storage and retrieval of IMAP and Discord credentials.
"""
import sqlite3
from typing import Optional, Dict, Any
from dataclasses import dataclass

from config import Config
from database import get_db_connection
from services.encryption import (
    get_encryption_service,
    is_encryption_available,
    is_encryption_configured,
    EncryptionError
)


@dataclass
class IMAPCredentials:
    """IMAP server credentials."""
    server: str
    port: int
    email_address: str
    password: str

    def is_configured(self) -> bool:
        """Check if all required fields are set."""
        return bool(self.server and self.email_address and self.password)


@dataclass
class DiscordCredentials:
    """Discord integration credentials."""
    webhook_url: str
    bot_token: str
    channel_id: str
    webhook_secret: str
    notify_threshold: float = 0.7

    def is_webhook_configured(self) -> bool:
        """Check if webhook is configured."""
        return bool(self.webhook_url)

    def is_bot_configured(self) -> bool:
        """Check if bot is configured."""
        return bool(self.bot_token and self.channel_id)

    def is_configured(self) -> bool:
        """Check if any Discord integration is configured."""
        return self.is_webhook_configured() or self.is_bot_configured()


@dataclass
class SMTPCredentials:
    """SMTP email sender credentials."""
    server: str
    port: int
    username: str
    password: str
    use_tls: bool
    from_address: str

    def is_configured(self) -> bool:
        """Check if all required fields are set."""
        return bool(self.server and self.username and self.password and self.from_address)


class CredentialsError(Exception):
    """Raised when credential operations fail."""
    pass


class UserCredentialsManager:
    """
    Manages encrypted storage of user credentials.

    Provides methods to save and retrieve IMAP and Discord credentials
    with automatic encryption/decryption. Falls back to environment
    variables for simple single-user deployments.
    """

    def __init__(self):
        """Initialize credentials manager."""
        self._encryption = None
        if is_encryption_available():
            try:
                self._encryption = get_encryption_service()
            except EncryptionError:
                pass  # Encryption not configured, will use fallback

    def _get_user_key(self, user_id: int) -> tuple:
        """
        Get encryption key material for a user.

        Returns:
            Tuple of (wrapped_key, salt) or (None, None) if not found
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT wrapped_key, key_salt FROM encryption_keys WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return row["wrapped_key"], row["key_salt"]
        return None, None

    def _ensure_user_key(self, user_id: int) -> tuple:
        """
        Ensure user has an encryption key, creating one if needed.

        Returns:
            Tuple of (wrapped_key, salt)
        """
        wrapped_key, salt = self._get_user_key(user_id)

        if wrapped_key is None:
            if not self._encryption:
                raise CredentialsError("Encryption not available")

            # Generate new key for user
            wrapped_key, salt = self._encryption.generate_user_key(user_id)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO encryption_keys (user_id, wrapped_key, key_salt)
                   VALUES (?, ?, ?)""",
                (user_id, wrapped_key, salt)
            )
            conn.commit()
            conn.close()

        return wrapped_key, salt

    def _encrypt_value(self, user_id: int, value: str,
                       wrapped_key: bytes, salt: bytes) -> Optional[bytes]:
        """Encrypt a value for a user."""
        if not value or not self._encryption:
            return None
        return self._encryption.encrypt(user_id, value, wrapped_key, salt)

    def _decrypt_value(self, user_id: int, ciphertext: bytes,
                       wrapped_key: bytes, salt: bytes) -> Optional[str]:
        """Decrypt a value for a user."""
        if not ciphertext or not self._encryption:
            return None
        try:
            return self._encryption.decrypt(user_id, ciphertext, wrapped_key, salt)
        except EncryptionError:
            return None

    # -------------------------------------------------------------------------
    # IMAP Credentials
    # -------------------------------------------------------------------------

    def get_imap_credentials(self, user_id: int) -> IMAPCredentials:
        """
        Get IMAP credentials for a user.

        Falls back to environment variables if no user-specific credentials
        are stored or if encryption is not available.

        Args:
            user_id: User ID

        Returns:
            IMAPCredentials object
        """
        # Try to get from database first
        if self._encryption:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT imap_server_enc, imap_port, email_address_enc, email_password_enc
                   FROM user_credentials WHERE user_id = ?""",
                (user_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if row and any([row["imap_server_enc"], row["email_address_enc"]]):
                wrapped_key, salt = self._get_user_key(user_id)
                if wrapped_key:
                    return IMAPCredentials(
                        server=self._decrypt_value(
                            user_id, row["imap_server_enc"], wrapped_key, salt
                        ) or "",
                        port=row["imap_port"] or 993,
                        email_address=self._decrypt_value(
                            user_id, row["email_address_enc"], wrapped_key, salt
                        ) or "",
                        password=self._decrypt_value(
                            user_id, row["email_password_enc"], wrapped_key, salt
                        ) or ""
                    )

        # Fallback to environment variables
        return IMAPCredentials(
            server=Config.IMAP_SERVER,
            port=Config.IMAP_PORT,
            email_address=Config.EMAIL_ADDRESS,
            password=Config.EMAIL_PASSWORD
        )

    def save_imap_credentials(self, user_id: int, credentials: IMAPCredentials) -> bool:
        """
        Save IMAP credentials for a user.

        Args:
            user_id: User ID
            credentials: IMAPCredentials to save

        Returns:
            True if saved successfully

        Raises:
            CredentialsError: If encryption is not available
        """
        if not self._encryption:
            raise CredentialsError(
                "Encryption not available. Set ENCRYPTION_MASTER_KEY to enable."
            )

        wrapped_key, salt = self._ensure_user_key(user_id)

        # Encrypt values
        server_enc = self._encrypt_value(user_id, credentials.server, wrapped_key, salt)
        email_enc = self._encrypt_value(user_id, credentials.email_address, wrapped_key, salt)
        password_enc = self._encrypt_value(user_id, credentials.password, wrapped_key, salt)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if record exists
        cursor.execute(
            "SELECT id FROM user_credentials WHERE user_id = ?",
            (user_id,)
        )
        exists = cursor.fetchone() is not None

        if exists:
            cursor.execute(
                """UPDATE user_credentials
                   SET imap_server_enc = ?, imap_port = ?, email_address_enc = ?,
                       email_password_enc = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = ?""",
                (server_enc, credentials.port, email_enc, password_enc, user_id)
            )
        else:
            cursor.execute(
                """INSERT INTO user_credentials
                   (user_id, imap_server_enc, imap_port, email_address_enc, email_password_enc)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, server_enc, credentials.port, email_enc, password_enc)
            )

        conn.commit()
        conn.close()
        return True

    def clear_imap_credentials(self, user_id: int) -> bool:
        """
        Clear IMAP credentials for a user.

        Args:
            user_id: User ID

        Returns:
            True if cleared successfully
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE user_credentials
               SET imap_server_enc = NULL, email_address_enc = NULL,
                   email_password_enc = NULL, updated_at = CURRENT_TIMESTAMP
               WHERE user_id = ?""",
            (user_id,)
        )
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0

    # -------------------------------------------------------------------------
    # Discord Credentials
    # -------------------------------------------------------------------------

    def get_discord_credentials(self, user_id: int) -> DiscordCredentials:
        """
        Get Discord credentials for a user.

        Falls back to environment variables if no user-specific credentials
        are stored or if encryption is not available.

        Args:
            user_id: User ID

        Returns:
            DiscordCredentials object
        """
        # Try to get from database first
        if self._encryption:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT discord_webhook_url_enc, discord_bot_token_enc,
                          discord_channel_id, discord_webhook_secret_enc,
                          discord_notify_threshold
                   FROM user_credentials WHERE user_id = ?""",
                (user_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if row and any([row["discord_webhook_url_enc"], row["discord_bot_token_enc"]]):
                wrapped_key, salt = self._get_user_key(user_id)
                if wrapped_key:
                    return DiscordCredentials(
                        webhook_url=self._decrypt_value(
                            user_id, row["discord_webhook_url_enc"], wrapped_key, salt
                        ) or "",
                        bot_token=self._decrypt_value(
                            user_id, row["discord_bot_token_enc"], wrapped_key, salt
                        ) or "",
                        channel_id=row["discord_channel_id"] or "",
                        webhook_secret=self._decrypt_value(
                            user_id, row["discord_webhook_secret_enc"], wrapped_key, salt
                        ) or "",
                        notify_threshold=row["discord_notify_threshold"] or 0.7
                    )

        # Fallback to environment variables
        return DiscordCredentials(
            webhook_url=Config.DISCORD_WEBHOOK_URL,
            bot_token=Config.DISCORD_BOT_TOKEN,
            channel_id=Config.DISCORD_CHANNEL_ID,
            webhook_secret=Config.DISCORD_WEBHOOK_SECRET,
            notify_threshold=Config.DISCORD_NOTIFY_THRESHOLD
        )

    def save_discord_credentials(self, user_id: int, credentials: DiscordCredentials) -> bool:
        """
        Save Discord credentials for a user.

        Args:
            user_id: User ID
            credentials: DiscordCredentials to save

        Returns:
            True if saved successfully

        Raises:
            CredentialsError: If encryption is not available
        """
        if not self._encryption:
            raise CredentialsError(
                "Encryption not available. Set ENCRYPTION_MASTER_KEY to enable."
            )

        wrapped_key, salt = self._ensure_user_key(user_id)

        # Encrypt values
        webhook_enc = self._encrypt_value(
            user_id, credentials.webhook_url, wrapped_key, salt
        )
        token_enc = self._encrypt_value(
            user_id, credentials.bot_token, wrapped_key, salt
        )
        secret_enc = self._encrypt_value(
            user_id, credentials.webhook_secret, wrapped_key, salt
        )

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if record exists
        cursor.execute(
            "SELECT id FROM user_credentials WHERE user_id = ?",
            (user_id,)
        )
        exists = cursor.fetchone() is not None

        if exists:
            cursor.execute(
                """UPDATE user_credentials
                   SET discord_webhook_url_enc = ?, discord_bot_token_enc = ?,
                       discord_channel_id = ?, discord_webhook_secret_enc = ?,
                       discord_notify_threshold = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = ?""",
                (webhook_enc, token_enc, credentials.channel_id, secret_enc,
                 credentials.notify_threshold, user_id)
            )
        else:
            cursor.execute(
                """INSERT INTO user_credentials
                   (user_id, discord_webhook_url_enc, discord_bot_token_enc,
                    discord_channel_id, discord_webhook_secret_enc, discord_notify_threshold)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, webhook_enc, token_enc, credentials.channel_id,
                 secret_enc, credentials.notify_threshold)
            )

        conn.commit()
        conn.close()
        return True

    def clear_discord_credentials(self, user_id: int) -> bool:
        """
        Clear Discord credentials for a user.

        Args:
            user_id: User ID

        Returns:
            True if cleared successfully
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE user_credentials
               SET discord_webhook_url_enc = NULL, discord_bot_token_enc = NULL,
                   discord_channel_id = NULL, discord_webhook_secret_enc = NULL,
                   updated_at = CURRENT_TIMESTAMP
               WHERE user_id = ?""",
            (user_id,)
        )
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0

    # -------------------------------------------------------------------------
    # SMTP Credentials
    # -------------------------------------------------------------------------

    def get_smtp_credentials(self, user_id: int) -> SMTPCredentials:
        """Get SMTP credentials for a user."""
        if self._encryption:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT smtp_server_enc, smtp_port, smtp_username_enc,
                          smtp_password_enc, smtp_use_tls, smtp_from_address_enc
                   FROM user_credentials WHERE user_id = ?""",
                (user_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if row and any([row["smtp_server_enc"], row["smtp_username_enc"]]):
                wrapped_key, salt = self._get_user_key(user_id)
                if wrapped_key:
                    return SMTPCredentials(
                        server=self._decrypt_value(
                            user_id, row["smtp_server_enc"], wrapped_key, salt
                        ) or "",
                        port=row["smtp_port"] or 587,
                        username=self._decrypt_value(
                            user_id, row["smtp_username_enc"], wrapped_key, salt
                        ) or "",
                        password=self._decrypt_value(
                            user_id, row["smtp_password_enc"], wrapped_key, salt
                        ) or "",
                        use_tls=bool(row["smtp_use_tls"]) if row["smtp_use_tls"] is not None else True,
                        from_address=self._decrypt_value(
                            user_id, row["smtp_from_address_enc"], wrapped_key, salt
                        ) or ""
                    )

        return SMTPCredentials(
            server="", port=587, username="", password="",
            use_tls=True, from_address=""
        )

    def save_smtp_credentials(self, user_id: int, credentials: SMTPCredentials) -> bool:
        """Save SMTP credentials for a user."""
        if not self._encryption:
            raise CredentialsError(
                "Encryption not available. Set ENCRYPTION_MASTER_KEY to enable."
            )

        wrapped_key, salt = self._ensure_user_key(user_id)

        server_enc = self._encrypt_value(user_id, credentials.server, wrapped_key, salt)
        username_enc = self._encrypt_value(user_id, credentials.username, wrapped_key, salt)
        password_enc = self._encrypt_value(user_id, credentials.password, wrapped_key, salt)
        from_enc = self._encrypt_value(user_id, credentials.from_address, wrapped_key, salt)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM user_credentials WHERE user_id = ?",
            (user_id,)
        )
        exists = cursor.fetchone() is not None

        if exists:
            cursor.execute(
                """UPDATE user_credentials
                   SET smtp_server_enc = ?, smtp_port = ?, smtp_username_enc = ?,
                       smtp_password_enc = ?, smtp_use_tls = ?, smtp_from_address_enc = ?,
                       updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = ?""",
                (server_enc, credentials.port, username_enc, password_enc,
                 1 if credentials.use_tls else 0, from_enc, user_id)
            )
        else:
            cursor.execute(
                """INSERT INTO user_credentials
                   (user_id, smtp_server_enc, smtp_port, smtp_username_enc,
                    smtp_password_enc, smtp_use_tls, smtp_from_address_enc)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, server_enc, credentials.port, username_enc,
                 password_enc, 1 if credentials.use_tls else 0, from_enc)
            )

        conn.commit()
        conn.close()
        return True

    def clear_smtp_credentials(self, user_id: int) -> bool:
        """Clear SMTP credentials for a user."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE user_credentials
               SET smtp_server_enc = NULL, smtp_username_enc = NULL,
                   smtp_password_enc = NULL, smtp_from_address_enc = NULL,
                   updated_at = CURRENT_TIMESTAMP
               WHERE user_id = ?""",
            (user_id,)
        )
        conn.commit()
        affected = cursor.rowcount
        conn.close()
        return affected > 0

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def has_user_credentials(self, user_id: int) -> Dict[str, bool]:
        """
        Check what credentials are configured for a user.

        Args:
            user_id: User ID

        Returns:
            Dict with 'imap' and 'discord' keys indicating if configured
        """
        imap_creds = self.get_imap_credentials(user_id)
        discord_creds = self.get_discord_credentials(user_id)

        return {
            "imap": imap_creds.is_configured(),
            "discord_webhook": discord_creds.is_webhook_configured(),
            "discord_bot": discord_creds.is_bot_configured()
        }

    def is_using_fallback(self, user_id: int) -> Dict[str, bool]:
        """
        Check if user is using environment variable fallback.

        Args:
            user_id: User ID

        Returns:
            Dict with 'imap' and 'discord' keys indicating fallback usage
        """
        if not self._encryption:
            return {"imap": True, "discord": True}

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT imap_server_enc, discord_webhook_url_enc, discord_bot_token_enc
               FROM user_credentials WHERE user_id = ?""",
            (user_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return {"imap": True, "discord": True}

        return {
            "imap": not row["imap_server_enc"],
            "discord": not row["discord_webhook_url_enc"] and not row["discord_bot_token_enc"]
        }

    def rotate_user_key(self, user_id: int) -> bool:
        """
        Rotate encryption key for a user.

        This re-encrypts all credentials with a new key.

        Args:
            user_id: User ID

        Returns:
            True if rotation successful
        """
        if not self._encryption:
            raise CredentialsError("Encryption not available")

        # Get current credentials (decrypted)
        imap_creds = self.get_imap_credentials(user_id)
        discord_creds = self.get_discord_credentials(user_id)

        # Get old key info
        old_wrapped_key, old_salt = self._get_user_key(user_id)
        if not old_wrapped_key:
            return False

        # Generate new key
        new_wrapped_key, new_salt = self._encryption.rotate_user_key(
            user_id, old_wrapped_key, old_salt
        )

        # Update key in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """UPDATE encryption_keys
               SET wrapped_key = ?, key_salt = ?, key_version = key_version + 1,
                   rotated_at = CURRENT_TIMESTAMP
               WHERE user_id = ?""",
            (new_wrapped_key, new_salt, user_id)
        )
        conn.commit()
        conn.close()

        # Re-encrypt credentials with new key
        if imap_creds.is_configured():
            self.save_imap_credentials(user_id, imap_creds)
        if discord_creds.is_webhook_configured() or discord_creds.is_bot_configured():
            self.save_discord_credentials(user_id, discord_creds)

        smtp_creds = self.get_smtp_credentials(user_id)
        if smtp_creds.is_configured():
            self.save_smtp_credentials(user_id, smtp_creds)

        return True

    def delete_user_credentials(self, user_id: int) -> bool:
        """
        Delete all credentials and encryption key for a user.

        Args:
            user_id: User ID

        Returns:
            True if deleted successfully
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete credentials
        cursor.execute("DELETE FROM user_credentials WHERE user_id = ?", (user_id,))

        # Delete encryption key
        cursor.execute("DELETE FROM encryption_keys WHERE user_id = ?", (user_id,))

        # Clear cache
        if self._encryption:
            self._encryption.clear_cache(user_id)

        conn.commit()
        conn.close()
        return True


# Singleton instance
_credentials_manager: Optional[UserCredentialsManager] = None


def get_credentials_manager() -> UserCredentialsManager:
    """Get the singleton credentials manager instance."""
    global _credentials_manager
    if _credentials_manager is None:
        _credentials_manager = UserCredentialsManager()
    return _credentials_manager

"""
Encryption service for Spambuster multi-user credentials.
Uses Fernet (AES-128-CBC) with PBKDF2 key derivation.
"""
import logging
import os
import base64
import secrets
from typing import Optional, Tuple, Dict

logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

from config import Config


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


class EncryptionService:
    """
    Handles encryption/decryption of user credentials.

    Key Hierarchy:
    - ENCRYPTION_MASTER_KEY (environment variable)
      └── PBKDF2 + per-user salt
          └── User KEK (Key Encryption Key)
              └── User DEK (Data Encryption Key) - stored wrapped in DB
    """

    SALT_LENGTH = 32
    ITERATIONS = 480000  # OWASP 2023 recommendation for PBKDF2-SHA256

    def __init__(self, master_key: str = None):
        """
        Initialize encryption service.

        Args:
            master_key: App-level master key. If not provided, uses
                       ENCRYPTION_MASTER_KEY environment variable.

        Raises:
            EncryptionError: If cryptography library not available or
                            master key not configured.
        """
        if not CRYPTO_AVAILABLE:
            raise EncryptionError(
                "cryptography library not installed. "
                "Install with: pip install cryptography"
            )

        self._master_key = master_key or Config.ENCRYPTION_MASTER_KEY
        if not self._master_key:
            if getattr(Config, 'ENVIRONMENT', 'development') == "production":
                raise EncryptionError(
                    "ENCRYPTION_MASTER_KEY must be set in production. "
                    "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            # Development only: temporary key
            self._master_key = secrets.token_hex(32)
            logger.warning("ENCRYPTION_MASTER_KEY not set. Using temporary key. Credentials will not persist across restarts.")

        self._user_keys: Dict[int, Fernet] = {}  # Cache: user_id -> Fernet instance

    def generate_user_key(self, user_id: int) -> Tuple[bytes, bytes]:
        """
        Generate a new Data Encryption Key (DEK) for a user.

        Args:
            user_id: User ID (for logging purposes)

        Returns:
            Tuple of (wrapped_key, salt) - Store these in encryption_keys table
        """
        # Generate random DEK
        dek = Fernet.generate_key()

        # Generate random salt for this user
        salt = secrets.token_bytes(self.SALT_LENGTH)

        # Derive KEK from master key + salt
        kek = self._derive_kek(salt)

        # Wrap (encrypt) the DEK with the KEK
        kek_fernet = Fernet(kek)
        wrapped_key = kek_fernet.encrypt(dek)

        return wrapped_key, salt

    def _derive_kek(self, salt: bytes) -> bytes:
        """
        Derive Key Encryption Key from master key and salt.

        Uses PBKDF2-HMAC-SHA256 with high iteration count.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        key = kdf.derive(self._master_key.encode())
        return base64.urlsafe_b64encode(key)

    def get_user_fernet(self, user_id: int, wrapped_key: bytes, salt: bytes) -> Fernet:
        """
        Get Fernet instance for a user (with caching).

        Args:
            user_id: User ID
            wrapped_key: Wrapped DEK from database
            salt: Salt from database

        Returns:
            Fernet instance for encrypting/decrypting user data
        """
        if user_id not in self._user_keys:
            # Derive KEK from master key + salt
            kek = self._derive_kek(salt)
            kek_fernet = Fernet(kek)

            # Unwrap DEK
            try:
                dek = kek_fernet.decrypt(wrapped_key)
            except Exception as e:
                raise EncryptionError(f"Failed to unwrap key for user {user_id}: {e}")

            # Create and cache Fernet with DEK
            self._user_keys[user_id] = Fernet(dek)

        return self._user_keys[user_id]

    def encrypt(self, user_id: int, plaintext: str,
                wrapped_key: bytes, salt: bytes) -> Optional[bytes]:
        """
        Encrypt a string value for a user.

        Args:
            user_id: User ID
            plaintext: String to encrypt
            wrapped_key: Wrapped DEK from database
            salt: Salt from database

        Returns:
            Encrypted bytes, or None if plaintext is empty
        """
        if not plaintext:
            return None

        try:
            fernet = self.get_user_fernet(user_id, wrapped_key, salt)
            return fernet.encrypt(plaintext.encode())
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    def decrypt(self, user_id: int, ciphertext: bytes,
                wrapped_key: bytes, salt: bytes) -> Optional[str]:
        """
        Decrypt a value for a user.

        Args:
            user_id: User ID
            ciphertext: Encrypted bytes
            wrapped_key: Wrapped DEK from database
            salt: Salt from database

        Returns:
            Decrypted string, or None if ciphertext is empty
        """
        if not ciphertext:
            return None

        try:
            fernet = self.get_user_fernet(user_id, wrapped_key, salt)
            return fernet.decrypt(ciphertext).decode()
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")

    def clear_cache(self, user_id: int = None):
        """
        Clear cached keys.

        Call this on logout or key rotation.

        Args:
            user_id: Specific user to clear, or None for all users
        """
        if user_id is not None:
            self._user_keys.pop(user_id, None)
        else:
            self._user_keys.clear()

    def rotate_user_key(self, user_id: int, old_wrapped_key: bytes,
                        old_salt: bytes) -> Tuple[bytes, bytes]:
        """
        Rotate a user's encryption key.

        This generates a new key but does NOT re-encrypt existing data.
        The caller is responsible for re-encrypting credentials with the new key.

        Args:
            user_id: User ID
            old_wrapped_key: Current wrapped key
            old_salt: Current salt

        Returns:
            Tuple of (new_wrapped_key, new_salt)
        """
        # Clear cached key for this user
        self.clear_cache(user_id)

        # Generate new key
        return self.generate_user_key(user_id)


# Singleton instance
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get the singleton encryption service instance."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


def is_encryption_available() -> bool:
    """Check if encryption is available (cryptography library installed)."""
    return CRYPTO_AVAILABLE


def is_encryption_configured() -> bool:
    """Check if encryption master key is configured."""
    return bool(Config.ENCRYPTION_MASTER_KEY)

"""
Spambuster Configuration
Load settings from environment variables with sensible defaults.
"""
import os
from enum import Enum

VERSION = "0.7.1"


class OperationMode(Enum):
    LEARNING = "learning"      # Dryrun: flag suspicious emails, collect feedback
    ENFORCEMENT = "enforcement"  # Protection: automatically move/delete spam


class Config:
    # Version
    VERSION = VERSION

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "")

    # Shared secret for the Discord webhook HTTP endpoint (/api/discord/label)
    # If not set, the endpoint is disabled entirely.
    DISCORD_WEBHOOK_SECRET = os.getenv("DISCORD_WEBHOOK_SECRET", "")

    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", "spambuster.db")

    # Email IMAP settings
    IMAP_SERVER = os.getenv("IMAP_SERVER", "")
    IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
    EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")

    # Operation mode
    OPERATION_MODE = OperationMode(os.getenv("OPERATION_MODE", "learning"))

    # Model settings
    MODEL_PATH = os.getenv("MODEL_PATH", "spam_model.pt")
    VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "vectorizer.pkl")

    # Spam detection threshold (0.0 - 1.0)
    SPAM_THRESHOLD = float(os.getenv("SPAM_THRESHOLD", "0.7"))

    # Scan interval in seconds
    SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))

    # Maximum emails to fetch per scan
    MAX_EMAILS_PER_SCAN = int(os.getenv("MAX_EMAILS_PER_SCAN", "50"))

    # Discord integration
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
    DISCORD_CHANNEL_ID = os.getenv("DISCORD_CHANNEL_ID", "")
    DISCORD_NOTIFY_THRESHOLD = float(os.getenv("DISCORD_NOTIFY_THRESHOLD", "0.7"))

    # Deleted email backup settings
    EML_STORAGE_PATH = os.getenv("EML_STORAGE_PATH", "data/deleted_emails")
    EML_RETENTION_DAYS = int(os.getenv("EML_RETENTION_DAYS", "30"))

    # Auto-start background scanning on boot
    AUTO_START_SCANNING = os.getenv("AUTO_START_SCANNING", "true").lower() in ("true", "1", "yes")

    # Encryption master key for credential storage
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    ENCRYPTION_MASTER_KEY = os.getenv("ENCRYPTION_MASTER_KEY", "")

    # Models directory for per-user models
    MODELS_DIR = os.getenv("MODELS_DIR", "models")

    # Environment and debug settings
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # Logging settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "")

    # Security settings
    # Set to "true" when running behind HTTPS reverse proxy (Nginx, Caddy, etc.)
    # Set to "false" for local development without HTTPS
    USE_HTTPS = os.getenv("USE_HTTPS", "false").lower() in ("true", "1", "yes")

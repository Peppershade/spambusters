"""
Logging configuration for Spambuster.
Call setup_logging() once at startup before Flask app is created.
"""
import logging
import sys


def setup_logging():
    """Configure root logger from LOG_LEVEL and LOG_FILE env vars."""
    # Import here to avoid circular imports during module load
    from config import Config

    level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    log_file = Config.LOG_FILE

    fmt = "[%(asctime)s] %(levelname)s [%(name)s] %(message)s"
    formatter = logging.Formatter(fmt)

    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("discord").setLevel(logging.WARNING)

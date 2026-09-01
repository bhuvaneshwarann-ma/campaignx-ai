import re
import hmac
import hashlib
import logging
from typing import Any
from backend.app.core.config import settings

# Regex patterns for identifying PII in log messages
PHONE_REGEX = re.compile(r'(\+?\d{1,4}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}')
UPI_REGEX = re.compile(r'[\w.-]+@[\w.-]+')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')


def hash_token(val: str, prefix: str = "PII") -> str:
    """Generate deterministic pseudonymized token using HMAC-SHA256."""
    h = hmac.new(settings.PII_HMAC_KEY.encode('utf-8'), val.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{prefix}_{h[:8].upper()}"


class PIIMaskingFormatter(logging.Formatter):
    """Custom logging formatter that automatically masks PII in log records."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Mask emails
        msg = EMAIL_REGEX.sub(lambda m: hash_token(m.group(0), "EMAIL"), msg)
        # Mask UPIs
        msg = UPI_REGEX.sub(lambda m: hash_token(m.group(0), "UPI"), msg)
        # Mask Phones
        msg = PHONE_REGEX.sub(lambda m: hash_token(m.group(0), "PHONE"), msg)
        return msg


def setup_logger(name: str = "campaignx") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = PIIMaskingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    return logger


logger = setup_logger()

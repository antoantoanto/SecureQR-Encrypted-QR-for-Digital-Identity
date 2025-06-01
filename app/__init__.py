"""
Cryptosign - A digital signature application.

This package provides functionality for creating and verifying digital signatures
using RSA and SHA-256 cryptography.
"""

from pathlib import Path
from typing import Optional

from .crypto import CryptoManager
from .config import (
    APP_NAME,
    APP_VERSION,
    APP_TITLE,
    BASE_DIR,
    KEYS_DIR,
    LOGS_DIR,
    SIGNATURE_EXTENSION,
    PRIVATE_KEY_EXTENSION,
    PUBLIC_KEY_EXTENSION,
    DEFAULT_KEY_NAME,
    DEFAULT_WINDOW_SIZE,
    MIN_WINDOW_SIZE,
    THEME_COLORS,
    LOGGING_CONFIG,
    get_config
)

__version__ = APP_VERSION
__author__ = 'Cryptosign Team'

__all__ = [
    'CryptoManager',
]

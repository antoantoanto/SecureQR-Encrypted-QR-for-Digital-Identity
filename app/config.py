"""
Configuration settings for the Cryptosign application.
"""

from pathlib import Path
from typing import Dict, Any

# Base directory
BASE_DIR = Path(__file__).parent.parent


# Application information
APP_NAME = "Cryptosign"
APP_VERSION = "1.0.0"
APP_TITLE = f"{APP_NAME} v{APP_VERSION}"

# File paths
BASE_DIR = Path(__file__).parent.parent
UI_DIR = BASE_DIR / "ui"
ASSETS_DIR = UI_DIR / "assets"
KEYS_DIR = BASE_DIR / "keys"
DATA_DIR = BASE_DIR / "data"  # Directory for storing application data
LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist
for directory in [KEYS_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# File extensions
SIGNATURE_EXTENSION = ".sig"
PRIVATE_KEY_EXTENSION = "_private.pem"
PUBLIC_KEY_EXTENSION = "_public.pem"

# Default key name
DEFAULT_KEY_NAME = "default"

# UI settings
DEFAULT_WINDOW_SIZE = "900x700"
MIN_WINDOW_SIZE = (800, 600)

# Theme colors
THEME_COLORS = {
    "primary": "#4a6da7",
    "primary_dark": "#3a5a8c",
    "secondary": "#6c757d",
    "accent": "#4a90e2",
    "success": "#28a745",
    "danger": "#dc3545",
    "warning": "#ffc107",
    "info": "#17a2b8",
    "light": "#f8f9fa",
    "dark": "#343a40",
    "background": "#f0f2f5",
    "surface": "#ffffff",
    "on_primary": "#ffffff",
    "on_surface": "#212529",
}

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        },
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": str(LOGS_DIR / "cryptosign.log"),
            "formatter": "standard",
            "encoding": "utf-8",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
    },
    "loggers": {
        "": {  # root logger
            "handlers": ["file", "console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}

def get_config() -> Dict[str, Any]:
    """Get the application configuration."""
    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "app_title": APP_TITLE,
        "base_dir": str(BASE_DIR),
        "keys_dir": str(KEYS_DIR),
        "logs_dir": str(LOGS_DIR),
        "signature_extension": SIGNATURE_EXTENSION,
        "private_key_extension": PRIVATE_KEY_EXTENSION,
        "public_key_extension": PUBLIC_KEY_EXTENSION,
        "default_key_name": DEFAULT_KEY_NAME,
    }

DEFAULT_ENCODING = 'utf-8'

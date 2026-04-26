"""
config.py
─────────
Centralised configuration for the Threat Intelligence Platform.

All settings are loaded from the .env file (or real environment variables)
via python-dotenv. Every value has a safe default so the app starts even
without a .env file present (useful in CI/CD pipelines).
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (one directory above this file if needed)
_env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=_env_path, override=False)


class Config:
    """
    Static configuration class.
    Access any setting as:  Config.VIRUSTOTAL_API_KEY
    """

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # ── MongoDB ────────────────────────────────────────────────────────────────
    MONGO_URI: str    = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "threat_intelligence")

    # Collection names (not configurable via env; kept here for single-source-of-truth)
    COLLECTION_THREATS: str = "threats"
    COLLECTION_ALERTS:  str = "alerts"

    # ── Flask ──────────────────────────────────────────────────────────────────
    FLASK_HOST:  str  = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT:  int  = int(os.getenv("FLASK_PORT", 5000))
    FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "False").strip().lower() == "true"

    # ── Scoring thresholds ─────────────────────────────────────────────────────
    LOW_THRESHOLD:  int = int(os.getenv("LOW_THRESHOLD", 30))
    HIGH_THRESHOLD: int = int(os.getenv("HIGH_THRESHOLD", 70))

    # ── Retry / resilience ─────────────────────────────────────────────────────
    MAX_RETRIES:  int   = int(os.getenv("MAX_RETRIES", 3))
    RETRY_DELAY:  float = float(os.getenv("RETRY_DELAY", 2.0))

    # ── Logging ────────────────────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_DIR:   str = os.getenv("LOG_DIR", "logs")
    LOG_FILE:  str = os.getenv("LOG_FILE", "tip.log")

    @classmethod
    def validate(cls) -> None:
        """
        Raise ValueError if required settings are missing.
        Call this once at application startup.
        """
        if not cls.VIRUSTOTAL_API_KEY:
            raise ValueError(
                "VIRUSTOTAL_API_KEY is not set. "
                "Add it to your .env file or environment."
            )
        if not cls.MONGO_URI:
            raise ValueError("MONGO_URI is not set.")

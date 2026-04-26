"""
logger.py
─────────
Configures and exposes the shared application logger.

Features
─────────────────────────────────────────────────────────────────────────────
• Writes to both the console (stdout) and a rotating log file
• Log level, log directory, and log filename are all read from Config
• File handler rotates at 5 MB with 3 backup files kept
• All modules import `logger` from here – one instance, consistent format

Usage::

    from logger import logger
    logger.info("Something happened")
    logger.error("Something went wrong: %s", exc)
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from config import Config


# ── Internal setup ────────────────────────────────────────────────────────────

def _build_logger(name: str = "TIP") -> logging.Logger:
    """Create and configure the application logger."""
    log = logging.getLogger(name)

    # Avoid adding duplicate handlers when modules are reloaded (e.g. in tests)
    if log.handlers:
        return log

    log.setLevel(getattr(logging, Config.LOG_LEVEL, logging.INFO))

    # Shared formatter
    fmt = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s – %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Console handler ───────────────────────────────────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(getattr(logging, Config.LOG_LEVEL, logging.INFO))
    log.addHandler(console_handler)

    # ── Rotating file handler ─────────────────────────────────────────────────
    try:
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        log_path = os.path.join(Config.LOG_DIR, Config.LOG_FILE)

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,   # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(logging.DEBUG)  # always capture debug in file
        log.addHandler(file_handler)
    except OSError as err:
        log.warning("Could not create log file handler: %s", err)

    return log


# ── Module-level singleton ─────────────────────────────────────────────────────
logger: logging.Logger = _build_logger()

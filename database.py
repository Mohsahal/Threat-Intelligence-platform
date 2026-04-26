"""
database.py
───────────
MongoDB connection management for the Threat Intelligence Platform.

Design decisions
─────────────────────────────────────────────────────────────────────────────
• A single MongoClient is created lazily (on first use) and reused across
  the entire process lifetime – this is the correct pattern for Flask apps.
• `get_db()` returns the top-level database object.
• `get_collection(name)` returns a named collection – used by storage.py
  and scorer.py to keep collection access in one place.
• A connection failure at startup raises immediately so the operator sees
  a clear error rather than cryptic failures during request handling.

Usage::

    from database import get_db, get_collection

    db  = get_db()
    col = get_collection("threats")
"""

import threading

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ConfigurationError

from config import Config
from logger import logger


# ── Connection state (module-level, protected by a lock) ──────────────────────

_client: MongoClient | None = None
_db:     Database    | None = None
_lock = threading.Lock()


# ── Public API ────────────────────────────────────────────────────────────────

def get_db() -> Database:
    """
    Return the shared MongoDB Database instance, creating it on first call.

    Raises:
        ConnectionFailure: If MongoDB is unreachable.
        ConfigurationError: If the URI is malformed.
    """
    global _client, _db

    if _db is not None:
        return _db

    with _lock:
        # Double-checked locking – another thread may have initialised while
        # we were waiting on the lock.
        if _db is not None:
            return _db

        logger.info("Connecting to MongoDB at %s …", _mask_uri(Config.MONGO_URI))
        try:
            _client = MongoClient(
                Config.MONGO_URI,
                serverSelectionTimeoutMS=5_000,   # fail fast
                connectTimeoutMS=5_000,
                socketTimeoutMS=10_000,
            )
            # Force connection attempt so we catch errors HERE, not later
            _client.admin.command("ping")

            _db = _client[Config.MONGO_DB_NAME]
            logger.info(
                "MongoDB connected successfully – database: '%s'",
                Config.MONGO_DB_NAME,
            )

            # Ensure useful indexes exist
            _ensure_indexes(_db)

        except (ConnectionFailure, ConfigurationError) as exc:
            logger.critical("Failed to connect to MongoDB: %s", exc)
            raise

    return _db


def get_collection(name: str) -> Collection:
    """
    Return a named collection from the shared database.

    Args:
        name: Collection name (e.g. Config.COLLECTION_THREATS).

    Returns:
        pymongo.collection.Collection
    """
    return get_db()[name]


# ── Private helpers ───────────────────────────────────────────────────────────

def _ensure_indexes(db: Database) -> None:
    """
    Create indexes idempotently.  Index creation is a no-op if the index
    already exists, making this safe to call on every startup.
    """
    try:
        # threats collection – unique index on indicator for fast upserts
        db[Config.COLLECTION_THREATS].create_index(
            "indicator", unique=True, background=True
        )
        # alerts collection – compound index for common filter + sort pattern
        db[Config.COLLECTION_ALERTS].create_index(
            [("severity", 1), ("triggered_at", -1)], background=True
        )
        logger.debug("MongoDB indexes verified.")
    except Exception as exc:
        logger.warning("Could not ensure MongoDB indexes: %s", exc)


def _mask_uri(uri: str) -> str:
    """Redact password from URI for safe logging (e.g. mongodb+srv://user:***@…)."""
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(uri)
        if parsed.password:
            masked = parsed._replace(
                netloc=f"{parsed.username}:***@{parsed.hostname}"
                + (f":{parsed.port}" if parsed.port else "")
            )
            return urlunparse(masked)
    except Exception:
        pass
    return uri

"""
storage.py
──────────
MongoDB persistence layer for threat indicators.

Provides upsert semantics so that running the same indicator twice
updates the record rather than creating a duplicate.
"""

from datetime import datetime, timezone

from pymongo.errors import PyMongoError

from config import Config
from database import get_collection
from logger import logger


# ── Public API ────────────────────────────────────────────────────────────────

def upsert_threat(document: dict) -> bool:
    """
    Insert or update a threat document in the threats collection.

    Uses the `indicator` field as the unique key for upsert.
    If a document with the same indicator already exists, it is
    updated in-place; otherwise a new document is created.

    Args:
        document: Normalised threat document from normalizer.normalize().

    Returns:
        bool: True on success, False on failure.
    """
    indicator = document.get("indicator")
    if not indicator:
        logger.error("upsert_threat called with document missing 'indicator'. Skipping.")
        return False

    # Stamp the update time before writing
    document["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        collection = get_collection(Config.COLLECTION_THREATS)

        result = collection.update_one(
            filter={"indicator": indicator},     # match key
            update={"$set": document},           # set all normalised fields
            upsert=True,                         # insert if not found
        )

        if result.upserted_id:
            logger.info("Inserted new threat document for %s.", indicator)
        else:
            logger.info("Updated existing threat document for %s (matched=%d).",
                        indicator, result.matched_count)

        return True

    except PyMongoError as exc:
        logger.error("MongoDB error while upserting %s: %s", indicator, exc)
        return False


def get_all_threats() -> list[dict]:
    """
    Retrieve every stored threat document (sorted by threat_score descending).

    Returns:
        list[dict]: List of threat documents; empty list on error.
    """
    try:
        collection = get_collection(Config.COLLECTION_THREATS)
        # Exclude MongoDB internal _id from results to keep JSON-safe output
        threats = list(
            collection.find({}, {"_id": 0}).sort("threat_score", -1)
        )
        return threats
    except PyMongoError as exc:
        logger.error("Failed to retrieve threats from MongoDB: %s", exc)
        return []


def get_threat_by_indicator(indicator: str) -> dict | None:
    """
    Fetch a single threat document by its indicator value.

    Args:
        indicator: IP or domain string.

    Returns:
        dict | None: The document, or None if not found.
    """
    try:
        collection = get_collection(Config.COLLECTION_THREATS)
        return collection.find_one({"indicator": indicator}, {"_id": 0})
    except PyMongoError as exc:
        logger.error("Failed to fetch indicator %s: %s", indicator, exc)
        return None


def get_alerts(severity_filter: str | None = None) -> list[dict]:
    """
    Retrieve alert documents, optionally filtered by severity.

    Args:
        severity_filter: One of 'low', 'medium', 'high', or None for all.

    Returns:
        list[dict]: Sorted by triggered_at descending.
    """
    try:
        collection = get_collection(Config.COLLECTION_ALERTS)
        query = {}
        if severity_filter and severity_filter in ("low", "medium", "high"):
            query["severity"] = severity_filter

        return list(
            collection.find(query, {"_id": 0}).sort("triggered_at", -1)
        )
    except PyMongoError as exc:
        logger.error("Failed to retrieve alerts: %s", exc)
        return []

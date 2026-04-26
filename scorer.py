"""
scorer.py
─────────
Converts a numeric threat_score (0–100) into a human-readable
severity label and decides whether to raise an alert.

Thresholds are read from Config so they can be tuned via .env:
  • threat_score  <  LOW_THRESHOLD   →  "low"
  • LOW_THRESHOLD ≤ threat_score  <  HIGH_THRESHOLD → "medium"
  • threat_score ≥  HIGH_THRESHOLD  →  "high"
"""

from datetime import datetime, timezone

from config import Config
from database import get_collection
from logger import logger


# ── Severity label constants ──────────────────────────────────────────────────
SEVERITY_LOW    = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH   = "high"


# ── Public API ────────────────────────────────────────────────────────────────

def classify_severity(threat_score: int) -> str:
    """
    Map a 0–100 threat score to a severity label.

    Args:
        threat_score: Integer between 0 and 100.

    Returns:
        str: One of 'low', 'medium', or 'high'.
    """
    if threat_score >= Config.HIGH_THRESHOLD:
        return SEVERITY_HIGH
    if threat_score >= Config.LOW_THRESHOLD:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def evaluate_and_alert(normalised_doc: dict) -> dict | None:
    """
    Evaluate a normalised threat document and, if warranted, store an alert.

    An alert is created whenever severity is 'medium' or 'high'.
    Low-severity indicators are still logged but do not generate alerts.

    Args:
        normalised_doc: Document returned by normalizer.normalize().

    Returns:
        dict | None: The alert document if one was created, else None.
    """
    indicator    = normalised_doc.get("indicator", "unknown")
    threat_score = normalised_doc.get("threat_score", 0)
    severity     = classify_severity(threat_score)

    logger.info(
        "Evaluated %s → score=%d, severity=%s",
        indicator, threat_score, severity.upper(),
    )

    if severity == SEVERITY_LOW:
        logger.debug("No alert for %s (low severity).", indicator)
        return None

    # Build alert document
    alert = {
        "indicator":      indicator,
        "indicator_type": normalised_doc.get("indicator_type", "unknown"),
        "threat_score":   threat_score,
        "severity":       severity,
        "malicious_count":  normalised_doc.get("malicious_count", 0),
        "suspicious_count": normalised_doc.get("suspicious_count", 0),
        "total_engines":    normalised_doc.get("total_engines", 0),
        "country":        normalised_doc.get("country", "unknown"),
        "as_owner":       normalised_doc.get("as_owner", "unknown"),
        "source":         normalised_doc.get("source", "virustotal"),
        "api_error":      normalised_doc.get("api_error", False),
        "triggered_at":   datetime.now(timezone.utc).isoformat(),
        "message":        _build_message(indicator, severity, threat_score),
    }

    # Persist to MongoDB alerts collection
    try:
        collection = get_collection(Config.COLLECTION_ALERTS)
        collection.insert_one(alert)
        logger.info("Alert stored for %s [%s].", indicator, severity.upper())
    except Exception as exc:
        logger.error("Failed to store alert for %s: %s", indicator, exc)

    # Remove MongoDB ObjectId (not JSON-serialisable) before returning
    alert.pop("_id", None)
    return alert


# ── Private helpers ───────────────────────────────────────────────────────────

def _build_message(indicator: str, severity: str, score: int) -> str:
    """Compose a human-readable alert message."""
    return (
        f"[{severity.upper()}] Threat detected: {indicator} "
        f"scored {score}/100 on VirusTotal."
    )

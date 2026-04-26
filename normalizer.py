"""
normalizer.py
─────────────
Transforms raw VirusTotal API responses into a clean, flat document
that can be stored in MongoDB.

Design goals
  ─────────────────────────────────────────────────────────────────────────────
  • All field access uses `.get()` – never raises KeyError on missing data
  • Produces a consistent schema regardless of which fields VT returns
  • Computes a numeric threat_score (0–100) used by the scorer module
"""

from datetime import datetime, timezone
from logger import logger


# ── Public API ───────────────────────────────────────────────────────────────

def normalize(raw: dict, indicator: str, indicator_type: str) -> dict:
    """
    Convert a raw VirusTotal response into a normalised threat document.

    Args:
        raw:            Full JSON dict returned by VirusTotal (may be empty).
        indicator:      The IP/domain string that was queried.
        indicator_type: One of 'ip' or 'domain'.

    Returns:
        dict: Normalised document ready to be upserted into MongoDB.
              Returns a minimal stub document if `raw` is empty.
    """
    if not raw:
        logger.warning("Empty API response for %s (%s). Using stub document.", indicator, indicator_type)
        return _stub(indicator, indicator_type)

    # Navigate the VT v3 response structure safely
    data: dict       = raw.get("data", {})
    attributes: dict = data.get("attributes", {})

    # ── Reputation & analysis stats ──────────────────────────────────────────
    last_analysis_stats: dict = attributes.get("last_analysis_stats", {})
    malicious_count:  int = last_analysis_stats.get("malicious", 0)
    suspicious_count: int = last_analysis_stats.get("suspicious", 0)
    harmless_count:   int = last_analysis_stats.get("harmless", 0)
    undetected_count: int = last_analysis_stats.get("undetected", 0)
    total_count: int = (
        malicious_count + suspicious_count + harmless_count + undetected_count
    )

    # ── Compute numeric threat score ─────────────────────────────────────────
    threat_score = _compute_threat_score(malicious_count, suspicious_count, total_count)

    # ── Build normalised document ─────────────────────────────────────────────
    document = {
        # --- Identity fields -------------------------------------------------
        "indicator":      indicator,
        "indicator_type": indicator_type,

        # --- VT reputation & community score ---------------------------------
        "reputation":     attributes.get("reputation", 0),

        # --- Analysis counts -------------------------------------------------
        "malicious_count":  malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count":   harmless_count,
        "undetected_count": undetected_count,
        "total_engines":    total_count,

        # --- Computed threat score (0-100) -----------------------------------
        "threat_score": threat_score,

        # --- Extra metadata (type-specific, gracefully absent) ---------------
        "country":        attributes.get("country", "unknown"),
        "as_owner":       attributes.get("as_owner", "unknown"),
        "network":        attributes.get("network", "unknown"),

        # --- Timestamps ------------------------------------------------------
        "last_analysis_date": _epoch_to_iso(attributes.get("last_analysis_date")),
        "fetched_at":         datetime.now(timezone.utc).isoformat(),

        # --- Source tracking -------------------------------------------------
        "source": "virustotal",
        "api_error": False,
    }

    logger.debug(
        "Normalized document for %s: score=%d, malicious=%d, total=%d",
        indicator, threat_score, malicious_count, total_count,
    )
    return document


# ── Private helpers ──────────────────────────────────────────────────────────

def _compute_threat_score(malicious: int, suspicious: int, total: int) -> int:
    """
    Produce a 0–100 threat score based on VirusTotal engine verdicts.

    Formula:
        score = ((malicious * 1.0) + (suspicious * 0.5)) / total * 100

    A purely malicious indicator scores 100.
    An indicator with no detections scores 0.

    Args:
        malicious:  Number of engines flagging as malicious.
        suspicious: Number of engines flagging as suspicious.
        total:      Total number of engines that scanned the indicator.

    Returns:
        int: Score in range [0, 100].
    """
    if total == 0:
        return 0

    weighted = (malicious * 1.0) + (suspicious * 0.5)
    score = (weighted / total) * 100
    return min(int(round(score)), 100)  # clamp to [0, 100]


def _epoch_to_iso(epoch: int | None) -> str | None:
    """Convert a Unix timestamp to an ISO-8601 string (UTC). Returns None if falsy."""
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _stub(indicator: str, indicator_type: str) -> dict:
    """Return a minimal stub document used when the API call failed entirely."""
    return {
        "indicator":      indicator,
        "indicator_type": indicator_type,
        "reputation":     0,
        "malicious_count":  0,
        "suspicious_count": 0,
        "harmless_count":   0,
        "undetected_count": 0,
        "total_engines":    0,
        "threat_score":   0,
        "country":        "unknown",
        "as_owner":       "unknown",
        "network":        "unknown",
        "last_analysis_date": None,
        "fetched_at":     datetime.now(timezone.utc).isoformat(),
        "source":         "virustotal",
        "api_error":      True,  # flag so callers know data is incomplete
    }

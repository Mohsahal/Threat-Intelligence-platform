"""
collector.py
────────────
Orchestrator that ties the pipeline together:

  VirusTotal API → normalizer → storage (MongoDB) → scorer (alerts)

Call `collect_indicators()` with a list of IPs / domains to run
the full pipeline for each indicator.
"""

from virustotal_client import lookup_ip, lookup_domain
from normalizer import normalize
from storage import upsert_threat
from scorer import evaluate_and_alert
from logger import logger


# ── Public API ────────────────────────────────────────────────────────────────

def collect_indicators(indicators: list[str]) -> list[dict]:
    """
    Run the full collection pipeline for a list of threat indicators.

    For each indicator the pipeline:
      1. Detects whether it is an IP or a domain
      2. Queries VirusTotal
      3. Normalises the raw response
      4. Upserts the document into MongoDB
      5. Evaluates severity and stores an alert if warranted

    Args:
        indicators: List of IPv4/IPv6 addresses or domain names.

    Returns:
        list[dict]: Normalised threat documents produced during this run.
    """
    results = []

    for item in indicators:
        item = item.strip()
        if not item:
            continue

        logger.info("Processing indicator: %s", item)

        # ── Step 1: Determine indicator type ──────────────────────────────────
        indicator_type = _detect_type(item)

        # ── Step 2: Fetch from VirusTotal ─────────────────────────────────────
        if indicator_type == "ip":
            raw_response = lookup_ip(item)
        else:
            raw_response = lookup_domain(item)

        # ── Step 3: Normalise ─────────────────────────────────────────────────
        doc = normalize(raw_response, item, indicator_type)

        # ── Step 4: Persist to MongoDB ────────────────────────────────────────
        success = upsert_threat(doc)
        if not success:
            logger.warning("Storage failed for %s. Continuing with next indicator.", item)

        # ── Step 5: Evaluate and alert ────────────────────────────────────────
        evaluate_and_alert(doc)

        results.append(doc)

    logger.info("Collection run complete. Processed %d indicator(s).", len(results))
    return results


# ── Private helpers ───────────────────────────────────────────────────────────

def _detect_type(indicator: str) -> str:
    """
    Heuristically decide if an indicator is an IP address or a domain.

    Strategy:
      • Split by '.'; if every part is numeric (0-255) → IP
      • Otherwise → domain

    Args:
        indicator: Raw indicator string.

    Returns:
        'ip' or 'domain'
    """
    parts = indicator.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return "ip"
        except ValueError:
            pass

    # Basic IPv6 detection
    if ":" in indicator:
        return "ip"

    return "domain"

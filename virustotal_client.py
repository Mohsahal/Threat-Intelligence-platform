"""
virustotal_client.py
─────────────────────
Thin HTTP client for the VirusTotal v3 public API.

Supported lookups
─────────────────────────────────────────────────────────────────────────────
  lookup_ip(ip)      → GET /api/v3/ip_addresses/{ip}
  lookup_domain(dom) → GET /api/v3/domains/{dom}

Resilience features
─────────────────────────────────────────────────────────────────────────────
  • Configurable retry loop (MAX_RETRIES, RETRY_DELAY from Config)
  • Exponential back-off between retries
  • Handles 429 Too Many Requests with Retry-After header
  • Returns an empty dict on unrecoverable errors so the caller can gracefully
    produce a stub document rather than crashing the pipeline

Usage::

    from virustotal_client import lookup_ip, lookup_domain

    raw = lookup_ip("8.8.8.8")
    raw = lookup_domain("example.com")
"""

import time

import requests

from config import Config
from logger import logger


# ── Constants ─────────────────────────────────────────────────────────────────

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT  = 20   # seconds per HTTP request


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_ip(ip: str) -> dict:
    """
    Query VirusTotal for an IPv4 / IPv6 address.

    Args:
        ip: IP address string (e.g. '8.8.8.8').

    Returns:
        dict: Raw VirusTotal JSON response, or {} on failure.
    """
    return _get(f"/ip_addresses/{ip}", label=ip)


def lookup_domain(domain: str) -> dict:
    """
    Query VirusTotal for a domain name.

    Args:
        domain: Domain string (e.g. 'example.com').

    Returns:
        dict: Raw VirusTotal JSON response, or {} on failure.
    """
    return _get(f"/domains/{domain}", label=domain)


# ── Private helpers ───────────────────────────────────────────────────────────

def _get(path: str, label: str) -> dict:
    """
    Perform a GET request against the VirusTotal v3 API with retry logic.

    Args:
        path:  API path, e.g. '/ip_addresses/8.8.8.8'.
        label: Human-readable label used in log messages.

    Returns:
        dict: Parsed JSON body, or {} if all attempts failed.
    """
    if not Config.VIRUSTOTAL_API_KEY:
        logger.error(
            "VIRUSTOTAL_API_KEY is not configured. "
            "Set it in .env and restart the server."
        )
        return {}

    url     = f"{_BASE_URL}{path}"
    headers = {
        "x-apikey": Config.VIRUSTOTAL_API_KEY,
        "Accept":   "application/json",
    }

    attempt = 0
    delay   = float(Config.RETRY_DELAY)

    while attempt < Config.MAX_RETRIES:
        attempt += 1
        logger.debug("VT request attempt %d/%d for %s", attempt, Config.MAX_RETRIES, label)

        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)

            # ── Rate-limit handling ───────────────────────────────────────────
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", delay))
                logger.warning(
                    "VirusTotal rate limit hit for %s. Waiting %ds before retry …",
                    label, retry_after,
                )
                time.sleep(retry_after)
                delay *= 2   # exponential back-off
                continue

            # ── Authentication errors (permanent – no retry) ──────────────────
            if response.status_code == 401:
                logger.error(
                    "VirusTotal API: 401 Unauthorized. Check your VIRUSTOTAL_API_KEY."
                )
                return {}

            # ── Resource not found (indicator unknown to VT) ──────────────────
            if response.status_code == 404:
                logger.warning("VirusTotal returned 404 for %s (indicator not in VT).", label)
                return {}

            # ── Other HTTP errors ─────────────────────────────────────────────
            if not response.ok:
                logger.warning(
                    "VirusTotal returned HTTP %d for %s on attempt %d/%d.",
                    response.status_code, label, attempt, Config.MAX_RETRIES,
                )
                _sleep_with_backoff(attempt, delay)
                continue

            # ── Success ───────────────────────────────────────────────────────
            data = response.json()
            logger.info("VirusTotal response received for %s (HTTP 200).", label)
            return data

        except requests.exceptions.Timeout:
            logger.warning(
                "Request to VirusTotal timed out for %s (attempt %d/%d).",
                label, attempt, Config.MAX_RETRIES,
            )
            _sleep_with_backoff(attempt, delay)

        except requests.exceptions.ConnectionError as exc:
            logger.warning(
                "Network error querying VirusTotal for %s (attempt %d/%d): %s",
                label, attempt, Config.MAX_RETRIES, exc,
            )
            _sleep_with_backoff(attempt, delay)

        except ValueError as exc:
            # JSON decode failure – unexpected response body
            logger.error("Failed to parse VirusTotal response for %s: %s", label, exc)
            return {}

        except Exception as exc:
            logger.error(
                "Unexpected error querying VirusTotal for %s: %s", label, exc
            )
            return {}

    logger.error(
        "All %d attempts to query VirusTotal for %s failed. Returning empty result.",
        Config.MAX_RETRIES, label,
    )
    return {}


def _sleep_with_backoff(attempt: int, base_delay: float) -> None:
    """Sleep for base_delay * attempt seconds (simple linear back-off)."""
    sleep_for = base_delay * attempt
    logger.debug("Backing off for %.1fs before next retry …", sleep_for)
    time.sleep(sleep_for)

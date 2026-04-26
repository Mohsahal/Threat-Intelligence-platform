"""
test_platform.py
────────────────
Integration test / demo script for the Threat Intelligence Platform.

WHAT IT DOES
─────────────────────────────────────────────────────────────────────────────
1. Verifies the Flask API is reachable (/health)
2. Submits a batch of sample IPs and domains via POST /collect
3. Fetches and displays all stored threats  (GET /threats)
4. Fetches and displays all alerts          (GET /alerts)
5. Fetches HIGH-severity alerts only        (GET /alerts?severity=high)
6. Looks up a single indicator              (GET /threats/<indicator>)

USAGE
─────────────────────────────────────────────────────────────────────────────
  # 1. Start the Flask server in another terminal:
  #       python app.py
  #
  # 2. Run this script:
  #       python test_platform.py

The script never crashes – every request is wrapped in try/except.
"""

import json
import sys
import time

import requests

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_URL       = "http://localhost:5000"
REQUEST_TIMEOUT = 15  # seconds

# Sample indicators: mix of IPs and domains
SAMPLE_INDICATORS = [
    "8.8.8.8",          # Google DNS – usually clean
    "1.1.1.1",          # Cloudflare DNS – usually clean
    "185.220.101.45",   # Known Tor exit node (often flagged)
    "45.33.32.156",     # Scanme.nmap.org – often scanned/known
    "example.com",      # Benign domain
    "malware.wicar.org",# Test malware domain (safe for testing purposes)
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_section(title: str) -> None:
    """Print a visually distinct section header."""
    print()
    print("=" * 65)
    print(f"  {title}")
    print("=" * 65)


def _pretty(data) -> str:
    """Pretty-print a dict/list as JSON."""
    return json.dumps(data, indent=2, default=str)


def _get(path: str, params: dict | None = None) -> dict | None:
    """Perform a GET request and return the JSON body, or None on error."""
    url = f"{BASE_URL}{path}"
    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        print(f"  [HTTP ERROR] {exc.response.status_code}: {exc.response.text[:200]}")
    except requests.ConnectionError:
        print(f"  [CONNECTION ERROR] Cannot reach {url}. Is the Flask server running?")
    except Exception as exc:
        print(f"  [UNEXPECTED ERROR] {exc}")
    return None


def _post(path: str, body: dict) -> dict | None:
    """Perform a POST request with a JSON body and return the JSON body, or None on error."""
    url = f"{BASE_URL}{path}"
    try:
        resp = requests.post(url, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        print(f"  [HTTP ERROR] {exc.response.status_code}: {exc.response.text[:200]}")
    except requests.ConnectionError:
        print(f"  [CONNECTION ERROR] Cannot reach {url}. Is the Flask server running?")
    except Exception as exc:
        print(f"  [UNEXPECTED ERROR] {exc}")
    return None


# ── Test steps ────────────────────────────────────────────────────────────────

def test_health() -> bool:
    """Step 1 – Verify the API is live."""
    _print_section("STEP 1 – Health Check")
    data = _get("/health")
    if data is None:
        print("  FAIL: Could not reach the API.")
        return False
    print(_pretty(data))
    healthy = data.get("status") == "ok"
    print(f"\n  Result: {'PASS ✓' if healthy else 'FAIL ✗'}")
    return healthy


def test_collect() -> None:
    """Step 2 – Trigger collection for sample indicators."""
    _print_section("STEP 2 – Collect Indicators")
    print("  Sending indicators:", SAMPLE_INDICATORS)
    print("  (This calls VirusTotal – may take a moment…)\n")

    data = _post("/collect", {"indicators": SAMPLE_INDICATORS})
    if data is None:
        print("  FAIL: Collection request failed.")
        return

    print(f"  Message : {data.get('message')}")
    results = data.get("results", [])
    for doc in results:
        print(
            f"    → {doc.get('indicator'):30s}  "
            f"type={doc.get('indicator_type'):6s}  "
            f"score={doc.get('threat_score'):3d}  "
            f"severity=N/A (use /alerts)  "
            f"api_error={doc.get('api_error')}"
        )


def test_get_threats() -> None:
    """Step 3 – Retrieve all stored threats."""
    _print_section("STEP 3 – Get All Threats")
    data = _get("/threats")
    if data is None:
        print("  FAIL: Could not retrieve threats.")
        return
    print(f"  Total threats stored: {data.get('count', 0)}")
    for doc in data.get("threats", []):
        print(
            f"    {doc.get('indicator'):30s}  "
            f"score={doc.get('threat_score'):3d}  "
            f"malicious={doc.get('malicious_count'):3d}"
        )


def test_get_alerts() -> None:
    """Step 4 – Retrieve all alerts."""
    _print_section("STEP 4 – Get All Alerts")
    data = _get("/alerts")
    if data is None:
        print("  FAIL: Could not retrieve alerts.")
        return
    print(f"  Total alerts: {data.get('count', 0)}")
    for alert in data.get("alerts", []):
        print(f"    [{alert.get('severity', '?').upper():6s}]  {alert.get('indicator'):30s}  {alert.get('message')}")


def test_get_high_alerts() -> None:
    """Step 5 – Filter for HIGH severity alerts only."""
    _print_section("STEP 5 – High-Severity Alerts Only")
    data = _get("/alerts", params={"severity": "high"})
    if data is None:
        print("  FAIL: Could not retrieve high-severity alerts.")
        return
    print(f"  High-severity alerts: {data.get('count', 0)}")
    for alert in data.get("alerts", []):
        print(f"    {alert.get('indicator'):30s}  score={alert.get('threat_score')}")


def test_single_indicator(indicator: str) -> None:
    """Step 6 – Look up a single indicator."""
    _print_section(f"STEP 6 – Single Indicator Lookup: {indicator}")
    data = _get(f"/threats/{indicator}")
    if data is None:
        print(f"  Indicator '{indicator}' not found or request failed.")
        return
    print(_pretty(data))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "★" * 65)
    print("   Threat Intelligence Platform – Integration Test Script")
    print("★" * 65)

    # Step 1: Health check (abort if API is down)
    if not test_health():
        print("\n  Cannot continue – please start the Flask server first:")
        print("      python app.py\n")
        sys.exit(1)

    # Step 2: Collection (network calls to VirusTotal)
    test_collect()

    # Allow a brief moment for DB writes to settle
    time.sleep(1)

    # Step 3–6: Query results
    test_get_threats()
    test_get_alerts()
    test_get_high_alerts()
    test_single_indicator(SAMPLE_INDICATORS[0])

    _print_section("ALL TESTS COMPLETE")
    print("  Check the 'logs/tip.log' file for detailed execution logs.\n")


if __name__ == "__main__":
    main()

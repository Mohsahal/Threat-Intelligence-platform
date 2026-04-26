"""
app.py
──────
Flask REST API for the Threat Intelligence Platform.

Endpoints
─────────────────────────────────────────────────────────────────────────────
GET  /health                  → liveness check
GET  /alerts                  → list all alerts (optional ?severity= filter)
GET  /threats                 → list all stored threat indicators
GET  /threats/<indicator>     → fetch a single indicator by value
POST /collect                 → trigger a collection run for supplied indicators
"""

from flask import Flask, jsonify, request

from config import Config
from database import get_db          # ensures MongoDB is reachable on startup
from storage import get_alerts, get_all_threats, get_threat_by_indicator
from collector import collect_indicators
from logger import logger

# ── Flask application factory ─────────────────────────────────────────────────
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False   # preserve insertion order in responses


# ── Health check ──────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """
    Simple liveness probe.
    Returns 200 when the application and MongoDB are reachable.
    """
    try:
        get_db().command("ping")
        return jsonify({"status": "ok", "database": "connected"}), 200
    except Exception as exc:
        logger.error("Health check failed: %s", exc)
        return jsonify({"status": "error", "database": "disconnected", "detail": str(exc)}), 503


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.route("/alerts", methods=["GET"])
def alerts():
    """
    Return stored alerts.

    Query params
    ────────────
    severity (optional): filter by 'low', 'medium', or 'high'.

    Example:
        GET /alerts
        GET /alerts?severity=high
    """
    severity_filter = request.args.get("severity", "").strip().lower() or None

    # Validate severity parameter
    if severity_filter and severity_filter not in ("low", "medium", "high"):
        return jsonify({
            "error": "Invalid severity. Choose from: low, medium, high."
        }), 400

    data = get_alerts(severity_filter=severity_filter)
    logger.info("GET /alerts → returned %d record(s) (filter=%s).", len(data), severity_filter)
    return jsonify({"count": len(data), "alerts": data}), 200


# ── Threats ───────────────────────────────────────────────────────────────────

@app.route("/threats", methods=["GET"])
def threats():
    """Return all stored threat documents sorted by threat_score descending."""
    data = get_all_threats()
    logger.info("GET /threats → returned %d record(s).", len(data))
    return jsonify({"count": len(data), "threats": data}), 200


@app.route("/threats/<path:indicator>", methods=["GET"])
def threat_detail(indicator: str):
    """
    Fetch a single threat document by its indicator value.

    Example:
        GET /threats/8.8.8.8
        GET /threats/example.com
    """
    doc = get_threat_by_indicator(indicator)
    if doc is None:
        return jsonify({"error": f"Indicator '{indicator}' not found."}), 404
    return jsonify(doc), 200


# ── Collection trigger ────────────────────────────────────────────────────────

@app.route("/collect", methods=["POST"])
def collect():
    """
    Trigger a collection run for a list of indicators.

    Request body (JSON):
        { "indicators": ["1.2.3.4", "evil.com"] }

    Returns the normalised documents produced during the run.
    """
    body = request.get_json(silent=True) or {}
    indicators: list = body.get("indicators", [])

    if not indicators or not isinstance(indicators, list):
        return jsonify({"error": "Provide a non-empty 'indicators' list in the JSON body."}), 400

    # Sanitise: keep only strings
    clean = [str(i) for i in indicators if i]
    if not clean:
        return jsonify({"error": "No valid indicators supplied."}), 400

    logger.info("POST /collect → collecting %d indicator(s): %s", len(clean), clean)
    results = collect_indicators(clean)

    return jsonify({
        "message": f"Collected {len(results)} indicator(s).",
        "results": results,
    }), 200


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found.", "hint": "Check /health for available routes."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "HTTP method not allowed on this endpoint."}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled internal server error.")
    return jsonify({"error": "Internal server error.", "detail": str(e)}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info(
        "Starting Threat Intelligence Platform API on %s:%d (debug=%s)",
        Config.FLASK_HOST, Config.FLASK_PORT, Config.FLASK_DEBUG,
    )
    # Eagerly verify MongoDB connectivity before accepting requests
    get_db()

    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.FLASK_DEBUG,
    )

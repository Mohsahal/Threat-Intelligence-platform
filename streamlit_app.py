"""
streamlit_app.py
────────────────
Browser UI for the Threat Intelligence Platform.

Uses the same MongoDB and VirusTotal pipeline as `app.py` (storage + collector).
Run from the project root::

    streamlit run streamlit_app.py
"""

from __future__ import annotations

import json
from typing import Any

import pandas as pd
import streamlit as st

from config import Config
from database import get_db
from storage import get_alerts, get_all_threats, get_threat_by_indicator
from collector import collect_indicators
from scorer import classify_severity


# ── Page setup ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ── Session state ─────────────────────────────────────────────────────────────

if "last_batch_summary" not in st.session_state:
    st.session_state.last_batch_summary = None  # list[dict] | None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ping_database() -> tuple[bool, str | None]:
    try:
        get_db().command("ping")
        return True, None
    except Exception as exc:
        return False, str(exc)


def _canonical_indicator(s: str) -> str:
    """Keep IPs as entered; normalise hostnames to lowercase for stable DB keys."""
    s = s.strip()
    parts = s.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return s
        except ValueError:
            pass
    if ":" in s:
        return s
    return s.lower()


def _parse_indicators(raw: str) -> list[str]:
    """Split input into clean, de-duplicated indicator strings (order preserved)."""
    seen: set[str] = set()
    out: list[str] = []
    for line in raw.splitlines():
        s = line.strip().strip("\ufeff")
        if not s:
            continue
        low = s.lower()
        for prefix in ("https://", "http://"):
            if low.startswith(prefix):
                s = s[len(prefix) :]
                low = s.lower()
        s = s.split("/")[0].split("?")[0].strip()
        if not s:
            continue
        canon = _canonical_indicator(s)
        key = canon.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(canon)
    return out


def _recency_ts(doc: dict) -> str:
    return str(doc.get("updated_at") or doc.get("fetched_at") or "")


def _sort_threats(threats: list[dict], mode: str) -> list[dict]:
    if mode == "Highest score":
        return sorted(threats, key=lambda d: int(d.get("threat_score") or 0), reverse=True)
    # Newest first (default)
    return sorted(threats, key=_recency_ts, reverse=True)


def _lookup_threat(indicator: str) -> dict | None:
    """Try exact and common variants so pasted URLs / casing still match Mongo."""
    raw = indicator.strip()
    if not raw:
        return None
    candidates: list[str] = [raw, _canonical_indicator(raw)]
    low = raw.lower()
    if low != raw:
        candidates.append(low)
    # Strip scheme/host noise already handled in collect; for lookup strip again
    for prefix in ("https://", "http://"):
        if low.startswith(prefix):
            rest = raw[len(prefix) :].split("/")[0].split("?")[0].strip()
            if rest and rest not in candidates:
                candidates.append(rest)
            if rest.lower() != rest:
                candidates.append(rest.lower())
    seen: set[str] = set()
    ordered: list[str] = []
    for c in candidates:
        k = c.strip()
        if k and k not in seen:
            seen.add(k)
            ordered.append(k)
    for q in ordered:
        doc = get_threat_by_indicator(q)
        if doc is not None:
            return doc
    return None


def _threats_dataframe(threats: list[dict]) -> pd.DataFrame:
    if not threats:
        return pd.DataFrame()
    df = pd.DataFrame(threats)
    if "severity" not in df.columns and "threat_score" in df.columns:
        df["severity"] = df["threat_score"].apply(lambda x: classify_severity(int(x or 0)))
    priority = [
        "indicator",
        "indicator_type",
        "threat_score",
        "severity",
        "malicious_count",
        "suspicious_count",
        "total_engines",
        "country",
        "fetched_at",
        "updated_at",
    ]
    present = [c for c in priority if c in df.columns]
    extra = [c for c in df.columns if c not in present]
    return df[present + extra]


def _alerts_dataframe(alerts: list[dict]) -> pd.DataFrame:
    if not alerts:
        return pd.DataFrame()
    df = pd.DataFrame(alerts)
    cols = ["indicator", "severity", "threat_score", "message", "triggered_at"]
    present = [c for c in cols if c in df.columns]
    extra = [c for c in df.columns if c not in present]
    return df[present + extra]


def _batch_summary(results: list[dict]) -> list[dict]:
    rows = []
    for doc in results:
        score = int(doc.get("threat_score") or 0)
        sev = classify_severity(score)
        alert = sev in ("medium", "high")
        rows.append(
            {
                "indicator": doc.get("indicator", ""),
                "type": doc.get("indicator_type", ""),
                "threat_score": score,
                "severity": sev,
                "alert_saved": "Yes" if alert else "No (low only)",
            }
        )
    return rows


def _pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── Sidebar (minimal) ─────────────────────────────────────────────────────────

with st.sidebar:
    st.subheader("Status")
    db_ok, db_err = _ping_database()
    if db_ok:
        st.success("MongoDB connected")
    else:
        st.error("MongoDB unreachable")
        if db_err:
            st.caption(db_err)
    vt_ok = bool(Config.VIRUSTOTAL_API_KEY.strip())
    st.caption("VirusTotal API key: " + ("configured" if vt_ok else "missing in `.env`"))
    if st.button("Reload", width="stretch"):
        st.rerun()
    with st.expander("Environment"):
        st.code(f"MONGO_URI={Config.MONGO_URI}\nDB={Config.MONGO_DB_NAME}", language="text")


# ── Header ────────────────────────────────────────────────────────────────────

st.title("Threat intelligence")
st.caption("Collect indicators via VirusTotal, store in MongoDB, and review threats and alerts.")

db_ok, _ = _ping_database()
if not db_ok:
    st.warning("Connect MongoDB before collecting or browsing data.")

# Quick metrics (same data as tables — no duplicate “overview” tab)
if db_ok:
    threats_all = get_all_threats()
    alerts_all = get_alerts()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threats in DB", len(threats_all))
    m2.metric("Alerts", len(alerts_all))
    m3.metric("High alerts", sum(1 for a in alerts_all if a.get("severity") == "high"))
    m4.metric("Medium alerts", sum(1 for a in alerts_all if a.get("severity") == "medium"))

tab_run, tab_threats, tab_alerts = st.tabs(["Collect", "Threats", "Alerts"])

# ── Collect ───────────────────────────────────────────────────────────────────

with tab_run:
    raw = st.text_area(
        "Indicators (one per line)",
        height=160,
        placeholder="8.8.8.8\nexample.com",
        help="IPs, IPv6, or domains. URLs are trimmed to the host automatically.",
    )
    run = st.button("Run collection", type="primary", disabled=not db_ok, width="stretch")

    if run:
        if not Config.VIRUSTOTAL_API_KEY.strip():
            st.error("Set `VIRUSTOTAL_API_KEY` in your `.env` file.")
        else:
            lines = _parse_indicators(raw)
            if not lines:
                st.error("Enter at least one indicator.")
            else:
                with st.spinner(f"Processing {len(lines)} indicator(s)…"):
                    try:
                        results = collect_indicators(lines)
                    except Exception as exc:
                        st.exception(exc)
                    else:
                        st.session_state.last_batch_summary = _batch_summary(results)
                        st.success(f"Saved {len(results)} threat record(s). See the table below — newest rows appear at the top of the Threats tab when sorted by “Newest first”.")
                        st.dataframe(
                            pd.DataFrame(st.session_state.last_batch_summary),
                            width="stretch",
                            hide_index=True,
                        )
                        with st.expander("Full JSON (this run)"):
                            st.code(_pretty_json(results), language="json")

    if st.session_state.last_batch_summary and not run:
        st.subheader("Last collection run")
        st.dataframe(
            pd.DataFrame(st.session_state.last_batch_summary),
            width="stretch",
            hide_index=True,
        )

    st.divider()
    st.subheader("Lookup stored indicator")
    q = st.text_input("Indicator", placeholder="IP or domain", key="lookup_q")
    do_lookup = st.button("Lookup in database", disabled=not (db_ok and bool(q.strip())))
    if do_lookup:
        doc = _lookup_threat(q)
        if doc is None:
            st.warning("Not found in the database. Run collection for this value first.")
        else:
            st.json(doc)

# ── Threats ───────────────────────────────────────────────────────────────────

with tab_threats:
    if not db_ok:
        st.info("MongoDB is not connected.")
    else:
        sort_mode = st.selectbox("Sort threats", ("Newest first", "Highest score"), index=0)
        needle = st.text_input("Filter by indicator (contains)", placeholder="e.g. 8.8. or evil.com")
        threats = _sort_threats(get_all_threats(), sort_mode)
        if needle.strip():
            n = needle.strip().lower()
            threats = [t for t in threats if n in str(t.get("indicator", "")).lower()]
        df = _threats_dataframe(threats)
        if df.empty:
            st.info("No rows match. Collect indicators first, or clear the filter.")
        else:
            st.caption(f"{len(threats)} row(s)")
            st.dataframe(df, width="stretch", hide_index=True)

# ── Alerts ─────────────────────────────────────────────────────────────────────

with tab_alerts:
    if not db_ok:
        st.info("MongoDB is not connected.")
    else:
        st.caption("Alerts are only stored for **medium** and **high** severity scores. Low scores will not appear here.")
        sev = st.selectbox("Severity", ("all", "high", "medium"), index=0)
        filt = None if sev == "all" else sev
        alerts = get_alerts(severity_filter=filt)
        adf = _alerts_dataframe(alerts)
        if adf.empty:
            st.info("No alerts for this filter. Collect an indicator that scores medium or higher.")
        else:
            st.caption(f"{len(alerts)} alert(s), newest first")
            st.dataframe(adf, width="stretch", hide_index=True)

"""
dashboard/data.py
──────────────────
Data layer for HB-IDS Dashboard.

Uses raw urllib calls to Elasticsearch so there is NO version mismatch
between the elasticsearch-py client and the ES server version.

Strategy:
  1. Try connecting to Elasticsearch (real data from running Docker stack)
  2. If ES is offline or unavailable → automatically fall back to SIMULATED data
  3. Dashboard always works — no crashes, no blank screens

ES Index convention (matches Filebeat config):
  nginx-logs-*  — raw ingested Nginx access logs
  alerts-*      — alerts written by detection_engine/main.py
"""

from __future__ import annotations

import datetime
import json
import os
import random
import urllib.request
import urllib.error
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────────────
ATTACK_TYPES = ["SQL Injection", "Brute Force", "DoS", "Path Traversal", "Evasion", "Port Scan"]
SEVERITIES   = ["CRITICAL", "CRITICAL", "WARNING", "WARNING", "INFO"]
ATTACKER_IPS = [
    "10.0.0.1", "192.168.99.12", "172.16.0.44",
    "10.10.5.200", "203.0.113.42", "198.51.100.7",
    "100.64.0.5",  "45.33.32.156",
]

ES_HOST     = os.getenv("ES_HOST", "http://localhost:9200")
LOGS_INDEX  = "nginx-logs-*"
ALERTS_INDEX = "alerts-*"
TIMEOUT     = 3   # seconds


# ─────────────────────────────────────────────────────────────────────────────
# Raw urllib ES helper
# ─────────────────────────────────────────────────────────────────────────────

def _es_request(path: str, body: dict | None = None) -> dict | None:
    """
    Make a GET (body=None) or POST (body=dict) request to Elasticsearch.
    Returns the parsed JSON response, or None on any error.
    """
    url  = f"{ES_HOST.rstrip('/')}{path}"
    data = json.dumps(body).encode() if body is not None else None
    method = "POST" if data else "GET"
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Accept":       "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _es_ping() -> bool:
    """Returns True if Elasticsearch is reachable and healthy."""
    result = _es_request("/_cluster/health")
    if result and result.get("status") in ("green", "yellow"):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Live Elasticsearch queries
# ─────────────────────────────────────────────────────────────────────────────

def _es_get_alerts(n: int = 80) -> list[dict]:
    """Pull recent alerts from the `alerts-*` index."""
    body = {
        "size": n,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
    }
    resp = _es_request(f"/{ALERTS_INDEX}/_search", body)
    if not resp:
        return []
    results = []
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        ts_raw = src.get("@timestamp", "")
        ts = ts_raw[11:19] if len(ts_raw) >= 19 else "—"
        results.append({
            "timestamp":  ts,
            "severity":   src.get("severity", "INFO").upper(),
            "type":       src.get("attack_type", "Unknown"),
            "source_ip":  src.get("source_ip", "0.0.0.0"),
            "risk_score": round(float(src.get("risk_score", 0.5)), 3),
            "rule":       src.get("rule", "UNKNOWN"),
        })
    return results


def _es_get_attack_distribution() -> dict[str, int]:
    """Aggregate attack types from last 24 h via ES aggregation."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "by_type": {
                "terms": {"field": "attack_type.keyword", "size": 20}
            }
        },
    }
    resp = _es_request(f"/{ALERTS_INDEX}/_search", body)
    if not resp:
        return {}
    buckets = resp.get("aggregations", {}).get("by_type", {}).get("buckets", [])
    return {b["key"]: b["doc_count"] for b in buckets}


def _es_get_event_count() -> int:
    """Count all log events in the last 24 h from nginx-logs-*."""
    body = {"query": {"range": {"@timestamp": {"gte": "now-24h"}}}}
    resp = _es_request(f"/{LOGS_INDEX}/_count", body)
    return resp.get("count", 0) if resp else 0


def _es_get_trend() -> list[int]:
    """60-minute alert counts, one bucket per minute."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
        "aggs": {
            "by_minute": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1m",
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": "now-1h",
                        "max": "now"
                    }
                }
            }
        },
    }
    resp = _es_request(f"/{ALERTS_INDEX}/_search", body)
    if not resp:
        return []
    buckets = resp.get("aggregations", {}).get("by_minute", {}).get("buckets", [])
    counts  = [b["doc_count"] for b in buckets]
    return (counts + [0] * 60)[:60]


# ─────────────────────────────────────────────────────────────────────────────
# Simulated data (fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _sim_alerts(n: int = 80) -> list[dict]:
    now    = datetime.datetime.now()
    alerts = []
    for _ in range(n):
        sev   = random.choice(SEVERITIES)
        atype = random.choice(ATTACK_TYPES)
        ip    = random.choice(ATTACKER_IPS)
        ts    = now - datetime.timedelta(seconds=random.randint(0, 3600))
        score = round(random.uniform(0.55 if sev == "INFO" else 0.75, 1.0), 3)
        alerts.append({
            "timestamp":  ts.strftime("%H:%M:%S"),
            "severity":   sev,
            "type":       atype,
            "source_ip":  ip,
            "risk_score": score,
            "rule":       f"{atype.replace(' ', '_').upper()}_RULE",
        })
    return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)


def _sim_attack_dist() -> dict[str, int]:
    return {t: random.randint(5, 80) for t in ATTACK_TYPES}


def _sim_event_count() -> int:
    return random.randint(2000, 8000)


def _sim_trend() -> list[int]:
    vals  = [random.randint(2, 20) for _ in range(55)]
    vals += [random.randint(15, 40) for _ in range(5)]
    return vals


# ─────────────────────────────────────────────────────────────────────────────
# Public API — used by app.py
# ─────────────────────────────────────────────────────────────────────────────

def get_data_source() -> tuple[bool, bool]:
    """
    Returns (es_live, es_live).
    First element is a bool flag used by data functions.
    Call once per page refresh in app.py.
    """
    live = _es_ping()
    return live, live


def get_alerts(es=None, n: int = 80) -> list[dict]:
    # `es` is now a bool (True = live)
    if es:
        data = _es_get_alerts(n)
        if data:
            return data
    return _sim_alerts(n)


def get_attack_distribution(es=None) -> dict[str, int]:
    if es:
        data = _es_get_attack_distribution()
        if data:
            return data
    return _sim_attack_dist()


def get_event_count(es=None) -> int:
    if es:
        count = _es_get_event_count()
        if count:
            return count
    return _sim_event_count()


def get_trend(es=None) -> list[int]:
    if es:
        data = _es_get_trend()
        if data:
            return data
    return _sim_trend()

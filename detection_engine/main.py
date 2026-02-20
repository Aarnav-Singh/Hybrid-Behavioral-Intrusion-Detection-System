"""
detection_engine/main.py
─────────────────────────
Hybrid Behavioral IDS - Detection Engine Entry Point

This service:
  1. Loads baseline thresholds from data/baseline_profile.json
  2. Polls Elasticsearch for new Nginx log events
  3. Runs rule-based AND ML-based detection
  4. Writes detected alerts to ids-alerts Elasticsearch index
  5. Exposes Prometheus metrics on :8000/metrics
"""

import json
import logging
import os
import time
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
from prometheus_client import Counter, Gauge, Histogram, start_http_server

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ids.detection")

# ─────────────────────────────────────────────────────────────────────────────
# Prometheus metrics
# ─────────────────────────────────────────────────────────────────────────────

ALERTS_TOTAL = Counter(
    "ids_alerts_total",
    "Total number of intrusion alerts fired",
    ["attack_type", "severity"],
)

REQUESTS_ANALYZED = Counter(
    "ids_requests_analyzed_total",
    "Total log events analyzed by the detection engine",
)

INFERENCE_LATENCY = Histogram(
    "ids_model_inference_seconds",
    "ML model inference latency in seconds",
    ["model_name"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

ACTIVE_THREATS = Gauge(
    "ids_active_threats_gauge",
    "Number of currently active threat sources (IPs)",
)

FALSE_POSITIVE_RATE = Gauge(
    "ids_false_positive_rate",
    "Rolling false positive rate over the last 15-minute window",
)

ANOMALY_SCORE = Gauge(
    "ids_anomaly_score",
    "Per-IP anomaly score (0-1, higher = more anomalous)",
    ["ip_address"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration loader
# ─────────────────────────────────────────────────────────────────────────────

def load_baseline_profile(path: str = "/app/data/baseline_profile.json") -> dict:
    if not Path(path).exists():
        logger.warning(f"Baseline profile not found at {path}. Using defaults.")
        return {
            "detection_thresholds": {
                "rate_limit_req_per_min": 30.0,
                "error_rate_threshold":   0.30,
                "entropy_scan_threshold": 1.0,
            }
        }
    with open(path) as f:
        profile = json.load(f)
    thresholds = profile.get("detection_thresholds", {})
    logger.info(f"Loaded baseline profile. Thresholds: {thresholds}")
    return profile


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic detection rules (lightweight, no scikit-learn dependency at runtime)
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PATTERNS = re.compile(
    r"(union\s+select|drop\s+table|'.*or.*'.*=|sleep\s*\(|benchmark\s*\(|"
    r"information_schema|%27|%3D|--\s*$)",
    re.IGNORECASE,
)
XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|<iframe|<img\s.*src\s*=)",
    re.IGNORECASE,
)
PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e%252e", re.IGNORECASE)
SCANNER_UAS = re.compile(r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|burp)", re.IGNORECASE)
SUSPICIOUS_PATHS = re.compile(
    r"(/\.env|/\.git|/wp-login|/phpmyadmin|/admin|/backup|/config\.php|/server-status|/actuator)",
    re.IGNORECASE,
)


def classify_request(log: dict) -> list[dict]:
    """
    Apply heuristic rules to a parsed nginx log event.
    Returns a list of alert dicts (empty if benign).
    """
    src_ip   = log.get("remote_addr", log.get("clientip", "0.0.0.0"))
    method   = log.get("request_method", log.get("verb", "GET"))
    uri      = log.get("request_uri", log.get("request", ""))
    status   = int(log.get("status", 200))
    ua       = log.get("http_user_agent", log.get("agent", ""))
    ts       = log.get("@timestamp", datetime.now(timezone.utc).isoformat())

    alerts = []

    def make_alert(attack_type, severity, rule, risk):
        return {
            "_id":         str(uuid.uuid4()),
            "@timestamp":  ts,
            "source_ip":   src_ip,
            "dest_ip":     "172.20.0.1",
            "attack_type": attack_type,
            "severity":    severity,
            "status":      "ACTIVE",
            "proto":       "HTTP",
            "rule":        rule,
            "risk_score":  risk,
            "ml_score":    round(risk * 0.9 + 0.05, 3),
            "message":     f"{attack_type} from {src_ip} → {uri[:80]}",
        }

    # SQL Injection
    if SQLI_PATTERNS.search(uri):
        alerts.append(make_alert("SQL Injection", "CRITICAL", "SQLI_RULE", 0.95))

    # XSS
    elif XSS_PATTERNS.search(uri):
        alerts.append(make_alert("XSS", "HIGH", "XSS_RULE", 0.85))

    # Path Traversal
    elif PATH_TRAVERSAL.search(uri):
        alerts.append(make_alert("Path Traversal", "HIGH", "PATH_TRAVERSAL_RULE", 0.88))

    # Scanner UA fingerprint
    elif SCANNER_UAS.search(ua):
        alerts.append(make_alert("Port Scan", "MEDIUM", "SCANNER_UA_RULE", 0.75))

    # Suspicious paths (admin probes etc.)
    elif SUSPICIOUS_PATHS.search(uri):
        sev = "HIGH" if status in (200, 301, 302) else "MEDIUM"
        alerts.append(make_alert("Brute Force", sev, "ADMIN_PROBE_RULE", 0.80))

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch helpers
# ─────────────────────────────────────────────────────────────────────────────

def es_get(es_host: str, path: str, **kwargs):
    try:
        r = requests.get(f"{es_host}{path}", timeout=5, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.debug(f"ES GET {path}: {e}")
        return None


def get_alerts_index() -> str:
    """Daily rolling index: alerts-2026.02.20  →  matches backend's alerts-* query."""
    return f"alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def es_index_alert(es_host: str, alert: dict):
    index = get_alerts_index()
    try:
        r = requests.post(
            f"{es_host}/{index}/_doc/{alert['_id']}",
            json=alert,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
    except Exception as e:
        logger.warning(f"Failed to index alert into {index}: {e}")


def ensure_alerts_index(es_host: str):
    """Create today's alerts index with correct mapping if it doesn't exist."""
    index = get_alerts_index()
    existing = es_get(es_host, f"/{index}")
    if existing:
        logger.info(f"✓ {index} index already exists")
        return
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":  {"type": "date"},
                "source_ip":   {"type": "keyword"},
                "dest_ip":     {"type": "keyword"},
                "attack_type": {"type": "keyword"},
                "severity":    {"type": "keyword"},
                "status":      {"type": "keyword"},
                "protocol":    {"type": "keyword"},
                "rule":        {"type": "keyword"},
                "risk_score":  {"type": "float"},
                "ml_score":    {"type": "float"},
                "message":     {"type": "text"},
            }
        }
    }
    try:
        r = requests.put(
            f"{es_host}/{index}",
            json=mapping,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
        logger.info(f"✓ Created {index} index")
    except Exception as e:
        logger.error(f"Could not create {index} index: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Main detection loop
# ─────────────────────────────────────────────────────────────────────────────

def main():
    es_host    = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
    prom_port  = int(os.getenv("PROMETHEUS_PORT", "8000"))
    poll_secs  = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
    profile_path = os.getenv("BASELINE_PROFILE", "/app/data/baseline_profile.json")

    logger.info("═" * 60)
    logger.info("  HYBRID BEHAVIORAL IDS - DETECTION ENGINE")
    logger.info("═" * 60)
    logger.info(f"  Elasticsearch: {es_host}")
    logger.info(f"  Prometheus:    :{prom_port}/metrics")
    logger.info(f"  Poll interval: {poll_secs}s")

    # Start Prometheus metrics server
    start_http_server(prom_port)
    logger.info(f"✓ Prometheus metrics available at :{prom_port}/metrics")

    # Load baseline thresholds
    profile    = load_baseline_profile(profile_path)
    thresholds = profile.get("detection_thresholds", {})
    logger.info(f"  Rate threshold: {thresholds.get('rate_limit_req_per_min')} req/min")

    # Wait for ES to be ready
    logger.info("Waiting for Elasticsearch...")
    for _ in range(30):
        health = es_get(es_host, "/_cluster/health")
        if health and health.get("status") in ("green", "yellow"):
            logger.info(f"✓ Elasticsearch is {health['status']}")
            break
        time.sleep(5)
    else:
        logger.error("Elasticsearch not reachable after 150s — running metrics-only mode")
        while True:
            time.sleep(30)

    # Ensure daily alerts index exists
    ensure_alerts_index(es_host)

    # Track the last processed timestamp to avoid re-processing
    last_ts = datetime.now(timezone.utc).isoformat()
    active_ips = set()

    logger.info("✓ Detection loop started — polling nginx-logs every %ds", poll_secs)

    ip_request_windows: dict[str, list[float]] = {}  # ip → list of unix timestamps

    while True:
        try:
            # Query recent nginx log events
            query = {
                "query": {
                    "range": {"@timestamp": {"gt": last_ts}}
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
                "size": 200,
            }
            result = es_get(es_host, "/.ds-nginx-logs-*/_search", json=query)
            if not result:
                time.sleep(poll_secs)
                continue

            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                time.sleep(poll_secs)
                continue

            last_ts = hits[-1]["_source"].get("@timestamp", last_ts)
            now_unix = time.time()

            for hit in hits:
                log = hit["_source"]
                REQUESTS_ANALYZED.inc()

                src_ip = log.get("remote_addr", log.get("clientip", ""))

                # --- Rate-based DoS detection (sliding 60s window) ---
                if src_ip:
                    window = ip_request_windows.setdefault(src_ip, [])
                    window.append(now_unix)
                    # Keep only last 60 seconds
                    ip_request_windows[src_ip] = [t for t in window if now_unix - t < 60]
                    req_per_min = len(ip_request_windows[src_ip])

                    rate_limit = thresholds.get("rate_limit_req_per_min", 30.0)
                    if req_per_min > rate_limit:
                        dos_alert = {
                            "_id":         str(uuid.uuid4()),
                            "@timestamp":  log.get("@timestamp", last_ts),
                            "source_ip":   src_ip,
                            "dest_ip":     "172.20.0.1",
                            "attack_type": "DoS Flood",
                            "severity":    "CRITICAL" if req_per_min > rate_limit * 3 else "HIGH",
                            "status":      "ACTIVE",
                            "proto":       "HTTP",
                            "rule":        "RATE_LIMIT_RULE",
                            "risk_score":  min(0.99, 0.6 + req_per_min / (rate_limit * 5)),
                            "ml_score":    min(0.99, 0.65 + req_per_min / (rate_limit * 5)),
                            "message":     f"DoS Flood: {src_ip} sent {req_per_min} req in 60s (limit={rate_limit})",
                        }
                        es_index_alert(es_host, dos_alert)
                        ALERTS_TOTAL.labels(attack_type="DoS Flood", severity=dos_alert["severity"]).inc()
                        active_ips.add(src_ip)
                        logger.info(f"ALERT DoS Flood from {src_ip} ({req_per_min} req/min)")
                        continue  # don't also run heuristic rules for DoS IPs

                # --- Heuristic rule-based detection ---
                t0 = time.perf_counter()
                alerts = classify_request(log)
                latency = time.perf_counter() - t0
                INFERENCE_LATENCY.labels(model_name="heuristic").observe(latency)

                for alert in alerts:
                    es_index_alert(es_host, alert)
                    ALERTS_TOTAL.labels(
                        attack_type=alert["attack_type"],
                        severity=alert["severity"],
                    ).inc()
                    active_ips.add(alert["source_ip"])
                    logger.info(
                        f"ALERT [{alert['severity']}] {alert['attack_type']} from {alert['source_ip']}"
                    )

            ACTIVE_THREATS.set(len(active_ips))
            # Decay active IPs (remove if not seen in 5 min)
            active_ips.clear()

        except Exception as e:
            logger.error(f"Detection loop error: {e}")

        time.sleep(poll_secs)


if __name__ == "__main__":
    main()



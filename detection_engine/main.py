"""
detection_engine/main.py
─────────────────────────
Hybrid Behavioral IDS - Detection Engine Entry Point

This service:
  1. Loads baseline thresholds from data/baseline_profile.json
  2. Polls Elasticsearch for new Nginx log events
  3. Runs rule-based AND ML-based detection
  4. Exposes Prometheus metrics on :8000/metrics
  5. Logs detection events via MLflow

Start: python detection_engine/main.py
       (or via docker-compose: docker-compose up detection)
"""

import json
import logging
import os
import time
from pathlib import Path

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
# These are the metrics Prometheus scrapes from /metrics endpoint.
# See prometheus/prometheus.yml for scrape configuration.
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
    """
    Load detection thresholds from baseline analysis output.
    All thresholds are DATA-DRIVEN, not hardcoded.
    """
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
# Main detection loop (stub - to be implemented in Module 2)
# ─────────────────────────────────────────────────────────────────────────────

def main():
    es_host    = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
    prom_port  = int(os.getenv("PROMETHEUS_PORT", "8000"))
    mlflow_uri = os.getenv("MLFLOW_TRACKING_URI", "http://mlflow:5000")
    profile_path = os.getenv("BASELINE_PROFILE", "/app/data/baseline_profile.json")

    logger.info("═" * 60)
    logger.info("  HYBRID BEHAVIORAL IDS - DETECTION ENGINE")
    logger.info("═" * 60)
    logger.info(f"  Elasticsearch: {es_host}")
    logger.info(f"  Prometheus:    :{prom_port}/metrics")
    logger.info(f"  MLflow:        {mlflow_uri}")

    # Start Prometheus metrics server
    start_http_server(prom_port)
    logger.info(f"✓ Prometheus metrics available at :{prom_port}/metrics")

    # Load baseline thresholds
    profile = load_baseline_profile(profile_path)
    thresholds = profile.get("detection_thresholds", {})

    logger.info("✓ Detection engine ready")
    logger.info(f"  Rate threshold:  {thresholds.get('rate_limit_req_per_min')} req/min")
    logger.info(f"  Error threshold: {thresholds.get('error_rate_threshold', 0):.2%}")
    logger.info(f"  Scan threshold:  {thresholds.get('entropy_scan_threshold')}")
    logger.info("")
    logger.info("  Detection loop will be implemented in Module 2.")
    logger.info("  Metrics endpoint is active and serving Prometheus.")

    # Keep alive (metrics server runs in background thread)
    while True:
        time.sleep(30)
        logger.debug("Detection engine heartbeat")


if __name__ == "__main__":
    main()

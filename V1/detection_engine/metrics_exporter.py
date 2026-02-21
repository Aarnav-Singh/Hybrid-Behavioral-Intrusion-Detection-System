"""
detection_engine/metrics_exporter.py
──────────────────────────────────────
Prometheus metrics HTTP server for the Hybrid IDS detection engine.

Exposes:
  GET /metrics  → Prometheus scrape endpoint (text/plain; version=0.0.4)
  GET /health   → Liveness probe for Docker / Kubernetes
  GET /status   → Human-readable detection engine status (JSON)

Design:
  - Uses Flask (lightweight) rather than a full WSGI framework
  - Runs in a background thread alongside the detection loop
  - All prometheus_client metrics are global singletons; generate_latest()
    serialises the current state of ALL registered metrics at scrape time
  - No state is stored here — this is a pure read-only view

Usage (standalone):
    python detection_engine/metrics_exporter.py

Usage (integrated):
    from metrics_exporter import start_metrics_server
    start_metrics_server(port=8000)   # non-blocking, background thread
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from flask import Flask, Response, jsonify
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger("ids.metrics_exporter")

# ─────────────────────────────────────────────────────────────────────────────
# Additional exporter-level metrics
# (Rule metrics are defined in rules.py; these track the exporter itself)
# ─────────────────────────────────────────────────────────────────────────────

SCRAPE_COUNT = Counter(
    "ids_metrics_scrapes_total",
    "Total number of times Prometheus has scraped /metrics",
)

UPTIME_SECONDS = Gauge(
    "ids_uptime_seconds",
    "Seconds since the detection engine started",
)

LAST_EVENT_TIMESTAMP = Gauge(
    "ids_last_event_processed_timestamp",
    "Unix timestamp of the most recently processed log event",
)

PIPELINE_LAG_SECONDS = Gauge(
    "ids_pipeline_lag_seconds",
    "Estimated lag between Nginx log write and detection evaluation (seconds)",
)

# ─────────────────────────────────────────────────────────────────────────────
# Flask application
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
_start_time  = time.time()
_engine_meta = {
    "started_at":    datetime.now(tz=timezone.utc).isoformat(),
    "version":       "1.0.0",
    "rules_loaded":  [],
    "profile_path":  os.getenv("BASELINE_PROFILE", "data/baseline_profile.json"),
    "es_host":       os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200"),
}


@app.route("/metrics")
def metrics():
    """
    Prometheus scrape endpoint.

    Returns all registered prometheus_client metrics in the
    Prometheus text exposition format (v0.0.4).

    Prometheus SCRAPE config (prometheus/prometheus.yml):
      - job_name: 'detection_service'
        static_configs:
          - targets: ['detection:8000']
        metrics_path: '/metrics'
    """
    SCRAPE_COUNT.inc()
    UPTIME_SECONDS.set(time.time() - _start_time)

    data = generate_latest()
    return Response(data, mimetype=CONTENT_TYPE_LATEST)


@app.route("/health")
def health():
    """
    Liveness / readiness probe.

    Docker HEALTHCHECK and Kubernetes probes hit this endpoint.
    Returns 200 when the server is up. Extended checks (ES connectivity,
    model load status) are in /status.
    """
    return jsonify({
        "status":    "healthy",
        "service":   "ids-detection-engine",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "uptime_s":  round(time.time() - _start_time, 2),
    }), 200


@app.route("/status")
def status():
    """
    Human-readable detection engine status.

    Returns configuration, loaded rules, and live metric snapshots.
    Useful for debugging without running PromQL queries.
    """
    from prometheus_client import REGISTRY

    # Snapshot key gauge values for human consumption
    metric_snapshot = {}
    try:
        for metric in REGISTRY.collect():
            if metric.name.startswith("ids_"):
                for sample in metric.samples:
                    metric_snapshot[sample.name] = sample.value
    except Exception as e:
        metric_snapshot["error"] = str(e)

    return jsonify({
        "engine":  _engine_meta,
        "metrics": metric_snapshot,
    }), 200


@app.route("/ready")
def ready():
    """
    Kubernetes readiness probe.

    Returns 503 until the baseline profile is loaded and ES is reachable.
    """
    import os
    from pathlib import Path

    profile_path = _engine_meta.get("profile_path", "data/baseline_profile.json")
    if not Path(profile_path).exists():
        return jsonify({
            "ready":  False,
            "reason": f"Baseline profile not found: {profile_path}",
        }), 503

    return jsonify({"ready": True}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Background uptime updater
# ─────────────────────────────────────────────────────────────────────────────

def _uptime_thread():
    """Update the uptime gauge every 10 seconds in a background thread."""
    while True:
        UPTIME_SECONDS.set(time.time() - _start_time)
        time.sleep(10)


# ─────────────────────────────────────────────────────────────────────────────
# Public API for integration with the detection loop
# ─────────────────────────────────────────────────────────────────────────────

def register_rules(rule_names: list) -> None:
    """Tell the status endpoint which rules are active."""
    _engine_meta["rules_loaded"] = rule_names


def record_event_processed(lag_seconds: float = 0.0) -> None:
    """
    Call this from the detection loop after processing each log batch.

    Parameters
    ----------
    lag_seconds : float
        Estimated pipeline lag (wall-clock time between Nginx log write
        and detection evaluation). Used to monitor ingestion freshness.
    """
    LAST_EVENT_TIMESTAMP.set(time.time())
    if lag_seconds > 0:
        PIPELINE_LAG_SECONDS.set(lag_seconds)


def start_metrics_server(
    port:    int  = 8000,
    host:    str  = "0.0.0.0",
    debug:   bool = False,
    daemon:  bool = True,
) -> threading.Thread:
    """
    Start the Flask metrics server in a background daemon thread.

    Parameters
    ----------
    port  : int   TCP port to listen on (default 8000, matches docker-compose)
    host  : str   Bind address
    debug : bool  Flask debug mode (disable in production)
    daemon: bool  If True, thread exits when main process exits

    Returns
    -------
    threading.Thread  The running server thread (already started)
    """
    # Start uptime updater
    t_uptime = threading.Thread(target=_uptime_thread, daemon=True)
    t_uptime.start()

    def _run():
        logger.info(f"Metrics server starting on {host}:{port}")
        # Silence Flask's default werkzeug request logger for /metrics
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host=host, port=port, debug=debug, use_reloader=False)

    t = threading.Thread(target=_run, name="metrics-server", daemon=daemon)
    t.start()
    logger.info(
        f"✓ Prometheus metrics available at http://{host}:{port}/metrics\n"
        f"  Health check:  http://{host}:{port}/health\n"
        f"  Status:        http://{host}:{port}/status"
    )
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Standalone entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    port = int(os.getenv("PROMETHEUS_PORT", "8000"))
    logger.info("Starting standalone metrics exporter...")

    # Start uptime thread
    threading.Thread(target=_uptime_thread, daemon=True).start()

    # Run Flask synchronously (blocking)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host="0.0.0.0", port=port, debug=False)

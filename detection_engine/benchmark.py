"""
detection_engine/benchmark.py
──────────────────────────────
Detection rule benchmarking and evaluation harness.

PURPOSE
───────
Measures each rule's accuracy on labelled test scenarios:
  - True Positive Rate (TPR / Recall)   — how many attacks are caught
  - False Positive Rate (FPR)           — how many safe requests are flagged
  - Precision                           — of flagged events, how many are real
  - F1 Score                            — harmonic mean of precision and recall
  - Inference latency (p50/p95/p99)     — measured via Prometheus histogram

WHY THIS MATTERS
────────────────
The detection engine is useless if:
  (a) FPR is high → SOC team drowns in noise, real attacks ignored
  (b) TPR is low  → Attacks go undetected

Target operating point (NIST SP 800-94 guidance for network IDS):
  TPR ≥ 0.95   (catch 95% of attacks)
  FPR ≤ 0.05   (false alarm rate under 5%)

USAGE
─────
    python detection_engine/benchmark.py
    python detection_engine/benchmark.py --scenario dos
    python detection_engine/benchmark.py --export-prometheus
"""

import argparse
import json
import logging
import random
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass  # pre-3.7 python, unlikely here

import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    push_to_gateway,
    write_to_textfile,
)

# Import the detection rules
sys.path.insert(0, str(Path(__file__).parent))
from rules import (
    ErrorRateSpikeRule,
    LoginBruteForceRule,
    PathTraversalRule,
    RateLimitRule,
    SQLInjectionRule,
    build_rule_set,
)

logger = logging.getLogger("ids.benchmark")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark-specific Prometheus metrics (separate registry to avoid conflicts)
# ─────────────────────────────────────────────────────────────────────────────

BENCHMARK_REGISTRY = CollectorRegistry()

BENCH_TPR = Gauge(
    "ids_benchmark_tpr",
    "True Positive Rate per rule per scenario",
    ["rule_name", "scenario"],
    registry=BENCHMARK_REGISTRY,
)

BENCH_FPR = Gauge(
    "ids_benchmark_fpr",
    "False Positive Rate per rule per scenario",
    ["rule_name", "scenario"],
    registry=BENCHMARK_REGISTRY,
)

BENCH_F1 = Gauge(
    "ids_benchmark_f1",
    "F1 Score per rule per scenario",
    ["rule_name", "scenario"],
    registry=BENCHMARK_REGISTRY,
)

BENCH_LATENCY_P95 = Gauge(
    "ids_benchmark_latency_p95_ms",
    "95th percentile detection latency per rule in milliseconds",
    ["rule_name"],
    registry=BENCHMARK_REGISTRY,
)

BENCH_LATENCY_P99 = Gauge(
    "ids_benchmark_latency_p99_ms",
    "99th percentile detection latency per rule in milliseconds",
    ["rule_name"],
    registry=BENCHMARK_REGISTRY,
)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic test scenario generators
# ─────────────────────────────────────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> str:
    """Generate an ISO timestamp offset from now."""
    return (datetime.now(tz=timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _make_normal_request(ip: str = "192.168.1.10", offset: int = 0) -> Dict:
    """Simulate a legitimate GET request."""
    endpoints = ["/", "/api/users", "/api/data", "/products", "/about", "/contact"]
    return {
        "remote_addr":   ip,
        "request_method": "GET",
        "request_uri":   random.choice(endpoints),
        "status":        200,
        "body_bytes_sent": random.randint(100, 5000),
        "request_time":  round(random.uniform(0.001, 0.05), 4),
        "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119",
        "timestamp":     _ts(offset),
        "_label":        "normal",
    }


def make_scenario_dos(n_attack: int = 200, n_normal: int = 100) -> List[Dict]:
    """
    Denial-of-Service scenario.
    Attacker IP hammers the server at 200 req/min (far above threshold).
    """
    events = []
    attacker = "10.0.0.1"
    # Attack traffic: rapid-fire requests
    for i in range(n_attack):
        events.append({**_make_normal_request(ip=attacker, offset=i // 10), "_label": "attack"})
    # Legitimate background traffic
    for i in range(n_normal):
        events.append(_make_normal_request(ip=f"192.168.1.{random.randint(10, 50)}", offset=i * 3))
    random.shuffle(events)
    return events


def make_scenario_brute_force(n_attack: int = 50, n_normal: int = 100) -> List[Dict]:
    """
    Login brute force scenario.
    Attacker sends multiple 401 responses against /admin.
    """
    events = []
    attacker = "10.0.0.2"
    for i in range(n_attack):
        events.append({
            "remote_addr":    attacker,
            "request_method": "POST",
            "request_uri":    "/admin",
            "status":         401,
            "body_bytes_sent": 45,
            "request_time":   0.001,
            "http_user_agent": "python-requests/2.31.0",
            "timestamp":      _ts(i * 2),
            "_label":         "attack",
        })
    for i in range(n_normal):
        events.append(_make_normal_request())
    random.shuffle(events)
    return events


def make_scenario_sqli(n_attack: int = 30, n_normal: int = 150) -> List[Dict]:
    """
    SQL injection scenario.
    Attacker probes endpoints with known SQLi payloads.
    """
    sqli_payloads = [
        "/api/users?id=1 OR 1=1",
        "/search?q='; DROP TABLE users;--",
        "/api/data?filter=1 UNION SELECT username,password FROM admin",
        "/products?id=1; EXEC xp_cmdshell('whoami')",
        "/api/users?name=' OR 'a'='a",
        "/search?q=1%27%20OR%20%271%27%3D%271",
        "/api/data?id=SLEEP(5)--",
        "/products?id=1 AND INFORMATION_SCHEMA.TABLES",
    ]
    events = []
    attacker = "10.0.0.3"
    for i, payload in enumerate(sqli_payloads * (n_attack // len(sqli_payloads) + 1)):
        if len(events) >= n_attack:
            break
        events.append({
            "remote_addr":    attacker,
            "request_method": "GET",
            "request_uri":    payload,
            "status":         random.choice([200, 500, 400]),
            "body_bytes_sent": 0,
            "request_time":   random.uniform(0.001, 2.0),
            "http_user_agent": "sqlmap/1.7.8",
            "timestamp":      _ts(i * 5),
            "_label":         "attack",
        })
    for i in range(n_normal):
        events.append(_make_normal_request())
    random.shuffle(events)
    return events


def make_scenario_path_traversal(n_attack: int = 30, n_normal: int = 150) -> List[Dict]:
    """
    Directory traversal scenario.
    Attacker tries to read /etc/passwd and other sensitive files.
    """
    traversal_payloads = [
        "/api/data?file=../../../etc/passwd",
        "/products/../../../etc/shadow",
        "/api/users?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/search?q=../../../../windows/win.ini",
        "/api/data?path=..\\..\\..\\windows\\system32",
        "/products?id=1%00.jpg/../../../etc/passwd",
        "/api/users?file=/proc/self/environ",
    ]
    events = []
    attacker = "10.0.0.4"
    for i, payload in enumerate(traversal_payloads * (n_attack // len(traversal_payloads) + 1)):
        if len(events) >= n_attack:
            break
        events.append({
            "remote_addr":    attacker,
            "request_method": "GET",
            "request_uri":    payload,
            "status":         random.choice([200, 403, 404]),
            "body_bytes_sent": 0,
            "request_time":   0.002,
            "http_user_agent": "Nikto/2.1.6",
            "timestamp":      _ts(i * 3),
            "_label":         "attack",
        })
    for i in range(n_normal):
        events.append(_make_normal_request())
    random.shuffle(events)
    return events


def make_scenario_error_spike(n_attack: int = 80, n_normal: int = 50) -> List[Dict]:
    """
    Error rate spike scenario.
    High volume of 5xx responses indicating server stress / injection success.
    """
    events = []
    attacker = "10.0.0.5"
    for i in range(n_attack):
        events.append({
            "remote_addr":    attacker,
            "request_method": "GET",
            "request_uri":    f"/api/data?id={random.randint(1, 9999)}",
            "status":         random.choice([500, 503, 500, 500, 502]),
            "body_bytes_sent": 0,
            "request_time":   random.uniform(0.1, 5.0),
            "http_user_agent": "python-requests/2.31.0",
            "timestamp":      _ts(i),
            "_label":         "attack",
        })
    for i in range(n_normal):
        events.append(_make_normal_request())
    random.shuffle(events)
    return events


SCENARIOS = {
    "dos":            make_scenario_dos,
    "brute_force":    make_scenario_brute_force,
    "sql_injection":  make_scenario_sqli,
    "path_traversal": make_scenario_path_traversal,
    "error_spike":    make_scenario_error_spike,
}


# ─────────────────────────────────────────────────────────────────────────────
# Confusion matrix calculation
# ─────────────────────────────────────────────────────────────────────────────

def calculate_confusion_matrix(
    detections:  List[Dict],
    events:      List[Dict],
) -> Tuple[int, int, int, int]:
    """
    Compute TP, FP, TN, FN from raw detections and labelled events.

    Parameters
    ----------
    detections : list of detection dicts (those with detected=True)
    events     : full event list with _label field ("attack" or "normal")

    Returns
    -------
    (tp, fp, tn, fn) — integers
    """
    # Build event index by (ip, uri, status) for matching
    detected_ips = {d.get("source_ip") for d in detections if d.get("source_ip")}

    tp, fp, tn, fn = 0, 0, 0, 0
    for ev in events:
        ip       = ev.get("remote_addr", "")
        is_real  = ev["_label"] == "attack"
        flagged  = ip in detected_ips

        if is_real and flagged:     tp += 1
        elif not is_real and flagged: fp += 1
        elif not is_real and not flagged: tn += 1
        else:                       fn += 1

    return tp, fp, tn, fn


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Compute standard detection metrics from confusion matrix."""
    tpr       = tp / (tp + fn)        if (tp + fn) > 0 else 0.0
    fpr       = fp / (fp + tn)        if (fp + tn) > 0 else 0.0
    precision = tp / (tp + fp)        if (tp + fp) > 0 else 0.0
    f1        = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0

    return {
        "TPR":       round(tpr, 4),
        "FPR":       round(fpr, 4),
        "Precision": round(precision, 4),
        "F1":        round(f1, 4),
        "Accuracy":  round(accuracy, 4),
        "TP":        tp, "FP": fp, "TN": tn, "FN": fn,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Core benchmark runner
# ─────────────────────────────────────────────────────────────────────────────

def run_benchmark(
    rules:        Optional[List] = None,
    scenario_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run all test scenarios through all rules and compute accuracy metrics.

    Parameters
    ----------
    rules          : list of rule objects (defaults to build_rule_set())
    scenario_names : subset of SCENARIOS to run (defaults to all)

    Returns
    -------
    results dict keyed by scenario → rule → metrics
    """
    if rules is None:
        rules = build_rule_set()

    if scenario_names is None:
        scenario_names = list(SCENARIOS.keys())

    results     = {}
    all_latencies: Dict[str, List[float]] = defaultdict(list)

    for scenario_name in scenario_names:
        if scenario_name not in SCENARIOS:
            logger.warning(f"Unknown scenario: {scenario_name}. Skipping.")
            continue

        logger.info(f"\n{'═'*60}")
        logger.info(f"  SCENARIO: {scenario_name.upper()}")
        logger.info(f"{'═'*60}")

        events = SCENARIOS[scenario_name]()
        n_attack = sum(1 for e in events if e["_label"] == "attack")
        n_normal = sum(1 for e in events if e["_label"] == "normal")
        logger.info(f"  Events: {len(events)} total ({n_attack} attack, {n_normal} normal)")

        results[scenario_name] = {}

        for rule in rules:
            detections   = []
            rule_latencies = []

            for event in events:
                t0     = time.perf_counter()
                result = rule.detect(event, historical_data=None)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                rule_latencies.append(elapsed_ms)
                all_latencies[rule.name].append(elapsed_ms)

                if result.get("detected"):
                    detections.append(result)

            tp, fp, tn, fn = calculate_confusion_matrix(detections, events)
            m = compute_metrics(tp, fp, tn, fn)
            m["detections"]  = len(detections)
            m["latency_p50"] = round(float(np.percentile(rule_latencies, 50)), 4)
            m["latency_p95"] = round(float(np.percentile(rule_latencies, 95)), 4)
            m["latency_p99"] = round(float(np.percentile(rule_latencies, 99)), 4)

            results[scenario_name][rule.name] = m

            # Update Prometheus gauges
            BENCH_TPR.labels(rule_name=rule.name, scenario=scenario_name).set(m["TPR"])
            BENCH_FPR.labels(rule_name=rule.name, scenario=scenario_name).set(m["FPR"])
            BENCH_F1.labels(rule_name=rule.name,  scenario=scenario_name).set(m["F1"])

            # Log result
            status_tpr = "✓" if m["TPR"] >= 0.95 else "✗"
            status_fpr = "✓" if m["FPR"] <= 0.05 else "✗"
            logger.info(
                f"  [{rule.name:<22}] "
                f"TPR={m['TPR']:.2%} {status_tpr}  "
                f"FPR={m['FPR']:.2%} {status_fpr}  "
                f"F1={m['F1']:.3f}  "
                f"lat_p95={m['latency_p95']:.2f}ms"
            )

    # Update latency gauges from all scenarios combined
    for rule_name, latencies in all_latencies.items():
        BENCH_LATENCY_P95.labels(rule_name=rule_name).set(np.percentile(latencies, 95))
        BENCH_LATENCY_P99.labels(rule_name=rule_name).set(np.percentile(latencies, 99))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_summary_table(results: Dict[str, Any]) -> None:
    """Print a formatted summary table of all benchmark results."""
    header = f"\n{'='*90}"
    print(header)
    print(f"  {'BENCHMARK SUMMARY':^86}")
    print(f"{'='*90}")
    print(
        f"  {'Scenario':<18} {'Rule':<22} {'TPR':>6} {'FPR':>6} "
        f"{'F1':>6} {'P':>7} {'p95ms':>8} {'p99ms':>8}"
    )
    print(f"  {'─'*84}")

    target_ok = True  # Track if all rules meet NIST targets
    for scenario, rule_results in results.items():
        for rule_name, m in rule_results.items():
            tpr_ok = m["TPR"] >= 0.95
            fpr_ok = m["FPR"] <= 0.05
            if not (tpr_ok and fpr_ok):
                target_ok = False
            row = (
                f"  {scenario:<18} {rule_name:<22} "
                f"{m['TPR']:>5.1%} {m['FPR']:>5.1%} "
                f"{m['F1']:>5.3f} {m.get('Precision', 0):>6.1%} "
                f"{m.get('latency_p95', 0):>7.2f} {m.get('latency_p99', 0):>7.2f}"
            )
            # Highlight failing rows
            flag = "" if (tpr_ok and fpr_ok) else " ← BELOW TARGET"
            print(row + flag)

    print(f"{'='*90}")
    print(f"  Target: TPR ≥ 95%  |  FPR ≤ 5%  (NIST SP 800-94)")
    print(f"  Overall: {'ALL TARGETS MET ✓' if target_ok else 'SOME TARGETS NOT MET ✗'}")
    print(f"{'='*90}\n")


def export_results(results: Dict[str, Any], path: str = "data/benchmark_results.json") -> None:
    """Save benchmark results as JSON for audit trail and CI comparison."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    output = {
        "run_at":   datetime.now(timezone.utc).isoformat(),
        "targets":  {"TPR": 0.95, "FPR": 0.05},
        "results":  results,
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    logger.info(f"✓ Results saved: {path}")


def export_prometheus_metrics(path: str = "data/benchmark_metrics.prom") -> None:
    """
    Write Prometheus metrics to a .prom text file.

    This file can be served by a Node Exporter (--collector.textfile) or
    pushed to a Pushgateway for one-shot benchmark runs.
    """
    from prometheus_client import write_to_textfile
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    write_to_textfile(path, BENCHMARK_REGISTRY)
    logger.info(f"✓ Prometheus metrics written: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark IDS detection rules",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        nargs="+",
        choices=list(SCENARIOS.keys()) + ["all"],
        default=["all"],
        help="Scenarios to run",
    )
    parser.add_argument(
        "--output",
        default="data/benchmark_results.json",
        help="JSON output path",
    )
    parser.add_argument(
        "--export-prometheus",
        action="store_true",
        help="Write Prometheus .prom text file",
    )
    parser.add_argument(
        "--pushgateway",
        default=None,
        help="Push metrics to Prometheus Pushgateway URL (e.g. http://localhost:9091)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    scenarios = (
        list(SCENARIOS.keys())
        if "all" in args.scenario
        else args.scenario
    )

    logger.info("╔══════════════════════════════════════════════════════════╗")
    logger.info("║    HYBRID IDS — RULE BENCHMARK                          ║")
    logger.info("╚══════════════════════════════════════════════════════════╝")
    logger.info(f"  Scenarios: {scenarios}")

    rules   = build_rule_set()
    results = run_benchmark(rules=rules, scenario_names=scenarios)
    print_summary_table(results)
    export_results(results, path=args.output)

    if args.export_prometheus:
        export_prometheus_metrics()

    if args.pushgateway:
        try:
            push_to_gateway(
                args.pushgateway,
                job="ids_benchmark",
                registry=BENCHMARK_REGISTRY,
            )
            logger.info(f"✓ Metrics pushed to {args.pushgateway}")
        except Exception as e:
            logger.error(f"Push failed: {e}")

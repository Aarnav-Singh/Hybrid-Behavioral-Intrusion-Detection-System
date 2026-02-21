"""
scripts/baseline_traffic.py
────────────────────────────
Realistic baseline traffic generator for the Hybrid IDS.

PURPOSE
-------
Generates ~10,000 HTTP requests following a Poisson process (exponential
inter-arrival times), which is the standard statistical model for web traffic.
This creates the GROUND TRUTH baseline that all detection thresholds reference.

WHY POISSON
-----------
Real web traffic inter-arrival times follow an exponential distribution
(memoryless property). If requests arrive at λ req/sec on average, the
time between consecutive requests is Exponential(λ). Attacks violate this:
  - DoS/DDoS: Fixed small inter-arrival times (deterministic, not random)
  - Scanning:  Burst patterns that don't fit a Poisson model
  - Slowloris: Very slow, near-zero rate with long-lived connections

USAGE
-----
    python scripts/baseline_traffic.py
    python scripts/baseline_traffic.py --duration 10 --rate 5
"""

import argparse
import random
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

import numpy as np
import requests
import json

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

BASE_URL = "http://localhost:18080"

# Realistic browser user agents sampled from real-world distributions
# (Chrome ~65%, Safari ~19%, Firefox ~4%, Edge ~4%, Mobile ~8%)
USER_AGENTS = [
    # Chrome on Windows (most common ~35%)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Chrome on macOS (~15%)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Safari on macOS (~10%)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/537.36",
    # Firefox (~4%)
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Edge (~4%)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    # Mobile Safari on iPhone (~8%)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # Chrome on Android (~8%)
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    # Bot/crawler that's legitimate (~2%)
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

# Endpoint weights reflect realistic traffic patterns
# (homepage gets most traffic, APIs get moderate, admin near-zero)
ENDPOINTS_WITH_WEIGHTS = [
    ("/",                   0.35),   # Homepage - highest traffic
    ("/api/users",          0.15),   # User API
    ("/api/data",           0.12),   # Data API
    ("/products",           0.12),   # Product listing
    ("/search?q=laptop",    0.08),   # Search
    ("/search?q=phone",     0.05),   # Search variant
    ("/about",              0.06),   # Static page
    ("/contact",            0.04),   # Static page
    ("/profile",            0.03),   # Profile
]

ENDPOINTS    = [e[0] for e in ENDPOINTS_WITH_WEIGHTS]
WEIGHTS      = [e[1] for e in ENDPOINTS_WITH_WEIGHTS]

# Simulated IP pool (multiple users)
IP_POOL = [f"192.168.1.{i}" for i in range(10, 50)]  # 40 distinct IPs


# ─────────────────────────────────────────────────────────────────────────────
# Traffic generation
# ─────────────────────────────────────────────────────────────────────────────

class TrafficStats:
    """Tracks rolling statistics during traffic generation."""

    def __init__(self):
        self.total_requests  = 0
        self.errors          = 0
        self.status_counts   = {}
        self.start_time      = datetime.now()
        self.last_report_time = datetime.now()
        self.last_report_count = 0
        self.request_times   = []

    def record(self, status_code: Optional[int], request_time: float):
        self.total_requests += 1
        if status_code is None:
            self.errors += 1
        else:
            self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1
        self.request_times.append(request_time)

    def elapsed_seconds(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()

    def current_rate(self) -> float:
        elapsed = self.elapsed_seconds()
        return self.total_requests / elapsed if elapsed > 0 else 0

    def instant_rate(self) -> float:
        """Rate over the last reporting window."""
        now = datetime.now()
        elapsed = (now - self.last_report_time).total_seconds()
        count = self.total_requests - self.last_report_count
        self.last_report_time = now
        self.last_report_count = self.total_requests
        return count / elapsed if elapsed > 0 else 0

    def print_report(self):
        elapsed = self.elapsed_seconds()
        rate    = self.current_rate()
        instant = self.instant_rate()
        error_rate = (self.errors / self.total_requests * 100) if self.total_requests > 0 else 0

        print(f"\n{'─'*60}")
        print(f"  Elapsed: {elapsed:.0f}s  |  Total: {self.total_requests}")
        print(f"  Overall rate: {rate:.2f} req/s  |  Last 100 rate: {instant:.2f} req/s")
        print(f"  Connection errors: {self.errors} ({error_rate:.1f}%)")
        print(f"  Status codes: {self.status_counts}")
        if self.request_times:
            rt = np.array(self.request_times[-200:])
            print(f"  Response time (last 200): mean={rt.mean()*1000:.1f}ms p95={np.percentile(rt, 95)*1000:.1f}ms")
        print(f"{'─'*60}")


def generate_baseline_traffic(
    duration_minutes: int = 83,
    mean_rps: float = 2.0,
    error_rate: float = 0.05,
):
    """
    Generate realistic baseline web traffic using a Poisson process.

    Parameters
    ----------
    duration_minutes : int
        How long to run (default 83 min ≈ 10,000 requests at 2 req/s)
    mean_rps : float
        Mean request rate. Inter-arrival times ~ Exponential(1/mean_rps).
    error_rate : float
        Fraction of requests that hit non-existent endpoints (404 errors).
        Default 0.05 = 5%, consistent with real-world baseline.
    """

    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    stats    = TrafficStats()
    session  = requests.Session()

    print(f"{'='*60}")
    print(f"  HYBRID IDS - BASELINE TRAFFIC GENERATOR")
    print(f"{'='*60}")
    print(f"  Duration:   {duration_minutes} minutes")
    print(f"  Mean rate:  {mean_rps} req/s (Poisson process)")
    print(f"  Error rate: {error_rate*100:.0f}% (normal 404 rate)")
    print(f"  Target:     {int(mean_rps * duration_minutes * 60):,} requests")
    print(f"  Started:    {stats.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    while datetime.now() < end_time:
        # Exponential inter-arrival time = Poisson process
        delay = np.random.exponential(1.0 / mean_rps)
        time.sleep(delay)

        # Select endpoint (weighted toward homepage)
        if random.random() < error_rate:
            # Simulate normal 404 traffic (missing pages, typos)
            endpoint = f"/nonexistent_{random.randint(1, 999)}"
        else:
            endpoint = random.choices(ENDPOINTS, weights=WEIGHTS, k=1)[0]

        ua        = random.choice(USER_AGENTS)
        client_ip = random.choice(IP_POOL)

        t_start = time.perf_counter()
        try:
            resp = session.get(
                BASE_URL + endpoint,
                headers={
                    "User-Agent":       ua,
                    "X-Forwarded-For":  client_ip,
                    "Accept":           "text/html,application/json,*/*;q=0.8",
                    "Accept-Language":  "en-US,en;q=0.9",
                    "Accept-Encoding":  "gzip, deflate",
                    "Connection":       "keep-alive",
                },
                timeout=5,
            )
            t_elapsed = time.perf_counter() - t_start
            stats.record(resp.status_code, t_elapsed)

        except requests.exceptions.ConnectionError:
            t_elapsed = time.perf_counter() - t_start
            stats.record(None, t_elapsed)
            print(f"  [WARN] Connection refused - is Nginx running on {BASE_URL}?")
            time.sleep(2)

        except requests.exceptions.Timeout:
            t_elapsed = time.perf_counter() - t_start
            stats.record(None, t_elapsed)
            print(f"  [WARN] Request timeout for {endpoint}")

        except Exception as e:
            t_elapsed = time.perf_counter() - t_start
            stats.record(None, t_elapsed)
            print(f"  [ERROR] {type(e).__name__}: {e}")

        # Print progress every 100 requests
        if stats.total_requests > 0 and stats.total_requests % 100 == 0:
            stats.print_report()

    # Final summary
    print(f"\n{'='*60}")
    print(f"  BASELINE GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Total requests:  {stats.total_requests:,}")
    print(f"  Duration:        {stats.elapsed_seconds() / 60:.1f} minutes")
    print(f"  Actual rate:     {stats.current_rate():.3f} req/s")
    print(f"  Status codes:    {stats.status_counts}")
    print(f"  Errors:          {stats.errors}")
    print(f"\n  Next step: Run scripts/analyze_baseline.py to compute thresholds")
    print(f"{'='*60}\n")

    # Save summary to file for audit trail
    summary = {
        "run_date":         stats.start_time.isoformat(),
        "duration_minutes": duration_minutes,
        "target_rps":       mean_rps,
        "actual_rps":       round(stats.current_rate(), 4),
        "total_requests":   stats.total_requests,
        "status_codes":     stats.status_counts,
        "connection_errors": stats.errors,
    }
    with open("data/baseline_run_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  Summary saved to data/baseline_run_summary.json")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate baseline traffic for Hybrid IDS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--duration", type=int,   default=83,  help="Duration in minutes")
    parser.add_argument("--rate",     type=float, default=2.0, help="Mean requests per second")
    parser.add_argument("--error-rate", type=float, default=0.05, help="Fraction of requests that are 404s")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    generate_baseline_traffic(
        duration_minutes=args.duration,
        mean_rps=args.rate,
        error_rate=args.error_rate,
    )

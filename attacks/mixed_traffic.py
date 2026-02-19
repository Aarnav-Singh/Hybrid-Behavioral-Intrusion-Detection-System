"""
attacks/mixed_traffic.py
──────────────────────────
Realistic mixed traffic scenario: normal users + embedded attackers.

PURPOSE
───────
After establishing a clean baseline (Module 1), this file generates
the realistic production scenario: traffic that contains BOTH legitimate
users and attackers at realistic proportions.

Industry data (Akamai, Cloudflare 2023 reports):
  - ~15-25% of internet traffic is malicious/automated
  - Attackers deliberately blend with legitimate traffic

TRAFFIC SPLIT (run with 100 users → ~85 normal, 15 attacker)
──────────────────────────────────────────────────────────────
  85% NormalUser             (realistic browsing, Poisson inter-arrivals)
   6% SlowBruteAttacker      (auth brute force, evasion timing)
   4% SQLiAttacker            (injection probing)
   3% ScannerAttacker         (web scanner, high entropy)
   2% DoSAttacker             (rate flood)

USAGE
─────
  # Full 100-user mixed scenario (15 min)
  locust -f attacks/mixed_traffic.py \\
         --users 100 --spawn-rate 10 --run-time 15m \\
         --host http://localhost:8080 --headless

  # Adjust split via environment variables
  ATTACK_RATIO=0.30 locust -f attacks/mixed_traffic.py --users 100 ...

DETECTION CHALLENGE
───────────────────
At 15% attack ratio the IDS must:
  - Maintain FPR ≤ 5% on legitimate users
  - Maintain TPR ≥ 95% on attackers
  - Do so within seconds, not minutes
"""

import os
import random
import time

from locust import HttpUser, between, events, task
from prometheus_client import Counter, Gauge, start_http_server

# ─────────────────────────────────────────────────────────────────────────────
# Prometheus — attack-side metrics
# ─────────────────────────────────────────────────────────────────────────────

MIXED_REQUESTS = Counter(
    "locust_mixed_requests_total",
    "Total requests in mixed scenario by traffic type",
    ["traffic_type", "endpoint"],
)

MIXED_ACTIVE = Gauge(
    "locust_mixed_active_users",
    "Active simulated users by traffic type",
    ["traffic_type"],
)


@events.init.add_listener
def on_init(environment, **kw):
    try:
        start_http_server(9647)  # Different port from locustfile.py
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Shared data
# ─────────────────────────────────────────────────────────────────────────────

_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 Safari/604.1",
]

_NORMAL_ENDPOINTS = ["/", "/api/users", "/api/data", "/products", "/about", "/contact", "/search?q=test"]
_ADMIN_PATHS      = ["/admin", "/backup", "/.env", "/config.php", "/wp-login.php", "/phpmyadmin"]
_SQLI_PAYLOADS    = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(5)--",
    "1%27%20OR%20%271%27%3D%271",
]
_PASSWORDS        = ["admin", "password", "123456", "letmein", "qwerty", "root"]


# ─────────────────────────────────────────────────────────────────────────────
# Normal user (85% weight)
# ─────────────────────────────────────────────────────────────────────────────

class NormalUser(HttpUser):
    """
    Realistic human user. Human-like timing, realistic endpoints, diverse UAs.

    This class provides the LEGITIMATE TRAFFIC BASELINE within the mixed scenario.
    The IDS must NOT flag these users (false positive = bad UX, pager fatigue).
    """

    wait_time = between(1, 6)
    weight    = 85

    def on_start(self):
        MIXED_ACTIVE.labels(traffic_type="normal").inc()
        self.ua = random.choice(_BROWSER_UAS)

    def on_stop(self):
        MIXED_ACTIVE.labels(traffic_type="normal").dec()

    @task(35)
    def home(self):
        self.client.get("/", headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/").inc()

    @task(18)
    def api_users(self):
        self.client.get("/api/users", headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/api/users").inc()

    @task(15)
    def api_data(self):
        self.client.get("/api/data", headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/api/data").inc()

    @task(12)
    def products(self):
        self.client.get("/products", headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/products").inc()

    @task(8)
    def search(self):
        q = random.choice(["laptop", "camera", "headset", "keyboard", "monitor"])
        self.client.get(f"/search?q={q}", headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/search").inc()

    @task(7)
    def about_contact(self):
        ep = random.choice(["/about", "/contact"])
        self.client.get(ep, headers={"User-Agent": self.ua},
                        context={"scenario": "mixed_normal"})
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint=ep).inc()

    @task(5)
    def not_found(self):
        """Normal 404 rate (~5% of tasks)."""
        path = f"/archive/{random.randint(2018, 2023)}"
        with self.client.get(
            path, headers={"User-Agent": self.ua},
            context={"scenario": "mixed_normal"},
            catch_response=True,
        ) as r:
            if r.status_code == 404:
                r.success()
        MIXED_REQUESTS.labels(traffic_type="normal", endpoint="/[404]").inc()


# ─────────────────────────────────────────────────────────────────────────────
# Slow brute force attacker (6% weight)
# ─────────────────────────────────────────────────────────────────────────────

class SlowBruteAttacker(HttpUser):
    """
    Low-and-slow brute force — stays under per-window threshold.

    Uses a browser UA to blend with legitimate traffic.
    The LoginBruteForceRule's sliding window is the primary detection mechanism;
    the ML anomaly model should catch the sustained pattern over multiple windows.
    """

    wait_time = between(7, 10)   # ~6–8 req/min → 9 per 65s window
    weight    = 6

    def on_start(self):
        MIXED_ACTIVE.labels(traffic_type="slow_brute").inc()
        self.attempts     = 0
        self.window_start = time.time()
        self.ua           = random.choice(_BROWSER_UAS)  # blend in

    def on_stop(self):
        MIXED_ACTIVE.labels(traffic_type="slow_brute").dec()

    @task
    def slow_brute(self):
        now     = time.time()
        elapsed = now - self.window_start

        if self.attempts >= 9 and elapsed < 65:
            time.sleep(65 - elapsed + 1)
            self.attempts     = 0
            self.window_start = time.time()
            return

        if elapsed >= 65:
            self.attempts     = 0
            self.window_start = time.time()

        with self.client.post(
            "/admin",
            data={"username": "admin", "password": random.choice(_PASSWORDS)},
            headers={"User-Agent": self.ua},
            context={"scenario": "mixed_slow_brute"},
            catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 403, 404):
                r.success()
        MIXED_REQUESTS.labels(traffic_type="slow_brute", endpoint="/admin").inc()
        self.attempts += 1


# ─────────────────────────────────────────────────────────────────────────────
# SQLi attacker (4% weight)
# ─────────────────────────────────────────────────────────────────────────────

class SQLiAttacker(HttpUser):
    """
    SQL injection probe — fires known payloads against data endpoints.
    SQLInjectionRule should detect on first request (signature match).
    """

    wait_time = between(1, 3)
    weight    = 4

    def on_start(self):
        MIXED_ACTIVE.labels(traffic_type="sqli").inc()
        self.ua = "sqlmap/1.7.8#stable"

    def on_stop(self):
        MIXED_ACTIVE.labels(traffic_type="sqli").dec()

    @task(6)
    def sqli_data(self):
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.get(
            f"/api/data?id={payload}",
            headers={"User-Agent": self.ua},
            context={"scenario": "mixed_sqli"},
            catch_response=True,
            name="/api/data?id=[sqli]",
        ) as r:
            if r.status_code in (200, 400, 500):
                r.success()
        MIXED_REQUESTS.labels(traffic_type="sqli", endpoint="/api/data").inc()

    @task(4)
    def sqli_search(self):
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.get(
            f"/search?q={payload}",
            headers={"User-Agent": self.ua},
            context={"scenario": "mixed_sqli"},
            catch_response=True,
            name="/search?q=[sqli]",
        ) as r:
            if r.status_code in (200, 400, 500):
                r.success()
        MIXED_REQUESTS.labels(traffic_type="sqli", endpoint="/search").inc()


# ─────────────────────────────────────────────────────────────────────────────
# Web scanner (3% weight)
# ─────────────────────────────────────────────────────────────────────────────

class ScannerAttacker(HttpUser):
    """
    Web scanner — maximises endpoint entropy by hitting all paths uniformly.
    Entropy-based detection should flag this within ~20 requests.
    """

    wait_time = between(0.3, 0.8)
    weight    = 3

    def on_start(self):
        MIXED_ACTIVE.labels(traffic_type="scanner").inc()
        self.path_idx = 0
        self.ua       = "Nikto/2.1.6"

    def on_stop(self):
        MIXED_ACTIVE.labels(traffic_type="scanner").dec()

    @task
    def scan(self):
        _paths = _ADMIN_PATHS + [
            "/debug", "/.git/config", "/actuator/env",
            "/server-status", "/.htpasswd",
        ]
        path = _paths[self.path_idx % len(_paths)]
        self.path_idx += 1

        with self.client.get(
            path,
            headers={"User-Agent": self.ua},
            context={"scenario": "mixed_scanner"},
            catch_response=True,
            name="[scan]" + path,
        ) as r:
            if r.status_code in (200, 301, 302, 400, 401, 403, 404, 500):
                r.success()
        MIXED_REQUESTS.labels(traffic_type="scanner", endpoint=path).inc()


# ─────────────────────────────────────────────────────────────────────────────
# DoS attacker (2% weight)
# ─────────────────────────────────────────────────────────────────────────────

class DoSAttacker(HttpUser):
    """
    High-rate single-IP flood — far above baseline rate threshold.
    RateLimitRule should detect within the first 60-second window.
    """

    wait_time = between(0.05, 0.15)  # ~7–20 req/s per user
    weight    = 2

    def on_start(self):
        MIXED_ACTIVE.labels(traffic_type="dos").inc()
        self.ua = "python-requests/2.31.0"

    def on_stop(self):
        MIXED_ACTIVE.labels(traffic_type="dos").dec()

    @task
    def flood(self):
        ep = random.choice(["/api/data", "/api/users", "/"])
        with self.client.get(
            ep,
            headers={"User-Agent": self.ua},
            context={"scenario": "mixed_dos"},
            catch_response=True,
        ) as r:
            if r.status_code in (200, 429, 503):
                r.success()
        MIXED_REQUESTS.labels(traffic_type="dos", endpoint=ep).inc()

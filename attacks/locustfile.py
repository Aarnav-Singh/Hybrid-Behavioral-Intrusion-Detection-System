"""
attacks/locustfile.py
──────────────────────
Locust attack simulation scenarios for the Hybrid IDS.

USER CLASSES
────────────
  NormalUser             — Realistic human browsing (baseline)
  AttackerBruteForce     — Fast login brute force (easy to detect)
  AttackerSlowBruteForce — Slow brute force (evasion: stays under threshold  per window)
  AttackerSQLi           — SQL injection probe
  AttackerPathTraversal  — Directory traversal / LFI probe
  AttackerScanner        — Web scanner with high endpoint entropy

PROMETHEUS INTEGRATION
──────────────────────
Locust fires events (request_success, request_failure) that we hook into
to export per-class metrics to Prometheus, providing a unified view of
"traffic generated" vs "traffic detected" in the same Grafana dashboard.

USAGE — individual class
────────────────────────
  locust -f attacks/locustfile.py AttackerBruteForce \\
         --users 20 --spawn-rate 10 --run-time 2m \\
         --host http://localhost:8080 --headless

USAGE — all classes (proportional)
────────────────────────────────────
  locust -f attacks/locustfile.py \\
         --users 100 --spawn-rate 10 --run-time 5m \\
         --host http://localhost:8080 --headless
"""

import random
import time
from typing import Optional

from locust import HttpUser, between, events, task
from prometheus_client import Counter, Gauge, Histogram, start_http_server

# ─────────────────────────────────────────────────────────────────────────────
# Prometheus metrics — attack-side telemetry
# Lets you correlate "attacks sent" vs "alerts fired" in one Grafana dashboard
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_REQUESTS = Counter(
    "locust_attack_requests_total",
    "Total attack requests sent per scenario",
    ["scenario", "method", "endpoint"],
)

ATTACK_FAILURES = Counter(
    "locust_attack_failures_total",
    "Total connection/timeout failures per scenario",
    ["scenario"],
)

ATTACK_LATENCY = Histogram(
    "locust_attack_response_seconds",
    "HTTP response time for attack requests",
    ["scenario"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
)

ACTIVE_ATTACKERS = Gauge(
    "locust_active_attackers",
    "Number of active simulated attacker users",
    ["scenario"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Locust event hooks — wired to Prometheus exports
# ─────────────────────────────────────────────────────────────────────────────

@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, context, **kw):
    """Record every Locust request into Prometheus metrics."""
    scenario = context.get("scenario", "unknown") if context else "unknown"
    if exception:
        ATTACK_FAILURES.labels(scenario=scenario).inc()
    else:
        ATTACK_REQUESTS.labels(
            scenario=scenario,
            method=request_type,
            endpoint=name,
        ).inc()
        ATTACK_LATENCY.labels(scenario=scenario).observe(response_time / 1000)


@events.init.add_listener
def on_locust_init(environment, **kw):
    """Start a sidecar Prometheus server when Locust master starts."""
    if environment.parsed_options:
        try:
            start_http_server(9646)
            print("[Locust] Prometheus metrics available at :9646/metrics")
        except OSError:
            pass  # Already running (multiple workers)


# ─────────────────────────────────────────────────────────────────────────────
# Helper data
# ─────────────────────────────────────────────────────────────────────────────

_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1",
]

_ATTACK_UAS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "python-requests/2.31.0",
    "masscan/1.3.2",
    "curl/7.88.1",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "1 UNION SELECT * FROM information_schema.tables",
    "'; EXEC xp_cmdshell('whoami');--",
    "1' AND SLEEP(5)--",
    "' OR 'a'='a",
    "1%27%20OR%20%271%27%3D%271",          # URL-encoded
    "1; SELECT * FROM users WHERE 1=1",
]

_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/../../../windows/win.ini",
    "/....//....//etc/passwd",
    "/%00/../../../etc/shadow",
    "/../../../proc/self/environ",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/../../../boot.ini",
]

_SCANNER_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/config", "/config.php", "/config.yml",
    "/debug", "/debug.php",
    "/phpMyAdmin", "/phpmyadmin", "/pma",
    "/.env", "/.git/config", "/.svn",
    "/wp-admin", "/wp-login.php",
    "/api/internal", "/api/v1/admin", "/api/v2/internal",
    "/actuator", "/actuator/health", "/actuator/env",
    "/console", "/solr/admin", "/jmx-console",
    "/server-status", "/nginx-status",
    "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml",
]

_COMMON_PASSWORDS = [
    "admin", "password", "123456", "letmein", "qwerty",
    "password1", "admin123", "root", "toor", "pass",
    "12345678", "welcome", "login", "master", "access",
]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Normal user — establishes baseline, used in mixed scenarios
# ─────────────────────────────────────────────────────────────────────────────

class NormalUser(HttpUser):
    """
    Simulates realistic human browsing behaviour.

    Traffic distribution mirrors real web analytics:
    - 35% homepage
    - 15% API calls
    - 10% product pages
    - 6% about/contact static pages
    - 5% search
    - 5% 404s (normal typos/bad links)
    """

    wait_time = between(1, 5)  # Human-like delays (seconds)
    weight    = 70              # 70% of users are normal

    def on_start(self):
        self.headers = {"User-Agent": random.choice(_BROWSER_UAS)}

    @task(35)
    def browse_home(self):
        self.client.get("/", headers=self.headers,
                        context={"scenario": "normal"})

    @task(15)
    def api_users(self):
        self.client.get("/api/users", headers=self.headers,
                        context={"scenario": "normal"})

    @task(12)
    def api_data(self):
        self.client.get("/api/data", headers=self.headers,
                        context={"scenario": "normal"})

    @task(10)
    def products(self):
        self.client.get("/products", headers=self.headers,
                        context={"scenario": "normal"})

    @task(8)
    def search(self):
        q = random.choice(["laptop", "phone", "tablet", "headphones", "monitor"])
        self.client.get(f"/search?q={q}", headers=self.headers,
                        context={"scenario": "normal"})

    @task(6)
    def about(self):
        self.client.get("/about", headers=self.headers,
                        context={"scenario": "normal"})

    @task(4)
    def contact(self):
        self.client.get("/contact", headers=self.headers,
                        context={"scenario": "normal"})

    @task(5)
    def not_found(self):
        """Normal 404 rate (~5%) — broken links, old bookmarks."""
        page = random.choice([
            f"/page_{random.randint(1, 100)}",
            "/old-product",
            "/archive/2022",
        ])
        with self.client.get(page, headers=self.headers,
                             context={"scenario": "normal"},
                             catch_response=True) as r:
            if r.status_code == 404:
                r.success()  # Expected for this task


# ─────────────────────────────────────────────────────────────────────────────
# 2. Fast brute force — straightforward DoS-style auth attack
# ─────────────────────────────────────────────────────────────────────────────

class AttackerBruteForce(HttpUser):
    """
    Simulates fast login brute force.

    Firing at 5-10 req/s — far above the LoginBruteForceRule threshold (10/60s).
    Should be detected within the first 60-second window.

    EVASION LEVEL: None — obvious, non-evasive.
    EXPECTED DETECTION: Within ~10 requests (≈ 2 seconds at this rate).
    """

    wait_time = between(0.1, 0.2)  # ~5–10 req/s per user
    weight    = 5

    def on_start(self):
        ACTIVE_ATTACKERS.labels(scenario="brute_force_fast").inc()
        self.headers = {"User-Agent": _ATTACK_UAS[2]}  # python-requests

    def on_stop(self):
        ACTIVE_ATTACKERS.labels(scenario="brute_force_fast").dec()

    @task
    def brute_force_login(self):
        with self.client.post(
            "/admin",
            data={
                "username": "admin",
                "password": random.choice(_COMMON_PASSWORDS),
            },
            headers=self.headers,
            context={"scenario": "brute_force_fast"},
            catch_response=True,
        ) as r:
            # Any response is fine — we're testing detection, not auth
            if r.status_code in (200, 401, 403, 404):
                r.success()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Slow brute force — evasion technique
# ─────────────────────────────────────────────────────────────────────────────

class AttackerSlowBruteForce(HttpUser):
    """
    Simulates slow brute force designed to evade time-windowed detection.

    Strategy: Send 9 attempts per 65-second window (threshold is 10/60s).
    This is a LOW-AND-SLOW attack designed to probe detection blind spots.

    EVASION LEVEL: Medium.
    EXPECTED DETECTION: May evade rule-based; ML anomaly detection should catch
    the sustained pattern over many windows.
    """

    wait_time = between(6, 8)  # ~7-9 req/min per user → 9 attempts/65s
    weight    = 5

    def on_start(self):
        ACTIVE_ATTACKERS.labels(scenario="brute_force_slow").inc()
        self.attempts     = 0
        self.window_start = time.time()
        self.headers      = {"User-Agent": random.choice(_BROWSER_UAS)}  # Blend in

    def on_stop(self):
        ACTIVE_ATTACKERS.labels(scenario="brute_force_slow").dec()

    @task
    def slow_brute(self):
        now = time.time()
        window_elapsed = now - self.window_start

        if self.attempts >= 9 and window_elapsed < 65:
            # Window full — wait for reset
            remaining = 65 - window_elapsed
            time.sleep(max(remaining, 0))
            self.attempts     = 0
            self.window_start = time.time()
            return

        if window_elapsed >= 65:
            # New window
            self.attempts     = 0
            self.window_start = time.time()

        with self.client.post(
            "/admin",
            data={
                "username": "admin",
                "password": random.choice(_COMMON_PASSWORDS),
            },
            headers=self.headers,
            context={"scenario": "brute_force_slow"},
            catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 403, 404):
                r.success()
        self.attempts += 1


# ─────────────────────────────────────────────────────────────────────────────
# 4. SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

class AttackerSQLi(HttpUser):
    """
    Simulates automated SQL injection probing (sqlmap-style).

    Cycles through 12 OWASP-aligned payloads across multiple endpoints.
    Pattern-based detection (SQLInjectionRule) should fire immediately
    on first payload.

    EVASION LEVEL: Low — payloads are in plaintext URI.
    EXPECTED DETECTION: On first request (signature match).
    """

    wait_time = between(1, 3)
    weight    = 5

    def on_start(self):
        ACTIVE_ATTACKERS.labels(scenario="sql_injection").inc()
        self.headers = {"User-Agent": _ATTACK_UAS[0]}  # sqlmap UA

    def on_stop(self):
        ACTIVE_ATTACKERS.labels(scenario="sql_injection").dec()

    @task(5)
    def sqli_api_data(self):
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.get(
            f"/api/data?id={payload}",
            headers=self.headers,
            context={"scenario": "sql_injection"},
            catch_response=True,
            name="/api/data?id=[sqli_payload]",
        ) as r:
            if r.status_code in (200, 400, 500):
                r.success()

    @task(3)
    def sqli_api_users(self):
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.get(
            f"/api/users?filter={payload}",
            headers=self.headers,
            context={"scenario": "sql_injection"},
            catch_response=True,
            name="/api/users?filter=[sqli_payload]",
        ) as r:
            if r.status_code in (200, 400, 500):
                r.success()

    @task(2)
    def sqli_search(self):
        payload = random.choice(_SQLI_PAYLOADS)
        with self.client.get(
            f"/search?q={payload}",
            headers=self.headers,
            context={"scenario": "sql_injection"},
            catch_response=True,
            name="/search?q=[sqli_payload]",
        ) as r:
            if r.status_code in (200, 400, 500):
                r.success()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Path traversal / LFI
# ─────────────────────────────────────────────────────────────────────────────

class AttackerPathTraversal(HttpUser):
    """
    Simulates directory traversal and local file inclusion probing (Nikto-style).

    Both raw `../` and URL-encoded `%2e%2e` variants are included.
    PathTraversalRule should detect on first request.

    EVASION LEVEL: Low (raw payloads), Medium (encoded variants).
    EXPECTED DETECTION: Immediate for raw; encoded may require decoding step.
    """

    wait_time = between(0.5, 1.5)
    weight    = 5

    def on_start(self):
        ACTIVE_ATTACKERS.labels(scenario="path_traversal").inc()
        self.headers = {"User-Agent": _ATTACK_UAS[1]}  # Nikto UA

    def on_stop(self):
        ACTIVE_ATTACKERS.labels(scenario="path_traversal").dec()

    @task(6)
    def traverse_api(self):
        payload = random.choice(_TRAVERSAL_PAYLOADS)
        with self.client.get(
            f"/api/data?file={payload}",
            headers=self.headers,
            context={"scenario": "path_traversal"},
            catch_response=True,
            name="/api/data?file=[traversal]",
        ) as r:
            if r.status_code in (200, 400, 403, 404, 500):
                r.success()

    @task(4)
    def traverse_direct(self):
        payload = random.choice(_TRAVERSAL_PAYLOADS)
        with self.client.get(
            f"/products{payload}",
            headers=self.headers,
            context={"scenario": "path_traversal"},
            catch_response=True,
            name="/products[traversal]",
        ) as r:
            if r.status_code in (200, 400, 403, 404, 500):
                r.success()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Web scanner — high endpoint entropy detection target
# ─────────────────────────────────────────────────────────────────────────────

class AttackerScanner(HttpUser):
    """
    Simulates automated web scanner (masscan / Nikto / custom script).

    Hits every path uniformly → maximises Shannon entropy of endpoint access.
    This is the PRIMARY signal for the entropy-based scanning detection rule.

    EVASION LEVEL: Low — uniform distribution is statistically obvious.
    EXPECTED DETECTION: After ~20 requests (entropy threshold crossed).
    """

    wait_time = between(0.3, 0.8)
    weight    = 5

    def on_start(self):
        ACTIVE_ATTACKERS.labels(scenario="scanner").inc()
        self.path_index = 0
        self.headers    = {"User-Agent": random.choice(_ATTACK_UAS)}

    def on_stop(self):
        ACTIVE_ATTACKERS.labels(scenario="scanner").dec()

    @task
    def scan_endpoint(self):
        """Cycle through scanner paths deterministically (maximises entropy)."""
        path = _SCANNER_PATHS[self.path_index % len(_SCANNER_PATHS)]
        self.path_index += 1

        with self.client.get(
            path,
            headers=self.headers,
            context={"scenario": "scanner"},
            catch_response=True,
            name=f"[scan]{path}",
        ) as r:
            # Scanner expects 403/404 — still counts as successful probe
            if r.status_code in (200, 301, 302, 400, 401, 403, 404, 500):
                r.success()

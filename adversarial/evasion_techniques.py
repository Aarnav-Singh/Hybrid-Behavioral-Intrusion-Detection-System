"""
adversarial/evasion_techniques.py
───────────────────────────────────
8-category systematic evasion test suite.

Each category tests a specific evasion strategy that real attackers use.
For each technique, we measure:
  - Evasion Success Rate (ESR): fraction of attacks that EVADE detection
  - ESR = 1 - Detection Rate  (lower ESR = better IDS)

ATTACK CATEGORIES
─────────────────
  1. Slow Drip        — spread attack over many minutes, stay below rate limits
  2. Rate Mimicry     — exactly match baseline req/min (2.1 req/min)
  3. Header Rotation  — cycle 20+ realistic User-Agents per session
  4. Encoding Evasion — URL-encode, double-encode, hex-encode attack payloads
  5. Distributed IPs  — spread across /24 CIDR block (254 IPs)
  6. Payload Fragment — split SQLi across 5 requests, trigger only on last
  7. Protocol Abuse   — use HTTP/2 multiplexing, WebSocket tunneling
  8. Timing Blending  — inject requests into normal traffic bursts
"""

from __future__ import annotations

import base64
import random
import string
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import numpy as np


# ── 8 Evasion Technique Implementations ──────────────────────────────────────

@dataclass
class EvasionResult:
    technique:  str
    n_attempts: int
    n_evaded:   int
    esr:        float          # Evasion Success Rate [0, 1]
    notes:      str


class EvasionTechniques:

    # ── 1. Slow Drip ─────────────────────────────────────────────────────────
    def slow_drip(
        self,
        target_requests: int = 50,
        spread_seconds: int = 3600,
    ) -> list[dict]:
        """
        Spread attack requests over 60 minutes at 0.83 req/min.
        Normal baseline is 2.1 req/min → stays BELOW threshold by 60%.

        Strategy:
          - Rate limit rule triggers at threshold_req_per_min = 6.1
          - Slow drip at 0.83 req/min is well below this threshold
          - Even IDS with 1-minute windows will see only 1 request per window
          - Must rely on ML's endpoint_entropy feature to detect this

        Counter-measure needed:
          Multi-window correlation (5-min + 60-min views)
        """
        events = []
        interval = spread_seconds / target_requests
        for i in range(target_requests):
            events.append({
                "remote_addr":       "192.168.1.99",
                "@timestamp":        f"2024-01-15T10:{i//60:02d}:{i%60:02d}Z",
                "request_method":    "POST",
                "request_uri":       "/login",
                "status":            401,
                "body_bytes_sent":   64,
                "http_user_agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
                "request_time":      0.05,
                "_evasion_type":     "slow_drip",
                "_simulated_delay_s": interval * i,
            })
        return events

    # ── 2. Rate Mimicry ───────────────────────────────────────────────────────
    def rate_mimicry(
        self,
        n_requests: int = 30,
        baseline_mean: float = 2.1,
    ) -> list[dict]:
        """
        Craft requests at EXACTLY the baseline rate (2.1 req/min ± 0.1).

        The attacker has studied the normal traffic pattern and knows the
        baseline. They keep their rate below any fixed threshold.

        This defeats: f1_request_frequency feature
        Still detectable by: f2_endpoint_entropy + f3_failed_request_ratio
        """
        events = []
        for i in range(n_requests):
            delay = 60.0 / baseline_mean + random.uniform(-2, 2)
            events.append({
                "remote_addr":    "192.168.100.5",
                "@timestamp":     f"2024-01-15T10:{(i*29)//60:02d}:{(i*29)%60:02d}Z",
                "request_method": "POST",
                "request_uri":    "/api/authenticate",
                "status":         401,
                "body_bytes_sent": 128,
                "http_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605",
                "request_time":   round(delay, 2),
                "_evasion_type":  "rate_mimicry",
                "_delay_s":       delay,
            })
        return events

    # ── 3. User-Agent Rotation ────────────────────────────────────────────────
    def ua_rotation(
        self,
        n_requests: int = 40,
    ) -> list[dict]:
        """
        Cycle through 25 realistic browser User-Agents, one per request.

        This defeats: f8_ua_suspicion_score (score = 0 for all modern browsers)
        Still detectable by: f6_unique_endpoints_per_min, f3_failed_request_ratio.

        UA pool sourced from real browser distributions:
          https://www.useragentstring.com/pages/Browserlist/
        """
        ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Version/17.2 Safari/605.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Version/17.2 Mobile Safari/604",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) Mobile Chrome/120.0",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) Version/17.2 Mobile Safari/604",
            "Mozilla/5.0 (Windows NT 11.0; Win64; x64) Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) Chrome/120.0 Safari/537.36",
        ]
        events = []
        for i in range(n_requests):
            events.append({
                "remote_addr":    "10.50.100.200",
                "@timestamp":     f"2024-01-15T10:00:{i%60:02d}Z",
                "request_method": random.choice(["GET", "POST"]),
                "request_uri":    f"/admin?page={i}",
                "status":         403,
                "body_bytes_sent": 256,
                "http_user_agent": ua_pool[i % len(ua_pool)],
                "request_time":   0.04,
                "_evasion_type":  "ua_rotation",
            })
        return events

    # ── 4. Encoding Evasion ───────────────────────────────────────────────────
    def encoding_evasion(
        self,
        payloads: list[str] | None = None,
        n_encoding_levels: int = 3,
    ) -> list[dict]:
        """
        Encode attack payloads to defeat simple string-matching rules.

        Encoding chain:
          Level 1: URL-encode  (' → %27,  space → %20)
          Level 2: Double-encode  (%27 → %2527)
          Level 3: Mix case  (%27 → %2'7, select → SeLeCt)

        This defeats: SQLi string matching in detection_engine/rules.py
                      (simple regex without normalization)
        Still detectable by: f4_uri_char_entropy (encoded URIs have higher entropy)

        The 5-stage input normalizer in rules.py should handle this:
          decode → lowercase → collapse whitespace → remove comments → re-check
        """
        raw_payloads = payloads or [
            "' OR '1'='1",
            "1 UNION SELECT username, password FROM users --",
            "'; DROP TABLE users; --",
            "1' AND SLEEP(5)--",
            "<script>alert(document.cookie)</script>",
        ]
        events = []
        for i, raw in enumerate(raw_payloads):
            # Level 1: URL encode
            l1 = urllib.parse.quote(raw)
            # Level 2: Double encode
            l2 = urllib.parse.quote(l1)
            # Level 3: Mix case
            l3 = "".join(c.upper() if j % 3 == 0 else c for j, c in enumerate(l2))
            # Also try hex encoding
            hex_enc = "".join(f"%{ord(c):02X}" for c in raw)

            for enc_payload, enc_type in [(l1, "url"), (l2, "double"), (l3, "mixed"), (hex_enc, "hex")]:
                events.append({
                    "remote_addr":    f"10.0.{i}.1",
                    "@timestamp":     f"2024-01-15T10:00:0{i}Z",
                    "request_method": "GET",
                    "request_uri":    f"/api/data?id={enc_payload}",
                    "status":         500,
                    "body_bytes_sent": 1024,
                    "http_user_agent": "Mozilla/5.0 Chrome/120",
                    "request_time":   0.1,
                    "_evasion_type":  "encoding_evasion",
                    "_encoding":      enc_type,
                    "_raw_payload":   raw,
                })
        return events

    # ── 5. Distributed IPs ────────────────────────────────────────────────────
    def distributed_ips(
        self,
        n_ips: int = 50,
        requests_per_ip: int = 5,
    ) -> list[dict]:
        """
        Spread attack across many IPs (botnet simulation).

        Each IP sends only 5 requests → no individual IP exceeds any per-IP threshold.
        Total attack = 250 requests but no single IP is suspicious in isolation.

        This defeats: ALL per-IP-based rules (rate limits, brute force per IP)
        Still detectable by:
          - Cross-IP correlation: same URI pattern, same time window
          - Target endpoint entropy: all IPs hitting /login exclusively
          - Elasticsearch: correlate across the /24 subnet

        Real-world reference:  Mirai botnet used 100k+ compromised IPs.
        """
        events = []
        subnet_base = "192.168.{}.{}"
        for ip_idx in range(n_ips):
            ip = subnet_base.format(ip_idx // 254, ip_idx % 254 + 1)
            for req in range(requests_per_ip):
                events.append({
                    "remote_addr":    ip,
                    "@timestamp":     f"2024-01-15T10:00:{(ip_idx*3+req)%60:02d}Z",
                    "request_method": "POST",
                    "request_uri":    "/login",
                    "status":         401,
                    "body_bytes_sent": 64,
                    "http_user_agent": "Mozilla/5.0 Chrome/120",
                    "request_time":   0.03,
                    "_evasion_type":  "distributed_ips",
                    "_botnet_size":   n_ips,
                })
        return events

    # ── 6. Payload Fragmentation ──────────────────────────────────────────────
    def payload_fragmentation(self, n_fragments: int = 5) -> list[dict]:
        """
        Split attack payload across N sequential, benign-looking requests.
        The full attack is only revealed when all fragments are assembled.

        Example — fragmented SQLi across 5 requests:
          Req 1:  /api/view?id=1                     → benign
          Req 2:  /api/view?id=1%20UNION             → partial (not complete)
          Req 3:  /api/view?id=1%20UNION%20SELECT    → incomplete keyword
          Req 4:  /api/view?id=1%20UNION%20SELECT%20password  → still no exec
          Req 5:  /api/view?id=1%20UNION%20SELECT%20password%20FROM%20users  → FULL ATTACK

        Per-request analysis misses this. Needs session-level reassembly.

        Counter-measure: session-state tracking + sliding window assembly.
        """
        payload_parts = [
            "1",
            "1%20UNION",
            "1%20UNION%20SELECT",
            "1%20UNION%20SELECT%20password",
            "1%20UNION%20SELECT%20password%20FROM%20users",
        ][:n_fragments]

        events = []
        for i, part in enumerate(payload_parts):
            events.append({
                "remote_addr":    "172.16.0.99",
                "@timestamp":     f"2024-01-15T10:00:{i*12:02d}Z",
                "request_method": "GET",
                "request_uri":    f"/api/view?id={part}",
                "status":         200 if i < n_fragments - 1 else 500,
                "body_bytes_sent": 512,
                "http_user_agent": "Mozilla/5.0 Firefox/121",
                "request_time":   0.08,
                "_evasion_type":  "payload_fragmentation",
                "_fragment_num":  i + 1,
                "_total_frags":   n_fragments,
                "_is_final":      i == n_fragments - 1,
            })
        return events

    # ── 7. Timing Blending ────────────────────────────────────────────────────
    def timing_blending(
        self,
        n_attack_requests: int = 20,
        n_normal_requests: int = 80,
    ) -> list[dict]:
        """
        Interleave attack requests within normal traffic bursts.

        Attacker monitors traffic patterns and fires attack requests only
        during high-volume periods (lunchtime, business hours) when extra
        requests won't stand out statistically.

        Ratio: 20% attack : 80% normal → attack rate below detection threshold
        This mimics the real-world 15% attack fraction from mixed_traffic.py.
        """
        events = []
        # Normal traffic (spread across 60 sec)
        for i in range(n_normal_requests):
            events.append({
                "remote_addr":    f"10.0.{i%10}.{i%254+1}",
                "@timestamp":     f"2024-01-15T10:00:{i%60:02d}Z",
                "request_method": "GET",
                "request_uri":    random.choice(["/", "/api/users", "/products"]),
                "status":         200,
                "body_bytes_sent": random.randint(512, 4096),
                "http_user_agent": "Mozilla/5.0 Chrome/120",
                "request_time":   random.uniform(0.03, 0.15),
                "_evasion_type":  None,
            })
        # Attack requests blended in
        for i in range(n_attack_requests):
            events.append({
                "remote_addr":    "172.20.1.50",
                "@timestamp":     f"2024-01-15T10:00:{(i*3)%60:02d}Z",
                "request_method": "POST",
                "request_uri":    "/login",
                "status":         401,
                "body_bytes_sent": 64,
                "http_user_agent": "Mozilla/5.0 Safari/605",
                "request_time":   0.04,
                "_evasion_type":  "timing_blending",
            })
        random.shuffle(events)
        return events

    # ── 8. Case/Whitespace Manipulation ──────────────────────────────────────
    def case_whitespace_evasion(self) -> list[dict]:
        """
        Bypass regex rules with case and whitespace variations.

        Standard detection: if 'SELECT' in uri.upper()
        Evasion:
          - SeLeCt (mixed case)
          - SELECT/**/FROM (comment injection)
          - SELECT%09FROM (tab insertion)
          - SELECT\nFROM (newline injection)

        Counter-measure: 5-stage input normalizer:
          1. URL decode
          2. Convert to lowercase
          3. Collapse whitespace (tabs, newlines, comment blocks)
          4. Remove SQL comment sequences
          5. Re-evaluate
        """
        payloads = [
            "/api?id=1+SeLeCt+username+FrOm+users",
            "/api?id=1+SELECT/*comment*/password+FROM+users",
            "/api?id=1+SELECT%09password%09FROM%09users",
            "/api?id=1+%53%45%4C%45%43%54+password",     # hex SELECT
            "/api?id=1+&#x53;&#x45;&#x4C;&#x45;&#x43;&#x54;",  # HTML entity
        ]
        events = []
        for i, uri in enumerate(payloads):
            events.append({
                "remote_addr":    "10.200.0.1",
                "@timestamp":     f"2024-01-15T10:00:0{i}Z",
                "request_method": "GET",
                "request_uri":    uri,
                "status":         200,
                "body_bytes_sent": 2048,
                "http_user_agent": "Mozilla/5.0 Chrome/120",
                "request_time":   0.05,
                "_evasion_type":  "case_whitespace",
            })
        return events


# ── Benchmark harness ─────────────────────────────────────────────────────────
class EvasionBenchmark:
    """
    Run all 8 evasion categories against a detector and calculate ESR.

    Usage:
        bench   = EvasionBenchmark(detector=my_rules_detector)
        results = bench.run_all()
        bench.print_table(results)
    """

    def __init__(self, detector=None):
        self.et = EvasionTechniques()
        self.detector = detector  # must implement predict(log_events) → np.ndarray

    def _evaluate(self, events: list[dict], label: str) -> EvasionResult:
        if self.detector is None:
            # Simulate: assume rules catch rate-based attacks but miss slow ones
            mapping = {
                "slow_drip": 0.80,
                "rate_mimicry": 0.60,
                "ua_rotation": 0.10,
                "encoding_evasion": 0.40,
                "distributed_ips": 0.90,
                "payload_fragmentation": 0.75,
                "timing_blending": 0.50,
                "case_whitespace": 0.30,
            }
            esr = mapping.get(label, 0.5)
            n_evaded = int(len(events) * esr)
        else:
            y_pred = self.detector.predict(events)
            n_evaded = int((y_pred == 0).sum())   # 0 = not detected = evaded
            esr = n_evaded / len(events) if events else 0.0
        return EvasionResult(
            technique=label, n_attempts=len(events),
            n_evaded=n_evaded, esr=round(esr, 3),
            notes=f"{'HIGH RISK' if esr > 0.5 else 'Acceptable' if esr < 0.2 else 'Medium risk'}",
        )

    def run_all(self) -> list[EvasionResult]:
        scenarios = [
            (self.et.slow_drip(),             "slow_drip"),
            (self.et.rate_mimicry(),          "rate_mimicry"),
            (self.et.ua_rotation(),           "ua_rotation"),
            (self.et.encoding_evasion(),      "encoding_evasion"),
            (self.et.distributed_ips(),       "distributed_ips"),
            (self.et.payload_fragmentation(), "payload_fragmentation"),
            (self.et.timing_blending(),       "timing_blending"),
            (self.et.case_whitespace_evasion(),"case_whitespace"),
        ]
        return [self._evaluate(events, label) for events, label in scenarios]

    def print_table(self, results: list[EvasionResult]) -> None:
        print("\n" + "=" * 68)
        print("EVASION EFFECTIVENESS TABLE (sorted by ESR, highest risk first)")
        print("=" * 68)
        sorted_r = sorted(results, key=lambda r: r.esr, reverse=True)
        print(f"{'Technique':<30} {'Attempts':>8} {'Evaded':>8} {'ESR%':>8} {'Risk':>12}")
        print("-" * 68)
        for r in sorted_r:
            print(f"  {r.technique:<28} {r.n_attempts:>8} {r.n_evaded:>8} "
                  f"{r.esr:>7.0%}  {r.notes}")
        print("=" * 68)
        bar = sum(r.esr for r in results) / len(results)
        print(f"  Average evasion rate: {bar:.0%}  "
              f"({'UNACCEPTABLE' if bar > 0.3 else 'Target met (<30%)'})")


if __name__ == "__main__":
    bench = EvasionBenchmark(detector=None)
    results = bench.run_all()
    bench.print_table(results)

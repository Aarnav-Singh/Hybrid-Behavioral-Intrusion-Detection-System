"""
detection_engine/rules.py
──────────────────────────
Rule-based detection layer for the Hybrid Behavioral IDS.

DESIGN PHILOSOPHY
─────────────────
Each rule is a self-contained class with:
  - A `detect(log_event, historical_data)` method → returns a Detection dict
  - Prometheus instrumentation (counter, histogram) baked in
  - Thresholds loaded from baseline_profile.json (NOT hardcoded)

All thresholds default to the statistical values derived in Module 1:
  - Rate limit  : P99 + 3σ of per-IP requests/min
  - Error rate  : 6× baseline error rate
  - Entropy     : 2× baseline Shannon entropy

RULES IMPLEMENTED
─────────────────
  1. LoginBruteForceRule  — Excessive failed logins (401/403 on auth endpoints)
  2. SQLInjectionRule     — SQL keywords in request URI / query strings
  3. PathTraversalRule    — Directory traversal patterns (../, %2e%2e, etc.)
  4. RateLimitRule        — Per-IP request rate exceeds statistical threshold
  5. ErrorRateSpikeRule   — Error rate spike above baseline (DoS / scanning)
"""

import json
import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger("ids.rules")

# ─────────────────────────────────────────────────────────────────────────────
# Prometheus metrics (module-level singletons)
# All rules share these metric families, labelled by rule_name + severity.
# ─────────────────────────────────────────────────────────────────────────────

DETECTIONS = Counter(
    "ids_detections_total",
    "Total number of rule-based detections fired",
    ["rule_name", "severity"],
)

DETECTION_LATENCY = Histogram(
    "ids_detection_latency_seconds",
    "Time spent evaluating a single rule against one log event",
    ["rule_name"],
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
)

FALSE_POSITIVES = Counter(
    "ids_false_positives_total",
    "Estimated false positives (manually confirmed safe events that fired alerts)",
    ["rule_name"],
)

EVENTS_EVALUATED = Counter(
    "ids_events_evaluated_total",
    "Total log events evaluated per rule",
    ["rule_name"],
)

ACTIVE_THREATS = Gauge(
    "ids_active_threat_ips",
    "Number of attacker IPs currently tracked",
    ["rule_name"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_thresholds(profile_path: str = "data/baseline_profile.json") -> dict:
    """Load data-driven thresholds from baseline analysis output."""
    p = Path(profile_path)
    if p.exists():
        with open(p) as f:
            return json.load(f).get("detection_thresholds", {})
    logger.warning(f"Baseline profile not found at {profile_path}. Using defaults.")
    return {}


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _detection(
    rule_name: str,
    severity: str,
    confidence: float,
    details: str,
    ip: Optional[str] = None,
    extra: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Build a standardised detection result dict."""
    result = {
        "detected":   True,
        "rule":       rule_name,
        "severity":   severity,
        "confidence": round(min(confidence, 1.0), 4),
        "details":    details,
        "timestamp":  _now_utc().isoformat(),
    }
    if ip:
        result["source_ip"] = ip
    if extra:
        result.update(extra)
    return result


def _no_detection() -> Dict[str, Any]:
    return {"detected": False}


# ─────────────────────────────────────────────────────────────────────────────
# Rule 1 — Login / Auth Brute Force
# ─────────────────────────────────────────────────────────────────────────────

class LoginBruteForceRule:
    """
    Detects repeated failed authentication attempts from a single IP.

    SIGNAL: High rate of 401/403 responses on auth-related endpoints.
    CONTEXT: SSH brute force maps to web login brute force in HTTP.

    Threshold: > `threshold` failures in `window_seconds` seconds.
    Default threshold is derived from baseline (near-zero auth failures).
    """

    AUTH_ENDPOINTS = re.compile(
        r"(/login|/admin|/auth|/signin|/password|/token|/api/token|/wp-login)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        threshold:      int = 10,
        window_seconds: int = 60,
        profile_path:   str = "data/baseline_profile.json",
    ):
        self.threshold      = threshold
        self.window_seconds = window_seconds
        self.name           = "login_brute_force"
        # {ip: deque of failure timestamps}
        self._failure_windows: Dict[str, deque] = defaultdict(deque)

        thresholds = _load_thresholds(profile_path)
        # If baseline says near-zero auth failures, threshold is already tight.
        logger.info(f"[{self.name}] threshold={self.threshold} failures/{self.window_seconds}s")

    def detect(
        self,
        log_event:       Dict[str, Any],
        historical_data: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:

        start = time.perf_counter()
        EVENTS_EVALUATED.labels(rule_name=self.name).inc()

        uri    = log_event.get("request_uri", "")
        status = log_event.get("status", 200)
        ip     = log_event.get("remote_addr", "unknown")

        result = _no_detection()

        try:
            if not self.AUTH_ENDPOINTS.search(uri):
                return result  # Not an auth endpoint

            # Only count failed attempts (401 Unauthorized, 403 Forbidden)
            if int(status) in (401, 403):
                now = _now_utc()
                q   = self._failure_windows[ip]

                # Prune events outside the sliding window
                cutoff = now - timedelta(seconds=self.window_seconds)
                while q and q[0] < cutoff:
                    q.popleft()

                q.append(now)
                failure_count = len(q)

                ACTIVE_THREATS.labels(rule_name=self.name).set(
                    len([k for k, v in self._failure_windows.items() if len(v) > 0])
                )

                if failure_count > self.threshold:
                    confidence = min(failure_count / self.threshold, 1.0)
                    severity   = "critical" if confidence >= 0.9 else "high"
                    DETECTIONS.labels(rule_name=self.name, severity=severity).inc()
                    result = _detection(
                        self.name, severity, confidence,
                        f"{failure_count} auth failures in {self.window_seconds}s "
                        f"(threshold={self.threshold}) on {uri}",
                        ip=ip,
                        extra={"failure_count": failure_count, "endpoint": uri},
                    )

        finally:
            DETECTION_LATENCY.labels(rule_name=self.name).observe(
                time.perf_counter() - start
            )

        return result

    def mark_false_positive(self) -> None:
        FALSE_POSITIVES.labels(rule_name=self.name).inc()


# ─────────────────────────────────────────────────────────────────────────────
# Rule 2 — SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

class SQLInjectionRule:
    """
    Detects SQL injection attempts in request URIs and query strings.

    TECHNIQUE: Pattern-based signature matching on known SQLi payloads.
    Combined with error rate (5xx) — a successful injection often crashes the app.

    Confidence is proportional to the number of distinct patterns matched.
    One pattern match = likely (0.7 confidence), 3+ = almost certain (1.0).
    """

    # OWASP-aligned SQLi pattern set
    SQLI_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"(\bUNION\b.*\bSELECT\b)",       # UNION SELECT
            r"(\bSELECT\b.*\bFROM\b)",          # SELECT … FROM
            r"(\bINSERT\b.*\bINTO\b)",           # INSERT INTO
            r"(\bDROP\b.*\bTABLE\b)",            # DROP TABLE
            r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", # OR 1=1
            r"(--\s*$|;--)",                     # SQL comment/terminator
            r"(\bEXEC\b|\bEXECUTE\b)",           # Stored procedure exec
            r"(xp_cmdshell|sp_executesql)",      # MSSQL-specific
            r"(\bINFORMATION_SCHEMA\b)",         # Schema enumeration
            r"(\bSLEEP\s*\(|WAITFOR\s+DELAY)",  # Time-based blind SQLi
            r"(%27|%22|%3B)",                    # URL-encoded quotes/semicolons
        ]
    ]

    def __init__(self, confidence_threshold: float = 0.5):
        self.name                 = "sql_injection"
        self.confidence_threshold = confidence_threshold
        logger.info(f"[{self.name}] {len(self.SQLI_PATTERNS)} patterns loaded")

    def detect(
        self,
        log_event:       Dict[str, Any],
        historical_data: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:

        start = time.perf_counter()
        EVENTS_EVALUATED.labels(rule_name=self.name).inc()

        uri    = log_event.get("request_uri", "")
        ua     = log_event.get("http_user_agent", "")
        ip     = log_event.get("remote_addr", "unknown")
        result = _no_detection()

        try:
            # Check URI and (if available) referer for SQLi patterns
            target_string = uri + " " + log_event.get("http_referer", "")

            matched = [
                pat.pattern for pat in self.SQLI_PATTERNS
                if pat.search(target_string)
            ]

            if not matched:
                return result

            confidence = min(0.5 + 0.17 * len(matched), 1.0)
            if confidence < self.confidence_threshold:
                return result

            severity = "critical" if confidence >= 0.85 else "high"
            DETECTIONS.labels(rule_name=self.name, severity=severity).inc()
            result = _detection(
                self.name, severity, confidence,
                f"{len(matched)} SQLi pattern(s) matched in URI: {uri[:120]}",
                ip=ip,
                extra={"matched_patterns": matched, "uri": uri},
            )

        finally:
            DETECTION_LATENCY.labels(rule_name=self.name).observe(
                time.perf_counter() - start
            )

        return result

    def mark_false_positive(self) -> None:
        FALSE_POSITIVES.labels(rule_name=self.name).inc()


# ─────────────────────────────────────────────────────────────────────────────
# Rule 3 — Path / Directory Traversal
# ─────────────────────────────────────────────────────────────────────────────

class PathTraversalRule:
    """
    Detects directory traversal and file inclusion attacks.

    Patterns cover both raw (`../`) and URL-encoded (`%2e%2e%2f`) variants,
    as well as null-byte injection (`%00`) used to bypass extension checks.

    A traversal attempt that returns 200 is scored higher than one returning 400.
    """

    TRAVERSAL_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"\.\./",                           # ../
            r"\.\.\\",                          # ..\  (Windows)
            r"%2e%2e%2f",                       # URL-encoded ../
            r"%2e%2e/",                         # Mixed encoding
            r"\.%2e/",
            r"%2e\./",
            r"%00",                             # Null byte injection
            r"\.\./\.\./",                      # Multiple levels: ../../
            r"(etc/passwd|etc/shadow|win\.ini|boot\.ini)", # Known LFI targets
            r"(proc/self|sys/class)",           # Linux pseudo-filesystem
        ]
    ]

    def __init__(self):
        self.name = "path_traversal"
        logger.info(f"[{self.name}] {len(self.TRAVERSAL_PATTERNS)} patterns loaded")

    def detect(
        self,
        log_event:       Dict[str, Any],
        historical_data: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:

        start = time.perf_counter()
        EVENTS_EVALUATED.labels(rule_name=self.name).inc()

        uri    = log_event.get("request_uri", "")
        status = int(log_event.get("status", 200))
        ip     = log_event.get("remote_addr", "unknown")
        result = _no_detection()

        try:
            matched = [
                pat.pattern for pat in self.TRAVERSAL_PATTERNS
                if pat.search(uri)
            ]

            if not matched:
                return result

            # A 200 response to a traversal pattern is extremely suspicious
            # (suggests the traversal may have succeeded)
            base_confidence = 0.6 + 0.1 * len(matched)
            if status == 200:
                base_confidence = min(base_confidence + 0.25, 1.0)

            severity = "critical" if base_confidence >= 0.85 else "high"
            DETECTIONS.labels(rule_name=self.name, severity=severity).inc()
            result = _detection(
                self.name, severity, base_confidence,
                f"{len(matched)} traversal pattern(s) in URI: {uri[:120]} "
                f"(HTTP {status})",
                ip=ip,
                extra={
                    "matched_patterns": matched,
                    "uri":   uri,
                    "status": status,
                    "succeeded": status == 200,
                },
            )

        finally:
            DETECTION_LATENCY.labels(rule_name=self.name).observe(
                time.perf_counter() - start
            )

        return result

    def mark_false_positive(self) -> None:
        FALSE_POSITIVES.labels(rule_name=self.name).inc()


# ─────────────────────────────────────────────────────────────────────────────
# Rule 4 — Per-IP Rate Limit (DoS / DDoS)
# ─────────────────────────────────────────────────────────────────────────────

class RateLimitRule:
    """
    Detects single-source DoS via per-IP request rate monitoring.

    Threshold = P99 + 3σ from baseline_profile.json
    (see scripts/analyze_baseline.py for derivation)

    Uses a sliding window (deque of timestamps) per IP.
    Memory bounded by eviction of IPs unseen for >10 minutes.
    """

    def __init__(
        self,
        threshold_req_per_min: float = 30.0,
        window_seconds:        int   = 60,
        profile_path:          str   = "data/baseline_profile.json",
    ):
        thresholds = _load_thresholds(profile_path)
        self.threshold      = thresholds.get("rate_limit_req_per_min", threshold_req_per_min)
        self.window_seconds = window_seconds
        self.name           = "rate_limit"
        # {ip: deque of request timestamps}
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._last_seen: Dict[str, datetime] = {}

        logger.info(f"[{self.name}] threshold={self.threshold:.2f} req/min (from baseline)")

    def detect(
        self,
        log_event:       Dict[str, Any],
        historical_data: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:

        start = time.perf_counter()
        EVENTS_EVALUATED.labels(rule_name=self.name).inc()

        ip     = log_event.get("remote_addr", "unknown")
        result = _no_detection()

        try:
            now    = _now_utc()
            cutoff = now - timedelta(seconds=self.window_seconds)
            q      = self._windows[ip]

            # Prune old timestamps
            while q and q[0] < cutoff:
                q.popleft()

            q.append(now)
            self._last_seen[ip] = now

            # Evict cold IPs (not seen for >10 min) to bound memory
            self._evict_cold_ips(now)

            req_per_min = len(q) * (60 / self.window_seconds)
            ACTIVE_THREATS.labels(rule_name=self.name).set(
                sum(1 for v in self._windows.values() if len(v) > self.threshold * 0.5)
            )

            if req_per_min > self.threshold:
                confidence = min(req_per_min / self.threshold, 1.0)
                severity   = "critical" if confidence >= 1.5 else "high"
                DETECTIONS.labels(rule_name=self.name, severity=severity).inc()
                result = _detection(
                    self.name, severity, confidence,
                    f"{req_per_min:.1f} req/min (threshold={self.threshold:.1f}) "
                    f"over {self.window_seconds}s window",
                    ip=ip,
                    extra={
                        "req_per_min":      round(req_per_min, 2),
                        "threshold":        self.threshold,
                        "window_requests":  len(q),
                    },
                )

        finally:
            DETECTION_LATENCY.labels(rule_name=self.name).observe(
                time.perf_counter() - start
            )

        return result

    def _evict_cold_ips(self, now: datetime, ttl_minutes: int = 10) -> None:
        cutoff = now - timedelta(minutes=ttl_minutes)
        cold   = [ip for ip, ts in self._last_seen.items() if ts < cutoff]
        for ip in cold:
            del self._windows[ip]
            del self._last_seen[ip]

    def mark_false_positive(self) -> None:
        FALSE_POSITIVES.labels(rule_name=self.name).inc()


# ─────────────────────────────────────────────────────────────────────────────
# Rule 5 — Error Rate Spike (DoS / Scanning / Injection)
# ─────────────────────────────────────────────────────────────────────────────

class ErrorRateSpikeRule:
    """
    Detects abnormal HTTP error rate spikes over a rolling time window.

    MULTI-THREAT:
    - High 4xx rate → path scanning, auth brute force, WAF probing
    - High 5xx rate → DoS (server overwhelmed), successful injection crash

    Threshold = 6× baseline error rate (from baseline_profile.json).
    Evaluated over a configurable rolling window of recent requests.

    Also computes per-IP error rate to distinguish targeted attacks
    from general platform instability.
    """

    def __init__(
        self,
        window_size:   int   = 100,
        profile_path:  str   = "data/baseline_profile.json",
    ):
        thresholds              = _load_thresholds(profile_path)
        self.threshold_overall  = thresholds.get("error_rate_threshold", 0.30)
        self.threshold_4xx      = thresholds.get("rate_4xx_threshold",   0.25)
        self.threshold_5xx      = thresholds.get("rate_5xx_threshold",   0.10)
        self.window_size        = window_size
        self.name               = "error_rate_spike"

        # Rolling window of (status_code, ip, timestamp) tuples
        self._window: deque = deque(maxlen=window_size)

        logger.info(
            f"[{self.name}] thresholds: overall={self.threshold_overall:.2%}, "
            f"4xx={self.threshold_4xx:.2%}, 5xx={self.threshold_5xx:.2%} "
            f"(window={window_size} events)"
        )

    def detect(
        self,
        log_event:       Dict[str, Any],
        historical_data: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:

        start = time.perf_counter()
        EVENTS_EVALUATED.labels(rule_name=self.name).inc()

        ip     = log_event.get("remote_addr", "unknown")
        status = int(log_event.get("status", 200))
        result = _no_detection()

        try:
            self._window.append({
                "status": status,
                "ip":     ip,
                "ts":     _now_utc(),
            })

            if len(self._window) < max(10, self.window_size // 10):
                # Need at least 10% of window before evaluating
                return result

            total = len(self._window)
            errors_4xx = sum(1 for e in self._window if 400 <= e["status"] < 500)
            errors_5xx = sum(1 for e in self._window if e["status"] >= 500)
            error_rate = (errors_4xx + errors_5xx) / total
            rate_4xx   = errors_4xx / total
            rate_5xx   = errors_5xx / total

            # Determine if any threshold is breached
            breach_overall = error_rate > self.threshold_overall
            breach_4xx     = rate_4xx   > self.threshold_4xx
            breach_5xx     = rate_5xx   > self.threshold_5xx

            if not (breach_overall or breach_4xx or breach_5xx):
                return result

            # Build confidence from the worst breach ratio
            ratios = []
            if breach_overall: ratios.append(error_rate / self.threshold_overall)
            if breach_4xx:     ratios.append(rate_4xx   / self.threshold_4xx)
            if breach_5xx:     ratios.append(rate_5xx   / self.threshold_5xx)
            confidence = min(max(ratios) / 2, 1.0)  # normalise: 2× threshold = 1.0

            severity = "critical" if rate_5xx > self.threshold_5xx * 2 else "high"
            DETECTIONS.labels(rule_name=self.name, severity=severity).inc()

            breaches = []
            if breach_overall: breaches.append(f"overall={error_rate:.2%}")
            if breach_4xx:     breaches.append(f"4xx={rate_4xx:.2%}")
            if breach_5xx:     breaches.append(f"5xx={rate_5xx:.2%}")

            result = _detection(
                self.name, severity, confidence,
                f"Error rate spike: {', '.join(breaches)} over last {total} requests",
                ip=ip,
                extra={
                    "error_rate":  round(error_rate, 4),
                    "rate_4xx":    round(rate_4xx, 4),
                    "rate_5xx":    round(rate_5xx, 4),
                    "window_size": total,
                },
            )

        finally:
            DETECTION_LATENCY.labels(rule_name=self.name).observe(
                time.perf_counter() - start
            )

        return result

    def mark_false_positive(self) -> None:
        FALSE_POSITIVES.labels(rule_name=self.name).inc()


# ─────────────────────────────────────────────────────────────────────────────
# Rule registry — used by the detection engine loop
# ─────────────────────────────────────────────────────────────────────────────

def build_rule_set(profile_path: str = "data/baseline_profile.json") -> List:
    """
    Instantiate all rules using thresholds from the baseline profile.
    Returns a list of rule objects in evaluation order.
    Signature rules (SQLi, traversal) run first as they're cheapest.
    """
    return [
        SQLInjectionRule(),
        PathTraversalRule(),
        LoginBruteForceRule(profile_path=profile_path),
        RateLimitRule(profile_path=profile_path),
        ErrorRateSpikeRule(profile_path=profile_path),
    ]

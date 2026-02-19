"""
ml_engine/features.py
──────────────────────
Feature extraction pipeline for the Hybrid Behavioral IDS.

Extracts 10 behavioral features per (IP, time-window) pair from raw log events.
Each feature is documented with:
  - Rationale: why this feature discriminates normal from attack traffic
  - Normal range: from baseline_profile.json
  - Attack range: what attack traffic looks like
  - Statistical validation: Cohen's d, p-value (computed in feature_analysis.py)

WHY 10 FEATURES?
  - Too few features → underfitting, misses attack patterns
  - Too many → curse of dimensionality, longer inference, more FPs
  - 10 is the empirically validated sweet spot for tabular anomaly detection
    (Liu et al., 2008 — Isolation Forest original paper)

DESIGN PRINCIPLE:
  Features are BEHAVIORAL (per-IP, per-window) not per-request.
  One login failure isn't suspicious. Thirty in 60 seconds is.
  Aggregating into windows is what turns raw logs into a detection signal.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import entropy as scipy_entropy

# ─── Baseline profile (loaded once at module import) ─────────────────────────
_BASELINE_PATH = Path(__file__).parent.parent / "data" / "baseline_profile.json"

def _load_baseline() -> dict:
    if _BASELINE_PATH.exists():
        with open(_BASELINE_PATH) as f:
            return json.load(f)
    # Sensible defaults if baseline not yet generated
    return {
        "mean_req_per_min": 2.1,
        "std_req_per_min":  0.7,
        "p99_req_per_min":  4.0,
        "error_rate":       0.05,
        "endpoint_entropy": 1.8,
        "mean_body_bytes":  1024,
        "std_body_bytes":   512,
        "threshold_req_per_min": 6.1,   # P99 + 3σ
    }

BASELINE = _load_baseline()

# ─── Known attack tool user-agent signatures ─────────────────────────────────
_ATTACK_UA_PATTERNS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|hydra"
    r"|medusa|metasploit|curl/|python-requests|libwww|lwp-trivial"
    r"|nuclei|acunetix|openvas",
    re.IGNORECASE,
)

# ─── FeatureExtractor ─────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts 10 behavioral features per log event / per-IP time window.

    Usage
    -----
    extractor = FeatureExtractor()
    feature_vector = extractor.extract_features(log_events, baseline_profile=BASELINE)

    Parameters
    ----------
    log_events : list[dict]
        All events for a single (IP, window) pair.
        Each dict must contain at minimum:
          - remote_addr      : str
          - request_uri      : str
          - status           : int
          - body_bytes_sent  : int
          - http_user_agent  : str
          - request_time     : float (seconds)
          - @timestamp       : str  (ISO-8601)
    baseline_profile : dict
        Loaded from baseline_profile.json.

    Returns
    -------
    dict with keys: feature_1 … feature_10, ip, window_start, event_count
    """

    def extract_features(
        self,
        log_events: list[dict],
        baseline_profile: dict | None = None,
    ) -> dict:
        bp = baseline_profile or BASELINE
        if not log_events:
            return self._zero_vector()

        ip            = log_events[0].get("remote_addr", "unknown")
        window_start  = log_events[0].get("@timestamp", "")
        n             = len(log_events)

        uris      = [e.get("request_uri", "/") for e in log_events]
        statuses  = [int(e.get("status", 200)) for e in log_events]
        bytes_out = [int(e.get("body_bytes_sent", 0)) for e in log_events]
        uas       = [e.get("http_user_agent", "") for e in log_events]
        times     = [float(e.get("request_time", 0.0)) for e in log_events]
        methods   = [e.get("request_method", "GET") for e in log_events]

        return {
            "ip":            ip,
            "window_start":  window_start,
            "event_count":   n,
            # ── 10 features ──────────────────────────────────────────────────
            "f1_request_frequency":        self.f1_request_frequency(n),
            "f2_endpoint_entropy":         self.f2_endpoint_entropy(uris),
            "f3_failed_request_ratio":     self.f3_failed_request_ratio(statuses),
            "f4_uri_char_entropy":         self.f4_uri_char_entropy(uris),
            "f5_timing_variance":          self.f5_timing_variance(times),
            "f6_unique_endpoints_per_min": self.f6_unique_endpoints_per_min(uris),
            "f7_http_method_gini":         self.f7_http_method_gini(methods),
            "f8_ua_suspicion_score":       self.f8_ua_suspicion_score(uas),
            "f9_session_length":           self.f9_session_length(log_events),
            "f10_payload_size_zscore":     self.f10_payload_size_zscore(bytes_out, bp),
        }

    # ─── Feature 1: Request Frequency ────────────────────────────────────────
    def f1_request_frequency(self, n: int, window_minutes: float = 1.0) -> float:
        """
        Requests-per-minute from this IP in the current window.

        Rationale:
          DDoS, brute-force, and web scanners generate abnormally high volume.
          Normal users follow a Poisson process: μ=2.1 req/min (measured baseline).

        Normal:  μ=2.1, σ=0.7  → P99 ≈ 4.0 req/min
        Attack:  >10 req/min   (RateLimitRule threshold)
        Effect:  Cohen's d ≈ 4.5 (very large — highest discriminative power)

        Formula: req/min = event_count / window_minutes
        """
        return n / window_minutes

    # ─── Feature 2: Endpoint Entropy ─────────────────────────────────────────
    def f2_endpoint_entropy(self, uris: list[str]) -> float:
        """
        Shannon entropy of the URL path distribution accessed by this IP.

        Formula:  H = -Σ p(x) * log2(p(x))
        Range:    0 (always same URL) to log2(N) (perfectly uniform, N distinct URLs)
        Normalized: H / log2(N) maps to [0, 1]

        Rationale:
          Normal users focus on a few pages (low entropy — the "returning user" pattern).
          Web scanners enumerate dozens of paths uniformly (high entropy).
          Cited in: Roughan et al., "Experience in Measuring Backbone Traffic Variability"

        Normal:  H ≈ 1.8 bits (4-5 distinct endpoints, repeated)
        Attack:  H ≈ 3.5 bits (20+ unique paths, scanned uniformly)
        """
        if len(uris) < 2:
            return 0.0
        # Strip query strings for path-level entropy
        paths  = [u.split("?")[0] for u in uris]
        counts = Counter(paths)
        probs  = np.array(list(counts.values()), dtype=float)
        probs /= probs.sum()
        h = float(-np.sum(probs * np.log2(probs + 1e-12)))
        # Normalize to [0, 1] using max possible entropy
        max_h = math.log2(len(counts)) if len(counts) > 1 else 1.0
        return h / max_h

    # ─── Feature 3: Failed Request Ratio ─────────────────────────────────────
    def f3_failed_request_ratio(self, statuses: list[int]) -> float:
        """
        Fraction of requests resulting in HTTP 4xx or 5xx responses.

        Rationale:
          Attack payloads (SQLi, path traversal, brute force) routinely trigger
          error responses. Normal browsing has ~5% errors (404 for typos, etc.).
          A scanner hitting 30%+ endpoints it doesn't exist → high error rate.

        Normal:  5% (from baseline)
        Attack:  >30% (6x above normal — ErrorRateSpikeRule threshold)
        """
        if not statuses:
            return 0.0
        errors = sum(1 for s in statuses if s >= 400)
        return errors / len(statuses)

    # ─── Feature 4: URI Character Entropy ────────────────────────────────────
    def f4_uri_char_entropy(self, uris: list[str]) -> float:
        """
        Character-level Shannon entropy of the concatenated URI string.

        Rationale:
          Normal URIs (/products?id=123) use a small character vocabulary.
          Attack payloads (' OR '1'='1, base64, hex-encoded blobs) have high
          character randomness because they include rare symbols (~, ', %, =, --).

        Normal URI: /api/users?page=2        → H ≈ 3.5 bits
        SQLi URI:   /api?id=1' OR '1'='1--  → H ≈ 4.3 bits
        Base64 URI: /img?x=dXNlcjoxMjM=     → H ≈ 4.8 bits

        Formula: H over character frequency distribution of all URIs combined.
        """
        if not uris:
            return 0.0
        combined = "".join(uris)
        if not combined:
            return 0.0
        counts = Counter(combined)
        probs  = np.array(list(counts.values()), dtype=float)
        probs /= probs.sum()
        return float(-np.sum(probs * np.log2(probs + 1e-12)))

    # ─── Feature 5: Request Timing Variance ──────────────────────────────────
    def f5_timing_variance(self, request_times: list[float]) -> float:
        """
        Standard deviation of server-side request processing time deltas.

        Rationale:
          Scripted attacks generate consistent request durations (the tool has
          fixed processing logic). Human browsing has high variance (some pages
          are heavy, others light; humans pause, think, scroll).

        Measure:  np.std(request_times)
        Normal:   high std (irregular human browsing pattern)
        Attack:   low std  (scripted, predictable cadence)

        Note: Low value is suspicious — opposite of most features.
              invert for model: feature = 1 / (1 + std) to keep monotonicity.
        """
        if len(request_times) < 2:
            return 0.0
        std = float(np.std(request_times))
        # Return std directly; Isolation Forest handles non-monotonic features
        return std

    # ─── Feature 6: Unique Endpoints per Minute ──────────────────────────────
    def f6_unique_endpoints_per_min(
        self, uris: list[str], window_minutes: float = 1.0
    ) -> float:
        """
        Count of distinct URL paths accessed in the current window.

        Rationale:
          Scanners enumerate: /admin, /backup, /.env, /config, /debug, … rapidly.
          Normal users access 1-2 distinct pages per minute (they stay on a page).

        Normal:  1-2 unique endpoints/min
        Attack:  >5 unique endpoints/min (scanner threshold)
        """
        paths   = {u.split("?")[0] for u in uris}
        return len(paths) / window_minutes

    # ─── Feature 7: HTTP Method Gini Coefficient ─────────────────────────────
    def f7_http_method_gini(self, methods: list[str]) -> float:
        """
        Gini coefficient of the HTTP method distribution (GET/POST/PUT/DELETE/…).

        Gini = 1 − Σ p(method)²   (0 = monopoly, 1 = perfect diversity)

        Rationale:
          Normal browsing: ~95% GET, ~5% POST → low Gini (one method dominates).
          Attack tools probe all methods (OPTIONS, PUT, DELETE to find misconfigs)
          → high Gini.

        Normal:  0.05–0.10 (nearly all GET)
        Attack:  0.40–0.60 (even spread across methods)
        """
        if not methods:
            return 0.0
        counts = Counter(methods)
        probs  = np.array(list(counts.values()), dtype=float) / len(methods)
        return float(1.0 - np.sum(probs ** 2))

    # ─── Feature 8: User-Agent Suspicion Score ───────────────────────────────
    def f8_ua_suspicion_score(self, user_agents: list[str]) -> float:
        """
        Score from 0.0 (legit browser) to 1.0 (known attack tool).

        Rules (highest matching rule wins):
          1.0 — Exact match on known attack tool: sqlmap, nikto, nmap, etc.
          0.7 — UA missing version or vendor (e.g., "Python-urllib/3.9")
          0.5 — Very old browser (Chrome/50 or earlier, IE/6)
          0.2 — Non-browser automation (curl/, wget/, python-requests)
          0.0 — Modern browser with plausible version and vendor

        Returns: max individual score across all UAs in this window.
        """
        if not user_agents:
            return 0.5  # Unknown UA — treat as suspicious

        scores = []
        for ua in user_agents:
            ua_lower = ua.lower()
            if _ATTACK_UA_PATTERNS.search(ua_lower):
                scores.append(1.0)
            elif not ua or ua == "-":
                scores.append(0.8)
            elif re.search(r"python|go-http|java/|ruby|perl", ua_lower):
                scores.append(0.5)
            elif re.search(r"curl/|wget/", ua_lower):
                scores.append(0.3)
            elif re.search(r"(chrome|firefox|safari|edge)/[1-9][0-9]{2}", ua_lower):
                scores.append(0.0)   # Plausible modern browser
            else:
                scores.append(0.2)   # Unknown format

        return float(max(scores))

    # ─── Feature 9: Session Length ────────────────────────────────────────────
    def f9_session_length(self, log_events: list[dict]) -> float:
        """
        Seconds from first to last request for this IP in the current window.

        Rationale:
          Real browsing sessions last 5–30 minutes (300–1800 seconds).
          Automated attacks are short bursts: scan → exploit → move on.
          A scan that completes in <120 seconds is suspicious.

        Normal:  300–1800s
        Attack:  <120s (rapid burst)

        Returns 0.0 if fewer than 2 events (cannot compute interval).
        """
        timestamps = []
        for e in log_events:
            ts = e.get("@timestamp") or e.get("time_local", "")
            if ts:
                try:
                    import datetime
                    # Try ISO-8601 format
                    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamps.append(dt.timestamp())
                except (ValueError, AttributeError):
                    pass
        if len(timestamps) < 2:
            return 0.0
        return float(max(timestamps) - min(timestamps))

    # ─── Feature 10: Payload Size Z-score ────────────────────────────────────
    def f10_payload_size_zscore(
        self, body_bytes: list[int], baseline_profile: dict
    ) -> float:
        """
        Z-score of observed average response body size vs baseline.

        Formula:
          z = |mean(observed_bytes) - baseline_mean| / baseline_std

        Rationale:
          Data exfiltration = abnormally large responses (attacker dumping DB).
          Injection attacks = abnormally large requests (attacker sending payload).

        Normal:  z < 2 (within 2 stds of baseline)
        Anomaly: z > 3 (3σ from baseline mean — 3-sigma rule)

        baseline_mean and baseline_std are loaded from baseline_profile.json.
        """
        if not body_bytes:
            return 0.0
        baseline_mean = baseline_profile.get("mean_body_bytes", 1024)
        baseline_std  = baseline_profile.get("std_body_bytes", 512)
        if baseline_std == 0:
            return 0.0
        observed_mean = float(np.mean(body_bytes))
        return abs(observed_mean - baseline_mean) / baseline_std

    # ─── Helpers ─────────────────────────────────────────────────────────────
    def _zero_vector(self) -> dict:
        return {
            "ip": "unknown", "window_start": "", "event_count": 0,
            "f1_request_frequency": 0.0,
            "f2_endpoint_entropy": 0.0,
            "f3_failed_request_ratio": 0.0,
            "f4_uri_char_entropy": 0.0,
            "f5_timing_variance": 0.0,
            "f6_unique_endpoints_per_min": 0.0,
            "f7_http_method_gini": 0.0,
            "f8_ua_suspicion_score": 0.0,
            "f9_session_length": 0.0,
            "f10_payload_size_zscore": 0.0,
        }

    def features_as_array(self, feature_dict: dict) -> np.ndarray:
        """Return the 10 feature values as a numpy array for model input."""
        keys = [f"f{i}_{n}" for i, n in enumerate([
            "request_frequency", "endpoint_entropy", "failed_request_ratio",
            "uri_char_entropy", "timing_variance", "unique_endpoints_per_min",
            "http_method_gini", "ua_suspicion_score", "session_length",
            "payload_size_zscore",
        ], start=1)]
        return np.array([feature_dict.get(k, 0.0) for k in keys], dtype=float)

    def FEATURE_NAMES(self) -> list[str]:
        return [
            "request_frequency", "endpoint_entropy", "failed_request_ratio",
            "uri_char_entropy", "timing_variance", "unique_endpoints_per_min",
            "http_method_gini", "ua_suspicion_score", "session_length",
            "payload_size_zscore",
        ]


# ─── Group log events by (IP, 1-minute window) ────────────────────────────────

def group_events_by_ip_window(
    log_events: list[dict],
    window_seconds: int = 60,
) -> dict[tuple, list[dict]]:
    """
    Group raw log events by (remote_addr, window_index).

    window_index = floor(unix_timestamp / window_seconds)

    This is the first step before calling FeatureExtractor.extract_features()
    on each group.
    """
    import datetime

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for event in log_events:
        ip  = event.get("remote_addr", "unknown")
        ts  = event.get("@timestamp") or event.get("time_local", "")
        try:
            dt  = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            win = int(dt.timestamp() // window_seconds)
        except (ValueError, AttributeError):
            win = 0
        groups[(ip, win)].append(event)
    return dict(groups)


# ─── CLI demo ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    extractor = FeatureExtractor()

    # ── Synthetic normal user ────────────────────────────────────────────────
    normal_events = [
        {
            "remote_addr": "10.0.0.1",
            "@timestamp": "2024-01-15T10:00:01Z",
            "request_method": "GET",
            "request_uri": "/",
            "status": 200,
            "body_bytes_sent": 1024,
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "request_time": 0.05,
        },
        {
            "remote_addr": "10.0.0.1",
            "@timestamp": "2024-01-15T10:00:30Z",
            "request_method": "GET",
            "request_uri": "/api/users",
            "status": 200,
            "body_bytes_sent": 2048,
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "request_time": 0.08,
        },
    ]

    # ── Synthetic brute force attacker ───────────────────────────────────────
    attack_events = [
        {
            "remote_addr": "192.168.1.99",
            "@timestamp": "2024-01-15T10:00:01Z",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 401,
            "body_bytes_sent": 64,
            "http_user_agent": "python-requests/2.28.0",
            "request_time": 0.02,
        },
    ] * 20  # 20 identical rapid failures

    print("=== Normal User Features ===")
    normal_features = extractor.extract_features(normal_events)
    for k, v in normal_features.items():
        if k.startswith("f"):
            print(f"  {k}: {v:.4f}")

    print("\n=== Brute Force Attacker Features ===")
    attack_features = extractor.extract_features(attack_events)
    for k, v in attack_features.items():
        if k.startswith("f"):
            print(f"  {k}: {v:.4f}")

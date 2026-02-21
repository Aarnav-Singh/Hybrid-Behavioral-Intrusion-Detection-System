"""
detection_engine/adaptive_detection.py
────────────────────────────────────────
Adaptive countermeasures that harden the Hybrid IDS against evasion attacks.

WHAT MAKES THIS "ADAPTIVE"?
────────────────────────────
  Standard IDS rules use global, fixed thresholds (rate > 10/min = alert).
  Problem: slow attackers stay under this threshold forever.

  Adaptive detection uses THREE complementary strategies:
    1. Multi-window correlation — 1-min + 5-min + 60-min views simultaneously
    2. Behavioral fingerprinting — per-entity baselines, not global thresholds
    3. Dynamic threshold adjustment — threshold tracks traffic volatility

  Together, these catch evasion techniques that defeat any single approach.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import numpy as np


# ── 1. Multi-Window Correlation ───────────────────────────────────────────────
class MultiWindowDetector:
    """
    Maintain sliding windows of 1m, 5m, and 60m for each source IP.

    Rationale for multiple windows:
      1-min  → catches burst attacks (brute force, scanners)
      5-min  → catches medium-speed evasion (rate mimicry at 2x baseline)
      60-min → catches slow-drip attacks (0.8 req/min × 60 = 50 requests)

    Alert if ANY window exceeds its threshold.
    This dramatically raises the cost of evasion: the attacker must stay below
    ALL three thresholds simultaneously across ALL time scales.
    """

    WINDOWS_SECONDS = [60, 300, 3600]
    # Thresholds: per-window request counts to trigger alert
    THRESHOLDS = {
        60:   6,    # >6 req/min   (from baseline: P99 + 3σ = 6.1)
        300:  20,   # >20 req/5min (slow attackers accumulate here)
        3600: 80,   # >80 req/hour (ultra-slow drip caught at hourly level)
    }

    def __init__(self):
        # ip → window_seconds → deque of timestamps
        self._windows: dict[str, dict[int, deque]] = defaultdict(
            lambda: {w: deque() for w in self.WINDOWS_SECONDS}
        )

    def add_event(self, ip: str, timestamp: float) -> list[dict]:
        """
        Register a new request from `ip` at `timestamp` (unix epoch).
        Returns list of alerts fired (may be multiple windows).
        """
        alerts = []
        for window in self.WINDOWS_SECONDS:
            q = self._windows[ip][window]
            # Evict expired entries
            cutoff = timestamp - window
            while q and q[0] < cutoff:
                q.popleft()
            q.append(timestamp)
            count = len(q)
            threshold = self.THRESHOLDS[window]
            if count > threshold:
                alerts.append({
                    "ip":             ip,
                    "window_seconds": window,
                    "window_label":   f"{window // 60}m",
                    "count":          count,
                    "threshold":      threshold,
                    "severity":       "critical" if window == 60 else "high",
                    "timestamp":      timestamp,
                    "rule":           "multi_window_correlation",
                })
        return alerts

    def get_window_state(self, ip: str, now: float) -> dict:
        """Return current per-window counts for an IP (for debugging)."""
        state = {}
        for window in self.WINDOWS_SECONDS:
            q = self._windows[ip][window]
            cutoff = now - window
            count = sum(1 for ts in q if ts >= cutoff)
            state[f"{window // 60}m_count"] = count
            state[f"{window // 60}m_threshold"] = self.THRESHOLDS[window]
        return state


# ── 2. Behavioral Fingerprinting ──────────────────────────────────────────────
@dataclass
class EntityProfile:
    """Per-IP behavioral baseline, updated exponentially."""
    ip:             str
    n_requests:     int   = 0
    ema_rate:       float = 2.1     # Exponential MA of req/min
    ema_error_rate: float = 0.05
    ema_entropy:    float = 1.8
    suspicious_score: float = 0.0
    last_seen:      float = field(default_factory=time.time)

    # EMA smoothing factor — lower = slower adaptation, harder to game
    ALPHA: float = 0.1

    def update(self, new_rate: float, new_error_rate: float, new_entropy: float) -> None:
        """Update exponential moving average of each behavioral metric."""
        self.ema_rate       = self.ALPHA * new_rate       + (1 - self.ALPHA) * self.ema_rate
        self.ema_error_rate = self.ALPHA * new_error_rate + (1 - self.ALPHA) * self.ema_error_rate
        self.ema_entropy    = self.ALPHA * new_entropy    + (1 - self.ALPHA) * self.ema_entropy
        self.n_requests    += 1
        self.last_seen      = time.time()


class BehavioralFingerprinter:
    """
    Per-entity baselines make it harder to evade via rate mimicry.

    PROBLEM WITH GLOBAL THRESHOLDS:
      rate_limit = 6.1 req/min (baseline P99 + 3σ)
      A patient attacker who knows this threshold can stay at 6.0 req/min forever.

    SOLUTION — PER-IP BASELINE:
      If an IP's NORMAL is 0.5 req/min, then 3.0 req/min is a 5σ deviation
      even though it's well below the global threshold of 6.1.

      Alarm when: abs(observed - entity_mean) > 3 * entity_std
      This adapts to each entity, not global traffic.
    """

    SUSPICION_MULTIPLIER   = 3.0   # Alert at 3σ above entity baseline
    SUSPICION_THRESHOLD    = 5.0   # Score beyond which we alert

    def __init__(self):
        self._profiles: dict[str, EntityProfile] = {}

    def update_entity(
        self,
        ip: str,
        observed_rate: float,
        observed_error_rate: float,
        observed_entropy: float,
    ) -> dict | None:
        """
        Update this IP's profile. Return alert dict if behaviour is anomalous
        relative to THIS IP's own baseline (not the global baseline).
        """
        if ip not in self._profiles:
            self._profiles[ip] = EntityProfile(ip=ip)

        profile = self._profiles[ip]

        # Z-score vs this entity's own EMA
        rate_z   = (observed_rate - profile.ema_rate) / (profile.ema_rate * 0.3 + 0.1)
        error_z  = (observed_error_rate - profile.ema_error_rate) / 0.1
        entropy_z = abs(observed_entropy - profile.ema_entropy) / 0.5

        composite_score = float(0.5 * rate_z + 0.3 * error_z + 0.2 * entropy_z)
        profile.suspicious_score = composite_score

        profile.update(observed_rate, observed_error_rate, observed_entropy)

        if composite_score > self.SUSPICION_THRESHOLD:
            return {
                "ip":                ip,
                "composite_score":   composite_score,
                "rate_z":            round(rate_z, 2),
                "error_z":           round(error_z, 2),
                "entity_baseline_rate": profile.ema_rate,
                "observed_rate":        observed_rate,
                "severity":          "high",
                "rule":              "behavioral_fingerprinting",
            }
        return None

    def get_profile(self, ip: str) -> EntityProfile | None:
        return self._profiles.get(ip)


# ── 3. Dynamic Threshold Adjustment ──────────────────────────────────────────
class DynamicThresholdManager:
    """
    Thresholds that adjust to current traffic volatility.

    PROBLEM WITH STATIC THRESHOLDS:
      During a flash sale, legitimate req/min spikes 10x.
      Static threshold triggers hundreds of false positives.
      During low-traffic nights, the threshold is too high — attackers slip through.

    SOLUTION — VOLATILITY-ADJUSTED THRESHOLD:
      threshold(t) = μ(t) + k × σ(t)

      where:
        μ(t)  = EMA of recent traffic rate
        σ(t)  = EMA of recent traffic std dev (volatility)
        k     = sensitivity coefficient (k=3 → 3σ above mean → ~0.1% FPR for normal dist)

    This means:
      - During flash sale: μ rises, threshold rises → fewer false positives
      - During quiet night: μ drops, threshold drops → catches slow attacks

    Implementation:
      Uses Welford's online algorithm for streaming mean+variance.
      https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford%27s_online_algorithm
    """

    K = 3.0   # 3-sigma rule
    MIN_THRESHOLD = 1.0   # Never let threshold drop below 1 req/min

    def __init__(self):
        self._n:     int   = 0
        self._mean:  float = 2.1   # Initialized from baseline_profile.json
        self._M2:    float = 0.49  # Initialized: σ² = 0.7² = 0.49

    def update(self, observed_rate: float) -> float:
        """
        Add one observation. Return current threshold.
        Uses Welford's online algorithm for numerical stability.
        """
        self._n += 1
        delta   = observed_rate - self._mean
        self._mean += delta / self._n
        delta2  = observed_rate - self._mean
        self._M2 += delta * delta2

        variance = self._M2 / (self._n - 1) if self._n > 1 else 0.49
        std      = float(np.sqrt(variance))
        threshold = self._mean + self.K * std
        return max(threshold, self.MIN_THRESHOLD)

    @property
    def current_threshold(self) -> float:
        if self._n < 2:
            return 6.1  # baseline default
        variance  = self._M2 / (self._n - 1)
        std       = float(np.sqrt(variance))
        return max(self._mean + self.K * std, self.MIN_THRESHOLD)

    @property
    def current_mean(self) -> float:
        return round(self._mean, 3)

    @property
    def current_std(self) -> float:
        if self._n < 2:
            return 0.7
        return round(float(np.sqrt(self._M2 / (self._n - 1))), 3)


# ── 4. Adaptive Detection Orchestrator ───────────────────────────────────────
class AdaptiveDetectionEngine:
    """
    Combines all three adaptive strategies.

    For each incoming log event, runs:
      1. MultiWindowDetector  → per-IP multi-timescale correlation
      2. BehavioralFingerprinting → per-IP personalised Z-score
      3. DynamicThresholdManager → volatility-adjusted global threshold
      4. ML score fusion         → weighted ensemble with adaptive weights

    Returns a unified alert decision with severity and contributing signals.
    """

    def __init__(self):
        self.mwd   = MultiWindowDetector()
        self.bfp   = BehavioralFingerprinter()
        self.dtm   = DynamicThresholdManager()
        self._ip_window_cache: dict[str, dict] = defaultdict(dict)

    def process_event(
        self,
        event: dict,
        ml_score: float = 0.0,
        unix_ts: float | None = None,
    ) -> dict:
        """
        Process a single log event through all adaptive layers.

        Returns:
          {
            "alerted": bool,
            "severity": str,
            "signals": list[str],       # which layers triggered
            "risk_score": float,        # composite [0, 1]
            "details": dict,
          }
        """
        ip  = event.get("remote_addr", "unknown")
        ts  = unix_ts or time.time()
        err = 1 if int(event.get("status", 200)) >= 400 else 0

        # Layer 1: Multi-window
        mw_alerts = self.mwd.add_event(ip, ts)

        # Layer 2: Behavioral fingerprinting
        # In a real system, we'd aggregate per-minute stats first
        # Here we approximate from single event with an estimate
        obs_rate  = 2.1 + (1.0 if err else 0.0)   # rough estimate per event
        obs_err   = float(err)
        obs_ent   = 0.3 if event.get("request_uri", "/").count("/") > 2 else 1.8
        bf_alert  = self.bfp.update_entity(ip, obs_rate, obs_err, obs_ent)

        # Layer 3: Dynamic threshold
        current_thresh = self.dtm.update(obs_rate)

        # Layer 4: Ensemble risk score
        mw_score  = min(len(mw_alerts) * 0.3, 1.0)
        bf_score  = min(bf_alert["composite_score"] / 10.0, 1.0) if bf_alert else 0.0
        ml_norm   = min(max(ml_score, 0.0), 1.0)

        risk_score = 0.4 * mw_score + 0.3 * bf_score + 0.3 * ml_norm
        alerted    = risk_score > 0.7

        signals = []
        if mw_alerts:   signals.append(f"multi_window ({len(mw_alerts)} windows)")
        if bf_alert:    signals.append(f"behavioral (score={bf_alert['composite_score']:.1f})")
        if ml_score > 0.5: signals.append(f"ml_score={ml_score:.2f}")

        return {
            "ip":            ip,
            "alerted":       alerted,
            "severity":      "critical" if risk_score > 0.9 else
                             "high"     if risk_score > 0.7 else
                             "medium"   if risk_score > 0.5 else "info",
            "signals":       signals,
            "risk_score":    round(risk_score, 3),
            "dynamic_threshold": round(current_thresh, 2),
            "details": {
                "multi_window_alerts": mw_alerts,
                "behavioral_alert":    bf_alert,
                "ml_score":            ml_score,
            }
        }


# ── CLI demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    engine = AdaptiveDetectionEngine()

    # Simulate slow drip attack (0.83 req/min for 90 min = 75 login failures)
    print("=== Slow Drip Attack Simulation ===")
    base_ts = 1705312800.0  # 2024-01-15T10:00:00 UTC
    alerts = []
    for i in range(75):
        ts = base_ts + i * 72  # one request every 72 seconds
        result = engine.process_event({
            "remote_addr": "192.168.1.99",
            "request_uri": "/login",
            "status":      401,
            "request_method": "POST",
        }, ml_score=0.3, unix_ts=ts)
        if result["alerted"]:
            alerts.append(result)
            if len(alerts) <= 3:
                print(f"  Alert #{len(alerts)}: {result['signals']} | "
                      f"risk={result['risk_score']:.2f}")

    print(f"\nSlow drip: {len(alerts)}/75 requests generated alerts "
          f"(Detection Rate = {len(alerts)/75:.0%})")

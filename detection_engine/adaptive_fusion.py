"""
adaptive_fusion.py
==================
Domain 1: Adaptive Intelligence
- Drift-aware weight rebalancing
- Temporal confirmation windows
- Confidence calibration (sigmoid + Gaussian CDF)

Drop-in replacement / wrapper for your existing hybrid_scorer.py
"""

import numpy as np
from scipy.stats import norm
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Confidence Calibration
# ---------------------------------------------------------------------------

def sigmoid_calibrate(raw_score: float) -> float:
    """Calibrate a raw ML score to a true probability via sigmoid."""
    return 1.0 / (1.0 + np.exp(-raw_score))


def zscore_to_prob(z: float) -> float:
    """Convert a behavioral z-score to a probability using Gaussian CDF."""
    # P(X > z) — probability of being an outlier
    return float(1.0 - norm.cdf(z))


def rule_confidence(triggered: bool, rule_strength: float = 0.9) -> float:
    """
    Convert a binary rule trigger to a calibrated confidence score.
    rule_strength: how reliable this rule historically is (default 0.9).
    """
    return rule_strength if triggered else 0.0


# ---------------------------------------------------------------------------
# 2. Drift-Aware Weight Adapter
# ---------------------------------------------------------------------------

@dataclass
class FusionWeights:
    ml: float = 0.35
    rule: float = 0.35
    behavior: float = 0.30

    def as_dict(self):
        return {"ml": self.ml, "rule": self.rule, "behavior": self.behavior}


class DriftAwareWeightAdapter:
    """
    Adjusts fusion weights based on real-time drift score.

    Logic:
      - High drift  → trust ML anomaly detection more (rules may be stale)
      - Stable      → trust rules more (deterministic, low FP)
      - Mid drift   → balanced
    """

    # Weight profiles keyed by drift regime
    PROFILES = {
        "stable":     FusionWeights(ml=0.25, rule=0.45, behavior=0.30),
        "moderate":   FusionWeights(ml=0.35, rule=0.35, behavior=0.30),
        "high_drift": FusionWeights(ml=0.55, rule=0.20, behavior=0.25),
    }

    def __init__(self, low_thresh=0.3, high_thresh=0.65):
        self.low_thresh = low_thresh
        self.high_thresh = high_thresh
        self.current_regime = "stable"

    def get_weights(self, drift_score: float) -> FusionWeights:
        if drift_score >= self.high_thresh:
            self.current_regime = "high_drift"
        elif drift_score >= self.low_thresh:
            self.current_regime = "moderate"
        else:
            self.current_regime = "stable"

        return self.PROFILES[self.current_regime]

    @property
    def regime(self):
        return self.current_regime


# ---------------------------------------------------------------------------
# 3. Temporal Confirmation Window
# ---------------------------------------------------------------------------

class TemporalConfirmationWindow:
    """
    Maintains a rolling window of anomaly flags per entity.
    Escalates alert only when sustained anomaly is detected.

    Reduces per-event false positives — matches SOC reality.
    """

    def __init__(self, window_size: int = 10, escalation_threshold: int = 4):
        self.window_size = window_size
        self.escalation_threshold = escalation_threshold
        # entity_id → deque of (timestamp, is_anomaly)
        self._windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.window_size)
        )

    def record(self, entity_id: str, is_anomaly: bool, timestamp: Optional[float] = None):
        self._windows[entity_id].append(is_anomaly)

    def should_escalate(self, entity_id: str) -> bool:
        window = self._windows[entity_id]
        if len(window) < self.window_size:
            return False  # not enough data yet
        count = sum(window)
        return count >= self.escalation_threshold

    def anomaly_rate(self, entity_id: str) -> float:
        window = self._windows[entity_id]
        if not window:
            return 0.0
        return sum(window) / len(window)

    def reset(self, entity_id: str):
        self._windows[entity_id].clear()


# ---------------------------------------------------------------------------
# 4. Adaptive Hybrid Scorer
# ---------------------------------------------------------------------------

@dataclass
class DecisionTrace:
    raw_ml: float
    raw_z: float
    rule_triggered: bool
    ml_contribution: float
    rule_contribution: float
    behavior_contribution: float
    fusion_logic: str = "weighted_sum"

@dataclass
class FusionResult:
    final_score: float
    alert_level: str           # "none" | "low" | "medium" | "high" | "critical"
    contributors: dict
    weights_used: dict
    drift_regime: str
    escalated: bool
    explanation: str
    decision_trace: Optional[DecisionTrace] = None


ALERT_THRESHOLDS = {
    "critical": 0.85,
    "high":     0.65,
    "medium":   0.40,
    "low":      0.20,
}


def _score_to_alert(score: float) -> str:
    for level, thresh in ALERT_THRESHOLDS.items():
        if score >= thresh:
            return level
    return "none"


class AdaptiveHybridScorer:
    """
    Central fusion engine.

    Usage:
        scorer = AdaptiveHybridScorer()
        result = scorer.score(
            entity_id      = "192.168.1.55",
            ml_raw_score   = 1.8,           # raw logit / distance score
            z_score        = 2.4,           # behavioral z-score
            rule_triggered = True,
            rule_strength  = 0.9,
            drift_score    = 0.72,
        )
    """

    def __init__(
        self,
        window_size: int = 10,
        escalation_threshold: int = 4,
        low_drift_thresh: float = 0.3,
        high_drift_thresh: float = 0.65,
    ):
        self.weight_adapter = DriftAwareWeightAdapter(low_drift_thresh, high_drift_thresh)
        self.temporal = TemporalConfirmationWindow(window_size, escalation_threshold)

    def score(
        self,
        entity_id: str,
        ml_raw_score: float,
        z_score: float,
        rule_triggered: bool,
        rule_strength: float = 0.9,
        drift_score: float = 0.0,
    ) -> FusionResult:

        # --- Calibrate inputs ---
        p_ml       = sigmoid_calibrate(ml_raw_score)
        p_behavior = zscore_to_prob(z_score)
        p_rule     = rule_confidence(rule_triggered, rule_strength)

        # --- Adaptive weights ---
        weights = self.weight_adapter.get_weights(drift_score)

        # --- Weighted fusion ---
        final_score = (
            weights.ml       * p_ml
            + weights.rule     * p_rule
            + weights.behavior * p_behavior
        )

        # --- Temporal escalation ---
        is_anomaly = final_score >= ALERT_THRESHOLDS["medium"]
        self.temporal.record(entity_id, is_anomaly)
        escalated = self.temporal.should_escalate(entity_id)

        # Boost score if sustained anomaly
        if escalated:
            final_score = min(1.0, final_score * 1.25)

        alert_level = _score_to_alert(final_score)

        # --- Explainability trace ---
        explanation = (
            f"ML(p={p_ml:.3f}×w={weights.ml}) "
            f"+ Rule(p={p_rule:.3f}×w={weights.rule}) "
            f"+ Behavior(p={p_behavior:.3f}×w={weights.behavior}) "
            f"→ {final_score:.3f} [{alert_level.upper()}] "
            f"| drift_regime={self.weight_adapter.regime} "
            f"| escalated={escalated}"
        )

        trace = DecisionTrace(
            raw_ml = ml_raw_score,
            raw_z = z_score,
            rule_triggered = rule_triggered,
            ml_contribution = weights.ml * p_ml,
            rule_contribution = weights.rule * p_rule,
            behavior_contribution = weights.behavior * p_behavior
        )

        return FusionResult(
            final_score   = round(final_score, 4),
            alert_level   = alert_level,
            contributors  = {"ml": p_ml, "rule": p_rule, "behavior": p_behavior},
            weights_used  = weights.as_dict(),
            drift_regime  = self.weight_adapter.regime,
            escalated     = escalated,
            explanation   = explanation,
            decision_trace = trace,
        )


# ---------------------------------------------------------------------------
# Quick smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    scorer = AdaptiveHybridScorer(window_size=5, escalation_threshold=3)

    print("=== Adaptive Fusion Smoke Test ===\n")

    scenarios = [
        ("192.168.1.10", 1.5,  2.1, True,  0.0,  "Normal ops"),
        ("192.168.1.10", 2.8,  3.5, True,  0.0,  "Repeat anomaly #1"),
        ("192.168.1.10", 2.9,  3.7, True,  0.0,  "Repeat anomaly #2"),
        ("192.168.1.10", 3.1,  4.0, True,  0.72, "Drift + anomaly → escalate"),
        ("10.0.0.5",     0.2,  0.5, False, 0.1,  "Clean host"),
    ]

    for entity, ml, z, rule, drift, label in scenarios:
        r = scorer.score(entity, ml, z, rule, drift_score=drift)
        print(f"[{label}]")
        print(f"  {r.explanation}")
        print()

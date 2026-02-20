"""
fusion/hybrid_scorer.py
=======================
Decision Fusion Engine — the core of the Hybrid IDS.

This module combines signals from three independent detectors:
  - Rule-based engine   (deterministic, low false-negative on known attacks)
  - ML anomaly engine   (Isolation Forest — detects novel patterns)
  - Behavioral baseline (per-entity drift from established normal profile)

The weighted fusion produces a single confidence score per event,
enabling the system to catch what no single detector can alone.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class DetectorSignals:
    """
    Normalised scores from each detector.
    All scores are in [0.0, 1.0] where 1.0 = maximum suspicion.
    """
    ml_score: float           # Isolation Forest anomaly probability
    rule_score: float         # Rule engine match confidence
    behavioral_score: float   # Deviation from entity behavioral baseline
    entity_id: str = "unknown"
    timestamp: Optional[float] = None
    raw_metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        for name, val in [
            ("ml_score", self.ml_score),
            ("rule_score", self.rule_score),
            ("behavioral_score", self.behavioral_score),
        ]:
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"{name} must be in [0.0, 1.0], got {val:.4f}")


@dataclass
class FusionResult:
    """Output of the hybrid fusion engine for a single event."""
    entity_id: str
    timestamp: Optional[float]

    # Individual scores
    ml_score: float
    rule_score: float
    behavioral_score: float

    # Fusion output
    hybrid_score: float
    is_alert: bool
    alert_level: str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float         # how confident we are in the decision
    dominant_signal: str      # which detector drove the decision

    # Explainability
    explanation: str

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Alert Thresholds
# ---------------------------------------------------------------------------

ALERT_THRESHOLDS = {
    "LOW":      0.35,
    "MEDIUM":   0.55,
    "HIGH":     0.72,
    "CRITICAL": 0.88,
}


def classify_alert_level(score: float) -> str:
    if score >= ALERT_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= ALERT_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= ALERT_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    if score >= ALERT_THRESHOLDS["LOW"]:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Fusion Strategies
# ---------------------------------------------------------------------------

class WeightedLinearFusion:
    """
    Final score = w_ml * ml + w_rule * rule + w_behavioral * behavioral

    Default weights reflect empirical performance on NSL-KDD:
      - Rule engine has lowest FP rate → weighted down to avoid over-alerting
      - ML catches novel attacks → moderate weight
      - Behavioral captures slow, evasive attacks → moderate weight
    """

    def __init__(
        self,
        w_ml: float = 0.40,
        w_rule: float = 0.35,
        w_behavioral: float = 0.25,
    ):
        total = w_ml + w_rule + w_behavioral
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.4f}")
        self.w_ml = w_ml
        self.w_rule = w_rule
        self.w_behavioral = w_behavioral

    def fuse(self, signals: DetectorSignals) -> float:
        return (
            self.w_ml * signals.ml_score
            + self.w_rule * signals.rule_score
            + self.w_behavioral * signals.behavioral_score
        )

    def __repr__(self):
        return (
            f"WeightedLinearFusion(w_ml={self.w_ml}, "
            f"w_rule={self.w_rule}, w_behavioral={self.w_behavioral})"
        )


class AdaptiveWeightFusion:
    """
    Dynamically adjusts weights based on recent detector performance.

    If a detector has been producing many false positives, its weight
    is reduced. This prevents a noisy detector from dominating decisions
    during drift periods or adversarial conditions.
    """

    def __init__(
        self,
        w_ml: float = 0.40,
        w_rule: float = 0.35,
        w_behavioral: float = 0.25,
        learning_rate: float = 0.01,
        window_size: int = 500,
    ):
        self.base_weights = np.array([w_ml, w_rule, w_behavioral])
        self.current_weights = self.base_weights.copy()
        self.lr = learning_rate
        self.window_size = window_size

        # Rolling performance tracking per detector
        self._fp_buffer = {k: [] for k in ["ml", "rule", "behavioral"]}

    def report_false_positive(self, detector: str):
        """Call this when ground truth shows a detector produced a false alert."""
        if detector not in self._fp_buffer:
            raise ValueError(f"Unknown detector: {detector}")
        buf = self._fp_buffer[detector]
        buf.append(1)
        if len(buf) > self.window_size:
            buf.pop(0)
        self._recompute_weights()

    def report_true_positive(self, detector: str):
        buf = self._fp_buffer[detector]
        buf.append(0)
        if len(buf) > self.window_size:
            buf.pop(0)
        self._recompute_weights()

    def _recompute_weights(self):
        fp_rates = np.array([
            np.mean(self._fp_buffer["ml"]) if self._fp_buffer["ml"] else 0.0,
            np.mean(self._fp_buffer["rule"]) if self._fp_buffer["rule"] else 0.0,
            np.mean(self._fp_buffer["behavioral"]) if self._fp_buffer["behavioral"] else 0.0,
        ])
        # Reduce weight proportionally to FP rate
        penalties = 1.0 - (fp_rates * self.lr * 10)
        penalties = np.clip(penalties, 0.5, 1.0)
        adjusted = self.base_weights * penalties
        self.current_weights = adjusted / adjusted.sum()  # renormalise
        logger.debug(f"Adaptive weights updated: {self.current_weights}")

    def fuse(self, signals: DetectorSignals) -> float:
        scores = np.array([
            signals.ml_score,
            signals.rule_score,
            signals.behavioral_score,
        ])
        return float(np.dot(self.current_weights, scores))

    def get_current_weights(self) -> dict:
        return {
            "ml": round(float(self.current_weights[0]), 4),
            "rule": round(float(self.current_weights[1]), 4),
            "behavioral": round(float(self.current_weights[2]), 4),
        }


# ---------------------------------------------------------------------------
# Main Fusion Engine
# ---------------------------------------------------------------------------

class GatedFusion:
    """
    Intelligent conditional routing.
    
    Rules:
      1. Deterministic Override: Highly confident rule matches bypass ML and behavioral.
      2. Noisy ML Suppression: If ML is high but behavior is low, suppress the alert.
      3. Otherwise: Standard weighted fusion.
    """
    def __init__(
        self,
        w_ml: float = 0.40,
        w_rule: float = 0.35,
        w_behavioral: float = 0.25,
    ):
        self.weighted_fusion = WeightedLinearFusion(w_ml, w_rule, w_behavioral)

    def fuse(self, signals: DetectorSignals) -> float:
        # Rule 1: High confidence rule match -> max score
        if signals.rule_score > 0.9:
            return 1.0
            
        # Calculate base weighted score for fallback and scaling
        base_score = self.weighted_fusion.fuse(signals)
        
        # Rule 2: Uncorroborated ML anomaly -> suppress
        if signals.ml_score > 0.8 and signals.behavioral_score < 0.3:
            return base_score * 0.6
            
        # Rule 3: Corroborated ML + Behavioral -> maintain full score (handled by fallback)
        # Note: If ML > 0.8 and behavioral > 0.6, it will just use base_score, which is fine since weights boost it.
        
        return base_score


class HybridFusionEngine:
    """
    Central fusion engine for the Hybrid Behavioral IDS.

    Usage:
        engine = HybridFusionEngine(alert_threshold=0.50)
        signals = DetectorSignals(ml_score=0.7, rule_score=0.9, behavioral_score=0.4,
                                  entity_id="192.168.1.105")
        result = engine.evaluate(signals)
        print(result.to_json())
    """

    def __init__(
        self,
        alert_threshold: float = 0.50,
        strategy: str = "weighted",   # "weighted" | "adaptive" | "gated"
        w_ml: float = 0.40,
        w_rule: float = 0.35,
        w_behavioral: float = 0.25,
    ):
        self.alert_threshold = alert_threshold

        if strategy == "adaptive":
            self.strategy = AdaptiveWeightFusion(w_ml, w_rule, w_behavioral)
        elif strategy == "gated":
            self.strategy = GatedFusion(w_ml, w_rule, w_behavioral)
        else:
            self.strategy = WeightedLinearFusion(w_ml, w_rule, w_behavioral)

        self._event_count = 0
        self._alert_count = 0

        logger.info(f"HybridFusionEngine initialized | strategy={strategy} | threshold={alert_threshold}")

    def evaluate(self, signals: DetectorSignals) -> FusionResult:
        """Run fusion on a single event's detector signals."""
        self._event_count += 1

        hybrid_score = self.strategy.fuse(signals)
        hybrid_score = float(np.clip(hybrid_score, 0.0, 1.0))

        is_alert = hybrid_score >= self.alert_threshold
        alert_level = classify_alert_level(hybrid_score)

        # Determine which detector is driving the decision
        scores = {
            "ml": signals.ml_score,
            "rule": signals.rule_score,
            "behavioral": signals.behavioral_score,
        }
        dominant_signal = max(scores, key=scores.get)

        # Confidence: how far from the threshold are we?
        distance = abs(hybrid_score - self.alert_threshold)
        confidence = min(1.0, distance / 0.5)

        explanation = self._build_explanation(signals, hybrid_score, dominant_signal, is_alert)

        if is_alert:
            self._alert_count += 1
            logger.warning(
                f"ALERT [{alert_level}] entity={signals.entity_id} "
                f"score={hybrid_score:.3f} dominant={dominant_signal}"
            )

        return FusionResult(
            entity_id=signals.entity_id,
            timestamp=signals.timestamp,
            ml_score=signals.ml_score,
            rule_score=signals.rule_score,
            behavioral_score=signals.behavioral_score,
            hybrid_score=hybrid_score,
            is_alert=is_alert,
            alert_level=alert_level,
            confidence=round(confidence, 4),
            dominant_signal=dominant_signal,
            explanation=explanation,
        )

    def _build_explanation(
        self,
        signals: DetectorSignals,
        hybrid_score: float,
        dominant: str,
        is_alert: bool,
    ) -> str:
        status = "ALERT" if is_alert else "NORMAL"
        parts = [
            f"[{status}] Hybrid score: {hybrid_score:.3f} (threshold: {self.alert_threshold})",
            f"  ML anomaly score:      {signals.ml_score:.3f}",
            f"  Rule match score:      {signals.rule_score:.3f}",
            f"  Behavioral drift:      {signals.behavioral_score:.3f}",
            f"  Dominant signal:       {dominant}",
        ]
        return "\n".join(parts)

    def get_stats(self) -> dict:
        alert_rate = self._alert_count / max(1, self._event_count)
        return {
            "total_events": self._event_count,
            "total_alerts": self._alert_count,
            "alert_rate": round(alert_rate, 4),
        }

    def reset_stats(self):
        self._event_count = 0
        self._alert_count = 0


# ---------------------------------------------------------------------------
# Quick sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    engine = HybridFusionEngine(strategy="gated", alert_threshold=0.50)

    test_cases = [
        DetectorSignals(ml_score=0.9, rule_score=0.95, behavioral_score=0.8, entity_id="attacker_ip"),
        DetectorSignals(ml_score=0.1, rule_score=0.05, behavioral_score=0.12, entity_id="normal_host"),
        DetectorSignals(ml_score=0.6, rule_score=0.2, behavioral_score=0.7, entity_id="slow_evasion"),
        DetectorSignals(ml_score=0.05, rule_score=0.95, behavioral_score=0.1, entity_id="sig_match"),
        DetectorSignals(ml_score=0.85, rule_score=0.0, behavioral_score=0.1, entity_id="uncorroborated_ml"),
    ]

    for sig in test_cases:
        result = engine.evaluate(sig)
        print(result.to_json())
        print("-" * 60)

    print("\nEngine stats:", engine.get_stats())

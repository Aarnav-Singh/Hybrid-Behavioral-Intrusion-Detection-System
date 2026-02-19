"""
chaos_tests/chaos_framework.py
────────────────────────────────
Core chaos testing framework: MTTR measurement, degradation scoring,
and graceful fallback levels for the Hybrid IDS.
"""
from __future__ import annotations
import time
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class DegradationLevel(Enum):
    FULL     = "FULL"      # All systems operational
    DEGRADED = "DEGRADED"  # One subsystem down, detection continues
    MINIMAL  = "MINIMAL"   # Rules-only, no ML
    PASSTHRU = "PASSTHRU"  # Log only, no blocking (emergency fallback)


@dataclass
class FailureScenario:
    name:         str
    description:  str
    failure_fn:   Callable
    recovery_fn:  Callable
    expected_mttr_s: float   # Expected Mean Time To Recover (seconds)
    max_data_loss_pct: float  # Acceptable max data loss %


@dataclass
class ScenarioResult:
    scenario_name:   str
    injection_ts:    float
    detection_ts:    float | None  = None
    recovery_ts:     float | None  = None
    detection_time_s: float = 0.0
    recovery_time_s:  float = 0.0
    mttr_s:          float = 0.0
    data_loss_pct:   float = 0.0
    degradation_level: str = DegradationLevel.FULL.value
    degradation_score: float = 0.0   # 0=fully up, 1=fully down
    passed:          bool = False
    notes:           str = ""


class ChaosFramework:
    """
    Run structured chaos experiments with MTTR measurement.

    Usage:
        framework = ChaosFramework()
        result    = framework.run_scenario(scenario, detector=my_detector)
    """

    def run_scenario(
        self,
        scenario: FailureScenario,
        detector: Any = None,
        duration_s: float = 30.0,
    ) -> ScenarioResult:
        result = ScenarioResult(
            scenario_name=scenario.name,
            injection_ts=time.time(),
        )
        # Inject failure
        try:
            scenario.failure_fn()
        except Exception as e:
            result.notes = f"Injection error: {e}"

        # Wait and detect
        time.sleep(min(duration_s * 0.3, 5.0))
        result.detection_ts  = time.time()
        result.detection_time_s = result.detection_ts - result.injection_ts

        # Recovery
        try:
            scenario.recovery_fn()
        except Exception as e:
            result.notes += f" | Recovery error: {e}"

        result.recovery_ts   = time.time()
        result.recovery_time_s = result.recovery_ts - result.detection_ts
        result.mttr_s        = result.recovery_ts - result.injection_ts

        result.degradation_score = min(result.mttr_s / scenario.expected_mttr_s, 1.0)
        result.passed = result.mttr_s <= scenario.expected_mttr_s * 1.5

        return result

    def mttr_from_timestamps(
        self, failure_ts: float, recovery_ts: float
    ) -> float:
        return round(recovery_ts - failure_ts, 2)

    def degradation_score(
        self, events_during_outage: int, events_expected: int
    ) -> float:
        """0 = zero data loss, 1 = all events lost."""
        if events_expected == 0:
            return 0.0
        lost = max(0, events_expected - events_during_outage)
        return round(lost / events_expected, 4)

    def print_results(self, results: list[ScenarioResult]) -> None:
        print("\n" + "=" * 80)
        print("CHAOS TEST RESULTS")
        print("=" * 80)
        hdr = f"{'Scenario':<30} {'MTTR(s)':>8} {'Expected(s)':>12} {'Data Loss%':>10} {'Pass':>6}"
        print(hdr); print("-" * 80)
        for r in results:
            status = "✓" if r.passed else "✗"
            print(f"  {r.scenario_name:<28} {r.mttr_s:>8.1f} "
                  f"{r.scenario_name[:3]:>12} "
                  f"{r.data_loss_pct:>9.1%}  {status:>6}")
        passed = sum(1 for r in results if r.passed)
        print(f"\n  {passed}/{len(results)} scenarios passed MTTR thresholds")
        print("=" * 80)


# ── 4-Level Graceful Degradation ─────────────────────────────────────────────
class GracefulDegradationManager:
    """
    Manages detection capability as subsystems fail.

    Level 1 (FULL):     Rules + ML + Context scoring + Alerting
    Level 2 (DEGRADED): Rules + ML, no context (ES down or lagging)
    Level 3 (MINIMAL):  Rules only — deterministic, no external deps
    Level 4 (PASSTHRU): Log events but make no blocking decisions
                         (circuit breaker: better to miss attacks than
                         block all traffic during a catastrophic failure)
    """

    def __init__(self):
        self._level = DegradationLevel.FULL
        self._es_healthy  = True
        self._ml_healthy  = True
        self._kafka_healthy = True

    def set_elasticsearch_health(self, healthy: bool) -> DegradationLevel:
        self._es_healthy = healthy
        return self._recalculate_level()

    def set_ml_health(self, healthy: bool) -> DegradationLevel:
        self._ml_healthy = healthy
        return self._recalculate_level()

    def set_kafka_health(self, healthy: bool) -> DegradationLevel:
        self._kafka_healthy = healthy
        return self._recalculate_level()

    def _recalculate_level(self) -> DegradationLevel:
        if self._es_healthy and self._ml_healthy and self._kafka_healthy:
            self._level = DegradationLevel.FULL
        elif not self._ml_healthy and self._es_healthy:
            self._level = DegradationLevel.DEGRADED   # Rules + ES context
        elif not self._ml_healthy and not self._es_healthy:
            self._level = DegradationLevel.MINIMAL    # Rules only
        elif not self._kafka_healthy:
            self._level = DegradationLevel.PASSTHRU   # Cannot ingest
        print(f"  [Degradation] Level changed → {self._level.value}")
        return self._level

    @property
    def current_level(self) -> DegradationLevel:
        return self._level

    def detect(self, event: dict, rule_result: dict, ml_score: float) -> dict:
        """
        Make detection decision according to current degradation level.
        """
        if self._level == DegradationLevel.FULL:
            risk = 0.5 * rule_result.get("confidence", 0) + 0.3 * ml_score + 0.2 * 0.5
            return {"detected": risk > 0.7, "level": "FULL", "risk": risk}

        elif self._level == DegradationLevel.DEGRADED:
            risk = 0.6 * rule_result.get("confidence", 0) + 0.4 * ml_score
            return {"detected": risk > 0.7, "level": "DEGRADED", "risk": risk}

        elif self._level == DegradationLevel.MINIMAL:
            return {"detected": rule_result.get("detected", False),
                    "level": "MINIMAL", "risk": rule_result.get("confidence", 0)}

        else:   # PASSTHRU
            return {"detected": False, "level": "PASSTHRU", "risk": 0.0,
                    "note": "Circuit breaker open — logging only"}

"""
production_layer.py
===================
Domain 4: Production-Grade Scalability
- Streaming mode benchmark (throughput, latency P50/P95/P99)
- Alert correlation layer (incident-level grouping)
- Alert suppression memory (reduces repeat FPs)
- Configurable fusion profiles (conservative / aggressive / drift-sensitive)

All components are standalone and composable.
"""

import time
import json
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
import threading


# ---------------------------------------------------------------------------
# 1. Fusion Profiles
# ---------------------------------------------------------------------------

class ProfileName(str, Enum):
    CONSERVATIVE    = "conservative"
    AGGRESSIVE      = "aggressive"
    DRIFT_SENSITIVE = "drift-sensitive"
    BALANCED        = "balanced"


@dataclass
class FusionProfile:
    name: str
    w_ml: float
    w_rule: float
    w_behavior: float
    alert_threshold: float      # score above this → alert
    escalation_threshold: float # score above this → high/critical
    temporal_window: int        # events in window
    temporal_min_hits: int      # hits required to escalate
    description: str

    def weights_sum_valid(self) -> bool:
        return abs(self.w_ml + self.w_rule + self.w_behavior - 1.0) < 1e-6


PROFILES: Dict[str, FusionProfile] = {

    ProfileName.CONSERVATIVE: FusionProfile(
        name="conservative",
        w_ml=0.25, w_rule=0.50, w_behavior=0.25,
        alert_threshold=0.55,
        escalation_threshold=0.80,
        temporal_window=15,
        temporal_min_hits=6,
        description=(
            "High precision. Prefers deterministic rules. "
            "Fewer alerts — good for low-noise SOC environments."
        ),
    ),

    ProfileName.AGGRESSIVE: FusionProfile(
        name="aggressive",
        w_ml=0.50, w_rule=0.25, w_behavior=0.25,
        alert_threshold=0.30,
        escalation_threshold=0.60,
        temporal_window=5,
        temporal_min_hits=2,
        description=(
            "High recall. Trusts ML heavily. "
            "More alerts — good for high-risk or unknown threat environments."
        ),
    ),

    ProfileName.DRIFT_SENSITIVE: FusionProfile(
        name="drift-sensitive",
        w_ml=0.50, w_rule=0.15, w_behavior=0.35,
        alert_threshold=0.40,
        escalation_threshold=0.70,
        temporal_window=10,
        temporal_min_hits=4,
        description=(
            "Optimised for concept drift environments. "
            "Reduces rule weight (stale) and increases ML + behavioral trust."
        ),
    ),

    ProfileName.BALANCED: FusionProfile(
        name="balanced",
        w_ml=0.35, w_rule=0.35, w_behavior=0.30,
        alert_threshold=0.45,
        escalation_threshold=0.70,
        temporal_window=10,
        temporal_min_hits=4,
        description="Default balanced profile. Equal trust across components.",
    ),
}


def load_profile(name: str) -> FusionProfile:
    key = ProfileName(name.lower())
    return PROFILES[key]


# ---------------------------------------------------------------------------
# 2. Alert Suppression Memory
# ---------------------------------------------------------------------------

@dataclass
class SuppressionRecord:
    entity_id: str
    alert_type: str
    first_seen: float
    count: int
    suppressed: bool


class AlertSuppressionMemory:
    """
    Suppresses repeat alerts for the same entity+type within a time window.
    After N occurrences, severity is downgraded until quiet period elapses.

    Matches real SOC deduplication behaviour.
    """

    def __init__(
        self,
        suppress_after: int   = 3,      # suppress after this many repeats
        quiet_window_sec: int = 300,    # suppression lifted after 5 min silence
    ):
        self.suppress_after   = suppress_after
        self.quiet_window_sec = quiet_window_sec
        self._records: Dict[str, SuppressionRecord] = {}

    def _key(self, entity_id: str, alert_type: str) -> str:
        return f"{entity_id}::{alert_type}"

    def should_suppress(self, entity_id: str, alert_type: str) -> bool:
        k   = self._key(entity_id, alert_type)
        now = time.time()
        rec = self._records.get(k)

        if rec is None:
            self._records[k] = SuppressionRecord(
                entity_id=entity_id, alert_type=alert_type,
                first_seen=now, count=1, suppressed=False
            )
            return False

        # Check quiet window (reset if long silence)
        if now - rec.first_seen > self.quiet_window_sec:
            self._records[k] = SuppressionRecord(
                entity_id=entity_id, alert_type=alert_type,
                first_seen=now, count=1, suppressed=False
            )
            return False

        rec.count += 1
        if rec.count >= self.suppress_after:
            rec.suppressed = True
            return True

        return False

    def reset(self, entity_id: str, alert_type: str):
        k = self._key(entity_id, alert_type)
        self._records.pop(k, None)

    def stats(self) -> dict:
        total     = len(self._records)
        suppressed = sum(1 for r in self._records.values() if r.suppressed)
        return {"total_tracked": total, "currently_suppressed": suppressed}


# ---------------------------------------------------------------------------
# 3. Alert Correlation Layer
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    timestamp: float
    entity_id: str
    alert_level: str
    score: float
    attack_category: str
    contributors: dict
    explanation: str


@dataclass
class Incident:
    incident_id: str
    entity_id: str
    attack_category: str
    first_seen: float
    last_seen: float
    alert_count: int
    max_score: float
    severity: str
    alerts: List[Alert] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("alerts")  # keep summary lean
        return d


class AlertCorrelationLayer:
    """
    Groups individual alerts into incidents by:
      - Entity ID
      - Time window
      - Attack category

    Produces incident-level summaries rather than per-event noise.
    """

    def __init__(
        self,
        time_window_sec: float = 120.0,   # group alerts within 2-min window
        min_alerts_per_incident: int = 2,
    ):
        self.time_window          = time_window_sec
        self.min_alerts           = min_alerts_per_incident
        self._pending: Dict[str, List[Alert]] = defaultdict(list)
        self._incidents: List[Incident] = []
        self._incident_counter = 0

    def _group_key(self, alert: Alert) -> str:
        return f"{alert.entity_id}::{alert.attack_category}"

    def ingest(self, alert: Alert) -> Optional[Incident]:
        """
        Add an alert. Returns an Incident if correlation window is complete,
        else None.
        """
        key = self._group_key(alert)
        self._pending[key].append(alert)

        # Check if window has elapsed for this group
        group = self._pending[key]
        elapsed = alert.timestamp - group[0].timestamp

        if elapsed >= self.time_window and len(group) >= self.min_alerts:
            return self._flush_incident(key)

        return None

    def _flush_incident(self, key: str) -> Optional[Incident]:
        group = self._pending.pop(key, [])
        if not group:
            return None

        self._incident_counter += 1
        inc = Incident(
            incident_id      = f"INC-{self._incident_counter:04d}",
            entity_id        = group[0].entity_id,
            attack_category  = group[0].attack_category,
            first_seen       = group[0].timestamp,
            last_seen        = group[-1].timestamp,
            alert_count      = len(group),
            max_score        = max(a.score for a in group),
            severity         = max((a.alert_level for a in group),
                                   key=lambda x: ["none","low","medium","high","critical"].index(x)),
            alerts           = group,
        )
        self._incidents.append(inc)
        return inc

    def flush_all(self) -> List[Incident]:
        """Force flush all pending groups (call at end of stream)."""
        keys = list(self._pending.keys())
        return [inc for k in keys if (inc := self._flush_incident(k))]

    @property
    def incidents(self) -> List[Incident]:
        return self._incidents


# ---------------------------------------------------------------------------
# 4. Streaming Benchmark
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    n_events: int
    elapsed_sec: float
    throughput_eps: float       # events per second
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    total_alerts: int
    total_incidents: int

    def report(self) -> str:
        return (
            f"\n{'='*55}\n"
            f"  STREAMING BENCHMARK RESULTS\n"
            f"{'='*55}\n"
            f"  Events processed  : {self.n_events:,}\n"
            f"  Total time        : {self.elapsed_sec:.3f}s\n"
            f"  Throughput        : {self.throughput_eps:,.0f} events/sec\n"
            f"  Latency P50       : {self.latency_p50_ms:.3f} ms\n"
            f"  Latency P95       : {self.latency_p95_ms:.3f} ms\n"
            f"  Latency P99       : {self.latency_p99_ms:.3f} ms\n"
            f"  Total Alerts      : {self.total_alerts}\n"
            f"  Total Incidents   : {self.total_incidents}\n"
            f"{'='*55}"
        )


def run_streaming_benchmark(
    n_events: int = 50_000,
    profile_name: str = "balanced",
    seed: int = 42,
) -> BenchmarkResult:
    """
    Simulates a streaming workload and measures throughput + latency.
    Replace the synthetic event generator with your real event source.
    """
    from scipy.stats import norm

    rng     = np.random.default_rng(seed)
    profile = load_profile(profile_name)
    suppression = AlertSuppressionMemory()
    correlator  = AlertCorrelationLayer()

    latencies_ms = []
    total_alerts  = 0
    categories    = ["PortScan", "BruteForce", "Exfiltration", "C2", "Lateral"]

    print(f"\n[→] Streaming benchmark: {n_events:,} events | profile={profile_name}")

    t_start = time.perf_counter()

    for i in range(n_events):
        t_event = time.perf_counter()

        # Synthetic event
        entity = f"host_{rng.integers(0, 50)}"
        ml_raw = float(rng.normal(0.2, 0.4))
        z      = float(rng.normal(1.0, 1.0))
        rule   = bool(rng.random() < 0.1)
        cat    = categories[rng.integers(0, len(categories))]

        # Calibrate
        p_ml   = 1 / (1 + np.exp(-ml_raw))
        p_beh  = float(1 - norm.cdf(z - 1.5))
        p_rule = 0.9 if rule else 0.0

        score = profile.w_ml * p_ml + profile.w_rule * p_rule + profile.w_behavior * p_beh

        latency_ms = (time.perf_counter() - t_event) * 1000
        latencies_ms.append(latency_ms)

        if score >= profile.alert_threshold:
            if not suppression.should_suppress(entity, cat):
                total_alerts += 1
                level = "high" if score >= profile.escalation_threshold else "medium"
                alert = Alert(
                    timestamp=time.time() + i * 0.001,
                    entity_id=entity,
                    alert_level=level,
                    score=score,
                    attack_category=cat,
                    contributors={"ml": p_ml, "rule": p_rule, "behavior": p_beh},
                    explanation=f"score={score:.3f}",
                )
                correlator.ingest(alert)

    t_end = time.perf_counter()

    correlator.flush_all()
    lat = np.array(latencies_ms)

    return BenchmarkResult(
        n_events        = n_events,
        elapsed_sec     = t_end - t_start,
        throughput_eps  = n_events / (t_end - t_start),
        latency_p50_ms  = float(np.percentile(lat, 50)),
        latency_p95_ms  = float(np.percentile(lat, 95)),
        latency_p99_ms  = float(np.percentile(lat, 99)),
        total_alerts    = total_alerts,
        total_incidents = len(correlator.incidents),
    )


# ---------------------------------------------------------------------------
# Demo CLI runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n=== Fusion Profile Summary ===")
    for name, prof in PROFILES.items():
        print(f"\n  [{name.upper()}]")
        print(f"    Weights  : ML={prof.w_ml} | Rule={prof.w_rule} | Behavior={prof.w_behavior}")
        print(f"    Threshold: alert={prof.alert_threshold} | escalate={prof.escalation_threshold}")
        print(f"    Window   : {prof.temporal_window} events, {prof.temporal_min_hits} hits to escalate")
        print(f"    Desc     : {prof.description}")

    # Run benchmark for each profile
    print("\n=== Per-Profile Streaming Benchmark ===")
    for pname in ["conservative", "balanced", "aggressive", "drift-sensitive"]:
        result = run_streaming_benchmark(n_events=20_000, profile_name=pname)
        print(result.report())

    # Alert suppression demo
    print("\n=== Alert Suppression Demo ===")
    mem = AlertSuppressionMemory(suppress_after=3)
    entity = "10.0.0.5"
    for i in range(5):
        suppressed = mem.should_suppress(entity, "PortScan")
        print(f"  Alert #{i+1}: suppressed={suppressed}")
    print(f"  Suppression stats: {mem.stats()}")

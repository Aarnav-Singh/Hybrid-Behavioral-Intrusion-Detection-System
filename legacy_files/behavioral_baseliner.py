"""
baseliner/behavioral_baseliner.py
==================================
Per-Entity Behavioral Baseline Engine.

This is NOT the same as anomaly detection.

Anomaly detection asks: "Is this event unusual in the global dataset?"
Behavioral baselining asks: "Is this event unusual for *this specific entity*?"

Each entity (IP, user, process, service) maintains its own statistical
profile. Deviation from that profile produces a behavioral_score that
feeds the fusion engine.

Key capabilities:
  - Per-entity rolling statistics (mean, std, percentiles)
  - Time-of-day aware profiling (day vs. night pattern separation)
  - Exponential moving average for gradual drift tolerance
  - Spike detection using z-score and IQR methods
  - Configurable warmup period before scoring is trusted
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WARMUP_EVENTS = 30          # minimum events before baseline is trusted
MAX_HISTORY = 1000          # rolling window per feature per entity
EMA_ALPHA = 0.05            # smoothing factor for exponential moving average
ZSCORE_THRESHOLD = 3.0      # standard deviations for spike detection
TIME_BUCKETS = 4            # time-of-day segments (0=00-06, 1=06-12, 2=12-18, 3=18-24)


# ---------------------------------------------------------------------------
# Feature Definitions
# ---------------------------------------------------------------------------

BEHAVIORAL_FEATURES = [
    "bytes_sent",
    "bytes_recv",
    "conn_duration",
    "conn_count_1min",
    "unique_ports_1min",
    "unique_dsts_1min",
    "failed_auth_count",
    "privilege_escalations",
    "process_spawns",
]


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class EntityEvent:
    """A single observed event for a given entity."""
    entity_id: str
    timestamp: float
    features: Dict[str, float]
    time_bucket: int = field(init=False)

    def __post_init__(self):
        hour = (self.timestamp % 86400) / 3600   # hours since midnight (approx)
        self.time_bucket = int(hour / (24 / TIME_BUCKETS)) % TIME_BUCKETS


@dataclass
class FeatureStats:
    """Rolling statistical profile for a single feature of a single entity."""
    values: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    ema: float = 0.0
    event_count: int = 0

    def update(self, value: float):
        self.values.append(value)
        self.event_count += 1
        if self.event_count == 1:
            self.ema = value
        else:
            self.ema = EMA_ALPHA * value + (1 - EMA_ALPHA) * self.ema

    @property
    def mean(self) -> float:
        return float(np.mean(self.values)) if self.values else 0.0

    @property
    def std(self) -> float:
        return float(np.std(self.values)) if len(self.values) > 1 else 1e-6

    @property
    def p95(self) -> float:
        return float(np.percentile(list(self.values), 95)) if self.values else 0.0

    @property
    def p99(self) -> float:
        return float(np.percentile(list(self.values), 99)) if self.values else 0.0

    def zscore(self, value: float) -> float:
        std = self.std
        if std < 1e-9:
            return 0.0
        return abs(value - self.mean) / std

    def is_trusted(self) -> bool:
        return self.event_count >= WARMUP_EVENTS


@dataclass
class EntityProfile:
    """
    Complete behavioral profile for a single entity.
    Tracks per-feature stats, optionally split by time-of-day bucket.
    """
    entity_id: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_events: int = 0

    # feature_stats[feature][time_bucket] = FeatureStats
    feature_stats: Dict[str, Dict[int, FeatureStats]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(FeatureStats))
    )

    def update(self, event: EntityEvent):
        self.last_seen = event.timestamp
        self.total_events += 1
        for feature, value in event.features.items():
            self.feature_stats[feature][event.time_bucket].update(value)
            # Also update global bucket (bucket -1)
            self.feature_stats[feature][-1].update(value)

    def get_stats(self, feature: str, time_bucket: int = -1) -> FeatureStats:
        return self.feature_stats[feature][time_bucket]

    def is_warmed_up(self) -> bool:
        """Profile is trusted when at least one feature has enough history."""
        for feature in self.feature_stats:
            if self.feature_stats[feature][-1].is_trusted():
                return True
        return False


# ---------------------------------------------------------------------------
# Behavioral Baseliner
# ---------------------------------------------------------------------------

class BehavioralBaseliner:
    """
    Maintains per-entity behavioral profiles and scores new events
    against those profiles.

    Usage:
        baseliner = BehavioralBaseliner()

        # During normal operation (or training):
        event = EntityEvent(
            entity_id="192.168.1.10",
            timestamp=time.time(),
            features={"bytes_sent": 1200, "conn_count_1min": 5, ...}
        )
        baseliner.ingest(event)   # update profile

        # Scoring a new event:
        score, detail = baseliner.score(event)
        # score is in [0.0, 1.0]
    """

    def __init__(
        self,
        zscore_threshold: float = ZSCORE_THRESHOLD,
        use_time_buckets: bool = True,
        max_entities: int = 50_000,
    ):
        self.zscore_threshold = zscore_threshold
        self.use_time_buckets = use_time_buckets
        self.max_entities = max_entities
        self._profiles: Dict[str, EntityProfile] = {}
        self._eviction_queue: deque = deque()   # for LRU eviction

        logger.info(
            f"BehavioralBaseliner initialized | "
            f"zscore_threshold={zscore_threshold} | "
            f"time_buckets={use_time_buckets}"
        )

    # ------------------------------------------------------------------
    # Profile Management
    # ------------------------------------------------------------------

    def _get_or_create_profile(self, entity_id: str) -> EntityProfile:
        if entity_id not in self._profiles:
            if len(self._profiles) >= self.max_entities:
                self._evict_oldest()
            self._profiles[entity_id] = EntityProfile(entity_id=entity_id)
            self._eviction_queue.append(entity_id)
            logger.debug(f"New entity profile created: {entity_id}")
        return self._profiles[entity_id]

    def _evict_oldest(self):
        while self._eviction_queue:
            candidate = self._eviction_queue.popleft()
            if candidate in self._profiles:
                del self._profiles[candidate]
                logger.debug(f"Evicted profile: {candidate}")
                return

    def ingest(self, event: EntityEvent):
        """Update baseline profile for this entity without scoring."""
        profile = self._get_or_create_profile(event.entity_id)
        profile.update(event)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, event: EntityEvent) -> Tuple[float, dict]:
        """
        Score an event against the entity's baseline.

        Returns:
            (behavioral_score, detail_dict)
            behavioral_score in [0.0, 1.0]
        """
        profile = self._get_or_create_profile(event.entity_id)

        if not profile.is_warmed_up():
            # Not enough data yet — return neutral score
            logger.debug(f"Entity {event.entity_id} still in warmup, returning neutral score")
            profile.update(event)
            return 0.2, {"status": "warmup", "events_seen": profile.total_events}

        bucket = event.time_bucket if self.use_time_buckets else -1
        feature_scores = {}
        raw_zscores = {}

        for feature, value in event.features.items():
            stats = profile.get_stats(feature, bucket)
            if not stats.is_trusted():
                # Fall back to global bucket stats
                stats = profile.get_stats(feature, -1)
            if not stats.is_trusted():
                continue

            z = stats.zscore(value)
            raw_zscores[feature] = round(z, 4)

            # Sigmoid normalisation: maps z-score to [0, 1]
            # z=3 → ~0.95, z=1 → ~0.73, z=0 → 0.5
            # We shift so z=0 (perfectly normal) → 0.0
            normalised = self._sigmoid(z) * 2 - 1   # -1 to 1
            normalised = max(0.0, normalised)         # 0 to 1

            # Boost score for features known to indicate attacks
            weight = self._feature_weight(feature)
            feature_scores[feature] = min(1.0, normalised * weight)

        if not feature_scores:
            profile.update(event)
            return 0.2, {"status": "insufficient_features"}

        # Aggregate: use 80th percentile of feature scores
        # (not mean — we don't want one high-score feature diluted by many normal ones)
        scores_array = sorted(feature_scores.values())
        p80_idx = int(0.80 * len(scores_array))
        behavioral_score = scores_array[min(p80_idx, len(scores_array) - 1)]

        # Update profile after scoring (online learning)
        profile.update(event)

        detail = {
            "status": "scored",
            "entity_id": event.entity_id,
            "total_events": profile.total_events,
            "time_bucket": bucket,
            "behavioral_score": round(behavioral_score, 4),
            "feature_scores": {k: round(v, 4) for k, v in feature_scores.items()},
            "raw_zscores": raw_zscores,
            "top_anomalous_feature": max(feature_scores, key=feature_scores.get)
                                     if feature_scores else None,
        }

        return round(behavioral_score, 4), detail

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1.0 / (1.0 + math.exp(-x))

    @staticmethod
    def _feature_weight(feature: str) -> float:
        """
        Domain knowledge weights — some features are stronger indicators
        of attack behavior than others.
        """
        weights = {
            "failed_auth_count":      1.8,
            "privilege_escalations":  2.0,
            "unique_dsts_1min":       1.5,
            "unique_ports_1min":      1.4,
            "process_spawns":         1.6,
            "conn_count_1min":        1.2,
            "bytes_sent":             1.0,
            "bytes_recv":             1.0,
            "conn_duration":          0.9,
        }
        return weights.get(feature, 1.0)

    # ------------------------------------------------------------------
    # Inspection & Persistence
    # ------------------------------------------------------------------

    def get_profile_summary(self, entity_id: str) -> Optional[dict]:
        if entity_id not in self._profiles:
            return None
        p = self._profiles[entity_id]
        summary = {
            "entity_id": entity_id,
            "total_events": p.total_events,
            "is_warmed_up": p.is_warmed_up(),
            "features": {},
        }
        for feature in p.feature_stats:
            gs = p.feature_stats[feature][-1]
            summary["features"][feature] = {
                "mean": round(gs.mean, 4),
                "std": round(gs.std, 4),
                "p95": round(gs.p95, 4),
                "p99": round(gs.p99, 4),
                "ema": round(gs.ema, 4),
                "count": gs.event_count,
            }
        return summary

    def list_entities(self) -> List[str]:
        return list(self._profiles.keys())

    def entity_count(self) -> int:
        return len(self._profiles)

    def export_profiles(self) -> dict:
        """Export all profiles for persistence (JSON-serialisable)."""
        export = {}
        for eid, profile in self._profiles.items():
            export[eid] = self.get_profile_summary(eid)
        return export


# ---------------------------------------------------------------------------
# Quick sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import random

    rng = random.Random(42)
    baseliner = BehavioralBaseliner()

    entity = "192.168.1.50"
    base_time = time.time()

    print("=== Building baseline (50 normal events) ===")
    for i in range(50):
        event = EntityEvent(
            entity_id=entity,
            timestamp=base_time + i * 60,
            features={
                "bytes_sent":        rng.gauss(5000, 500),
                "bytes_recv":        rng.gauss(12000, 1200),
                "conn_count_1min":   rng.gauss(8, 2),
                "unique_ports_1min": rng.gauss(3, 1),
                "unique_dsts_1min":  rng.gauss(2, 0.5),
                "failed_auth_count": rng.gauss(0.1, 0.1),
                "conn_duration":     rng.gauss(30, 10),
                "privilege_escalations": 0,
                "process_spawns":    rng.gauss(2, 1),
            },
        )
        baseliner.ingest(event)

    print(f"Profile summary:\n{baseliner.get_profile_summary(entity)}\n")

    print("=== Scoring a NORMAL event ===")
    normal_event = EntityEvent(
        entity_id=entity,
        timestamp=base_time + 55 * 60,
        features={
            "bytes_sent": 4800, "bytes_recv": 11500, "conn_count_1min": 7,
            "unique_ports_1min": 3, "unique_dsts_1min": 2, "failed_auth_count": 0,
            "conn_duration": 28, "privilege_escalations": 0, "process_spawns": 2,
        },
    )
    score, detail = baseliner.score(normal_event)
    print(f"Score: {score} | Detail: {detail}\n")

    print("=== Scoring an ATTACK event (port scan) ===")
    attack_event = EntityEvent(
        entity_id=entity,
        timestamp=base_time + 60 * 60,
        features={
            "bytes_sent": 4900, "bytes_recv": 800, "conn_count_1min": 350,
            "unique_ports_1min": 280, "unique_dsts_1min": 90, "failed_auth_count": 45,
            "conn_duration": 0.3, "privilege_escalations": 2, "process_spawns": 15,
        },
    )
    score, detail = baseliner.score(attack_event)
    print(f"Score: {score} | Detail: {detail}")

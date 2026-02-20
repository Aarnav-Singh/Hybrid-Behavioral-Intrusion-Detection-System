"""
drift/drift_simulator.py
=========================
Concept Drift Simulator for Hybrid IDS Evaluation.

Simulates three types of concept drift that occur in real network environments:

  1. SUDDEN DRIFT   — an abrupt distribution change (e.g. new device, policy change)
  2. GRADUAL DRIFT  — slow distribution shift over time (e.g. business growth)
  3. RECURRING DRIFT — periodic pattern (e.g. day/night traffic, weekly batches)

Why this matters for the "Adaptive" in Hybrid Behavioral IDS:
  - Static models degrade under drift — recall drops silently
  - The behavioral baseliner's EMA provides partial resistance
  - This simulator lets you PROVE that your system handles drift better
    than a static Isolation Forest baseline

Usage:
    sim = DriftSimulator(seed=42)
    stream = sim.generate_stream(n_events=2000, drift_type="gradual")
    for event, label in stream:
        score, _ = baseliner.score(event)
        ...
"""

from __future__ import annotations

import logging
import math
import random
import time
from dataclasses import dataclass
from typing import Generator, Iterator, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class SimulatedEvent:
    """A generated event with ground truth label."""
    entity_id: str
    timestamp: float
    features: dict
    is_attack: bool
    attack_type: Optional[str]
    drift_phase: Optional[str]   # "pre_drift" | "during_drift" | "post_drift"


# ---------------------------------------------------------------------------
# Traffic Profiles
# ---------------------------------------------------------------------------

class TrafficProfile:
    """
    Defines a statistical profile for generating synthetic traffic.
    Each field is (mean, std) for a Gaussian distribution.
    """

    NORMAL_ENTERPRISE = {
        "bytes_sent":        (5_000,   800),
        "bytes_recv":        (12_000,  2_000),
        "conn_count_1min":   (8,       2),
        "unique_ports_1min": (3,       1),
        "unique_dsts_1min":  (2,       0.5),
        "failed_auth_count": (0.1,     0.15),
        "conn_duration":     (30,      10),
        "privilege_escalations": (0,   0.05),
        "process_spawns":    (2,       1),
    }

    NORMAL_SERVER = {
        "bytes_sent":        (50_000,  5_000),
        "bytes_recv":        (2_000,   500),
        "conn_count_1min":   (80,      15),
        "unique_ports_1min": (5,       2),
        "unique_dsts_1min":  (30,      8),
        "failed_auth_count": (0.5,     0.3),
        "conn_duration":     (8,       3),
        "privilege_escalations": (0,   0.02),
        "process_spawns":    (5,       2),
    }

    # Post-drift profile: after company expansion, higher traffic baseline
    DRIFTED_ENTERPRISE = {
        "bytes_sent":        (15_000,  2_000),
        "bytes_recv":        (35_000,  5_000),
        "conn_count_1min":   (25,      5),
        "unique_ports_1min": (8,       2),
        "unique_dsts_1min":  (6,       1.5),
        "failed_auth_count": (0.2,     0.2),
        "conn_duration":     (45,      12),
        "privilege_escalations": (0,   0.05),
        "process_spawns":    (4,       1.5),
    }


ATTACK_PROFILES = {
    "port_scan": {
        "bytes_sent":        (200,    30),
        "bytes_recv":        (100,    20),
        "conn_count_1min":   (350,    50),
        "unique_ports_1min": (280,    40),
        "unique_dsts_1min":  (90,     15),
        "failed_auth_count": (45,     8),
        "conn_duration":     (0.2,    0.05),
        "privilege_escalations": (0,  0.1),
        "process_spawns":    (2,      1),
    },
    "brute_force": {
        "bytes_sent":        (800,    100),
        "bytes_recv":        (400,    80),
        "conn_count_1min":   (120,    20),
        "unique_ports_1min": (2,      1),
        "unique_dsts_1min":  (1,      0.3),
        "failed_auth_count": (85,     10),
        "conn_duration":     (2,      0.5),
        "privilege_escalations": (0,  0.2),
        "process_spawns":    (1,      0.5),
    },
    "data_exfil": {
        "bytes_sent":        (150_000_000, 20_000_000),
        "bytes_recv":        (5_000,       1_000),
        "conn_count_1min":   (3,           1),
        "unique_ports_1min": (1,           0.3),
        "unique_dsts_1min":  (1,           0.3),
        "failed_auth_count": (0,           0.1),
        "conn_duration":     (3600,        600),
        "privilege_escalations": (1,       0.3),
        "process_spawns":    (1,           0.5),
    },
    "lateral_movement": {
        "bytes_sent":        (3_000,   500),
        "bytes_recv":        (2_000,   400),
        "conn_count_1min":   (40,      8),
        "unique_ports_1min": (12,      3),
        "unique_dsts_1min":  (18,      4),
        "failed_auth_count": (12,      3),
        "conn_duration":     (5,       2),
        "privilege_escalations": (2,   0.5),
        "process_spawns":    (8,       3),
    },
    "c2_beacon": {
        "bytes_sent":        (150,     20),
        "bytes_recv":        (80,      15),
        "conn_count_1min":   (60,      5),
        "unique_ports_1min": (1,       0.2),
        "unique_dsts_1min":  (1,       0.2),
        "failed_auth_count": (0,       0.1),
        "conn_duration":     (0.5,     0.1),
        "privilege_escalations": (0,   0.1),
        "process_spawns":    (1,       0.3),
    },
}


# ---------------------------------------------------------------------------
# Drift Simulator
# ---------------------------------------------------------------------------

class DriftSimulator:
    """
    Generates synthetic event streams with controllable concept drift.

    Parameters:
        seed: random seed for reproducibility
        attack_ratio: fraction of events that are attacks (default 5%)
        n_entities: number of simulated entities (IPs/users)
    """

    def __init__(
        self,
        seed: int = 42,
        attack_ratio: float = 0.05,
        n_entities: int = 20,
    ):
        self.rng = np.random.default_rng(seed)
        self.py_rng = random.Random(seed)
        self.attack_ratio = attack_ratio
        self.entities = [f"192.168.1.{10 + i}" for i in range(n_entities)]
        self._base_time = time.time()

    # ------------------------------------------------------------------
    # Stream Generators
    # ------------------------------------------------------------------

    def generate_stream(
        self,
        n_events: int,
        drift_type: str = "none",    # "none" | "sudden" | "gradual" | "recurring"
        drift_start: float = 0.4,    # fraction of stream where drift begins
        drift_end: float = 0.6,      # fraction of stream where drift completes
    ) -> List[SimulatedEvent]:
        """
        Generate a labelled stream of events with optional drift.

        Returns:
            List of (SimulatedEvent) in order
        """
        if drift_type not in ("none", "sudden", "gradual", "recurring"):
            raise ValueError(f"Unknown drift_type: {drift_type}")

        stream = []
        attack_types = list(ATTACK_PROFILES.keys())

        logger.info(
            f"Generating {n_events} events | drift={drift_type} | "
            f"attack_ratio={self.attack_ratio}"
        )

        for i in range(n_events):
            progress = i / n_events
            timestamp = self._base_time + i * 10   # 10-second intervals

            # Determine drift phase
            if progress < drift_start:
                drift_phase = "pre_drift"
            elif progress < drift_end:
                drift_phase = "during_drift"
            else:
                drift_phase = "post_drift"

            # Determine if this event is an attack
            is_attack = self.py_rng.random() < self.attack_ratio
            attack_type = self.py_rng.choice(attack_types) if is_attack else None

            # Select entity
            entity_id = self.py_rng.choice(self.entities)

            # Generate features
            if is_attack:
                features = self._sample_attack(attack_type)
            else:
                features = self._sample_normal(drift_type, progress, drift_start, drift_end)

            features = {k: max(0.0, float(v)) for k, v in features.items()}

            stream.append(SimulatedEvent(
                entity_id=entity_id,
                timestamp=timestamp,
                features=features,
                is_attack=is_attack,
                attack_type=attack_type,
                drift_phase=drift_phase,
            ))

        attack_count = sum(1 for e in stream if e.is_attack)
        logger.info(
            f"Stream generated: {n_events} events, "
            f"{attack_count} attacks ({100*attack_count/n_events:.1f}%)"
        )
        return stream

    def _sample_normal(
        self,
        drift_type: str,
        progress: float,
        drift_start: float,
        drift_end: float,
    ) -> dict:
        """Sample a normal event, applying drift if configured."""

        if drift_type == "none" or progress < drift_start:
            profile = TrafficProfile.NORMAL_ENTERPRISE
            return self._sample_profile(profile)

        elif drift_type == "sudden":
            # Abrupt switch at drift_start
            profile = TrafficProfile.DRIFTED_ENTERPRISE
            return self._sample_profile(profile)

        elif drift_type == "gradual":
            # Linear interpolation between profiles
            if progress <= drift_end:
                t = (progress - drift_start) / (drift_end - drift_start)
            else:
                t = 1.0
            return self._interpolate_profiles(
                TrafficProfile.NORMAL_ENTERPRISE,
                TrafficProfile.DRIFTED_ENTERPRISE,
                t,
            )

        elif drift_type == "recurring":
            # Oscillates between two profiles based on hour-of-day simulation
            cycle = math.sin(2 * math.pi * progress * 5)   # 5 cycles over stream
            t = (cycle + 1) / 2   # 0 to 1
            return self._interpolate_profiles(
                TrafficProfile.NORMAL_ENTERPRISE,
                TrafficProfile.NORMAL_SERVER,
                t,
            )

        return self._sample_profile(TrafficProfile.NORMAL_ENTERPRISE)

    def _sample_profile(self, profile: dict) -> dict:
        return {
            feature: float(self.rng.normal(mean, std))
            for feature, (mean, std) in profile.items()
        }

    def _interpolate_profiles(
        self,
        profile_a: dict,
        profile_b: dict,
        t: float,
    ) -> dict:
        """Linear interpolation between two profiles at factor t ∈ [0, 1]."""
        result = {}
        for feature in profile_a:
            mean_a, std_a = profile_a[feature]
            mean_b, std_b = profile_b[feature]
            mean = mean_a + t * (mean_b - mean_a)
            std  = std_a  + t * (std_b  - std_a)
            result[feature] = float(self.rng.normal(mean, std))
        return result

    def _sample_attack(self, attack_type: str) -> dict:
        profile = ATTACK_PROFILES[attack_type]
        return {
            feature: float(self.rng.normal(mean, std))
            for feature, (mean, std) in profile.items()
        }

    # ------------------------------------------------------------------
    # Analysis Helpers
    # ------------------------------------------------------------------

    def compute_stream_stats(self, stream: List[SimulatedEvent]) -> dict:
        """Compute descriptive stats over a generated stream."""
        n = len(stream)
        attacks = [e for e in stream if e.is_attack]
        normals = [e for e in stream if not e.is_attack]

        phases = {"pre_drift": 0, "during_drift": 0, "post_drift": 0}
        for e in stream:
            if e.drift_phase in phases:
                phases[e.drift_phase] += 1

        attack_types = {}
        for e in attacks:
            attack_types[e.attack_type] = attack_types.get(e.attack_type, 0) + 1

        return {
            "total_events": n,
            "attack_events": len(attacks),
            "normal_events": len(normals),
            "attack_ratio": round(len(attacks) / n, 4),
            "phase_counts": phases,
            "attack_type_distribution": attack_types,
        }


# ---------------------------------------------------------------------------
# Quick sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sim = DriftSimulator(seed=42, attack_ratio=0.05)

    for drift_type in ["none", "sudden", "gradual", "recurring"]:
        stream = sim.generate_stream(1000, drift_type=drift_type)
        stats = sim.compute_stream_stats(stream)
        print(f"\n=== Drift: {drift_type} ===")
        print(f"  Total: {stats['total_events']} | Attacks: {stats['attack_events']} ({100*stats['attack_ratio']:.1f}%)")
        print(f"  Phase counts: {stats['phase_counts']}")
        print(f"  Attack types: {stats['attack_type_distribution']}")

        # Show feature shift for gradual drift
        if drift_type == "gradual":
            pre = [e.features["bytes_sent"] for e in stream if e.drift_phase == "pre_drift" and not e.is_attack]
            post = [e.features["bytes_sent"] for e in stream if e.drift_phase == "post_drift" and not e.is_attack]
            if pre and post:
                import numpy as np
                print(f"  bytes_sent pre-drift mean:  {np.mean(pre):.0f}")
                print(f"  bytes_sent post-drift mean: {np.mean(post):.0f}")

"""
detectors/ml_detector.py
=========================
ML-based Anomaly Detector using Isolation Forest.

Produces ml_score in [0.0, 1.0] for use in the fusion engine.

Key design decisions:
  - Isolation Forest is chosen for its low memory footprint, fast inference,
    and effectiveness on network traffic without needing labelled attack data.
  - Score normalisation maps sklearn's raw anomaly score (negative, unbounded)
    to a clean probability-like value in [0, 1].
  - Online partial_fit capability via incremental updates using a buffer.
  - Supports saving/loading trained models for production deployment.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "bytes_sent",
    "bytes_recv",
    "conn_duration",
    "conn_count_1min",
    "unique_ports_1min",
    "unique_dsts_1min",
    "failed_auth_count",
    "privilege_escalations",
    "process_spawns",
    # Derived features
    "bytes_ratio",        # bytes_sent / (bytes_recv + 1)
    "port_diversity",     # unique_ports / conn_count
]


def engineer_features(raw: Dict[str, float]) -> np.ndarray:
    """
    Convert a raw feature dict to the final feature vector.
    Computes derived features and returns a 1D numpy array.
    """
    bytes_sent = raw.get("bytes_sent", 0)
    bytes_recv = raw.get("bytes_recv", 0)
    conn_count = max(raw.get("conn_count_1min", 1), 1)
    unique_ports = raw.get("unique_ports_1min", 0)

    derived = {
        "bytes_ratio":    bytes_sent / (bytes_recv + 1),
        "port_diversity": unique_ports / conn_count,
    }

    vector = []
    for col in FEATURE_COLUMNS:
        val = raw.get(col) if col in raw else derived.get(col, 0.0)
        vector.append(float(val if val is not None else 0.0))

    return np.array(vector, dtype=np.float32)


# ---------------------------------------------------------------------------
# ML Detector
# ---------------------------------------------------------------------------

class MLAnomalyDetector:
    """
    Isolation Forest-based anomaly detector.

    Produces a normalised ml_score in [0.0, 1.0] representing
    anomaly probability. This score feeds into the HybridFusionEngine.

    Usage:
        detector = MLAnomalyDetector(contamination=0.05)
        detector.fit(normal_training_data)   # list of feature dicts
        score, meta = detector.score_event(event_features)
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        random_state: int = 42,
        buffer_size: int = 500,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.buffer_size = buffer_size

        self._model: Optional[IsolationForest] = None
        self._scaler = StandardScaler()
        self._is_fitted = False
        self._score_buffer: List[float] = []   # for online calibration
        self._update_buffer: List[np.ndarray] = []

        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )

        logger.info(
            f"MLAnomalyDetector initialized | "
            f"contamination={contamination} | n_estimators={n_estimators}"
        )

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, training_events: List[Dict[str, float]]) -> "MLAnomalyDetector":
        """
        Train on a list of feature dicts representing normal behaviour.
        The training data should be predominantly benign traffic.
        """
        if len(training_events) < 50:
            raise ValueError(f"Need at least 50 training events, got {len(training_events)}")

        X = np.stack([engineer_features(e) for e in training_events])
        X = self._scaler.fit_transform(X)
        self._model.fit(X)
        self._is_fitted = True

        # Calibrate score boundaries from training set
        raw_scores = self._model.score_samples(X)
        self._score_min = float(np.percentile(raw_scores, 1))
        self._score_max = float(np.percentile(raw_scores, 99))

        logger.info(
            f"Model fitted on {len(training_events)} events | "
            f"score range [{self._score_min:.4f}, {self._score_max:.4f}]"
        )
        return self

    def partial_update(self, new_events: List[Dict[str, float]], force: bool = False):
        """
        Buffer new events and retrain when buffer is full.
        This provides approximate online learning — Isolation Forest
        does not support true incremental training.
        """
        for e in new_events:
            self._update_buffer.append(engineer_features(e))

        if len(self._update_buffer) >= self.buffer_size or force:
            logger.info(f"Retraining on {len(self._update_buffer)} buffered events")
            X_new = np.stack(self._update_buffer)
            X_new = self._scaler.transform(X_new)
            self._model.fit(X_new)
            raw_scores = self._model.score_samples(X_new)
            self._score_min = float(np.percentile(raw_scores, 1))
            self._score_max = float(np.percentile(raw_scores, 99))
            self._update_buffer.clear()

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_event(self, features: Dict[str, float]) -> Tuple[float, dict]:
        """
        Score a single event.

        Returns:
            (ml_score, meta_dict)
            ml_score in [0.0, 1.0]
        """
        if not self._is_fitted:
            raise RuntimeError("Model not fitted. Call fit() first.")

        x = engineer_features(features).reshape(1, -1)
        x_scaled = self._scaler.transform(x)

        raw_score = float(self._model.score_samples(x_scaled)[0])
        ml_score = self._normalise_score(raw_score)

        is_anomaly_raw = bool(self._model.predict(x_scaled)[0] == -1)

        meta = {
            "raw_if_score": round(raw_score, 6),
            "ml_score": round(ml_score, 4),
            "is_anomaly_raw": is_anomaly_raw,
            "feature_vector": {
                col: round(float(v), 4)
                for col, v in zip(FEATURE_COLUMNS, x[0])
            },
        }

        return round(ml_score, 4), meta

    def _normalise_score(self, raw: float) -> float:
        """
        Map sklearn's raw anomaly score (higher = more normal, unbounded)
        to [0, 1] where 1 = highly anomalous.

        sklearn returns negative scores for anomalies.
        We invert and clip to [0, 1].
        """
        if not hasattr(self, "_score_min"):
            # Fallback if not calibrated
            return float(np.clip(-raw / 0.5, 0.0, 1.0))

        score_range = self._score_max - self._score_min
        if score_range < 1e-9:
            return 0.5
        normalised = (self._score_max - raw) / score_range
        return float(np.clip(normalised, 0.0, 1.0))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str):
        payload = {
            "model": self._model,
            "scaler": self._scaler,
            "score_min": getattr(self, "_score_min", None),
            "score_max": getattr(self, "_score_max", None),
            "is_fitted": self._is_fitted,
            "config": {
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
            },
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(payload, f)
        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: str) -> "MLAnomalyDetector":
        with open(path, "rb") as f:
            payload = pickle.load(f)
        cfg = payload["config"]
        instance = cls(
            contamination=cfg["contamination"],
            n_estimators=cfg["n_estimators"],
        )
        instance._model = payload["model"]
        instance._scaler = payload["scaler"]
        instance._is_fitted = payload["is_fitted"]
        if payload["score_min"] is not None:
            instance._score_min = payload["score_min"]
            instance._score_max = payload["score_max"]
        logger.info(f"Model loaded from {path}")
        return instance


# ---------------------------------------------------------------------------
# Quick sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import random

    rng = random.Random(42)

    def gen_normal():
        return {
            "bytes_sent":        rng.gauss(5000, 500),
            "bytes_recv":        rng.gauss(12000, 1200),
            "conn_count_1min":   max(0, rng.gauss(8, 2)),
            "unique_ports_1min": max(0, rng.gauss(3, 1)),
            "unique_dsts_1min":  max(0, rng.gauss(2, 0.5)),
            "failed_auth_count": max(0, rng.gauss(0.1, 0.1)),
            "conn_duration":     max(0, rng.gauss(30, 10)),
            "privilege_escalations": 0,
            "process_spawns":    max(0, rng.gauss(2, 1)),
        }

    def gen_attack():
        return {
            "bytes_sent": rng.gauss(200, 20),
            "bytes_recv": rng.gauss(100, 10),
            "conn_count_1min": rng.gauss(400, 50),
            "unique_ports_1min": rng.gauss(350, 40),
            "unique_dsts_1min": rng.gauss(80, 10),
            "failed_auth_count": rng.gauss(50, 5),
            "conn_duration": rng.gauss(0.2, 0.05),
            "privilege_escalations": rng.gauss(3, 1),
            "process_spawns": rng.gauss(20, 5),
        }

    train_data = [gen_normal() for _ in range(300)]
    detector = MLAnomalyDetector(contamination=0.05)
    detector.fit(train_data)

    print("--- Normal event ---")
    score, meta = detector.score_event(gen_normal())
    print(f"ml_score={score} | raw_if_score={meta['raw_if_score']}")

    print("\n--- Attack event (port scan) ---")
    score, meta = detector.score_event(gen_attack())
    print(f"ml_score={score} | raw_if_score={meta['raw_if_score']}")

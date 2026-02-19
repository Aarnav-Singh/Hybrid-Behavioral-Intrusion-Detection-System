"""
adversarial/drift_simulation.py
─────────────────────────────────
Simulate 4 types of concept drift to test the PSI + KS monitoring system.

WHAT IS CONCEPT DRIFT?
──────────────────────
  The ML model was trained on last month's traffic. Today's traffic is different.
  The model's accuracy degrades silently — no exceptions, no errors, just missed attacks.

  Types simulated here:
    1. Gradual drift   — new mobile apps gradually shift traffic patterns
    2. Sudden shift    — competitor goes offline, all their traffic floods us
    3. Seasonal peak   — Black Friday / flash sale 10x traffic spike
    4. Attack pattern  — attackers change technique; new features look "normal"
"""

from __future__ import annotations
import numpy as np
import pandas as pd
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class DriftSimulator:
    """Generates feature distributions that drift over time (4 scenarios)."""

    FEATURE_NAMES = [
        "f1_request_frequency", "f2_endpoint_entropy", "f3_failed_request_ratio",
        "f4_uri_char_entropy", "f5_timing_variance", "f6_unique_endpoints_per_min",
        "f7_http_method_gini", "f8_ua_suspicion_score", "f9_session_length",
        "f10_payload_size_zscore",
    ]

    BASELINE = {
        "mean": np.array([2.1, 0.3, 0.05, 3.5, 0.1, 1.5, 0.05, 0.0, 900, 0.5]),
        "std":  np.array([0.7, 0.1, 0.02, 0.3, 0.05, 0.5, 0.02, 0.0, 200, 0.3]),
    }

    def generate_gradual_drift(
        self, n_weeks: int = 4, samples_per_week: int = 1000
    ) -> list[pd.DataFrame]:
        """
        Week-by-week data where features drift ±20% over 4 weeks.
        Mobile app adoption: session_length decreases (mobile sessions shorter).
        API clients: method_gini increases (more POST/DELETE calls).
        """
        rng = np.random.default_rng(42)
        weekly_data = []
        for week in range(n_weeks):
            drift_factor = 1.0 + week * 0.05  # 5% drift per week
            mean = self.BASELINE["mean"].copy()
            mean[8] *= (1.0 - week * 0.1)   # session_length shrinks (mobile)
            mean[6] *= (1.0 + week * 0.1)   # method_gini grows (API clients)
            std  = self.BASELINE["std"] * drift_factor
            data = rng.normal(mean, std, (samples_per_week, 10))
            df   = pd.DataFrame(data, columns=self.FEATURE_NAMES)
            df["week"] = week
            df["drift_type"] = "gradual"
            weekly_data.append(df)
        return weekly_data

    def generate_sudden_shift(
        self, n_before: int = 1000, n_after: int = 1000
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Abrupt traffic change (competitor outage / product launch).
        Before: normal API traffic. After: dramatically higher req_frequency.
        """
        rng = np.random.default_rng(99)
        before_data = rng.normal(self.BASELINE["mean"], self.BASELINE["std"], (n_before, 10))
        after_mean  = self.BASELINE["mean"].copy()
        after_mean[0] *= 4.0   # req_frequency 4x after sudden influx
        after_mean[1] *= 1.5   # endpoint_entropy higher (new users, unfamiliar navigation)
        after_data  = rng.normal(after_mean, self.BASELINE["std"] * 1.5, (n_after, 10))
        df_before = pd.DataFrame(before_data, columns=self.FEATURE_NAMES)
        df_after  = pd.DataFrame(after_data,  columns=self.FEATURE_NAMES)
        df_before["phase"] = "before"; df_after["phase"] = "after"
        return df_before, df_after

    def generate_seasonal_peak(self, peak_multiplier: float = 10.0) -> dict[str, pd.DataFrame]:
        """Black Friday scenario: 10x traffic, all features scale up."""
        rng = np.random.default_rng(7)
        n = 2000
        normal_data = rng.normal(self.BASELINE["mean"], self.BASELINE["std"], (n, 10))
        peak_mean   = self.BASELINE["mean"].copy()
        peak_mean[0] *= peak_multiplier   # req_frequency
        peak_mean[5] *= peak_multiplier   # unique_endpoints
        peak_data   = rng.normal(peak_mean, self.BASELINE["std"] * 3, (n, 10))
        return {
            "normal": pd.DataFrame(normal_data, columns=self.FEATURE_NAMES),
            "peak":   pd.DataFrame(peak_data,   columns=self.FEATURE_NAMES),
        }

    def generate_attack_pattern_shift(
        self, n: int = 500
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Attackers shift from fast brute force to slow-and-low SQLi.
        Old attack: high req_frequency + high failed_ratio
        New attack: normal req_frequency + high uri_char_entropy
        """
        rng = np.random.default_rng(17)
        old_mean = np.array([15, 0.9, 0.40, 3.6, 0.01, 8.0, 0.45, 0.8, 90, 3.5])
        new_mean = np.array([2.3, 0.4, 0.07, 4.9, 0.09, 1.8, 0.07, 0.2, 850, 0.6])
        old_attacks = rng.normal(old_mean, self.BASELINE["std"] * 2, (n, 10))
        new_attacks = rng.normal(new_mean, self.BASELINE["std"] * 0.5, (n, 10))
        df_old = pd.DataFrame(old_attacks, columns=self.FEATURE_NAMES)
        df_new = pd.DataFrame(new_attacks, columns=self.FEATURE_NAMES)
        return df_old, df_new

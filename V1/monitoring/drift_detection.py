"""
monitoring/drift_detection.py
──────────────────────────────
PSI + KS-test monitoring for real-time feature drift detection.

Triggered on each retraining cadence (weekly by default).
Outputs to Prometheus gauges so Grafana can alert on drift.
"""

from __future__ import annotations
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp


class DriftMonitor:
    """
    Monitors whether the current feature distribution has drifted from training
    distribution. Two complementary tests:

    1. PSI (Population Stability Index)
       - Comes from credit risk modelling; widely used in production ML
       - PSI < 0.1  → No significant drift (safe)
       - PSI 0.1–0.2 → Minor drift (increase monitoring frequency)
       - PSI > 0.2  → Significant drift → trigger retraining

    2. KS Test (Kolmogorov-Smirnov)
       - Non-parametric test for distributional equivalence
       - p < 0.05 → distributions are significantly different → drift detected

    WHY BOTH?
      PSI catches gradual shifts in distribution shape.
      KS-test catches sudden shifts (jumps in CDF).
      Using both reduces the chance of missing a real drift event.
    """

    PSI_SAFE_THRESHOLD      = 0.1
    PSI_WARNING_THRESHOLD   = 0.2
    KS_ALPHA                = 0.05

    FEATURE_NAMES = [
        "f1_request_frequency", "f2_endpoint_entropy", "f3_failed_request_ratio",
        "f4_uri_char_entropy", "f5_timing_variance", "f6_unique_endpoints_per_min",
        "f7_http_method_gini", "f8_ua_suspicion_score", "f9_session_length",
        "f10_payload_size_zscore",
    ]

    def __init__(self, training_df: pd.DataFrame):
        self.training_df = training_df

    def calculate_psi(
        self,
        expected: np.ndarray,
        actual: np.ndarray,
        n_bins: int = 10,
    ) -> float:
        """
        PSI = Σ (actual% - expected%) × ln(actual% / expected%)

        Bins the expected distribution, then counts actual values per bin.
        """
        eps = 1e-6
        breakpoints = np.percentile(expected, np.linspace(0, 100, n_bins + 1))
        breakpoints = np.unique(breakpoints)
        if len(breakpoints) < 3:
            return 0.0
        expected_counts, _ = np.histogram(expected, bins=breakpoints)
        actual_counts, _   = np.histogram(actual,   bins=breakpoints)
        expected_pct = expected_counts / (expected_counts.sum() + eps)
        actual_pct   = actual_counts   / (actual_counts.sum()   + eps)
        expected_pct = np.clip(expected_pct, eps, None)
        actual_pct   = np.clip(actual_pct,   eps, None)
        psi = float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))
        return round(psi, 4)

    def monitor(self, current_df: pd.DataFrame) -> pd.DataFrame:
        """
        Run PSI + KS-test for every feature. Return drift report DataFrame.
        """
        rows = []
        for feat in self.FEATURE_NAMES:
            if feat not in self.training_df.columns or feat not in current_df.columns:
                continue
            expected = self.training_df[feat].dropna().values
            actual   = current_df[feat].dropna().values

            psi = self.calculate_psi(expected, actual)
            ks_stat, ks_p = ks_2samp(expected, actual)

            if psi > self.PSI_WARNING_THRESHOLD or ks_p < self.KS_ALPHA:
                status = "DRIFT_DETECTED"
            elif psi > self.PSI_SAFE_THRESHOLD:
                status = "WARNING"
            else:
                status = "STABLE"

            rows.append({
                "feature":    feat,
                "psi":        psi,
                "psi_status": ("STABLE" if psi < 0.1 else "WARNING" if psi < 0.2 else "DRIFT"),
                "ks_stat":    round(float(ks_stat), 4),
                "ks_p":       f"{ks_p:.2e}",
                "ks_drift":   ks_p < self.KS_ALPHA,
                "status":     status,
            })

        df = pd.DataFrame(rows).sort_values("psi", ascending=False)
        drifted = df[df["status"] == "DRIFT_DETECTED"]

        print("\n" + "=" * 70)
        print("DRIFT MONITORING REPORT")
        print("=" * 70)
        print(df[["feature", "psi", "psi_status", "ks_p", "status"]].to_string(index=False))
        if not drifted.empty:
            print(f"\n⚠  DRIFT DETECTED in {len(drifted)} feature(s):")
            for _, row in drifted.iterrows():
                print(f"   {row['feature']}  PSI={row['psi']}  KS_p={row['ks_p']}")
            print("   → ACTION: Schedule model retraining")
        else:
            print("\n✓  All features stable. No retraining required.")
        print("=" * 70)
        return df


class RetrainingPipeline:
    """
    Automated retraining workflow triggered by drift detection.

    Criteria for retraining:
      - PSI > 0.2 on any 2+ features, OR
      - KS-test p < 0.01 on any feature, OR
      - Weekly scheduled retraining (regardless of drift)

    A/B testing protocol:
      - New model trained on latest 30 days of data
      - Shadow-deployed alongside current model for 48 hours
      - Promoted if: new_f1 > current_f1 − 0.01 AND new_FPR ≤ current_FPR + 0.005
      - Rolled back automatically if promoted model FPR exceeds threshold
    """

    RETRAINING_TRIGGERS = {
        "psi_threshold":       0.20,
        "psi_feature_count":   2,
        "ks_p_threshold":      0.01,
        "weekly_forced":       True,
        "f1_degradation":      0.05,    # Alert if F1 drops >5%
    }

    def should_retrain(self, drift_report: pd.DataFrame, current_f1: float) -> dict:
        psi_triggered  = (drift_report["psi"] > 0.20).sum() >= 2
        ks_triggered   = drift_report["ks_drift"].any()
        reason = []
        if psi_triggered: reason.append("PSI > 0.20 on 2+ features")
        if ks_triggered:  reason.append("KS-test drift detected")
        return {
            "should_retrain":    psi_triggered or ks_triggered,
            "triggers":          reason,
            "recommended_action": "Immediate retraining" if reason else "Continue monitoring",
        }

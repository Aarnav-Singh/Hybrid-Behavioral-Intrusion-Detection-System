"""
ml_engine/feature_analysis.py
───────────────────────────────
SciPy-based statistical validation of each feature's discriminative power.

PURPOSE
───────
Before training the Isolation Forest, we need to PROVE each feature actually
separates normal from attack traffic. We don't just eyeball histograms — we
use peer-reviewed statistical tests with quantified effect sizes.

WHY MANN-WHITNEY U INSTEAD OF T-TEST?
────────────────────────────────────────
  - T-test assumes normality. Network traffic features are almost never normal
    (Shapiro-Wilk confirms this in analyze_baseline.py).
  - Mann-Whitney U is non-parametric: works on any distribution.
  - It's more robust to outliers (which attack traffic generates many of).

WHY COHEN'S D?
  - p-value only tells you "is there a difference?" not "how big is it?"
  - Cohen's d = (attack_mean - normal_mean) / pooled_std
  - Interpretation (standard thresholds, Cohen 1988):
      |d| < 0.2  → small effect     → weak discriminator
      |d| ≥ 0.5  → medium effect    → worth including
      |d| ≥ 0.8  → large effect     → strong discriminator
      |d| ≥ 2.0  → very large effect → excellent signal for model

WHY KL DIVERGENCE?
  - Cohen's d measures mean shift; KL measures full distribution difference.
  - If distributions have the same mean but different tails, KL catches it.
  - KL = 0 means identical distributions; higher = more separable.

USAGE
─────
  from ml_engine.feature_analysis import FeatureAnalysis
  analysis = FeatureAnalysis()

  results = analysis.run_all_validations(features_df_normal, features_df_attack)
  print(results)

  analysis.visualize_distributions("f1_request_frequency", normal_vals, attack_vals)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy
from scipy.stats import mannwhitneyu, shapiro, ttest_ind


class FeatureAnalysis:
    """
    Statistical validation of feature discriminative power.

    Methods
    -------
    validate_feature_discrimination(normal, attack)  → metrics dict
    run_all_validations(df_normal, df_attack)         → summary DataFrame
    visualize_distributions(name, normal, attack)     → saves PNG
    correlation_matrix(features_df)                   → DataFrame + PNG
    """

    FEATURE_NAMES = [
        "f1_request_frequency",
        "f2_endpoint_entropy",
        "f3_failed_request_ratio",
        "f4_uri_char_entropy",
        "f5_timing_variance",
        "f6_unique_endpoints_per_min",
        "f7_http_method_gini",
        "f8_ua_suspicion_score",
        "f9_session_length",
        "f10_payload_size_zscore",
    ]

    EFFECT_SIZE_LABELS = {
        "small":      "|d| < 0.2 — weak discriminator",
        "medium":     "|d| 0.2–0.8 — moderate discriminator",
        "large":      "|d| 0.8–2.0 — strong discriminator",
        "very large": "|d| ≥ 2.0 — excellent discriminator",
    }

    def validate_feature_discrimination(
        self,
        feature_values_normal: list[float],
        feature_values_attack: list[float],
    ) -> dict[str, Any]:
        """
        Full SciPy statistical validation of one feature against normal/attack split.

        Returns
        -------
        dict with keys:
          p_value_ttest       : parametric (t-test) p-value
          p_value_mannwhitney : non-parametric (Mann-Whitney U) p-value
          cohens_d            : standardised effect size
          effect_size         : human label (small/medium/large/very large)
          kl_divergence       : KL divergence (distribution separation)
          normal_mean         : mean of normal feature values
          attack_mean         : mean of attack feature values
          mean_delta          : attack_mean - normal_mean
          significant         : True if Mann-Whitney p < 0.05
          recommended         : True if |Cohen's d| >= 0.5 (include in model)
        """
        n_arr = np.array(feature_values_normal, dtype=float)
        a_arr = np.array(feature_values_attack, dtype=float)

        if len(n_arr) < 10 or len(a_arr) < 10:
            return {"error": "Insufficient samples (need >= 10 per class)"}

        # ── T-test (parametric) ───────────────────────────────────────────────
        t_stat, p_ttest = ttest_ind(n_arr, a_arr, equal_var=False)

        # ── Mann-Whitney U (non-parametric — preferred for network data) ──────
        u_stat, p_mw = mannwhitneyu(n_arr, a_arr, alternative="two-sided")

        # ── Cohen's d (effect size) ────────────────────────────────────────────
        mean_diff   = np.mean(a_arr) - np.mean(n_arr)
        pooled_std  = np.sqrt((np.var(n_arr, ddof=1) + np.var(a_arr, ddof=1)) / 2)
        cohens_d    = float(mean_diff / pooled_std) if pooled_std > 0 else 0.0

        # ── KL Divergence (distribution distance) ────────────────────────────
        # Bin both distributions on the same scale, add epsilon to avoid log(0)
        combined_min = min(n_arr.min(), a_arr.min())
        combined_max = max(n_arr.max(), a_arr.max()) + 1e-9
        bins = np.linspace(combined_min, combined_max, 51)
        hist_n, _ = np.histogram(n_arr, bins=bins, density=True)
        hist_a, _ = np.histogram(a_arr, bins=bins, density=True)
        eps     = 1e-10
        hist_n  = hist_n + eps
        hist_a  = hist_a + eps
        kl_div  = float(scipy_entropy(hist_a, hist_n))

        # ── Effect size label ─────────────────────────────────────────────────
        abs_d = abs(cohens_d)
        if abs_d >= 2.0:
            effect_label = "very large"
        elif abs_d >= 0.8:
            effect_label = "large"
        elif abs_d >= 0.5:
            effect_label = "medium"
        else:
            effect_label = "small"

        return {
            "normal_mean":         float(np.mean(n_arr)),
            "attack_mean":         float(np.mean(a_arr)),
            "mean_delta":          float(mean_diff),
            "normal_std":          float(np.std(n_arr, ddof=1)),
            "attack_std":          float(np.std(a_arr, ddof=1)),
            "p_value_ttest":       float(p_ttest),
            "p_value_mannwhitney": float(p_mw),
            "cohens_d":            cohens_d,
            "effect_size":         effect_label,
            "kl_divergence":       kl_div,
            "significant":         bool(p_mw < 0.05),
            "recommended":         bool(abs_d >= 0.5),
        }

    def run_all_validations(
        self,
        features_df_normal: pd.DataFrame,
        features_df_attack: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Run validate_feature_discrimination for all 10 features.

        Parameters
        ----------
        features_df_normal : DataFrame with feature columns for normal traffic
        features_df_attack : DataFrame with feature columns for attack traffic

        Returns
        -------
        DataFrame with one row per feature, columns:
          feature | normal_mean | attack_mean | cohens_d | effect_size
          | kl_divergence | p_mw | significant | recommended
        """
        rows = []
        available = [f for f in self.FEATURE_NAMES
                     if f in features_df_normal.columns and f in features_df_attack.columns]

        for feature in available:
            normal_vals = features_df_normal[feature].dropna().tolist()
            attack_vals = features_df_attack[feature].dropna().tolist()
            stats = self.validate_feature_discrimination(normal_vals, attack_vals)

            if "error" in stats:
                print(f"  [SKIP] {feature}: {stats['error']}")
                continue

            rows.append({
                "feature":         feature,
                "normal_mean":     round(stats["normal_mean"], 4),
                "attack_mean":     round(stats["attack_mean"], 4),
                "mean_delta":      round(stats["mean_delta"], 4),
                "cohens_d":        round(stats["cohens_d"], 3),
                "effect_size":     stats["effect_size"],
                "kl_divergence":   round(stats["kl_divergence"], 4),
                "p_value_mw":      f"{stats['p_value_mannwhitney']:.2e}",
                "significant":     "✓" if stats["significant"] else "✗",
                "recommended":     "✓ INCLUDE" if stats["recommended"] else "✗ DROP",
            })

        df = pd.DataFrame(rows)
        if not df.empty:
            df = df.sort_values("cohens_d", key=abs, ascending=False)

        print("\n" + "=" * 90)
        print("FEATURE DISCRIMINATION ANALYSIS")
        print("=" * 90)
        print(df.to_string(index=False))
        print("\nFeatures recommended (|Cohen's d| ≥ 0.5):",
              df[df["recommended"] == "✓ INCLUDE"]["feature"].tolist())

        return df

    def visualize_distributions(
        self,
        feature_name: str,
        normal_data: list[float],
        attack_data: list[float],
        save_dir: str = "reports/feature_distributions",
    ) -> str:
        """
        Overlapping KDE/histogram plots: normal (blue) vs attack (red).

        Title includes Cohen's d and p-value for quick assessment.
        A vertical line is drawn at the optimal decision boundary
        (midpoint between means) when applicable.

        Returns path of saved PNG.
        """
        os.makedirs(save_dir, exist_ok=True)
        stats = self.validate_feature_discrimination(normal_data, attack_data)

        n_arr = np.array(normal_data, dtype=float)
        a_arr = np.array(attack_data, dtype=float)

        fig, ax = plt.subplots(figsize=(9, 5))
        fig.patch.set_facecolor("#1a1a2e")
        ax.set_facecolor("#16213e")

        bins = np.linspace(
            min(n_arr.min(), a_arr.min()),
            max(n_arr.max(), a_arr.max()),
            40,
        )
        ax.hist(n_arr, bins=bins, alpha=0.55, color="#4cc9f0", label="Normal traffic",   density=True)
        ax.hist(a_arr, bins=bins, alpha=0.55, color="#f72585", label="Attack traffic",   density=True)

        # Optimal boundary line (midpoint)
        boundary = (np.mean(n_arr) + np.mean(a_arr)) / 2
        ax.axvline(boundary, color="#ffd60a", linestyle="--", linewidth=1.5,
                   label=f"Decision boundary ≈ {boundary:.2f}")

        # Labels
        d     = stats.get("cohens_d", float("nan"))
        p_mw  = stats.get("p_value_mannwhitney", float("nan"))
        ax.set_title(
            f"{feature_name}\n"
            f"Cohen's d = {d:.2f} ({stats.get('effect_size','?')}) | "
            f"Mann-Whitney p = {p_mw:.2e}",
            color="white", fontsize=12,
        )
        ax.set_xlabel(feature_name, color="white")
        ax.set_ylabel("Density", color="white")
        ax.tick_params(colors="white")
        ax.legend(framealpha=0.3, labelcolor="white")
        plt.tight_layout()

        out_path = os.path.join(save_dir, f"{feature_name}.png")
        plt.savefig(out_path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved → {out_path}")
        return out_path

    def correlation_matrix(
        self,
        features_df: pd.DataFrame,
        save_dir: str = "reports/feature_distributions",
    ) -> pd.DataFrame:
        """
        Pearson correlation heatmap for all 10 features.

        Flags redundant pairs (|r| > 0.8) — these are candidates for removal
        to reduce multicollinearity in the feature set.
        High correlation between features doesn't automatically hurt Isolation
        Forest (which sub-samples features per tree), but it does reduce the
        effective information content.

        Returns the correlation DataFrame and saves a heatmap PNG.
        """
        import matplotlib.colors as mcolors

        feat_cols = [c for c in self.FEATURE_NAMES if c in features_df.columns]
        corr = features_df[feat_cols].corr(method="pearson")

        os.makedirs(save_dir, exist_ok=True)

        fig, ax = plt.subplots(figsize=(12, 10))
        fig.patch.set_facecolor("#1a1a2e")
        ax.set_facecolor("#16213e")

        cmap = plt.cm.RdYlGn
        im   = ax.imshow(corr.values, cmap=cmap, vmin=-1, vmax=1, aspect="auto")
        plt.colorbar(im, ax=ax, label="Pearson r")

        ax.set_xticks(range(len(feat_cols)))
        ax.set_yticks(range(len(feat_cols)))
        short = [f.replace("f1_", "").replace("_", "\n") for f in feat_cols]
        ax.set_xticklabels(short, rotation=45, ha="right", color="white", fontsize=8)
        ax.set_yticklabels(short, color="white", fontsize=8)
        ax.set_title("Feature Correlation Matrix", color="white", fontsize=13)

        # Annotate cells
        for i in range(len(feat_cols)):
            for j in range(len(feat_cols)):
                val = corr.values[i, j]
                color = "black" if 0.3 < abs(val) < 0.9 else "white"
                ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                        color=color, fontsize=7)

        plt.tight_layout()
        out_path = os.path.join(save_dir, "correlation_matrix.png")
        plt.savefig(out_path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  Saved → {out_path}")

        # Print redundant pairs
        print("\nRedundant feature pairs (|r| > 0.8 — consider dropping one):")
        found = False
        for i in range(len(feat_cols)):
            for j in range(i + 1, len(feat_cols)):
                r = corr.values[i, j]
                if abs(r) > 0.8:
                    print(f"  {feat_cols[i]} ↔ {feat_cols[j]}  r={r:.3f}")
                    found = True
        if not found:
            print("  None — all pairs have |r| ≤ 0.8. Full feature set recommended.")

        return corr


# ─── CLI demo ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import numpy as np

    rng = np.random.default_rng(42)
    # Simulate 500 normal samples and 200 attack samples per feature
    n_normal = 500
    n_attack = 200

    # f1_request_frequency: normal ~2 req/min, attack ~15 req/min
    normal_freq  = rng.exponential(2.0, n_normal)
    attack_freq  = rng.exponential(15.0, n_attack)

    analyzer = FeatureAnalysis()
    result = analyzer.validate_feature_discrimination(
        normal_freq.tolist(), attack_freq.tolist()
    )
    print("f1_request_frequency validation:")
    for k, v in result.items():
        print(f"  {k}: {v}")

    analyzer.visualize_distributions(
        "f1_request_frequency (demo)",
        normal_freq.tolist(),
        attack_freq.tolist(),
        save_dir="reports/feature_distributions",
    )

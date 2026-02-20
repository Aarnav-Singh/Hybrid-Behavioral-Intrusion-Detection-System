"""
evaluation_harness.py
=====================
Domain 2: Research-Grade Evaluation
- Multi-run statistical evaluation (mean ± std)
- Ablation study across all component configurations
- ROC & Precision-Recall curves
- Drift-performance degradation curve

Requires: numpy, scikit-learn, matplotlib
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.metrics import (
    roc_curve, auc, precision_recall_curve, average_precision_score,
    f1_score, confusion_matrix, classification_report
)
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
import warnings
warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    f1: float
    precision: float
    recall: float
    fpr: float          # False Positive Rate
    scores: np.ndarray  # raw fusion scores for ROC
    labels: np.ndarray  # ground-truth labels


@dataclass
class AggregateResult:
    name: str
    f1_mean: float
    f1_std: float
    precision_mean: float
    recall_mean: float
    fpr_mean: float
    all_scores: List[np.ndarray]
    all_labels: List[np.ndarray]

    def summary(self) -> str:
        return (
            f"{self.name:25s} | F1={self.f1_mean:.4f}±{self.f1_std:.4f} "
            f"| Prec={self.precision_mean:.4f} "
            f"| Rec={self.recall_mean:.4f} "
            f"| FPR={self.fpr_mean:.4f}"
        )


# ---------------------------------------------------------------------------
# Synthetic Dataset Generator (replace with your real data loader)
# ---------------------------------------------------------------------------

def generate_dataset(
    n_samples: int = 1000,
    attack_ratio: float = 0.15,
    seed: int = 42,
    drift_factor: float = 0.0,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates a synthetic IDS dataset.
    Features: [ml_score, z_score, rule_score]

    Replace this function with your real dataset loader.
    drift_factor (0–1): shifts normal distribution to simulate concept drift.
    """
    rng = np.random.default_rng(seed)
    n_attack = int(n_samples * attack_ratio)
    n_normal = n_samples - n_attack

    # Normal traffic
    normal = rng.normal(loc=[0.2 + drift_factor * 0.5, 0.8, 0.1], scale=[0.3, 0.4, 0.1],
                        size=(n_normal, 3)).clip(0, 1)

    # Attack traffic
    attack = rng.normal(loc=[0.75, 3.2, 0.85], scale=[0.2, 0.5, 0.15],
                        size=(n_attack, 3)).clip(0, 1)

    X = np.vstack([normal, attack])
    y = np.array([0] * n_normal + [1] * n_attack)

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# Mode Scorers  (plug in your real scorers here)
# ---------------------------------------------------------------------------

def score_rule_only(X: np.ndarray) -> np.ndarray:
    """Rule engine: use rule_score column."""
    return X[:, 2]


def score_ml_only(X: np.ndarray) -> np.ndarray:
    """ML anomaly: use ml_score column."""
    return X[:, 0]


def score_behavioral_only(X: np.ndarray) -> np.ndarray:
    """Behavioral z-score converted to prob: use z_score column."""
    from scipy.stats import norm
    return 1 - norm.cdf(X[:, 1] - 1.5)   # shifted to [0,1]


def score_hybrid_full(X: np.ndarray) -> np.ndarray:
    """Weighted hybrid: all three sources."""
    return 0.35 * score_ml_only(X) + 0.35 * score_rule_only(X) + 0.30 * score_behavioral_only(X)


def score_hybrid_no_ml(X: np.ndarray) -> np.ndarray:
    return 0.50 * score_rule_only(X) + 0.50 * score_behavioral_only(X)


def score_hybrid_no_rule(X: np.ndarray) -> np.ndarray:
    return 0.55 * score_ml_only(X) + 0.45 * score_behavioral_only(X)


def score_hybrid_no_behavior(X: np.ndarray) -> np.ndarray:
    return 0.50 * score_ml_only(X) + 0.50 * score_rule_only(X)


# ---------------------------------------------------------------------------
# Core Evaluation Logic
# ---------------------------------------------------------------------------

THRESHOLD = 0.45   # classification threshold

def _evaluate_once(
    scorer: Callable,
    X: np.ndarray,
    y: np.ndarray,
) -> RunResult:
    scores = scorer(X)
    preds  = (scores >= THRESHOLD).astype(int)
    f1     = f1_score(y, preds, zero_division=0)
    prec   = f1_score(y, preds, average="binary", zero_division=0)
    rec    = np.sum((preds == 1) & (y == 1)) / (np.sum(y == 1) + 1e-9)
    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    fpr    = fp / (fp + tn + 1e-9)
    return RunResult(f1=f1, precision=prec, recall=rec, fpr=fpr,
                     scores=scores, labels=y)


# ---------------------------------------------------------------------------
# 1. Multi-Run Statistical Evaluation
# ---------------------------------------------------------------------------

def multi_run_evaluation(
    scorer: Callable,
    name: str,
    n_runs: int = 10,
    n_samples: int = 1000,
) -> AggregateResult:
    """Run scorer n_runs times with different seeds and aggregate."""
    results = []
    for seed in range(n_runs):
        X, y = generate_dataset(n_samples=n_samples, seed=seed)
        results.append(_evaluate_once(scorer, X, y))

    f1s   = [r.f1  for r in results]
    precs = [r.precision for r in results]
    recs  = [r.recall for r in results]
    fprs  = [r.fpr for r in results]

    return AggregateResult(
        name            = name,
        f1_mean         = float(np.mean(f1s)),
        f1_std          = float(np.std(f1s)),
        precision_mean  = float(np.mean(precs)),
        recall_mean     = float(np.mean(recs)),
        fpr_mean        = float(np.mean(fprs)),
        all_scores      = [r.scores for r in results],
        all_labels      = [r.labels for r in results],
    )


# ---------------------------------------------------------------------------
# 2. Ablation Study
# ---------------------------------------------------------------------------

ABLATION_CONFIGS: Dict[str, Callable] = {
    "Rule Only":             score_rule_only,
    "ML Only":               score_ml_only,
    "Behavioral Only":       score_behavioral_only,
    "Hybrid (Full)":         score_hybrid_full,
    "Hybrid (-ML)":          score_hybrid_no_ml,
    "Hybrid (-Rules)":       score_hybrid_no_rule,
    "Hybrid (-Behavioral)":  score_hybrid_no_behavior,
}


def run_ablation_study(n_runs: int = 10) -> Dict[str, AggregateResult]:
    print("\n" + "=" * 70)
    print("ABLATION STUDY")
    print("=" * 70)
    results = {}
    for name, scorer in ABLATION_CONFIGS.items():
        result = multi_run_evaluation(scorer, name, n_runs=n_runs)
        results[name] = result
        print(result.summary())
    return results


# ---------------------------------------------------------------------------
# 3. ROC & PR Curves
# ---------------------------------------------------------------------------

def plot_roc_pr_curves(
    ablation_results: Dict[str, AggregateResult],
    output_path: str = "roc_pr_curves.png",
):
    """Plot ROC and PR curves, averaged across runs."""

    # Focus on key configs for clarity
    highlight = ["Rule Only", "ML Only", "Behavioral Only", "Hybrid (Full)"]
    colors    = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12"]

    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("ROC & Precision-Recall Curves — Hybrid IDS Evaluation", fontsize=14, fontweight="bold")

    for name, color in zip(highlight, colors):
        if name not in ablation_results:
            continue
        res = ablation_results[name]

        # Aggregate across runs by interpolating on common FPR grid
        mean_fpr = np.linspace(0, 1, 100)
        tprs, aps = [], []

        for scores, labels in zip(res.all_scores, res.all_labels):
            # ROC
            fpr, tpr, _ = roc_curve(labels, scores)
            tprs.append(np.interp(mean_fpr, fpr, tpr))

            # PR
            prec, rec, _ = precision_recall_curve(labels, scores)
            aps.append(average_precision_score(labels, scores))

        mean_tpr = np.mean(tprs, axis=0)
        roc_auc  = auc(mean_fpr, mean_tpr)

        ax_roc.plot(mean_fpr, mean_tpr, color=color, lw=2,
                    label=f"{name} (AUC={roc_auc:.3f})")

        # PR — plot last run for illustration + annotate AP
        last_scores = res.all_scores[-1]
        last_labels = res.all_labels[-1]
        prec, rec, _ = precision_recall_curve(last_labels, last_scores)
        ap = np.mean(aps)
        ax_pr.plot(rec, prec, color=color, lw=2, label=f"{name} (AP={ap:.3f})")

    # Decorate ROC
    ax_roc.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random")
    ax_roc.set_xlabel("False Positive Rate", fontsize=11)
    ax_roc.set_ylabel("True Positive Rate", fontsize=11)
    ax_roc.set_title("ROC Curves")
    ax_roc.legend(fontsize=9)
    ax_roc.grid(alpha=0.3)

    # Decorate PR
    ax_pr.set_xlabel("Recall", fontsize=11)
    ax_pr.set_ylabel("Precision", fontsize=11)
    ax_pr.set_title("Precision-Recall Curves")
    ax_pr.legend(fontsize=9)
    ax_pr.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"\n[✓] ROC/PR plot saved → {output_path}")


# ---------------------------------------------------------------------------
# 4. Drift-Performance Degradation Curve
# ---------------------------------------------------------------------------

def plot_drift_performance_curve(
    output_path: str = "drift_performance.png",
    n_seeds: int = 5,
):
    """
    Simulate gradual concept drift and plot F1 degradation over drift intensity.
    Shows hybrid recovery vs single-component degradation.
    """
    drift_levels = np.linspace(0.0, 1.0, 15)

    configs = {
        "Rule Only":     score_rule_only,
        "ML Only":       score_ml_only,
        "Hybrid (Full)": score_hybrid_full,
    }
    colors = {"Rule Only": "#e74c3c", "ML Only": "#3498db", "Hybrid (Full)": "#f39c12"}

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_title("F1 vs Concept Drift Intensity", fontsize=14, fontweight="bold")

    for name, scorer in configs.items():
        f1_by_drift = []
        for drift in drift_levels:
            run_f1s = []
            for seed in range(n_seeds):
                X, y = generate_dataset(seed=seed, drift_factor=drift)
                r = _evaluate_once(scorer, X, y)
                run_f1s.append(r.f1)
            f1_by_drift.append((np.mean(run_f1s), np.std(run_f1s)))

        means = [m for m, _ in f1_by_drift]
        stds  = [s for _, s in f1_by_drift]

        ax.plot(drift_levels, means, color=colors[name], lw=2.5, marker="o",
                markersize=4, label=name)
        ax.fill_between(drift_levels,
                         [m - s for m, s in zip(means, stds)],
                         [m + s for m, s in zip(means, stds)],
                         alpha=0.15, color=colors[name])

    ax.axvline(0.3, color="gray", ls="--", alpha=0.5, label="Drift threshold")
    ax.set_xlabel("Drift Intensity", fontsize=12)
    ax.set_ylabel("F1 Score (mean ± std)", fontsize=12)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    ax.set_ylim(0, 1.05)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"[✓] Drift performance plot saved → {output_path}")


# ---------------------------------------------------------------------------
# 5. Ablation Bar Chart
# ---------------------------------------------------------------------------

def plot_ablation_bar(
    ablation_results: Dict[str, AggregateResult],
    output_path: str = "ablation_study.png",
):
    names  = list(ablation_results.keys())
    means  = [ablation_results[n].f1_mean for n in names]
    stds   = [ablation_results[n].f1_std  for n in names]

    palette = ["#c0392b" if "Full" in n else "#2980b9" for n in names]

    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.bar(names, means, yerr=stds, color=palette, capsize=5,
                  edgecolor="white", linewidth=0.8)

    ax.set_ylabel("F1 Score (mean ± std)", fontsize=12)
    ax.set_title("Ablation Study — Component Contribution", fontsize=14, fontweight="bold")
    ax.set_xticklabels(names, rotation=25, ha="right", fontsize=9)
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)

    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + std + 0.02,
                f"{mean:.3f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"[✓] Ablation bar chart saved → {output_path}")


# ---------------------------------------------------------------------------
# Master Evaluation Runner
# ---------------------------------------------------------------------------

def run_full_evaluation(output_dir: str = "."):
    print("\n" + "=" * 70)
    print("HYBRID IDS — RESEARCH-GRADE EVALUATION HARNESS")
    print("=" * 70)

    # 1. Ablation
    ablation = run_ablation_study(n_runs=10)

    # 2. Plots
    plot_roc_pr_curves(ablation,  output_path=f"{output_dir}/roc_pr_curves.png")
    plot_ablation_bar(ablation,   output_path=f"{output_dir}/ablation_study.png")
    plot_drift_performance_curve( output_path=f"{output_dir}/drift_performance.png")

    print("\n[✓] Full evaluation complete.\n")
    return ablation


if __name__ == "__main__":
    import os
    os.makedirs("eval_output", exist_ok=True)
    run_full_evaluation(output_dir="eval_output")

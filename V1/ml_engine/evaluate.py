"""
ml_engine/evaluate.py
──────────────────────
Model evaluation harness: ROC curves, confusion matrices, error analysis,
and latency profiling for the Hybrid Behavioral IDS ML component.
"""
from __future__ import annotations
import os
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, auc, confusion_matrix, precision_recall_curve

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ModelEvaluator:

    # ── ROC Curve ────────────────────────────────────────────────────────────
    def generate_roc_curve(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        label: str = "Isolation Forest",
        save_path: str | None = None,
    ) -> dict:
        """
        Generate and save an ROC curve.

        AUC interpretation:
          1.0  → perfect classifier
          0.9+ → excellent
          0.7–0.9 → good
          0.5  → random guessing (useless model)

        y_scores = anomaly scores (higher = more anomalous = more likely attack).
        For IsolationForest: use -model.score_samples(X) to get positive scores.
        """
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        # Find optimal threshold (Youden's J statistic: TPR - FPR is maximised)
        j_scores = tpr - fpr
        best_idx  = int(np.argmax(j_scores))
        best_thresh = float(thresholds[best_idx])

        fig, ax = plt.subplots(figsize=(7, 6))
        fig.patch.set_facecolor("#1a1a2e"); ax.set_facecolor("#16213e")
        ax.plot(fpr, tpr, color="#4cc9f0", lw=2, label=f"{label} (AUC = {roc_auc:.3f})")
        ax.plot([0, 1], [0, 1], "w--", lw=1, label="Random (AUC = 0.5)")
        ax.scatter(fpr[best_idx], tpr[best_idx], color="#f72585", zorder=5,
                   label=f"Optimal threshold = {best_thresh:.2f}")
        ax.set_xlabel("False Positive Rate", color="white")
        ax.set_ylabel("True Positive Rate", color="white")
        ax.set_title("ROC Curve — Isolation Forest IDS", color="white", fontsize=12)
        ax.legend(framealpha=0.3, labelcolor="white")
        ax.tick_params(colors="white")
        [sp.set_edgecolor("gray") for sp in ax.spines.values()]
        plt.tight_layout()

        out = save_path or str(REPORTS_DIR / "roc_curve.png")
        plt.savefig(out, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        print(f"  ROC saved → {out}  (AUC={roc_auc:.4f})")
        return {"auc": roc_auc, "optimal_threshold": best_thresh,
                "fpr": fpr.tolist(), "tpr": tpr.tolist()}

    # ── Confusion matrix at threshold ────────────────────────────────────────
    def confusion_matrix_at_threshold(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        threshold: float,
    ) -> dict:
        """
        At a given anomaly score threshold, compute:
          y_pred = 1 (attack) if score > threshold else 0 (normal)

        Returns TP, FP, TN, FN, Precision, Recall, F1, Accuracy.
        """
        y_pred = (y_scores > threshold).astype(int)
        cm     = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(y_true)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "threshold": threshold,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "accuracy":  round(accuracy, 4),
            "fpr":       round(fpr, 4),
        }

    # ── Error analysis ───────────────────────────────────────────────────────
    def error_analysis(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        feature_names: list[str],
    ) -> pd.DataFrame:
        """
        Analyse model mistakes to guide improvement:

        False Positives (normal traffic flagged as attack):
          - Which features are highest for FP events?
          - These are the features causing over-sensitivity.

        False Negatives (attacks missed):
          - Which features are lowest for FN events?
          - These reveal how attackers stay stealthy.

        Returns DataFrame with error type, feature means, and likely cause.
        """
        fp_mask = (y_true == 0) & (y_pred == 1)
        fn_mask = (y_true == 1) & (y_pred == 0)

        rows = []

        if fp_mask.sum() > 0:
            fp_means = X[fp_mask].mean(axis=0)
            top_feat = feature_names[int(np.argmax(fp_means))]
            rows.append({
                "error_type":  "False Positive",
                "count":       int(fp_mask.sum()),
                "top_feature": top_feat,
                "top_value":   round(float(fp_means.max()), 4),
                "likely_cause": f"High {top_feat} — legitimate power users or API clients",
                **{f: round(float(v), 4) for f, v in zip(feature_names, fp_means)}
            })

        if fn_mask.sum() > 0:
            fn_means = X[fn_mask].mean(axis=0)
            low_feat = feature_names[int(np.argmin(fn_means))]
            rows.append({
                "error_type":  "False Negative",
                "count":       int(fn_mask.sum()),
                "top_feature": low_feat,
                "top_value":   round(float(fn_means.min()), 4),
                "likely_cause": f"Low {low_feat} — slow/stealth attacker mimicking normal traffic",
                **{f: round(float(v), 4) for f, v in zip(feature_names, fn_means)}
            })

        df = pd.DataFrame(rows)
        print("\nError Analysis:")
        if not df.empty:
            print(df[["error_type", "count", "top_feature", "likely_cause"]].to_string(index=False))
        else:
            print("  No errors on this dataset — model perfect on this sample.")
        return df

    # ── Precision-Recall curve ───────────────────────────────────────────────
    def precision_recall_curve_plot(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        save_path: str | None = None,
    ) -> dict:
        """
        Plot Precision-Recall curve (better than ROC when classes are imbalanced,
        which they are in IDS — attacks are <5% of traffic).
        """
        prec, rec, thresholds = precision_recall_curve(y_true, y_scores)
        f1_scores = 2 * prec * rec / (prec + rec + 1e-9)
        best_idx  = int(np.argmax(f1_scores))

        fig, ax = plt.subplots(figsize=(7, 5))
        fig.patch.set_facecolor("#1a1a2e"); ax.set_facecolor("#16213e")
        ax.plot(rec, prec, color="#4cc9f0", lw=2)
        ax.scatter(rec[best_idx], prec[best_idx], color="#f72585", zorder=5,
                   label=f"Best F1={f1_scores[best_idx]:.3f} @ thresh={thresholds[best_idx]:.2f}")
        ax.set_xlabel("Recall", color="white"); ax.set_ylabel("Precision", color="white")
        ax.set_title("Precision-Recall Curve", color="white", fontsize=12)
        ax.legend(framealpha=0.3, labelcolor="white")
        ax.tick_params(colors="white")
        plt.tight_layout()

        out = save_path or str(REPORTS_DIR / "pr_curve.png")
        plt.savefig(out, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()
        return {"best_f1": float(f1_scores[best_idx]),
                "best_threshold": float(thresholds[best_idx])}

    # ── Latency profiler ─────────────────────────────────────────────────────
    def latency_profile(
        self,
        model,
        X: np.ndarray,
        n_repeats: int = 100,
    ) -> dict:
        """
        Measure inference latency distribution.
        Runs model.predict() in a loop and records per-sample latency.

        Returns P50, P95, P99 in milliseconds.
        """
        import time
        latencies = []
        for _ in range(n_repeats):
            t0 = time.perf_counter()
            model.predict(X)
            elapsed_ms = (time.perf_counter() - t0) / len(X) * 1000
            latencies.append(elapsed_ms)

        arr = np.array(latencies)
        return {
            "p50_ms":  round(float(np.percentile(arr, 50)), 3),
            "p95_ms":  round(float(np.percentile(arr, 95)), 3),
            "p99_ms":  round(float(np.percentile(arr, 99)), 3),
            "mean_ms": round(float(arr.mean()), 3),
        }

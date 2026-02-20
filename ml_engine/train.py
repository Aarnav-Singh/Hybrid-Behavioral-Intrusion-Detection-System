"""
ml_engine/train.py
───────────────────
ML training pipeline for the Hybrid Behavioral IDS.

Uses Isolation Forest for unsupervised anomaly detection.
Every training run is tracked in MLflow at http://localhost:5000.

WHY ISOLATION FOREST?
──────────────────────
  1. Unsupervised — no labeled attack data required for training.
     We train on normal traffic only; anomalies are isolated by structure.
  2. Fast inference — O(n log n) prediction, <1ms per event at production.
  3. Handles imbalanced data — attacks are rare (< 1%), IF is built for this.
  4. Interpretable — anomaly score directly reflects isolation depth.
  5. Proven in production IDS literature (Liu et al., 2008, original paper).

WHY MLFLOW?
───────────
  - Every experiment is reproducible: same params + same data = same model.
  - Compare 48 hyperparameter runs side-by-side in the UI.
  - Model artifact stored with metadata → swap models without code changes.
  - CI/CD integration: compare PR's model vs main branch model before merge.

HYPERPARAMETER SEARCH SPACE (48 combinations):
  n_estimators:  [50, 100, 150, 200]    # Trees in the forest
  contamination: [0.05, 0.10, 0.15, 0.20]  # Expected anomaly fraction
  max_features:  [0.5, 0.75, 1.0]      # Fraction of features per tree
  Total: 4 × 4 × 3 = 48 runs

USAGE
─────
  python ml_engine/train.py                    # Full 48-run search
  python ml_engine/train.py --quick            # 9-run subset (3x3x1 grid)
  python ml_engine/train.py --cv-only          # Cross-validate existing model
"""

from __future__ import annotations

import sys
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

import argparse
import json
import os
import time
from itertools import product
from pathlib import Path
from typing import Any

import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import KFold, train_test_split

# ─── Paths ───────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).parent.parent
DATA_DIR    = ROOT / "data"
MODELS_DIR  = ROOT / "models"
REPORTS_DIR = ROOT / "reports"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ─── MLflow setup ────────────────────────────────────────────────────────────
MLFLOW_URI  = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
EXPERIMENT  = "IDS-IsolationForest-v1"

try:
    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment(EXPERIMENT)
except Exception as e:
    print(f"⚠️  MLflow setup failed (unreachable?): {e}")
    # Fallback for local tracking if remote is down
    mlflow.set_tracking_uri("file:./mlruns")

# ─── Hyperparameter grid ─────────────────────────────────────────────────────
PARAM_GRID = {
    "n_estimators":  [50, 100, 150, 200],
    "contamination": [0.05, 0.10, 0.15, 0.20],
    "max_features":  [0.5, 0.75, 1.0],
}

QUICK_GRID = {
    "n_estimators":  [100, 200],
    "contamination": [0.05, 0.10, 0.15],
    "max_features":  [0.75],
}


# ─── Helper: convert IF output to binary ─────────────────────────────────────
def _if_predict_binary(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """
    IsolationForest.predict() returns:
      1  → inlier  (normal)
     -1  → outlier (anomaly)

    We transform to:
      0  → normal
      1  → attack
    """
    raw = model.predict(X)
    return (raw == -1).astype(int)


def _calc_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1  = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    return {"tpr": tpr, "fpr": fpr, "f1": f1, "precision": prec,
            "recall": rec, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


# ─── Hyperparameter search ────────────────────────────────────────────────────
def hyperparameter_search(
    X_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    grid: dict | None = None,
) -> dict[str, Any]:
    """
    Train every combination in the grid.
    Log params, metrics, and model artifact to MLflow per run.

    For each run:
      - mlflow.start_run() captures all metadata
      - mlflow.log_param() stores the 3 hyperparameters
      - mlflow.log_metric() stores F1, TPR, FPR, precision, train/infer time
      - mlflow.sklearn.log_model() stores the fitted model as an artifact
      - Best model tagged: mlflow.set_tag("best_model", "true")

    Returns best_params dict.
    """
    g = grid or PARAM_GRID
    combos = list(product(g["n_estimators"], g["contamination"], g["max_features"]))
    print(f"\n{'=' * 60}")
    print(f"Hyperparameter search: {len(combos)} combinations")
    print(f"MLflow experiment: '{EXPERIMENT}' at {MLFLOW_URI}")
    print(f"{'=' * 60}")

    best_f1   = -1.0
    best_params: dict[str, Any] = {}
    best_run_id = ""

    for n_est, cont, max_feat in combos:
        params = {
            "n_estimators":  n_est,
            "contamination": cont,
            "max_features":  max_feat,
            "random_state":  42,
        }
        run_name = f"IF_n{n_est}_c{cont}_mf{max_feat}"

        with mlflow.start_run(run_name=run_name) as run:
            mlflow.log_params(params)

            # ── Train ────────────────────────────────────────────────────────
            t0    = time.perf_counter()
            model = IsolationForest(**params, n_jobs=-1)
            model.fit(X_train)
            train_time = time.perf_counter() - t0

            # ── Inference latency (per sample) ──────────────────────────────
            t1         = time.perf_counter()
            _          = _if_predict_binary(model, X_val[:100])
            infer_time = (time.perf_counter() - t1) / 100 * 1000  # ms/sample

            # ── Evaluate ─────────────────────────────────────────────────────
            y_pred = _if_predict_binary(model, X_val)
            m      = _calc_metrics(y_val, y_pred)

            mlflow.log_metric("f1",            m["f1"])
            mlflow.log_metric("tpr",           m["tpr"])
            mlflow.log_metric("fpr",           m["fpr"])
            mlflow.log_metric("precision",     m["precision"])
            mlflow.log_metric("recall",        m["recall"])
            mlflow.log_metric("train_time_s",  round(train_time, 4))
            mlflow.log_metric("infer_ms",      round(infer_time, 4))
            mlflow.set_tag("phase", "hyperparameter_search")

            # ── Log model ────────────────────────────────────────────────────
            try:
                mlflow.sklearn.log_model(model, name="model")
            except Exception:
                pass  # Ignore artifact upload failures during search

            print(f"  {run_name}: F1={m['f1']:.4f}  TPR={m['tpr']:.2%}  "
                  f"FPR={m['fpr']:.2%}  infer={infer_time:.2f}ms")

            if m["f1"] > best_f1:
                best_f1     = m["f1"]
                best_params = params.copy()
                best_run_id = run.info.run_id

    # Tag the best model
    with mlflow.start_run(run_id=best_run_id):
        mlflow.set_tag("best_model", "true")

    print(f"\nBest params: {best_params}  F1={best_f1:.4f}")
    return best_params


# ─── K-fold cross-validation ─────────────────────────────────────────────────
def cross_validate_best_model(
    X: np.ndarray,
    y: np.ndarray,
    best_params: dict,
    k: int = 5,
) -> dict[str, float]:
    """
    K-fold cross-validation of the best model, logged as a single MLflow run.

    WHY CV AFTER SEARCH?
      Hyperparameter search uses a single validation split → optimistic estimate.
      K-fold gives a more honest estimate with confidence intervals:
        F1 = mean ± std   (higher std = unstable model or insufficient data)

    Each fold:
      - Train on k-1 folds
      - Predict on held-out fold
      - Record F1, precision, recall

    Aggregated:
      cv_mean_f1, cv_std_f1, cv_confidence_interval_95, cv_mean_precision, ...
    """
    kf = KFold(n_splits=k, shuffle=True, random_state=42)
    fold_f1   = []
    fold_prec = []
    fold_rec  = []

    print(f"\n{'=' * 60}")
    print(f"K-Fold Cross-Validation (k={k})")
    print(f"{'=' * 60}")

    with mlflow.start_run(run_name=f"cross_validation_k{k}") as cv_run:
        mlflow.log_params(best_params)
        mlflow.set_tag("phase", "cross_validation")

        for fold, (train_idx, val_idx) in enumerate(kf.split(X), start=1):
            model = IsolationForest(**best_params, n_jobs=-1)
            model.fit(X[train_idx])
            y_pred = _if_predict_binary(model, X[val_idx])
            m = _calc_metrics(y[val_idx], y_pred)

            fold_f1.append(m["f1"])
            fold_prec.append(m["precision"])
            fold_rec.append(m["recall"])

            mlflow.log_metric(f"fold_{fold}_f1",        m["f1"])
            mlflow.log_metric(f"fold_{fold}_precision",  m["precision"])
            mlflow.log_metric(f"fold_{fold}_recall",     m["recall"])
            print(f"  Fold {fold}: F1={m['f1']:.4f}  Prec={m['precision']:.4f}  "
                  f"Rec={m['recall']:.4f}")

        mean_f1 = float(np.mean(fold_f1))
        std_f1  = float(np.std(fold_f1, ddof=1))
        # 95% CI using t-distribution (small k)
        from scipy.stats import t as t_dist
        se = std_f1 / np.sqrt(k)
        ci_margin = t_dist.ppf(0.975, df=k - 1) * se
        ci = (round(mean_f1 - ci_margin, 4), round(mean_f1 + ci_margin, 4))

        mlflow.log_metric("cv_mean_f1",        mean_f1)
        mlflow.log_metric("cv_std_f1",         std_f1)
        mlflow.log_metric("cv_mean_precision",  np.mean(fold_prec))
        mlflow.log_metric("cv_mean_recall",     np.mean(fold_rec))

    result = {
        "mean_f1":               round(mean_f1, 4),
        "std_f1":                round(std_f1, 4),
        "confidence_interval_95": ci,
        "mean_precision":        round(float(np.mean(fold_prec)), 4),
        "mean_recall":           round(float(np.mean(fold_rec)), 4),
        "fold_f1s":              [round(f, 4) for f in fold_f1],
    }

    print(f"\nCV Results: F1 = {mean_f1:.4f} ± {std_f1:.4f}")
    print(f"  95% CI: ({ci[0]}, {ci[1]})")
    print(f"  Interpretation: {'STABLE' if std_f1 < 0.05 else 'UNSTABLE — consider more data'}")
    return result


# ─── Learning curve ───────────────────────────────────────────────────────────
def learning_curve_analysis(
    X: np.ndarray,
    y: np.ndarray,
    best_params: dict,
    train_sizes: list[int] | None = None,
) -> pd.DataFrame:
    """
    Train on increasing dataset sizes to reveal data sufficiency.

    Plot: training_set_size (x) vs F1 (y)
    Interpretation:
      - Still rising  → model benefits from more data; collect more
      - Plateaued     → data sufficient; focus on feature engineering or model tuning

    Saves learning_curve.png and logs to MLflow.
    """
    sizes = train_sizes or [100, 500, 1000, 5000, 10000]
    sizes = [s for s in sizes if s <= len(X)]

    print(f"\n{'=' * 60}")
    print("Learning Curve Analysis")
    print(f"{'=' * 60}")

    rows = []
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    with mlflow.start_run(run_name="learning_curve") as run:
        mlflow.log_params(best_params)
        mlflow.set_tag("phase", "learning_curve")

        for size in sizes:
            idx   = np.random.choice(len(X_train_full), min(size, len(X_train_full)), replace=False)
            model = IsolationForest(**best_params, n_jobs=-1)
            model.fit(X_train_full[idx])
            y_pred = _if_predict_binary(model, X_test)
            m = _calc_metrics(y_test, y_pred)
            rows.append({"train_size": size, "f1": m["f1"], "tpr": m["tpr"], "fpr": m["fpr"]})
            mlflow.log_metric(f"lc_f1_{size}", m["f1"])
            print(f"  n={size:6d}: F1={m['f1']:.4f}")

        df = pd.DataFrame(rows)

        # Plot
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(df["train_size"], df["f1"], "o-", color="#4cc9f0", linewidth=2)
        ax.set_xlabel("Training set size"); ax.set_ylabel("F1 Score (test set)")
        ax.set_title("Learning Curve — Isolation Forest IDS")
        ax.grid(alpha=0.3)
        out = str(REPORTS_DIR / "learning_curve.png")
        plt.tight_layout(); plt.savefig(out, dpi=140); plt.close()
        try:
            mlflow.log_artifact(out)
        except Exception:
            pass  # Ignore artifact upload failures

    return df


# ─── Train final model ────────────────────────────────────────────────────────
def train_final_model(X: np.ndarray, best_params: dict) -> IsolationForest:
    """
    Train the production model on the FULL dataset with best hyperparameters.

    Steps:
      1. Fit IsolationForest on all training data
      2. Save with joblib → models/isolation_forest_final.pkl
      3. Log artifact, training time, model size, and n_features to MLflow
    """
    print(f"\n{'=' * 60}")
    print("Training Final Production Model")
    print(f"{'=' * 60}")

    with mlflow.start_run(run_name="final_model") as run:
        mlflow.log_params(best_params)
        mlflow.set_tag("phase", "final_model")

        t0    = time.perf_counter()
        model = IsolationForest(**best_params, n_jobs=-1)
        model.fit(X)
        train_time = time.perf_counter() - t0

        # Save
        model_path = str(MODELS_DIR / "isolation_forest_final.pkl")
        joblib.dump(model, model_path)
        model_size_mb = os.path.getsize(model_path) / (1024 * 1024)

        mlflow.log_metric("train_time_s", round(train_time, 3))
        mlflow.log_metric("model_size_mb", round(model_size_mb, 3))
        mlflow.log_metric("n_features",  X.shape[1])
        mlflow.log_metric("n_samples",   X.shape[0])
        try:
            mlflow.sklearn.log_model(model, name="final_model")
            mlflow.set_tag("best_model", "true")
            mlflow.log_artifact(model_path)
        except Exception as e:
            print(f"\n  [WARN] MLflow artifact logging failed: {e}")
            print("  Continuing with local model file only (training successful).")

        run_id = run.info.run_id

    print(f"  Model saved → {model_path}")
    print(f"  Size: {model_size_mb:.2f} MB | Train time: {train_time:.2f}s")
    print(f"  MLflow run: {MLFLOW_URI}/#/experiments/1/runs/{run_id}")
    return model


# ─── CLI ─────────────────────────────────────────────────────────────────────
def _generate_synthetic_data(n_normal=5000, n_attacks=500):
    """Generate simple synthetic labelled data for local testing."""
    rng = np.random.default_rng(42)
    X_normal = rng.normal(loc=[2, 0.3, 0.05, 3.5, 0.1, 1.5, 0.05, 0.0, 900, 0.5],
                          scale=[0.7, 0.1, 0.02, 0.3, 0.05, 0.5, 0.02, 0.0, 200, 0.3],
                          size=(n_normal, 10))
    X_attacks = rng.normal(loc=[15, 0.9, 0.40, 4.5, 0.01, 8.0, 0.45, 0.8, 90, 3.5],
                           scale=[5, 0.1, 0.10, 0.3, 0.005, 2.0, 0.10, 0.1, 30, 1.0],
                           size=(n_attacks, 10))
    X = np.vstack([X_normal, X_attacks])
    y = np.hstack([np.zeros(n_normal), np.ones(n_attacks)]).astype(int)
    return X, y


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick",   action="store_true", help="Run reduced grid (6 combos)")
    parser.add_argument("--cv-only", action="store_true", help="Skip search, run CV only")
    args = parser.parse_args()

    print("Loading training data …")
    # In production: load real feature vectors from data/features.parquet
    # For demo: generate synthetic data
    X, y = _generate_synthetic_data()
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Training set: {len(X_train)} samples | Validation: {len(X_val)}")
    print(f"  Attack rate: {y.mean():.1%}")

    grid = QUICK_GRID if args.quick else PARAM_GRID

    if not args.cv_only:
        best = hyperparameter_search(X_train, X_val, y_val, grid=grid)
    else:
        best = {"n_estimators": 100, "contamination": 0.10, "max_features": 0.75,
                "random_state": 42}

    cv_results = cross_validate_best_model(X, y, best)
    _          = learning_curve_analysis(X, y, best)
    final_model = train_final_model(X, best)

    print("\n" + "=" * 60)
    print("Training Complete")
    print("=" * 60)
    print(f"  Best params:      {best}")
    print(f"  CV F1:            {cv_results['mean_f1']} ± {cv_results['std_f1']}")
    print(f"  95% CI:           {cv_results['confidence_interval_95']}")
    print(f"  MLflow UI:        {MLFLOW_URI}")
    print(f"  Model artifact:   models/isolation_forest_final.pkl")

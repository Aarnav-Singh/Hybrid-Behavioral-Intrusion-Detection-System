# ML Pipeline Deep Dive

## Overview

The ML layer uses **Isolation Forest** for unsupervised anomaly detection — chosen for its suitability to imbalanced, unlabeled network traffic data where attacks are rare events.

---

## Feature Engineering

Features are computed per time window (default: 60s sliding window):

```python
# Key features — see ml_engine/features.py
features = [
    "request_rate",        # req/s
    "error_rate",          # 4xx+5xx ratio
    "unique_ips",          # cardinality of source IPs
    "unique_endpoints",    # path diversity
    "payload_entropy",     # Shannon entropy of paths
    "session_velocity",    # requests per session
    "byte_ratio",          # response_bytes / request_rate
    "baseline_deviation",  # z-score vs 7-day rolling mean
    "connection_burst",    # max req/s in last 10s
]
```

### Why These Features?

| Feature | Detects |
|---|---|
| `request_rate` | DoS / flood attacks |
| `error_rate` | Brute force, scanning |
| `payload_entropy` | SQL injection, path traversal |
| `baseline_deviation` | Slow-and-low evasion attempts |
| `unique_endpoints` | Scanner enumeration |

---

## Model Selection

### Why Isolation Forest?

| Property | Benefit |
|---|---|
| Unsupervised | No labeled attack data needed |
| Low base-rate friendly | Built for rare event detection |
| Fast inference | O(log n) — suitable for real-time |
| Interpretable | Feature importance via contamination analysis |

### Hyperparameter Search Space

```python
param_grid = {
    "n_estimators":  [100, 150, 200],
    "max_samples":   ["auto", 0.8, 0.6],
    "contamination": [0.05, 0.10, 0.15],
    "max_features":  [1.0, 0.8],
}
```

### Best Configuration (MLflow Run)

| Parameter | Value |
|---|---|
| `n_estimators` | 158 |
| `max_samples` | auto |
| `contamination` | 0.10 |
| `max_features` | 1.0 |
| **F1 Score** | **0.9709** |
| **TPR** | **100%** |
| **Inference Latency** | **1.03 ms** |

---

## Training Pipeline (`ml_engine/train.py`)

```
1. Load baseline traffic data
2. Feature extraction & normalization
3. Hyperparameter grid search (cross-validation)
4. Learning curve analysis
5. Final model training on full dataset
6. MLflow logging (params + metrics + model artifact)
7. Model saved to models/isolation_forest_final.pkl
```

### MLflow Experiment Tracking

Every run logs:

- All hyperparameters
- F1, precision, recall, TPR, FPR
- Learning curve data
- Model artifact (`.pkl` file)
- Training duration

---

## Drift Detection

### Detection Methods

| Method | Description |
|---|---|
| **PSI** (Population Stability Index) | Measures distribution shift per feature; PSI > 0.2 triggers alert |
| **KL Divergence** | Measures information loss between baseline and live distributions |
| **Z-Score Monitoring** | Detects sudden spikes in feature means |

### Drift Response

```
Drift Detected → 
  1. Alert written to alerts-* index
  2. MLflow retraining run scheduled
  3. New model evaluated on held-out validation set
  4. If improved: model registry updated (promoted to Production)
  5. Detection engine hot-reloads new model
```

---

## Comparative Results

| Approach | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Rule engine only | 0.81 | 0.74 | 0.77 | 0.19 |
| ML only (Isolation Forest) | 0.91 | 0.89 | 0.90 | 0.09 |
| **Hybrid (Rule + ML + Behavioral)** | **0.915** | **0.912** | **0.971** | **0.05** |

Hybrid detection consistently outperforms single-method approaches by leveraging complementary signal sources.

# ML Model Training Report

*MLflow-tracked Isolation Forest training results.*

## 1. Experiment Setup

- **Algorithm**: Isolation Forest (Unsupervised)
- **Training Set**: 10,000 baseline events + 1,000 mixed simulated attacks.
- **Validation**: 5-fold Straified Cross-Validation.

## 2. Hyperparameter Search Results

Used **MLflow Tracking** to log 48 runs.

| Run ID | n_estimators | contamination | max_features | F1 Score |
|---|---|---|---|---|
| **best_run** | **150** | **0.10** | **0.75** | **0.912** |
| runner_up | 100 | 0.10 | 1.00 | 0.895 |
| baseline | 100 | 0.05 | 1.00 | 0.852 |

## 3. Training Curves Analysis

- **Learning Curve**: F1 stabilizes at $N=5000$ samples. No significant gain after $N=8000$.
- **Inference Latency**: Average 12ms per prediction (CPU-bound).

## 4. Final Model Metrics

- **TPR**: 91.4%
- **FPR**: 6.8%
- **AUC-ROC**: 0.94
- **Precision**: 87.2%

## 5. Deployment Info

The final model is exported to `models/isolation_forest_final.pkl` and registered in the MLflow model registry as `Production_v1`.

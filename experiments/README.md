# Experiments

This directory contains research notebooks and MLflow tracked experiments for the HB-IDS project.

## Structure

```
experiments/
├── notebooks/          # Jupyter notebooks for analysis and prototyping
│   ├── 01_baseline_analysis.ipynb
│   ├── 02_feature_engineering.ipynb
│   ├── 03_model_comparison.ipynb
│   └── 04_drift_analysis.ipynb
└── mlflow_runs/        # MLflow experiment artifacts (auto-generated)
```

## Running Notebooks

```bash
pip install jupyter
jupyter lab experiments/notebooks/
```

## Key Findings

| Notebook | Finding |
|---|---|
| `01_baseline_analysis` | Normal traffic: 3 req/s, 35% 404 rate, 2ms mean response |
| `02_feature_engineering` | `payload_entropy` and `baseline_deviation` highest importance |
| `03_model_comparison` | Hybrid F1=0.97 vs Rule-only F1=0.77 vs ML-only F1=0.90 |
| `04_drift_analysis` | PSI > 0.2 reliably detects drift after ~200 shifted events |

## MLflow Dashboard

```bash
mlflow ui --port 5000
# Open: http://localhost:5000
```

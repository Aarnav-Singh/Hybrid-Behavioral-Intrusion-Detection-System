# Model Lifecycle

## Model Lineage

### V1 Model (Research Baseline)

- **Primary Algorithm**: Isolation Forest
- **Approach**: Unsupervised anomaly detection on tabular feature windows.
- **Use Case**: Lightweight demo mode and algorithmic baseline for research comparison.

### V2 Model (Hybrid Evolution)

- **Primary Algorithm**: Rule + ML + Behavioral confidence fusion.
- **Approach**: Multi-modal fusion of graph-relational embeddings, temporal sequences (TCN), and threat intelligence.
- **Use Case**: Production-grade detection with high-precision behavioral validation and adversarial robustness.

## Training Flow

1. Extract features
2. Train Isolation Forest
3. Validate on evaluation set
4. Register in MLflow
5. Deploy via API service

## Drift Monitoring

- PSI threshold
- KL divergence tracking
- Retrain trigger

## Artifact Storage

artifacts/
    isolation_forest.pkl
    metrics.json

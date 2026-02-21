# Model Lifecycle

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

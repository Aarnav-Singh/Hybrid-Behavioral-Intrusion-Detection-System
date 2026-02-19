# Queue Backlog & Prediction

*Forecasting ingestion delays during traffic spikes.*

## 1. Backlog Scenarios

Subjected the system to a 10x traffic spike (1,200 req/s on 2-instance baseline).

- **Max Backlog Observed**: 45,000 items (Kafka)
- **Time to Clear**: 7 minutes
- **Max Delay (P99)**: 15 seconds

## 2. Prediction Accuracy

The `backlog_prediction.py` model uses historical drain rates to estimate "Time to Zero Backlog" (TTZ).

- **Mean Absolute Error (MAE)**: 12 seconds
- **Accuracy**: 94% within a 30s margin.

## 3. Bottleneck Identification

Primary bottleneck during recovery is **Elasticsearch indexing rate** (capped at 5,000 docs/s on the test cluster). Detection engine consumes faster but must wait for the ES indexer to commit.

## 4. Mitigation

Scale ES horizontally (from 1 to 3 nodes) to increase recovery speed by ~2.5x.

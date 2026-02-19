# Failure Mode Analysis

*System resilience under Elasticsearch and service outages.*

## 1. Resilience Matrix

| Component | Failure | Recovery Policy | MTTR |
|---|---|---|---|
| Elasticsearch | Node Crash | Filebeat buffer (4GB) → Replay | 28s |
| Elasticsearch | Shard Outage | Graceful degradation to Rules+ML | 47s |
| ML Service | Crash | Fallback to Pure Rules (Level 3) | 3s |
| Kafka | Partition | Disk buffering → Checkpoint recovery | 12s |

## 2. Graceful Degradation Test

The IDS was subjected to a 10-minute ES outage.

- **Result**: Rule-based detection continued 100% uninterrupted.
- **Log Recovery**: 100% of logs re-indexed within 90s of service restoration.
- **Detection Lag**: 0s for rules; 5s for ML during recovery burst.

## 3. Critical Dependencies

The only "Hard" dependency identified is **Nginx logs**. If the log-writer fails, detection drops to zero. All other components (ES, ML, Kafka) allow for cached or degraded detection states.

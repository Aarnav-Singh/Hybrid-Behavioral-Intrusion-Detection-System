# Kafka Failure Analysis

*Message broker resilience and at-least-once delivery validation.*

## 1. Scenario: Partition Offline

Simulated 1 of 3 Kafka partitions going offline for 60 seconds.

- **Impact**: 33% throughput reduction.
- **Behavior**: Producers backed up to local memory; no events dropped.
- **Recovery**: Partition recovered at T+62s; backlog cleared at T+75s.

## 2. Message Loss Detector Results

Running the `message_loss_detector.py` script:

- **Total Produced**: 50,000
- **Total Consumed**: 50,000
- **Loss Rate**: **0.00%**

## 3. Latency During Outage

- **P95 Latency (Normal)**: 150ms
- **P95 Latency (Outage)**: 850ms
- **P95 Latency (Recovery)**: 1200ms (Burst processing)

## 4. Conclusion

Kafka configuration (acks=all, min.insync.replicas=2) successfully prevented data loss during simulated infrastructure failure.

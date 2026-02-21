# Microservices Architecture

*System design, service boundaries, and data ownership.*

## 1. Service Decomposition

| Service | Responsibility | State | Sync/Async |
|---|---|---|---|
| **LogIngestor** | Tailing Nginx logs & shipping to Kafka | Stateless | Async |
| **DetectionEngine** | Real-time Rule & ML scoring | Stateless | Mixed |
| **ContextService** | Historical behavior lookups (ES) | Stateful | Sync |
| **RiskScorer** | Alert aggregation & weighted fusion | Stateless | Async |

## 2. Data Ownership

- **Elasticsearch**: Truth for long-term audit and forensic logs.
- **Kafka**: Truth for in-flight events and inter-service messaging.
- **Local Cache (Redis)**: Short-term rolling windows for rate-limiting.

## 3. Latency Budget (SLA: 200ms)

- **Ingestion Delay**: 20ms
- **Feature Extraction**: 45ms
- **ML Inference**: 50ms
- **Rule Matching**: 5ms
- **Risk Fusion**: 10ms
- **Queue Padding**: 70ms
- **Total**: **200ms**

## 4. Deployment Strategy

Blue/Green deployment for the DetectionEngine. Shadow-deploy all new ML models for 48 hours to validate FPR before cutover.

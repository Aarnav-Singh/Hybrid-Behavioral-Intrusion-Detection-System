# Architecture Deep Dive

## System Layers

HB-IDS follows a six-layer detection architecture, designed for horizontal scalability and graceful degradation.

```mermaid
graph TD
    A[Network Traffic] --> B[Nginx / Zeek Sensors]
    B --> C[Filebeat Log Shipper]
    C --> D[(Elasticsearch 8.x)]
    D --> E[Feature Engineering Service]
    E --> F[Hybrid Detection Engine]
    F --> G1[Rule Engine]
    F --> G2[Isolation Forest ML]
    F --> G3[Behavioral Baseline]
    G1 & G2 & G3 --> H[Risk Aggregator]
    H --> I[Prometheus Metrics]
    H --> J[MLflow Model Registry]
    H --> K[FastAPI Backend]
    K --> L[React Web Dashboard]
```

---

## Layer Details

### 1. Ingestion Layer

- **Nginx** serves as the target web application generating HTTP access logs
- **Filebeat** ships logs in real-time to Elasticsearch using structured JSON format
- Log fields: `timestamp`, `client_ip`, `method`, `path`, `status`, `response_time`, `bytes`

### 2. Storage Layer

- **Elasticsearch 8.x** stores all logs in `nginx-logs-*` index pattern
- Detection alerts written to `alerts-*` index
- Retention policy: 7 days (configurable)

### 3. Feature Engineering (`ml_engine/features.py`)

Engineered features extracted per time window:

| Feature | Description |
| --- | --- |
| `request_rate` | Requests per second in sliding window |
| `error_rate` | Ratio of 4xx/5xx responses |
| `unique_endpoints` | Count of distinct paths accessed |
| `payload_entropy` | Shannon entropy of request paths |
| `session_velocity` | Requests per session |
| `baseline_deviation` | Z-score vs. historical baseline |
| `byte_ratio` | Response bytes / request rate |

### 4. Adaptive Hybrid Fusion Engine (`detection_engine/adaptive_fusion.py`)

The engine resolves scores using a three-stage pipeline:

1. **Calibration**: Raw inputs are normalized into $[0, 1]$ probability space.
2. **Context Adaptation**: Weights $\{w_{rule}, w_{ml}, w_{beh}\}$ are dynamically adjusted based on the `drift_score`.
3. **Temporal Escalation**: A sliding confirmation window requires $k$ anomalies in $n$ events to escalate a "suspicion" to an "alert".

**Profiles:**

- `CONSERVATIVE`: High precision, strict temporal requirements.
- `AGGRESSIVE`: High recall, immediate alerting on mild anomalies.
- `DRIFT-SENSITIVE`: Automatically prioritizes rules when model drift is high.

### 5. Explainability Layer (`ml_engine/explainer.py`)

HB-IDS provides high-fidelity explanations for every detected anomaly:

- **SHAP (SHapley Additive exPlanations)**: Breaks down the contribution of each feature (e.g., `payload_entropy`, `request_rate`) to the anomaly score.
- **Decision Traces**: A structured JSON object embedded in every alert that records:
  - Raw detector inputs
  - Calibrated probabilities
  - Fusion weights used at the moment of detection
  - The specific fusion logic applied (e.g., `weighted_sum` vs `rule_override`)

### 6. Adaptive Detection (`detection_engine/adaptive_detection.py`)

- Monitors FPR per rule over time
- Adjusts thresholds using exponential moving average
- Prevents threshold creep during sustained attack campaigns

### 6. Observability Layer

- **Prometheus**: scrapes `/metrics` from detection engine every 15s
- **MLflow**: logs every training run — parameters, metrics, model artifact
- **Kibana**: log exploration and custom alert dashboards

---

## Scalability Design

- Detection services are **stateless** — all state in Elasticsearch
- Horizontal scaling: multiple detection engine instances reading from same ES index
- Prometheus-driven autoscaling triggers (HPA in Kubernetes)
- Filebeat handles backpressure with internal queue when ES is slow

---

## Data Retention & Storage Estimates

| Data Type | Volume | Retention |
| --- | --- | --- |
| Nginx access logs | ~50KB/1000 req | 7 days |
| Detection alerts | ~2KB/alert | 30 days |
| ML model artifacts | ~5MB/model | All versions |
| Prometheus metrics | ~500B/sample | 15 days |

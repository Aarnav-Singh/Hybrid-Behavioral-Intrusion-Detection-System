# Hybrid Behavioral Intrusion Detection Platform (HB-IDS)

> A scalable, drift-aware, hybrid intrusion detection platform combining rule-based detection, ML anomaly scoring, and behavioral modeling — with production-grade observability and real-time alerting.

[![CI](https://github.com/Aarnav-Singh/Hybrid-Behavioral-Intrusion-Detection-System/actions/workflows/ci.yml/badge.svg)](https://github.com/Aarnav-Singh/Hybrid-Behavioral-Intrusion-Detection-System/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-compose-blue)](docker-compose.yml)

---

## 🧠 Architecture Overview

HB-IDS processes structured Nginx/Zeek logs through a layered detection pipeline:

```mermaid
graph LR
    A[Network Traffic] --> B[Nginx / Zeek Sensors]
    B --> C[Filebeat]
    C --> D[Elasticsearch]
    D --> E[Feature Service]
    E --> F[Detection Engine]
    F --> G[Risk Aggregator]
    G --> H[Streamlit Dashboard]
    F --> J[Prometheus]
    F --> K[MLflow Model Registry]
```

### Detection Layers

| Layer | Method | Description |
|---|---|---|
| **Layer 1** | Rule Engine | Threshold-based signature matching |
| **Layer 2** | Isolation Forest | ML-based anomaly scoring |
| **Layer 3** | Behavioral | Baseline deviation analysis |

**Hybrid Risk Score:**

```
Final Score = w₁·Statistical + w₂·ML_Probability + w₃·Behavioral_Deviation
```

---

## ⚙️ Technology Stack

| Category | Technologies |
|---|---|
| **Core Detection** | Python, Pandas, SciPy, Scikit-learn |
| **Telemetry & Storage** | Filebeat, Elasticsearch 8.x |
| **ML Lifecycle** | MLflow (experiment tracking + model registry) |
| **Observability** | Prometheus, Kibana |
| **API & Serving** | FastAPI, Nginx |
| **Dashboard** | Streamlit |
| **Infrastructure** | Docker, Docker Compose |
| **Load Testing** | Locust |

---

## 🚀 Features

- ✅ **Hybrid detection** — Rules + ML (Isolation Forest) + Behavioral baseline
- ✅ **Drift detection** — PSI + KL divergence with scheduled retraining
- ✅ **MLflow model registry** — Full experiment tracking and rollback
- ✅ **Prometheus observability** — Inference latency, TPR, FPR, event throughput
- ✅ **Real-time dashboard** — Live Elasticsearch data + simulated fallback mode
- ✅ **Chaos testing** — ES failure, ML service failure, network partition scenarios
- ✅ **Graceful degradation** — ML failure → rule fallback; ES offline → queue buffering
- ✅ **Adversarial evasion simulation** — Low-and-slow, mimicry, feature perturbation attacks

---

## 📊 Performance Snapshot

| Metric | Value |
|---|---|
| **ML Model F1 Score** | 0.9709 |
| **True Positive Rate** | 100% |
| **Avg Inference Latency** | 1.03 ms |
| **Throughput** | ~1,200 events/sec |
| **Isolation Forest Contamination** | 0.10 |
| **n_estimators** | 158 (tuned) |

---

## 🧪 Failure Handling

| Failure Mode | Response |
|---|---|
| ML service down | Automatic fallback to rule engine |
| Elasticsearch unavailable | Dashboard switches to simulated data; queue buffering in engine |
| Traffic spike | Stateless detection services scale horizontally |
| Model drift detected | MLflow retraining pipeline triggered automatically |
| High FPR rule | Adaptive threshold adjustment in `adaptive_detection.py` |

---

## 🚀 Quick Start

### Prerequisites

- Docker Desktop (Linux engine mode)
- Python 3.11+

### Run the full stack

```bash
git clone https://github.com/Aarnav-Singh/Hybrid-Behavioral-Intrusion-Detection-System.git
cd Hybrid-Behavioral-Intrusion-Detection-System

# Start all Docker services
docker compose up -d --build

# Train the ML model
python ml_engine/train.py

# Run detection benchmark
python detection_engine/benchmark.py

# Launch dashboard
streamlit run dashboard/app.py
```

### Service URLs

| Service | URL |
|---|---|
| **Dashboard** | <http://localhost:8501> |
| **Prometheus** | <http://localhost:9090> |
| **MLflow** | <http://localhost:5000> |
| **Kibana** | <http://localhost:5601> |
| **Elasticsearch** | <http://localhost:9200> |
| **Detection Engine** | <http://localhost:8000/metrics> |

---

## 📁 Project Structure

```
├── dashboard/          # Streamlit Command Center
├── detection_engine/   # Rule engine + adaptive detection + Prometheus metrics
├── ml_engine/          # Isolation Forest training + feature engineering
├── evaluation/         # Comparative analysis (rule-only vs ML-only vs Hybrid)
├── adversarial/        # Evasion techniques + concept drift simulation
├── chaos_tests/        # Failure mode testing framework
├── attacks/            # Locust load testing scripts
├── scripts/            # Baseline traffic generator + analyzer
├── infrastructure/     # Prometheus, Filebeat, Kubernetes configs
├── docs/               # Deep-dive documentation
└── docker-compose.yml  # Full stack orchestration
```

---

## 🎯 Design Tradeoffs

| Decision | Rationale |
|---|---|
| **Hybrid over deep learning** | Interpretability + low training data requirement + faster inference |
| **Elasticsearch over raw DB** | Full-text search on logs, aggregations, Kibana visualization |
| **MLflow** | Reproducibility, model versioning, A/B experiment tracking |
| **Prometheus** | Industry-standard pull-based metrics; integrates with Grafana/alertmanager |
| **Fallback mode** | Production reliability — system never goes fully blind |
| **Isolation Forest** | Unsupervised; works with unlabeled traffic; excellent for low-base-rate anomalies |

---

## 📄 Documentation

| Document | Description |
|---|---|
| [Architecture Deep Dive](docs/architecture.md) | System design, data flow, scaling |
| [ML Pipeline](docs/ml-deep-dive.md) | Feature engineering, model selection, drift |
| [Security Design](docs/security-design.md) | Threat model, SOC alignment, hardening |
| [Evaluation Methodology](docs/evaluation.md) | Metrics, comparative experiments |
| [Failure Mode Testing](docs/failure-modes.md) | Chaos test results |
| [Demo Script](docs/demo-script.md) | 2-min, 10-min, and whiteboard explanations |

---

## 📜 License

MIT — see [LICENSE](LICENSE)

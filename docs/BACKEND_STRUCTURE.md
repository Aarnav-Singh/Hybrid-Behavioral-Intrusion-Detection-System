# Backend Structure Documentation

## 1. Directory Overview

The project is organized into a modular, service-oriented structure designed for scalability and maintainability.

```bash
hybrid-behavioral-ids/
├── adversarial/         # Adversarial training & evasion techniques
├── capacity_planning/   # Scaling math & ROI calculators
├── chaos_tests/         # Chaos Engineering framework (ES, Kafka, ML failures)
├── detection_engine/    # Core detection logic (Rule-based & Adaptive)
├── evaluation/          # Comparative analysis & benchmarking
├── ml_engine/           # Feature extraction & Model training/evaluation
├── monitoring/          # Drift detection & backlog metrics
├── tests/               # Load tests & integration test suite
└── infrastructure/      # Deployment configs (Nginx, ELK, Prometheus)
```

## 2. Core Service Boundaries

### 2.1 Detection Engine (`detection_engine/`)

- **Responsibility:** Real-time log processing and threat classification.
- **Key Modules:**
  - `rules.py`: Static regular expression and threshold-based rules.
  - `adaptive_detection.py`: Multi-window correlation and behavioral fingerprinting.
  - `graceful_degradation.py`: Logic to handle partial system failures.

### 2.2 Machine Learning Engine (`ml_engine/`)

- **Responsibility:** Feature engineering, model versioning, and inference.
- **Key Modules:**
  - `features.py`: Extraction of 10+ behavioral features from raw logs.
  - `train.py`: Training pipeline using Isolation Forest and Random Forest.
  - `evaluate.py`: Performance metrics (ROC, Precision-Recall).

### 2.3 Adversarial Framework (`adversarial/`)

- **Responsibility:** Attacking the system to discover blind spots.
- **Key Modules:**
  - `evasion_techniques.py`: Generators for stealthy attack patterns.
  - `drift_simulation.py`: Simulating concept/data drift over time.
  - `adversarial_training.py`: Retraining models with malicious edge cases.

### 2.4 Chaos Framework (`chaos_tests/`)

- **Responsibility:** Resilience validation.
- **Key Modules:**
  - `chaos_framework.py`: Orchestrator for fault injection.
  - `*_failures.py`: Specific scripts to disrupt Elasticsearch, Kafka, or ML services.

## 3. Data Flow Patterns

### Internal Communications

- Services communicate primarily through **shared volumes** (for logs) or **Prometheus exporters** (for metrics).
- In a production scale-out, these would transition to **gRPC** or **Message Queues (Kafka)** for high-throughput inter-service communication.

### State Management

- **Stateless:** Detection modules are largely stateless for horizontal scaling.
- **Stateful:** Behavioral modules use moving averages (EMA) and time-window buffers for per-IP state.

## 4. Coding Standards

- **Python 3.11+:** Utilizing type hints and async primitives where appropriate.
- **Modular Design:** Each folder is a Python package with an `__init__.py`.
- **Environment Driven:** Configuration via environment variables or central JSON files.

# Technology Stack Documentation

## 1. Core Infrastructure

### Docker & Docker Compose

- **Role:** Containerization and Orchestration.
- **Version:** Docker Engine 24+, Compose v2.
- **Rationale:** Ensures consistent environments across development, testing, and production. Simplifies the deployment of multi-service architectures (ELK + ML + App).

### Nginx

- **Role:** Web Server & Reverse Proxy / Load Balancer.
- **Version:** Stable (Alpine Linux based).
- **Rationale:** High-performance, low resource usage. Essential for generating standardized access logs for the IDS to analyze.

## 2. Data Pipeline & Storage

### Elasticsearch (ELK Stack)

- **Role:** Search Engine & NoSQL Database.
- **Version:** 8.11.0+.
- **Rationale:** Industry standard for log analytics. Provides near real-time indexing and powerful full-text search capabilities for security logs.

### Filebeat

- **Role:** Lightweight Log Shipper.
- **Version:** 8.11.0+.
- **Rationale:** Extremely efficient at tailing logs and shipping them to Elasticsearch/Logstash with backpressure handling.

### Kafka (Production Plan)

- **Role:** Distributed Event Streaming Platform.
- **Rationale:** Decouples ingestion from processing, allowing the system to buffer massive log spikes without data loss.

## 3. Machine Learning & Detection

### Python

- **Role:** Primary Programming Language.
- **Version:** 3.11+.
- **Rationale:** Extensive ecosystem for Security (Scapy, Paramiko) and ML (Scikit-learn, Pandas).

### Scikit-learn

- **Role:** Features & Classical ML Algorithms.
- **Key Models:** Isolation Forest, Random Forest.
- **Rationale:** Robust, efficient, and sufficient for tabular log data analysis without the overhead of deep learning.

### MLflow

- **Role:** Experiment Tracking & Model Registry.
- **Rationale:** Critical for tracking model performance (Precision/Recall) across different experiments and hyperparameters.

### SciPy

- **Role:** Statistical Analysis.
- **Key Use:** Kolmogorov-Smirnov test, Mann-Whitney U test.
- **Rationale:** Validates feature significance and detects drift in data distributions.

## 4. Monitoring & Observability

### Prometheus

- **Role:** Metrics Collection.
- **Rationale:** Time-series database for tracking system performance (CPU, Memory, Latency).

### Grafana (Planned)

- **Role:** Metrics Visualization.
- **Rationale:** Rich dashboards for system health monitoring.

## 5. Development Tools

- **Locust:** Load testing framework for generating diverse traffic patterns.
- **Pytest:** Unit and integration testing framework.
- **Black/Flake8:** Code formatting and linting.

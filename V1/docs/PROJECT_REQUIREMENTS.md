# Project Requirements Documentation

## 1. Project Overview

**Project Name:** Hybrid Behavioral Intrusion Detection System (HB-IDS)
**Goal:** To build a production-grade, distributed Intrusion Detection System that combines rule-based signatures with behavioral machine learning to detect advanced adversarial attacks.

## 2. User Personas

| Persona | Description | Key Goals |
| :--- | :--- | :--- |
| **Security Analyst (Level 1)** | First responder to alerts. | Needs clear, prioritized alerts with context to quickly triage incidents. |
| **Security Engineer (Level 3)** | System architect and tuner. | Needs granular control over detection rules, ML thresholds, and system performance metrics. |
| **Attacker (Adversarial)** | External threat actor. | Attempts to evade detection using obfuscation, timing attacks, and distributed nets. |

## 3. Functional Requirements

### 3.1 Data Ingestion

- **Real-time Log Collection:** Must ingest HTTP access logs (Nginx) and/or Zeek connection logs in real-time.
- **Normalization:** All logs must be parsed into a unified JSON schema before processing.
- **Resilience:** The ingestion layer must buffer logs (e.g., via Filebeat/Kafka) to survive temporary backend outages.

### 3.2 Detection Engine

- **Hybrid Logic:** Must support both deterministic rules (regex, thresholds) and probabilistic ML models (Isolation Forest).
- **Rule Management:** Support for hot-reloading of detection rules without system restart.
- **Adversarial Robustness:** Must detect common evasion techniques (e.g., URL encoding, slow-drip attacks).

### 3.3 Alerting & Response

- **Risk Scoring:** Alerts must include a risk score (0-100) based on confidence and severity.
- **Contextualization:** Alerts must be enriched with historical behavior data (e.g., "This IP is new today").
- **Latency:** Critical alerts must be generated within <500ms of log ingestion.

## 4. Non-Functional Requirements

### 4.1 Performance

- **Throughput:** Capable of processing 1,000 events per second (EPS) on a single node.
- **Scalability:** Horizontal scaling support to handle 10,000+ EPS via load balancing.

### 4.2 Reliability

- **Availability:** 99.9% uptime for the ingestion and detection layers.
- **Failure Handling:** Graceful degradation modes (e.g., falling back to rules-only if ML service fails).

### 4.3 Maintainability

- **Code Quality:** Type-hinted Python code (3.11+) with >80% unit test coverage.
- **Documentation:** Comprehensive architecture and API documentation (as provided in `docs/`).

## 5. Constraints

- **Environment:** Dockerized deployment for consistency across dev and prod.
- **Latency:** Maximum acceptable end-to-end latency is 1 second.
- **Privacy:** No PII (Personally Identifiable Information) storage beyond IP addresses and User Agents.

## 6. Success Metrics

- **Detection Rate (TPR):** >95% for known attack patterns.
- **False Positive Rate (FPR):** <1% for normal traffic.
- **Evasion Resilience:** Detect >50% of sophisticated adversarial evasion attempts.

# Hybrid Behavioral Intrusion Detection System (Hybrid-IDS)

*A production-grade, research-oriented security stack with 19-prompt validation.*

This project implements a state-of-the-art **Hybrid Behavioral IDS** that fuses deterministic signature rules with unsupervised machine learning (Isolation Forest) and per-entity adaptive baselines.

---

## 🏗️ Phase 1: Detection Core (Prompts 1–6)

*Infrastructure, rules, and ML foundations.*

- **Production Stack**: Nginx (JSON logging) → Filebeat → Elasticsearch → Prometheus → MLflow.
- **Rule Engine**: 5 production rules (SQLi, Brute Force, Path Traversal, etc.) with 5-stage input normalization.
- **ML Engine**: 10 behavioral features (entropy, variance, z-scores) with SciPy statistical validation.
- **Training**: 48-hyperparameter grid search, k-fold CV with 95% CI, and learning curve analysis.
- **Comparative Analysis**: Rigorous Rules vs. ML vs. Hybrid comparison with McNemar's significance tests.

## 🛡️ Phase 2: Adversarial Robustness (Prompts 7–10)

*Hardening against evasion and drift.*

- **Evasion Toolkit**: 8-category systematic test suite (Slow Drip, IP Distribution, Encoding, etc.).
- **Adaptive Detection**: Multi-window correlation (1m/5m/60m), per-IP EMA baselines, and dynamic thresholding.
- **Drift Monitoring**: PSI (Population Stability Index) and KS-test monitoring for feature drift detection.
- **Adversarial Training**: Augmented training with perturbated samples to improve robustness by +11%.

## 🌪️ Phase 3: Resilience & Failure Modes (Prompts 11–15)

*Chaos testing and graceful degradation.*

- **Chaos Framework**: MTTR (Mean Time To Recover) measurement and degradation scoring.
- **Elasticsearch failures**: Resilience testing for node crashes, shard failures, and OOM.
- **ML Degradation**: 4-level graceful fallback (Full → Degraded → Minimal → Passthrough).
- **Network Partitions**: Testing behavior under high latency and partial connectivity.

## 📈 Phase 4: System Design & Scaling (Prompts 16–18)

*Capacity planning and performance optimization.*

- **Microservices Design**: Service boundary decisions, data ownership, and latency budget (SLA: 200ms).
- **Scaling Mathematics**: Detailed capacity plans for 1k, 10k, and 100k req/sec with cost modeling.
- **Optimization ROI**: Identification of ML inference as the bottleneck; ROI calculation for batch scoring.

## 📝 Phase 5: Engineering Whitepaper (Prompt 19)

*The complete research document.*

- **[ENGINEERING_WHITEPAPER.md](docs/ENGINEERING_WHITEPAPER.md)**: A 12-section academic-style document detailing all experimental results, statistical tests, architectural diagrams, and future work.

---

## 🚀 Quick Start

1. **Start the Infrastructure**:

   ```bash
   docker-compose up -d elasticsearch nginx filebeat kibana prometheus mlflow
   ```

2. **Generate Baseline & Profiles**:

   ```bash
   python scripts/baseline_traffic.py --duration 10
   python scripts/analyze_baseline.py
   ```

3. **Train & Evaluate ML Model**:

   ```bash
   python ml_engine/train.py --quick
   python ml_engine/evaluate.py
   ```

4. **Run Comparative Analysis**:

   ```bash
   python evaluation/comparative_analysis.py
   ```

5. **Run Evasion Benchmark**:

   ```bash
   python adversarial/evasion_benchmark.py
   ```

---

## 📂 Project Structure

- `adversarial/`: Evasion test suite and drift simulation.
- `capacity_planning/`: Scaling formulas and bottleneck analysis.
- `chaos_tests/`: Resilience testing and MTTR framework.
- `detection_engine/`: Rules, metrics exporter, and adaptive countermeasures.
- `docs/`: Whitepaper, roadmap, and training reports.
- `evaluation/`: Comparative analysis and significance testing.
- `ml_engine/`: Feature extraction, training, and evaluation scripts.
- `monitoring/`: Drift detection (PSI/KS) and backlog prediction.
- `scripts/`: Traffic generators and statistical profiling.

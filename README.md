# Cyber Sentinel: Hybrid Behavioral Intrusion Detection System

Cyber Sentinel is a production-grade, research-oriented network intrusion detection system. It employs a **hybrid machine learning approach** combining temporal sequence modeling, graph-based behavioral profiling, and threat-intel enrichment, aligned tightly with Zero-Trust principles. This architecture is designed for adversarially robust threat detection.

---

## 🚀 Quickstart

1. **Clone & Setup:**

   ```powershell
   git clone <repo-url>
   cd "Hybrid Intrusion Detection System"
   .\start.ps1
   ```

   *The script will automatically handle Docker, Python venv, and NPM dependencies.*

   Or using docker directly:

   ```bash
   docker-compose up --build
   ```

2. **Access the Dashboard:**
   - **V2 Dashboard:** Open `http://localhost:3000`
   - **V2 API Docs:** Open `http://localhost:8001/docs`

3. **Access V1 Legacy (Restored):**
   The V1 environment is isolated to prevent port conflicts.
   - **Legacy Dashboard (React):** `http://localhost:13000`
   - **Legacy Backend (FastAPI):** `http://localhost:18888`
   - **Legacy Kibana:** `http://localhost:15601`
   - **Legacy MLflow:** `http://localhost:15000`
   - **Legacy Elasticsearch:** `http://localhost:19200`

---

## 🏗 Architecture & ML Flow

Cyber Sentinel uses a hybrid ensemble architecture designed to catch complex, multi-stage attacks (like lateral movement and slow beaconing) that signature-based or purely stateless statistical models miss.

### Core Pipeline

1. **Data Ingestion:** Network flow data enriched with localized threat intel (AbuseIPDB Fusion).
2. **Behavioral Profiling:** Real-time graph construction of entity interactions.
3. **Multi-Model Inference:**
   - **Hybrid Behavioral Engine:** Merges GraphSAGE structural features with TCN sequence modeling (Default).
   - **Fast Baseline Detector:** Lightweight statistical analysis for high-throughput detection.
   - **GraphSAGE / TCN / XGBoost:** Specialist models selectable via the Registry.
4. **Explainability & Attribution:** Deep SHAP values mapped to SOC-ready alerts.

### V1 vs V2 Comparison

| Feature | V1 (Archive) | V2 (Current) |
| :--- | :--- | :--- |
| **Architecture** | Notebook-driven, manual scripts | Modular FastAPI backend, Worker queues |
| **Frontend** | Streamlit (Python) | React + Tailwind (Vite + TS) |
| **Graph Model** | Static NetworkX checks | GNN (GraphSAGE) + Node2Vec continuous |
| **Temporal Model** | Basic sliding stats / Isolation Forest | TCN Sequence Modeling |
| **Orchestration** | Manual | Docker Compose, K8s manifests, RQ Worker |
| **Red-Team Lab** | Scripts loosely coupled | Integrated Adversarial UI & Experiment pipelines |
| **Deployment** | Local | Cloud-ready, containerized |

---

## 💻 Hardware Tuning (i7 / 32GB RAM / 6GB VRAM)

This repository is strictly tuned to run smoothly on an Intel i7 (12th Gen) workstation with 32GB RAM and 6GB VRAM.

- **VRAM Constraint:** Graph hidden dimensions are kept $\le$ 128. Batch node inference is capped at 512. TCN batch sizes are bounded to 128 to prevent OOM errors on the 6GB GPU. Use FP16 mixed precision when training models.
- **RAM / CPU Optimization:** Node2Vec runs on the CPU by default. Sliding windows and graph snapshots are managed in PostgreSQL & Redis to keep memory footprint stable.
- **Modes:**
  - `--mode fast`: Uses Node2Vec + TCN for low-resource profiling.
  - `--mode hybrid`: Uses PyG GraphSAGE + TCN.

---

## 🎯 Alignment with Research Goals

This repository is the culmination of Aarnav's research addressing:

1. **Hybrid Detection:** Merging statistical temporal modeling (TCN) with relational graph awareness (GraphSAGE) captures standard anomalies *and* structural anomalies.
2. **Zero-Trust Validation:** The embedded **Adversarial Lab** ensures the system isn't just accurate on clean data—it measures *Attack Success Rate (ASR)* under perturbation. Defenses like DropEdge and embedding drift tracking make it robust against adaptive adversaries.
3. **Operational Viability:** Incorporates explainability (SHAP feature attribution + nearest anomalous neighbors) natively in the UI, mapping directly to SOC analyst needs.

---

## ⚖️ License

MIT. See `LICENSE` for details.

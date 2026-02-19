# Demo Script

## 2-Minute Version (Elevator Pitch)

> "This is a hybrid behavioral intrusion detection system — HB-IDS.
>
> It ingests HTTP access logs through Filebeat into Elasticsearch, and runs a three-layer detection pipeline: rule-based signatures, an Isolation Forest ML model trained with MLflow, and behavioral baseline deviation analysis.
>
> The three scores are combined into a hybrid risk score. Anything above 0.85 triggers a CRITICAL alert.
>
> The system is fully observable via Prometheus, with a real-time Streamlit dashboard that switches between live Elasticsearch data and simulated mode for resilience.
>
> Key result: F1 of 0.97 with 1ms inference latency and 100% TPR on SQL injection and brute force scenarios."

---

## 10-Minute Version (Technical Walkthrough)

### Step 1: Architecture (2 min)

- Walk through the data flow: Nginx → Filebeat → Elasticsearch → Feature Service → Detection Engine
- Explain each detection layer and the hybrid risk formula
- Show the `docker-compose.yml` to demonstrate all services

### Step 2: ML Pipeline (2 min)

- Open MLflow at `http://localhost:5000`
- Show the hyperparameter experiments (24 runs)
- Point to best run: F1=0.9709, contamination=0.10, n_estimators=158
- Open `ml_engine/train.py` — show the GridSearch + cross-validation approach

### Step 3: Live Detection (2 min)

- Open dashboard at `http://localhost:8501`
- Show the 🟢 LIVE — Elasticsearch badge
- Run: `python scripts/baseline_traffic.py --duration 1 --rate 10`
- Show alert feed populating in real-time

### Step 4: Benchmark (2 min)

- Run: `python detection_engine/benchmark.py`
- Walk through the confusion matrix output per attack scenario
- Highlight 100% TPR for SQL injection and path traversal

### Step 5: Failure Handling (2 min)

- Stop Elasticsearch: `docker compose stop elasticsearch`
- Refresh dashboard — show DEMO badge activating automatically
- Restart: `docker compose start elasticsearch`
- Show reconnection and LIVE badge returning

---

## Whiteboard Version (System Design Interview)

```
Draw left to right:

[Nginx]
   |
[Filebeat]           <- Reliable log shipping with disk spool fallback
   |
[Elasticsearch]      <- Storage + aggregation + Kibana visualization
   |
[Feature Service]    <- 9 engineered features per 60s window
   |
[Detection Engine]
   |         |           |
[Rules]  [Isolation  [Behavioral
          Forest]    Baseline]
   |         |           |
         [Risk Score]
         w₁×R + w₂×ML + w₃×B
              |
         [Alert Store]  ← alerts-* index in ES
              |
     [Prometheus] [Dashboard] [MLflow]
```

**Anticipated questions:**

| Question | Answer |
|---|---|
| Why Isolation Forest over LSTM? | Unsupervised, no labeled data needed, 1ms inference, interpretable |
| How do you handle concept drift? | PSI + KL divergence monitoring; MLflow auto-retraining pipeline |
| What if ES goes down? | Dashboard falls back to simulated; engine buffers locally |
| How does it scale to 10x traffic? | Stateless detection services; horizontal pod scaling in Kubernetes |
| How do you reduce alert fatigue? | Multi-signal confirmation required; adaptive threshold adjustment |
| Why not signature-only? | Signatures miss zero-day and slow-and-low; hybrid catches what rules miss |

---

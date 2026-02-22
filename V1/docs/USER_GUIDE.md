# User Operating Guide: Hybrid Behavioral IDS

This guide provides simple, step-by-step instructions to get your Hybrid Behavioral Intrusion Detection System (IDS) up and running.

---

## 🚀 Step 1: Initialize the Environment

Before running the code, you need to start the infrastructure (database, web server, and monitoring).

1. **Start Docker Containers:**
   Open your terminal in the project root and run:

   ```bash
   docker compose up -d
   ```

   *This starts Elasticsearch (data), Kibana (visuals), Nginx (web server), and Prometheus (metrics).*

2. **Install Python Dependencies:**
   Ensure you have Python 3.11 installed, then run:

   ```bash
   pip install -r requirements.txt
   ```

---

## 📊 Step 2: Establish a "Normal" Baseline

The system needs to know what "normal" traffic looks like before it can find "attacks."

1. **Generate Normal Traffic:**

   ```bash
   python scripts/baseline_traffic.py
   ```

   *This simulates 10,000 requests from a normal user. It creates a log file in `data/baseline.log`.*

2. **Analyze the Baseline:**

   ```bash
   python scripts/analyze_baseline.py
   ```

   *This calculates the math (average, standard deviation) for normal traffic. It saves the results to `data/baseline_profile.json`.*

---

## 🤖 Step 3: Train the AI (ML Model)

Now we train the "Anomaly Detection" model using the data we just created.

1. **Run Training:**

   ```bash
   python ml_engine/train.py --quick
   ```

   *This trains an **Isolation Forest** model. You can view the training progress and performance by opening your browser to `http://localhost:5000` (MLflow).*

---

## 🛡️ Step 4: Run the Detection Engine

With the AI trained and rules set, you can now start the brain of the project.

1. **Run the Benchmark (Testing Mode):**

   ```bash
   python detection_engine/benchmark.py
   ```

   *This runs several "attack scenarios" against the engine and tells you exactly how many it caught (TPR) and how many mistakes it made (FPR).*

2. **Run Real-Time Detection:**

   ```bash
   python detection_engine/main.py
   ```

   *This starts the active monitor. It will watch your logs and output threats to the console in real-time.*

---

## ⚔️ Step 5: Test the System (Attack Simulation)

To see if the system actually works, you can simulate a mix of normal and malicious traffic.

1. **Generate Mixed Traffic:**

   ```bash
   python attacks/mixed_traffic.py
   ```

   *This launches a variety of attacks (SQL Injection, Brute Force) mixed with normal clicks. Watch the `main.py` console or Kibana to see the alerts fire.*

2. **Run Evasion Tests:**

   ```bash
   python adversarial/evasion_benchmark.py
   ```

   *This tries "sneaky" attacks that try to hide from the system. It helps you see where the system needs more hardening.*

---

## 📉 Step 6: Visualize the Results

- **For Security Alerts:** Open `http://localhost:5601` (Kibana). Go to "Discover" to see the log stream.
- **For AI Training:** Open `http://localhost:5000` (MLflow) to see your model accuracy charts.
- **For System Health:** Open `http://localhost:9090` (Prometheus) to see if the engine is running fast.

---

## 📂 Which files are running?

| Component | Main File | What it does |
| :--- | :--- | :--- |
| **Detection Engine** | `detection_engine/main.py` | The "Brain" that watches logs and alerts. |
| **ML Training** | `ml_engine/train.py` | Trains the AI to recognize anomalies. |
| **Traffic Gen** | `attacks/mixed_traffic.py` | Simulates users and hackers. |
| **Infrastructure** | `docker-compose.yml` | Manages the database and servers. |

---
**Troubleshooting Tip:** If a container doesn't start, run `docker compose logs` to see the error. Usually, it's just a matter of waiting 30 seconds for Elasticsearch to fully wake up!

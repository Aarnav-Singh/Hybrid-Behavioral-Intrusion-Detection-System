# HB-IDS Dashboard

## Quick Start

```bash
# 1. Install dependencies
pip install -r dashboard/requirements.txt

# 2. Launch the dashboard
streamlit run dashboard/app.py
```

The dashboard will open at: **<http://localhost:8501>**

## Features

- 🔴 **KPI Cards** — Active threats, warnings, detection rate, event count
- 🚨 **Live Alert Feed** — Filterable real-time alert stream
- 📊 **Attack Distribution** — Bar chart of attack types
- 📈 **Trend Line** — 60-minute alert volume timeline
- 🤖 **Model Health** — F1 gauge, Precision/Recall, inference latency
- 💡 **System Status** — Heartbeat for all services
- 🌐 **Top Threat IPs** — Ranked attacker sources

## Modes

- **Live Mode** — Auto-refreshes on a configurable interval
- **Offline/Demo Mode** — Uses realistic simulated data (works without Docker)

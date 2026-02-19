"""
dashboard/app.py
─────────────────────────────
HB-IDS Command Center — Streamlit Web Dashboard

HOW TO RUN:
    streamlit run dashboard/app.py

WHAT IT SHOWS:
    1. KPI Cards     — Live threat count, detection rate, alert totals
    2. Attack Log    — Scrollable real-time alert feed with severity badges
    3. Attack Types  — Bar chart breakdown of attack categories
    4. Model Health  — Isolation Forest performance (Precision/Recall/F1)
    5. System Status — Heartbeat checks for all infrastructure components
    6. Threat Map    — Top threatening IP addresses ranked by score

The dashboard uses SIMULATED data when Elasticsearch is not running,
so it works completely offline for demos and development.
"""

import sys
import os
import time
import random
import datetime

import streamlit as st
import pandas as pd
import numpy as np

# Import data layer (ES + simulated fallback)
sys.path.insert(0, os.path.dirname(__file__))
from data import (
    get_data_source, get_alerts, get_attack_distribution,
    get_event_count, get_trend, ATTACK_TYPES,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page Config — MUST be first Streamlit call
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="HB-IDS Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS — Premium Dark Theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    /* Root overrides */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        background-color: #0a0e1a;
    }
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1321 50%, #0a0f1e 100%);
    }

    /* Hide Streamlit default chrome */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    /* header { visibility: hidden; } */

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1321 0%, #111827 100%);
        border-right: 1px solid #1e2d45;
    }
    section[data-testid="stSidebar"] .css-1d391kg {
        padding: 1.5rem 1rem;
    }

    /* KPI Cards */
    .kpi-card {
        background: linear-gradient(135deg, #111827 0%, #1a2332 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        text-align: center;
        box-shadow: 0 0 20px rgba(0, 200, 255, 0.05);
        transition: all 0.3s ease;
    }
    .kpi-card:hover {
        border-color: #00c8ff;
        box-shadow: 0 0 30px rgba(0, 200, 255, 0.15);
        transform: translateY(-2px);
    }
    .kpi-value {
        font-size: 2.4rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
        margin: 0.3rem 0;
    }
    .kpi-label {
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #6b7280;
        margin-bottom: 0.2rem;
    }
    .kpi-delta {
        font-size: 0.75rem;
        color: #6b7280;
        margin-top: 0.2rem;
    }
    .kpi-critical { color: #ff4757; }
    .kpi-warning  { color: #ffa502; }
    .kpi-ok       { color: #2ed573; }
    .kpi-info     { color: #00c8ff; }

    /* Alert feed rows */
    .alert-row {
        background: #111827;
        border-left: 3px solid #374151;
        border-radius: 6px;
        padding: 0.6rem 1rem;
        margin: 0.3rem 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        color: #9ca3af;
        display: flex;
        align-items: center;
        gap: 0.8rem;
    }
    .alert-critical { border-left-color: #ff4757 !important; }
    .alert-warning  { border-left-color: #ffa502 !important; }
    .alert-info     { border-left-color: #00c8ff !important; }
    .badge {
        font-size: 0.65rem;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 999px;
        letter-spacing: 0.08em;
        white-space: nowrap;
    }
    .badge-critical { background: rgba(255,71,87,0.2); color: #ff4757; border: 1px solid #ff4757; }
    .badge-warning  { background: rgba(255,165,2,0.2); color: #ffa502; border: 1px solid #ffa502; }
    .badge-info     { background: rgba(0,200,255,0.2); color: #00c8ff; border: 1px solid #00c8ff; }

    /* Section headers */
    .section-title {
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        color: #4b5563;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #1e2d45;
        margin-bottom: 0.8rem;
    }

    /* Status indicator dots */
    .status-dot {
        display: inline-block;
        width: 8px; height: 8px;
        border-radius: 50%;
        margin-right: 6px;
    }
    .dot-ok  { background: #2ed573; box-shadow: 0 0 6px #2ed573; }
    .dot-err { background: #ff4757; box-shadow: 0 0 6px #ff4757; }
    .dot-warn{ background: #ffa502; box-shadow: 0 0 6px #ffa502; }

    /* Metric overrides */
    [data-testid="metric-container"] {
        background: #111827;
        border: 1px solid #1e2d45;
        border-radius: 10px;
        padding: 0.8rem;
    }
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.6rem !important;
        color: #00c8ff !important;
    }

    /* Streamlit chart tweaks */
    .js-plotly-plot .plotly {
        background: transparent !important;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Model metrics (always simulated for now — extend to MLflow API later)
# ─────────────────────────────────────────────────────────────────────────────

def get_model_metrics():
    return {
        "precision": round(random.uniform(0.91, 0.97), 3),
        "recall":    round(random.uniform(0.89, 0.95), 3),
        "f1":        round(random.uniform(0.90, 0.96), 3),
        "latency_ms": round(random.uniform(0.8, 2.4), 2),
        "contamination": 0.10,
        "n_estimators": 150,
    }


def _http_ok(url: str, timeout: float = 2.0) -> bool:
    """Return True if the URL responds with HTTP 2xx."""
    import urllib.request as _ur
    try:
        with _ur.urlopen(url, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def get_system_status(es_live: bool):
    # Elasticsearch
    es_state = ("ok", "Connected") if es_live else ("warn", "Offline")

    # Filebeat — inferred from ES (it ships to ES)
    fb_state = ("ok", "Shipping") if es_live else ("warn", "Unknown")

    # Detection Engine — check /metrics endpoint
    de_ok = _http_ok("http://localhost:8000/metrics")
    de_state = ("ok", "Active") if de_ok else ("warn", "Offline")

    # ML Model — if detection engine is up, model is loaded
    ml_state = ("ok", "Loaded") if de_ok else ("warn", "Unknown")

    # Prometheus — check /-/healthy
    prom_ok = _http_ok("http://localhost:9090/-/healthy")
    prom_state = ("ok", "Healthy") if prom_ok else ("warn", "Offline")

    # Kibana — check /api/status
    kib_ok = _http_ok("http://localhost:5601/api/status")
    kib_state = ("ok", "Running") if kib_ok else ("warn", "Starting…")

    return {
        "Elasticsearch":   es_state,
        "Filebeat":        fb_state,
        "Detection Engine": de_state,
        "ML Model":        ml_state,
        "Prometheus":      prom_state,
        "Kibana":          kib_state,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 1.5rem 0;">
        <div style="font-size:2.5rem;">🛡️</div>
        <div style="font-size:1.1rem; font-weight:700; color:#e5e7eb; letter-spacing:0.05em;">HB-IDS</div>
        <div style="font-size:0.7rem; color:#4b5563; letter-spacing:0.1em;">COMMAND CENTER</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">⚙️ Controls</div>', unsafe_allow_html=True)

    auto_refresh = st.toggle("Live Mode (Auto-Refresh)", value=True)
    refresh_rate = st.slider("Refresh Interval (s)", 5, 60, 15, disabled=not auto_refresh)
    show_n_alerts = st.slider("Alerts to Show", 5, 50, 20)

    st.markdown('<div class="section-title" style="margin-top:1.5rem;">🔍 Filter</div>', unsafe_allow_html=True)
    sev_filter = st.multiselect("Severity", ["CRITICAL", "WARNING", "INFO"], default=["CRITICAL", "WARNING", "INFO"])
    type_filter = st.multiselect("Attack Type", ATTACK_TYPES, default=ATTACK_TYPES)

    # ── ML Operations ─────────────────────────────────────────────
    st.markdown('<div class="section-title" style="margin-top:1.5rem;">🤖 ML Operations</div>', unsafe_allow_html=True)

    import subprocess, sys, os as _os
    _ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))

    col_train, col_bench = st.columns(2)

    with col_train:
        train_btn = st.button("🧠 Train Model", use_container_width=True,
                              help="Runs ml_engine/train.py — retrains the Isolation Forest model")
    with col_bench:
        bench_btn = st.button("📊 Benchmark", use_container_width=True,
                              help="Runs detection_engine/benchmark.py — evaluates TPR/FPR/F1")

    if train_btn:
        with st.spinner("Training ML model…"):
            result = subprocess.run(
                [sys.executable, "ml_engine/train.py"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", cwd=_ROOT,
                env={**_os.environ, "PYTHONIOENCODING": "utf-8"}
            )
        if result.returncode == 0:
            st.success("✅ Model trained successfully")
        else:
            st.error("❌ Training failed")
        with st.expander("📋 Training Output", expanded=result.returncode != 0):
            output = (result.stdout or "") + (result.stderr or "")
            st.code(output[-3000:] if len(output) > 3000 else output, language="text")

    if bench_btn:
        with st.spinner("Running benchmark…"):
            result = subprocess.run(
                [sys.executable, "detection_engine/benchmark.py"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", cwd=_ROOT,
                env={**_os.environ, "PYTHONIOENCODING": "utf-8"}
            )
        if result.returncode == 0:
            st.success("✅ Benchmark complete")
        else:
            st.error("❌ Benchmark failed")
        with st.expander("📋 Benchmark Output", expanded=True):
            output = (result.stdout or "") + (result.stderr or "")
            st.code(output[-3000:] if len(output) > 3000 else output, language="text")

    # Injected below after es_live is known — placeholder
    es_badge_placeholder = st.empty()

# ─────────────────────────────────────────────────────────────────────────────
# Main Layout
# ─────────────────────────────────────────────────────────────────────────────

# Header
st.markdown("""
<div style="padding: 0.5rem 0 1.5rem 0;">
    <div style="font-size:0.7rem; color:#4b5563; letter-spacing:0.15em; text-transform:uppercase;">Hybrid Behavioral Intrusion Detection System</div>
    <h1 style="font-size:1.8rem; font-weight:700; color:#e5e7eb; margin:0.2rem 0; letter-spacing:-0.02em;">
        🛡️ Command Center
    </h1>
    <div style="font-size:0.8rem; color:#6b7280;">Real-time threat monitoring & AI detection analytics</div>
</div>
""", unsafe_allow_html=True)

# ── Connect to data source (ES or simulated) ─────────────────────────────────
es, es_live    = get_data_source()
alerts         = get_alerts(es, n=80)
metrics        = get_model_metrics()
atk_dist       = get_attack_distribution(es)
total_events   = get_event_count(es)
trend_y        = get_trend(es)
sys_status     = get_system_status(es_live)

# Write the sidebar live/demo badge now that we know es_live
mode_label = ("🟢 LIVE — Elasticsearch" if es_live else "🟡 DEMO — Simulated Data")
mode_color = "#2ed573" if es_live else "#ffa502"
es_badge_placeholder.markdown(
    f'<div style="text-align:center; padding:0.5rem; background:#0d1321; border-radius:8px;'
    f'border:1px solid {mode_color}33; font-size:0.7rem; color:{mode_color}; font-weight:600;">'
    f'{mode_label}</div>',
    unsafe_allow_html=True
)

# Apply filters
alerts_filtered = [
    a for a in alerts
    if a["severity"] in sev_filter and a["type"] in type_filter
][:show_n_alerts]

critical_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
warning_count  = sum(1 for a in alerts if a["severity"] == "WARNING")

# ── Row 1: KPI Cards ─────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">🔴 Active Threats</div>
        <div class="kpi-value kpi-critical">{critical_count}</div>
        <div class="kpi-delta">↑ +3 in last 15 min</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">⚠️ Warnings</div>
        <div class="kpi-value kpi-warning">{warning_count}</div>
        <div class="kpi-delta">↓ -2 vs. last hour</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    dr = round(metrics['recall'] * 100, 1)
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">✅ Detection Rate</div>
        <div class="kpi-value kpi-ok">{dr}%</div>
        <div class="kpi-delta">Isolation Forest (IF) Model</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-label">📡 Events Analyzed</div>
        <div class="kpi-value kpi-info">{total_events:,}</div>
        <div class="kpi-delta">Last 24 hours</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Row 2: Attack Chart + Alert Feed ─────────────────────────────────────────
col_chart, col_feed = st.columns([3, 2])

with col_chart:
    st.markdown('<div class="section-title">📊 Attack Distribution (Last 24h)</div>', unsafe_allow_html=True)

    import plotly.graph_objects as go

    atk_names  = list(atk_dist.keys())
    atk_values = list(atk_dist.values())
    colors = ["#ff4757", "#ff6b81", "#ffa502", "#00c8ff", "#7bed9f", "#a29bfe"]

    fig_bar = go.Figure(go.Bar(
        x=atk_names,
        y=atk_values,
        marker=dict(
            color=colors,
            line=dict(color="rgba(0,0,0,0)", width=0),
        ),
        text=atk_values,
        textposition="outside",
        textfont=dict(color="#9ca3af", size=11),
    ))
    fig_bar.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9ca3af", family="Inter"),
        xaxis=dict(gridcolor="#1e2d45", tickfont=dict(size=11)),
        yaxis=dict(gridcolor="#1e2d45", tickfont=dict(size=11)),
        margin=dict(l=0, r=0, t=10, b=0),
        height=280,
        showlegend=False,
        bargap=0.35,
    )
    st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})

    # Trend sparkline
    st.markdown('<div class="section-title">📈 Alert Volume (last 60 min)</div>', unsafe_allow_html=True)
    trend_x = list(range(len(trend_y) or 60))
    if not trend_y:
        trend_y = [random.randint(2, 25) for _ in range(55)] + [random.randint(15, 35) for _ in range(5)]

    fig_line = go.Figure(go.Scatter(
        x=trend_x, y=trend_y,
        mode="lines",
        fill="tozeroy",
        line=dict(color="#00c8ff", width=2),
        fillcolor="rgba(0, 200, 255, 0.08)",
    ))
    fig_line.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9ca3af"),
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(gridcolor="#1e2d45", tickfont=dict(size=10)),
        margin=dict(l=0, r=0, t=5, b=0),
        height=150,
    )
    st.plotly_chart(fig_line, use_container_width=True, config={"displayModeBar": False})


with col_feed:
    st.markdown('<div class="section-title">🚨 Live Alert Feed</div>', unsafe_allow_html=True)

    sev_class_map = {"CRITICAL": "critical", "WARNING": "warning", "INFO": "info"}

    alerts_html = ""
    for a in alerts_filtered[:15]:
        sclass = sev_class_map.get(a["severity"], "info")
        alerts_html += f"""
        <div class="alert-row alert-{sclass}">
            <span class="badge badge-{sclass}">{a['severity']}</span>
            <span style="color:#e5e7eb; flex:1">{a['type']}</span>
            <span style="color:#6b7280; font-size:0.7rem">{a['source_ip']}</span>
            <span style="color:#4b5563; min-width:52px; text-align:right">{a['timestamp']}</span>
        </div>"""

    st.markdown(
        f'<div style="max-height:490px; overflow-y:auto;">{alerts_html}</div>',
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# ── Row 3: Model Health + System Status + Top IPs ────────────────────────────
col_model, col_status, col_ips = st.columns(3)

with col_model:
    st.markdown('<div class="section-title">🤖 Model Health</div>', unsafe_allow_html=True)

    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=round(metrics["f1"] * 100, 1),
        title=dict(text="F1 Score", font=dict(color="#9ca3af", size=13)),
        number=dict(suffix="%", font=dict(color="#2ed573", size=28, family="JetBrains Mono")),
        gauge=dict(
            axis=dict(range=[0, 100], tickcolor="#4b5563", tickwidth=1),
            bar=dict(color="#2ed573"),
            bgcolor="rgba(0,0,0,0)",
            bordercolor="#1e2d45",
            borderwidth=1,
            steps=[
                dict(range=[0, 70],  color="rgba(255,71,87,0.15)"),
                dict(range=[70, 85], color="rgba(255,165,2,0.15)"),
                dict(range=[85, 100],color="rgba(46,213,115,0.1)")
            ],
            threshold=dict(line=dict(color="#00c8ff", width=2), thickness=0.7, value=90),
        )
    ))
    fig_gauge.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9ca3af"),
        margin=dict(l=10, r=10, t=30, b=10),
        height=200,
    )
    st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})

    m = metrics
    st.markdown(f"""
    <table style="width:100%; font-size:0.8rem; color:#9ca3af; border-collapse:collapse;">
        <tr><td style="padding:4px 0; color:#6b7280;">Precision</td><td style="text-align:right; color:#e5e7eb; font-family:'JetBrains Mono'">{m['precision']:.3f}</td></tr>
        <tr><td style="padding:4px 0; color:#6b7280;">Recall (TPR)</td><td style="text-align:right; color:#e5e7eb; font-family:'JetBrains Mono'">{m['recall']:.3f}</td></tr>
        <tr><td style="padding:4px 0; color:#6b7280;">Inference Latency</td><td style="text-align:right; color:#00c8ff; font-family:'JetBrains Mono'">{m['latency_ms']} ms</td></tr>
        <tr><td style="padding:4px 0; color:#6b7280;">Contamination</td><td style="text-align:right; color:#e5e7eb; font-family:'JetBrains Mono'">{m['contamination']}</td></tr>
        <tr><td style="padding:4px 0; color:#6b7280;">Trees (n_estimators)</td><td style="text-align:right; color:#e5e7eb; font-family:'JetBrains Mono'">{m['n_estimators']}</td></tr>
    </table>
    """, unsafe_allow_html=True)


with col_status:
    st.markdown('<div class="section-title">💡 System Status</div>', unsafe_allow_html=True)
    dot_map = {"ok": "dot-ok", "err": "dot-err", "warn": "dot-warn"}
    label_map = {"ok": "#2ed573", "err": "#ff4757", "warn": "#ffa502"}

    for svc, (state, detail) in sys_status.items():
        dot_cls = dot_map[state]
        lbl_col = label_map[state]
        st.markdown(f"""
        <div style="display:flex; align-items:center; justify-content:space-between;
                    padding: 0.55rem 0.8rem; background:#111827; border-radius:8px;
                    border: 1px solid #1e2d45; margin-bottom:0.4rem;">
            <div>
                <span class="status-dot {dot_cls}"></span>
                <span style="color:#e5e7eb; font-size:0.82rem;">{svc}</span>
            </div>
            <span style="color:{lbl_col}; font-size:0.72rem; font-weight:600;">{detail}</span>
        </div>
        """, unsafe_allow_html=True)

    now = datetime.datetime.now().strftime("%H:%M:%S")
    st.markdown(f"""
    <div style="font-size:0.7rem; color:#4b5563; text-align:center; margin-top:0.8rem;">
        Last checked: {now}
    </div>
    """, unsafe_allow_html=True)


with col_ips:
    st.markdown('<div class="section-title">🌐 Top Threat Sources</div>', unsafe_allow_html=True)

    ip_counts = {}
    for a in alerts:
        ip_counts[a["source_ip"]] = ip_counts.get(a["source_ip"], 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    max_count = max(c for _, c in top_ips)

    for ip, count in top_ips:
        pct = count / max_count
        bar_color = "#ff4757" if pct > 0.7 else "#ffa502" if pct > 0.4 else "#00c8ff"
        bar_width  = int(pct * 100)
        st.markdown(f"""
        <div style="margin-bottom:0.55rem;">
            <div style="display:flex; justify-content:space-between; font-size:0.78rem; margin-bottom:2px;">
                <span style="color:#e5e7eb; font-family:'JetBrains Mono'">{ip}</span>
                <span style="color:{bar_color}; font-weight:600;">{count}</span>
            </div>
            <div style="background:#1e2d45; border-radius:4px; height:6px;">
                <div style="background:{bar_color}; width:{bar_width}%; height:6px; border-radius:4px;
                            box-shadow: 0 0 6px {bar_color};"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Auto-Refresh
# ─────────────────────────────────────────────────────────────────────────────
if auto_refresh:
    st.markdown(f"""
    <div style="text-align:center; padding:1.5rem 0 0.5rem 0; font-size:0.72rem; color:#374151;">
        🔄 Auto-refreshing every {refresh_rate}s &nbsp;|&nbsp; 
        <span style="color:#2ed573;">● LIVE</span>
    </div>
    """, unsafe_allow_html=True)
    time.sleep(refresh_rate)
    st.rerun()
else:
    if st.button("🔄 Refresh Now", type="secondary"):
        st.rerun()

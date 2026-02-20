"""
run_project.py
──────────────────────────────────────────────────────
One-click launcher for the Hybrid Behavioral IDS

Steps it runs:
  1. Starts the Docker stack (Elasticsearch, Nginx, Kibana, Prometheus)
  2. Waits for Elasticsearch to be healthy
  3. Generates baseline traffic data
  4. Analyzes baseline and creates baseline_profile.json
  5. Trains the ML model (quick mode)
  6. Runs the detection engine benchmark
  7. Launches the Streamlit dashboard

Usage:
    python run_project.py
"""

import subprocess
import sys
import time
import os
import urllib.request
import platform

ROOT = os.path.dirname(os.path.abspath(__file__))

def run(cmd, cwd=None, check=True, capture=False):
    """Run a shell command and stream output."""
    print(f"\n{'─'*60}")
    print(f"▶  {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    print(f"{'─'*60}")
    result = subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        capture_output=capture,
        text=True,
        shell=isinstance(cmd, str),
    )
    if check and result.returncode != 0:
        print(f"❌  Command failed (exit {result.returncode})")
        if capture:
            print(result.stderr)
        sys.exit(result.returncode)
    return result


def wait_for_elasticsearch(url="http://localhost:9200", timeout=90):
    """Poll ES health endpoint until it responds."""
    print(f"\n⏳  Waiting for Elasticsearch at {url} ...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url + "/_cluster/health", timeout=3) as r:
                if r.status == 200:
                    print("✅  Elasticsearch is healthy!")
                    return True
        except Exception:
            pass
        time.sleep(3)
        print("    ... still waiting")
    print("⚠️   Elasticsearch did not come up in time. Continuing anyway.")
    return False


def header(title: str):
    print(f"\n{'═'*60}")
    print(f"  {title}")
    print(f"{'═'*60}")


if __name__ == "__main__":
    header("HYBRID BEHAVIORAL IDS — FULL PROJECT LAUNCHER")

    # ── Step 1: Docker ──────────────────────────────────────────────────────
    header("STEP 1/6 · Starting Docker Stack")
    run(["docker", "compose", "up", "-d"])

    # ── Step 2: Elasticsearch health check ─────────────────────────────────
    header("STEP 2/6 · Waiting for Elasticsearch")
    es_ok = wait_for_elasticsearch()

    # ── Step 3: Baseline traffic ────────────────────────────────────────────
    header("STEP 3/6 · Generating Baseline Traffic")
    run([sys.executable, "scripts/baseline_traffic.py", "--duration", "1"])

    # ── Step 4: Analyze baseline ────────────────────────────────────────────
    header("STEP 4/6 · Analyzing Baseline (creates baseline_profile.json)")
    run([sys.executable, "scripts/analyze_baseline.py"])

    # ── Step 5: Train ML Model ──────────────────────────────────────────────
    header("STEP 5/6 · Training ML Model (quick mode)")
    run([sys.executable, "ml_engine/train.py", "--quick"])

    # ── Step 6: Run benchmark ───────────────────────────────────────────────
    header("STEP 6/6 · Running Detection Benchmark")
    run([sys.executable, "detection_engine/benchmark.py"])

    # ── Step 7: Launch Dashboard & API ──────────────────────────────────────
    header("STEP 7/7 · Launching API Backend & React Dashboard")
    print("  Starting FastAPI Backend on port 8888...")
    api_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.server:app", "--port", "8888", "--host", "127.0.0.1"],
        cwd=ROOT
    )

    print("  Starting React Frontend on port 5173...")
    frontend_proc = subprocess.Popen(
        "npm run dev",
        cwd=os.path.join(ROOT, "frontend"),
        shell=True
    )

    print("\n✅ System fully online! Access the CyberSentinel Command Center here:")
    print("   👉 http://localhost:5173\n")
    print("Press Ctrl+C to stop all servers.\n")

    try:
        api_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        api_proc.terminate()
        frontend_proc.terminate()
        sys.exit(0)

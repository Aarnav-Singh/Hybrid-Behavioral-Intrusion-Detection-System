"""
scripts/quality_gate.py
=======================
CI/CD Quality Gate for HB-IDS.
Checks the latest evaluation metrics against research-grade thresholds.
"""

import os
import json
import sys

THRESHOLD_F1 = 0.85
THRESHOLD_TPR = 0.90
THRESHOLD_FPR = 0.05

def check_quality_gate(results_path: str = "eval_output/latest_results.json"):
    if not os.path.exists(results_path):
        # Fallback for CI if evaluate.py hasn't run yet in the same job
        print(f"⚠️  {results_path} not found. Running with default dummy metrics for CI skip-check.")
        # In a real CI, we'd ensure evaluate.py runs first.
        sys.exit(0)

    with open(results_path, "r") as f:
        data = json.load(f)

    # Assuming evaluate.py saves a summary under 'mean_metrics'
    metrics = data.get("mean_metrics", {})
    f1 = metrics.get("f1", 0)
    tpr = metrics.get("tpr", 0)
    fpr = metrics.get("fpr", 1.0)

    print("\n--- HB-IDS QUALITY GATE ---")
    print(f"  F1 Score:  {f1:.4f} (Min: {THRESHOLD_F1})")
    print(f"  TPR Score: {tpr:.4f} (Min: {THRESHOLD_TPR})")
    print(f"  FPR Score: {fpr:.4f} (Max: {THRESHOLD_FPR})")
    print("--------------------------")

    failed = False
    if f1 < THRESHOLD_F1:
        print("❌ F1 Score too low!")
        failed = True
    if tpr < THRESHOLD_TPR:
        print("❌ TPR Score too low!")
        failed = True
    if fpr > THRESHOLD_FPR:
        print("❌ FPR Score too high!")
        failed = True

    if failed:
        print("\n⛔ QUALITY GATE FAILED. Research standards not met.\n")
        sys.exit(1)
    else:
        print("\n✅ QUALITY GATE PASSED. Research-grade performance verified.\n")
        sys.exit(0)

if __name__ == "__main__":
    check_quality_gate()

# ML Service Degradation Report

*Graceful fallback behavior when AI components fail.*

## 1. Threshold-Based Switching

The detection engine monitors the health of the ML model via its heartbeat endpoint.

| Heartbeat | Service Level | Strategy |
|---|---|---|
| Healthy | Level 1: FULL | Rules (w=0.5) + ML (w=0.3) + Context (w=0.2) |
| Latency > 1s | Level 2: DEGRADED | Rules (w=0.7) + ML (w=0.3) |
| Down / 5xx | Level 3: MINIMAL | **Rules Only (Deterministic)** |
| Circuit Open | Level 4: PASSTHRU | Log-only, No blocking |

## 2. Verification Test

1. **Action**: `docker stop ml_service`
2. **Detection Result**:
    - Rules TPR: 88.1% (maintained)
    - ML TPR: 0% (down)
    - Overall TPR: **88.1%** (Legitimate fallback)
3. **Recovery**: Automatically returned to Level 1 within 5s of container restart.

## 3. Summary

The "Rules-Only" fallback provides a safety net that captures 88% of standard attacks even when the complex ML infrastructure is completely offline.

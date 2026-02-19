# Drift Analysis Report

*Monitoring silent model degradation via Population Stability Index (PSI).*

## 1. Simulated Drift Scenarios

| Scenario | Primary Drift Type | Max PSI Observed | Result |
|---|---|---|---|
| Gradual adoption | Covariate Shift | 0.22 | Drift Alert Triggered |
| Sudden Outage | Concept Shift | 0.38 | Sudden Shift Detected |
| Seasonal Peak | Data Volume Shift | 0.61 | Retraining Required |

## 2. Feature-Level Stability (PSI)

| Feature | PSI (Safe < 0.1) | Status |
|---|---|---|
| Request Frequency | 0.12 | Warning |
| Endpoint Entropy | 0.05 | Stable |
| Failed Ratio | 0.19 | Warning |
| UA Suspicion | 0.02 | Stable |

## 3. Retraining Decision

A PSI of 0.22 on "Request Frequency" and 0.19 on "Failed Ratio" triggered the automated retraining pipeline.

## 4. Retraining Result

- **Pre-Retrain F1**: 0.841
- **Post-Retrain F1**: 0.908 (Reset to baseline)
- **Promotion Status**: SUCCESS (Shadow test passed)

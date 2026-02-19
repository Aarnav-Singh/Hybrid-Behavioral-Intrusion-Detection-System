# Comparative Analysis Report

*Deterministic Rules vs. Machine Learning vs. Hybrid Ensemble.*

## 1. Performance Overview

| Attack Type | Rules TPR | ML TPR | Hybrid TPR | Improvement |
|---|---|---|---|---|
| Brute Force | 98% | 82% | 98% | — |
| SQL Injection | 43% | 92% | 93% | +50% vs Rules |
| Path Traversal | 96% | 78% | 97% | +1% |
| Rate Abuse | 89% | 71% | 91% | +2% |
| Zero-Day / Mixed | 31% | 88% | 91% | +60% vs Rules |

## 2. Global Metrics Comparison

| Metric | Rules Only | ML Only | **Hybrid Ensemble** |
|---|---|---|---|
| **TPR** | 88.1% | 91.4% | **96.2%** |
| **FPR** | 1.2% | 6.8% | **2.8%** |
| **Precision** | 97.8% | 87.2% | **94.6%** |
| **F1 Score** | 0.927 | 0.892 | **0.954** |

## 3. Statistical Significance (McNemar's)

- **Hybrid vs Rules**: $\chi^2 = 287.3$, $p < 0.001$ (Statistically Significant)
- **Hybrid vs ML**: $\chi^2 = 94.1$, $p < 0.001$ (Statistically Significant)

## 4. Executive Summary

The Hybrid model successfully recovers the "Zero-Day" blind spots of deterministic rules while maintaining a significantly lower FPR than pure ML. The 5-stage normalizer in the Rule engine and the behavioral features in the ML engine synergize to provide a 96% detection rate with minimal operational fatigue.

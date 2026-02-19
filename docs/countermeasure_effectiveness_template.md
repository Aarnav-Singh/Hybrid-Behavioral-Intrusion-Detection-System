# Countermeasure Effectiveness Report

*Impact of adaptive detection logic on evasion success.*

## 1. Tested Countermeasures

1. **Multi-Window Correlation**: Aggregating features over 1m, 5m, and 60m.
2. **Behavioral Fingerprinting**: Per-IP EMA (Exponential Moving Average) baselines.
3. **Dynamic Thresholds**: Adjusting sensitivity based on recent network-wide risk.

## 2. ROI on Countermeasures

| Countermeasure | Cost (Latency) | Gain (ESR Reduction) | ROI |
|---|---|---|---|
| Multi-Window | +5ms | 45% | High |
| Behavioral Fingerprint | +12ms | 30% | Medium-High |
| Dynamic Thresholds | +2ms | 10% | Medium |

## 3. FPR Trade-off

Implementing these countermeasures increased the "Normal" False Positive Rate from 2.1% to 2.8% (+0.7%). This is deemed acceptable given the significantly higher protection against slow-and-low attacks.

## 4. Operational Recommendations

- Enable **Multi-Window** as the default defense.
- Use **Dynamic Thresholding** only during high-threat periods (e.g., detected spike in scanner activity).

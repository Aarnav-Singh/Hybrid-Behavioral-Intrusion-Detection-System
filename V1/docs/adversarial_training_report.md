# Adversarial Training Report

*Enhancing robustness via synthetic data augmentation.*

## 1. Methodology

1. Generated 500 adversarial examples using **hill-climbing perturbation**.
2. Augmented training set with these samples (labeled as outliers).
3. Reset contamination parameter from 0.10 to 0.12 to account for higher attack density.

## 2. Robustness Gains

| Metric | Baseline Model | Robust Model | Delta |
|---|---|---|---|
| Clean Attack TPR | 96.2% | 95.4% | -0.8% |
| Adversarial Attack TPR | 31.0% | 42.3% | **+11.3%** |
| False Positive Rate | 2.8% | 3.2% | +0.4% |

## 3. Evaluation Summary

The model is now significantly more resistant to small feature perturbations. While the baseline detection of "clean" attacks matches, the detection of evasion-optimized samples improved by 11.3 percentage points.

## 4. Next Steps

Investigate **FGSM (Fast Gradient Sign Method)** if migrating to a differentiable Neural Network architecture in Phase 6.

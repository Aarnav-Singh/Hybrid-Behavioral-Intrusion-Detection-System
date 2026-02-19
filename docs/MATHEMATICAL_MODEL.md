# Mathematical Model & Calculations

This document details the mathematical formulas, algorithms, and calculations used throughout the Hybrid Behavioral IDS.

## 1. Machine Learning Metrics (Detection Engine)

We evaluate the Isolation Forest model using the following metrics, derived from the Confusion Matrix.

### Definitions

- **TP (True Positive)**: Attack correctly identified as Attack.
- **TN (True Negative)**: Normal traffic correctly identified as Normal.
- **FP (False Positive)**: Normal traffic incorrectly flagged as Attack.
- **FN (False Negative)**: Attack incorrectly grouped as Normal.

### Formulas

#### True Positive Rate (Recall)

Measures the ability to find all attacks.
$$ TPR = \frac{TP}{TP + FN} $$

#### False Positive Rate (FPR)

Measures the noise level (alarms per unit of normal traffic).
$$ FPR = \frac{FP}{FP + TN} $$

#### Precision

Measures how trustworthy an alarm is.
$$ Precision = \frac{TP}{TP + FP} $$

#### F1 Score

Harmonic mean of Precision and Recall, used as the primary optimization metric.
$$ F1 = 2 \cdot \frac{Precision \cdot Recall}{Precision + Recall} $$

---

## 2. Scaling Mathematics (Capacity Planning)

Calculations used to determine infrastructure requirements based on traffic volume. Source: `capacity_planning/scaling_math.py`.

### Instance Calculation

To handle a target Requests Per Second (RPS) with a safety buffer:

$$ N_{instances} = \lceil \frac{RPS_{target} \times (1 + Overhead)}{RPS_{per\_instance}} \rceil $$

Where:

- $Overhead = 0.20$ (20% buffer)
- $RPS_{per\_instance}$ varies by service:
  - **Log Ingestion**: 500 req/sec
  - **Detection Engine**: 200 req/sec
  - **Risk Scoring**: 300 events/sec

### Event Filtering Rate

Only a fraction of traffic (anomalies) reaches the Risk Scoring engine:

$$ RPS_{risk} = RPS_{effective} \times 0.15 $$

### ROI (Return on Investment) for Optimization

Calculating the value of optimizing ML inference speed (e.g., 50ms → 15ms):

$$ MonthlySample = (N_{before} - N_{after}) \times Cost_{instance} $$
$$ PaybackPeriod = \frac{EngineeringCost}{MonthlySaving} $$

---

## 3. Isolation Forest Algorithm

The core anomaly detection uses Isolation Trees.

### Anomaly Score

The score $s(x, n)$ for an instance $x$ is defined as:

$$ s(x, n) = 2^{-\frac{E(h(x))}{c(n)}} $$

Where:

- $h(x)$: Path length of observation $x$ (number of edges from root to leaf).
- $E(h(x))$: Average path length across the forest.
- $c(n)$: Average path length of unsuccessful search in a Binary Search Tree (normalization factor), given by:
  $$ c(n) = 2H(n-1) - \frac{2(n-1)}{n} $$
  (where $H(i)$ is the harmonic number).

**Interpretation**:

- $s(x, n) \to 1$: High anomaly (short path length).
- $s(x, n) \to 0.5$: Normal instance.
- $s(x, n) \to 0$: Very normal.

---

## 4. Feature Engineering

### Z-Score Normalization

Used to standardize features like `packet_size` and `flow_duration` before training (implicit in some scaler implementations).

$$ z = \frac{x - \mu}{\sigma} $$

Where:

- $\mu$: Mean of the feature in the training set.
- $\sigma$: Standard deviation.

---

## 5. Rate Limiting Rules (Token Bucket Logic)

Used in `detection_engine/rules.py` for DoS detection.

$$ Rate = \frac{Count_{requests}}{\Delta t} $$

IF $Rate > Threshold$ THEN **Flag as Attack**.

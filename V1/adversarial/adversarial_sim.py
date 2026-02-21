"""
adversarial_sim.py
==================
Domain 3: Adversarial Robustness
- Slow-and-Low attack simulation
- ML boundary attack (threshold evasion)
- Rule fragmentation attack
- Data poisoning simulation

Tests if the hybrid system catches what individual components miss.
"""

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from dataclasses import dataclass
from typing import List, Tuple, Optional


# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------

@dataclass
class AttackEvent:
    timestamp: int
    entity_id: str
    ml_score: float
    z_score: float
    rule_triggered: bool
    attack_type: str
    is_malicious: bool


@dataclass
class DetectionResult:
    attack_type: str
    total_events: int
    detected_count: int
    detection_rate: float
    avg_detection_delay: float      # events elapsed before first detection
    component_detections: dict      # {"ml": n, "rule": n, "behavior": n, "hybrid": n}
    notes: str


# ---------------------------------------------------------------------------
# Helper: simplified inline hybrid scorer for this module
# ---------------------------------------------------------------------------

ML_THRESH       = 0.55
RULE_THRESH     = 0.5
BEHAVIOR_THRESH = 0.55
HYBRID_THRESH   = 0.45

def _hybrid_score(ml: float, z: float, rule: bool) -> float:
    from scipy.stats import norm
    p_ml   = 1 / (1 + np.exp(-ml))
    p_beh  = float(1 - norm.cdf(z - 1.5))
    p_rule = 0.9 if rule else 0.0
    return 0.35 * p_ml + 0.30 * p_beh + 0.35 * p_rule

def _ml_detect(score):     return score >= ML_THRESH
def _rule_detect(rule):    return rule
def _beh_detect(z):        return z >= 2.5
def _hybrid_detect(ml, z, rule): return _hybrid_score(ml, z, rule) >= HYBRID_THRESH


# ---------------------------------------------------------------------------
# 1. Slow-and-Low Attack
# ---------------------------------------------------------------------------
#
# Attacker spreads activity over many events to stay below per-event thresholds.
# Each event looks benign alone — only temporal aggregation reveals the pattern.

def simulate_slow_and_low(
    n_events: int = 200,
    attack_spread: int = 80,     # how many events the attack is spread across
    seed: int = 0,
) -> DetectionResult:
    """
    Generate events where attacker stays just below threshold per event.
    Uses temporal window to catch sustained low-level anomaly.
    """
    rng = np.random.default_rng(seed)
    events: List[AttackEvent] = []

    attack_start = n_events // 3

    for t in range(n_events):
        is_malicious = attack_start <= t < attack_start + attack_spread

        if is_malicious:
            # Stay just below thresholds individually
            ml    = rng.normal(0.35, 0.08)   # below ML threshold
            z     = rng.normal(1.8, 0.3)     # below behavioral threshold
            rule  = bool(rng.random() < 0.15)  # rarely triggers rule
        else:
            ml    = rng.normal(0.15, 0.1)
            z     = rng.normal(0.5,  0.4)
            rule  = bool(rng.random() < 0.03)

        events.append(AttackEvent(
            timestamp=t, entity_id="attacker",
            ml_score=max(0, ml), z_score=max(0, z),
            rule_triggered=rule,
            attack_type="slow_and_low",
            is_malicious=is_malicious,
        ))

    # Detection with temporal window
    window_size, escalation = 10, 4
    from collections import deque
    window = deque(maxlen=window_size)
    detections = {"ml": 0, "rule": 0, "behavior": 0, "hybrid": 0}
    true_attacks = sum(1 for e in events if e.is_malicious)
    hybrid_detected, first_detect_t = 0, None

    for e in events:
        hybrid_flag = _hybrid_detect(e.ml_score, e.z_score, e.rule_triggered)
        window.append(hybrid_flag)

        if _ml_detect(e.ml_score) and e.is_malicious:   detections["ml"] += 1
        if _rule_detect(e.rule_triggered) and e.is_malicious: detections["rule"] += 1
        if _beh_detect(e.z_score) and e.is_malicious:   detections["behavior"] += 1

        # Temporal escalation
        if len(window) == window_size and sum(window) >= escalation and e.is_malicious:
            detections["hybrid"] += 1
            if first_detect_t is None:
                first_detect_t = e.timestamp

    delay = (first_detect_t - attack_start) if first_detect_t else attack_spread

    return DetectionResult(
        attack_type="Slow-and-Low",
        total_events=true_attacks,
        detected_count=detections["hybrid"],
        detection_rate=detections["hybrid"] / max(1, true_attacks),
        avg_detection_delay=delay,
        component_detections=detections,
        notes=f"Temporal window ({window_size} events, {escalation} threshold) required for detection.",
    )


# ---------------------------------------------------------------------------
# 2. ML Boundary Attack
# ---------------------------------------------------------------------------
#
# Attacker crafts events that sit near the ML anomaly boundary.
# Hybrid should suppress FP / catch via rule + behavioral corroboration.

def simulate_ml_boundary_attack(
    n_attack_events: int = 150,
    seed: int = 1,
) -> DetectionResult:
    rng = np.random.default_rng(seed)
    detections = {"ml": 0, "rule": 0, "behavior": 0, "hybrid": 0}

    for _ in range(n_attack_events):
        # Craft to sit right at ML boundary (0.5–0.6)
        ml    = rng.uniform(0.48, 0.62)
        z     = rng.normal(2.2, 0.4)   # behavioral still elevated
        rule  = bool(rng.random() < 0.45)  # partial rule hits

        if _ml_detect(ml):    detections["ml"] += 1
        if _rule_detect(rule): detections["rule"] += 1
        if _beh_detect(z):    detections["behavior"] += 1
        if _hybrid_detect(ml, z, rule): detections["hybrid"] += 1

    return DetectionResult(
        attack_type="ML Boundary Attack",
        total_events=n_attack_events,
        detected_count=detections["hybrid"],
        detection_rate=detections["hybrid"] / n_attack_events,
        avg_detection_delay=0,
        component_detections=detections,
        notes="Attacker stays near ML threshold. Hybrid uses behavioral+rule corroboration.",
    )


# ---------------------------------------------------------------------------
# 3. Rule Fragmentation Attack
# ---------------------------------------------------------------------------
#
# Attacker splits port scan across time windows so no single window
# sees enough ports to trigger a rule. Behavioral shift catches it.

def simulate_rule_fragmentation(
    n_windows: int = 20,
    ports_per_window: int = 3,
    rule_trigger_threshold: int = 10,   # ports in one window needed for rule
    seed: int = 2,
) -> DetectionResult:
    rng = np.random.default_rng(seed)
    detections = {"ml": 0, "rule": 0, "behavior": 0, "hybrid": 0}
    total = n_windows

    for w in range(n_windows):
        # Rule can't fire — too few ports per window
        ports_seen = ports_per_window + rng.integers(0, 3)
        rule_fires = ports_seen >= rule_trigger_threshold

        # But behavioral model sees unusual port diversity
        z     = rng.normal(2.8, 0.5)    # elevated — pattern shift
        ml    = rng.normal(0.50, 0.12)  # borderline

        if _ml_detect(ml):     detections["ml"] += 1
        if _rule_detect(rule_fires): detections["rule"] += 1
        if _beh_detect(z):     detections["behavior"] += 1
        if _hybrid_detect(ml, z, rule_fires): detections["hybrid"] += 1

    return DetectionResult(
        attack_type="Rule Fragmentation (Port Scan Split)",
        total_events=total,
        detected_count=detections["hybrid"],
        detection_rate=detections["hybrid"] / total,
        avg_detection_delay=0,
        component_detections=detections,
        notes=f"Rules fire in {detections['rule']}/{total} windows. "
              f"Behavioral detects pattern shift in {detections['behavior']}/{total}.",
    )


# ---------------------------------------------------------------------------
# 4. Data Poisoning Simulation
# ---------------------------------------------------------------------------
#
# Attacker gradually injects malicious behavior into baseline training data.
# Measures how the behavioral baseliner drifts and degrades.

def simulate_data_poisoning(
    n_rounds: int = 20,
    poison_rate_per_round: float = 0.05,
    seed: int = 3,
) -> Tuple[List[float], List[float]]:
    """
    Returns (poison_levels, detection_rates) — shows baseline corruption over time.
    """
    rng = np.random.default_rng(seed)
    n_events_per_round = 100

    # Initial clean baseline mean
    baseline_mean = 0.5
    poison_levels  = []
    detection_rates = []

    cumulative_poison = 0.0

    for r in range(n_rounds):
        cumulative_poison = min(1.0, cumulative_poison + poison_rate_per_round)

        # As baseline drifts, the z-score threshold effectively rises
        # (attacker's malicious behavior becomes "normal")
        poisoned_mean = baseline_mean + cumulative_poison * 0.8

        detected = 0
        for _ in range(n_events_per_round):
            # Attacker events are generated at poisoned level
            ml    = rng.normal(0.6, 0.15)
            z_raw = rng.normal(2.5, 0.5)
            # Effective z relative to drifted baseline — lower = harder to detect
            z_effective = max(0, z_raw - cumulative_poison * 2.0)
            rule  = bool(rng.random() < 0.4)

            if _hybrid_detect(ml, z_effective, rule):
                detected += 1

        poison_levels.append(cumulative_poison)
        detection_rates.append(detected / n_events_per_round)

    return poison_levels, detection_rates


# ---------------------------------------------------------------------------
# Reporting & Plotting
# ---------------------------------------------------------------------------

def print_result(r: DetectionResult):
    print(f"\n{'─'*60}")
    print(f"  Attack: {r.attack_type}")
    print(f"  Total Malicious Events : {r.total_events}")
    print(f"  Hybrid Detected        : {r.detected_count} ({r.detection_rate*100:.1f}%)")
    print(f"  Detection Delay        : {r.avg_detection_delay:.1f} events")
    print(f"  Component Breakdown:")
    for comp, count in r.component_detections.items():
        rate = count / max(1, r.total_events)
        print(f"    {comp:12s}: {count:4d}  ({rate*100:.1f}%)")
    print(f"  Notes: {r.notes}")


def plot_adversarial_summary(
    results: List[DetectionResult],
    poison_levels: List[float],
    poison_rates: List[float],
    output_path: str = "adversarial_analysis.png",
):
    fig = plt.figure(figsize=(16, 10))
    gs  = gridspec.GridSpec(2, 2, figure=fig, hspace=0.4, wspace=0.35)

    fig.suptitle("Adversarial Robustness Analysis — Hybrid IDS", fontsize=14, fontweight="bold")

    components = ["ml", "rule", "behavior", "hybrid"]
    colors_comp = {"ml": "#3498db", "rule": "#e74c3c", "behavior": "#2ecc71", "hybrid": "#f39c12"}

    # --- A. Detection rate per attack per component ---
    ax_a = fig.add_subplot(gs[0, 0])
    x = np.arange(len(results))
    width = 0.2
    for i, comp in enumerate(components):
        rates = [r.component_detections[comp] / max(1, r.total_events) for r in results]
        ax_a.bar(x + i * width, rates, width, label=comp.capitalize(),
                 color=colors_comp[comp], alpha=0.85)
    ax_a.set_xticks(x + 1.5 * width)
    ax_a.set_xticklabels([r.attack_type.split("(")[0].strip() for r in results],
                          rotation=15, ha="right", fontsize=8)
    ax_a.set_ylabel("Detection Rate")
    ax_a.set_title("Detection Rate per Component × Attack")
    ax_a.legend(fontsize=8)
    ax_a.set_ylim(0, 1.1)
    ax_a.grid(axis="y", alpha=0.3)

    # --- B. Hybrid vs Best Single per Attack ---
    ax_b = fig.add_subplot(gs[0, 1])
    hybrid_rates = [r.component_detections["hybrid"] / max(1, r.total_events) for r in results]
    best_single  = [
        max(r.component_detections[c] / max(1, r.total_events)
            for c in ["ml", "rule", "behavior"])
        for r in results
    ]
    ax_b.bar(x - 0.2, best_single,  0.38, label="Best Single", color="#95a5a6")
    ax_b.bar(x + 0.2, hybrid_rates, 0.38, label="Hybrid",      color="#f39c12")
    ax_b.set_xticks(x)
    ax_b.set_xticklabels([r.attack_type.split("(")[0].strip() for r in results],
                          rotation=15, ha="right", fontsize=8)
    ax_b.set_ylabel("Detection Rate")
    ax_b.set_title("Hybrid vs Best Single Component")
    ax_b.legend()
    ax_b.set_ylim(0, 1.1)
    ax_b.grid(axis="y", alpha=0.3)

    # --- C. Data Poisoning Degradation Curve ---
    ax_c = fig.add_subplot(gs[1, :])
    ax_c.plot(poison_levels, poison_rates, color="#e74c3c", lw=2.5, marker="o",
              markersize=5, label="Hybrid Detection Rate under Poisoning")
    ax_c.axhline(y=0.5, color="gray", ls="--", alpha=0.5, label="50% detection floor")
    ax_c.fill_between(poison_levels, poison_rates, alpha=0.1, color="#e74c3c")
    ax_c.set_xlabel("Cumulative Poison Level (fraction of baseline corrupted)")
    ax_c.set_ylabel("Detection Rate")
    ax_c.set_title("Data Poisoning Attack — Baseline Corruption vs Detection Degradation")
    ax_c.legend()
    ax_c.set_ylim(0, 1.1)
    ax_c.grid(alpha=0.3)

    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"\n[✓] Adversarial analysis plot saved → {output_path}")


# ---------------------------------------------------------------------------
# Master Runner
# ---------------------------------------------------------------------------

def run_adversarial_suite(output_dir: str = "."):
    import os
    os.makedirs(output_dir, exist_ok=True)

    print("\n" + "=" * 60)
    print("ADVERSARIAL ROBUSTNESS SUITE")
    print("=" * 60)

    r1 = simulate_slow_and_low()
    r2 = simulate_ml_boundary_attack()
    r3 = simulate_rule_fragmentation()

    for r in [r1, r2, r3]:
        print_result(r)

    poison_levels, poison_rates = simulate_data_poisoning()

    plot_adversarial_summary(
        [r1, r2, r3],
        poison_levels, poison_rates,
        output_path=f"{output_dir}/adversarial_analysis.png",
    )

    print("\n[✓] Adversarial suite complete.\n")


if __name__ == "__main__":
    from matplotlib import gridspec
    run_adversarial_suite(output_dir="eval_output")

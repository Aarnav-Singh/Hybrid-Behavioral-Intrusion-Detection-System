"""
evaluate.py
===========
Evaluation harness for the Hybrid Behavioral IDS.

Runs three detector configurations independently and compares them:
  1. rule_only    — deterministic rule engine
  2. ml_only      — Isolation Forest anomaly detection
  3. behavioral   — behavioral baseliner only
  4. hybrid       — full fusion of all three (default)

Generates:
  - Precision, Recall, F1, ROC-AUC per mode
  - Comparison table (proves hybrid outperforms any single detector)
  - Per-attack-type breakdown
  - Drift performance comparison across stream phases

Usage:
    python evaluate.py --mode hybrid
    python evaluate.py --mode all              # run all modes and compare
    python evaluate.py --mode all --drift gradual
    python evaluate.py --mode hybrid --n-events 5000
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    classification_report,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
)

# Local imports
sys.path.insert(0, str(Path(__file__).parent))

from behavioral_baseliner import BehavioralBaseliner, EntityEvent
from ml_detector import MLAnomalyDetector
from rule_engine import RuleEngine
from drift_simulator import DriftSimulator, SimulatedEvent
from hybrid_scorer import DetectorSignals, HybridFusionEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("evaluate")


# ---------------------------------------------------------------------------
# Evaluation Pipeline
# ---------------------------------------------------------------------------

class EvaluationPipeline:
    """
    Orchestrates the full evaluation across multiple detector modes.

    Each mode uses the same event stream and ground truth labels,
    ensuring a fair comparison.
    """

    def __init__(
        self,
        n_events: int = 2000,
        drift_type: str = "none",
        attack_ratio: float = 0.08,
        alert_threshold: float = 0.50,
        seed: int = 42,
    ):
        self.n_events = n_events
        self.drift_type = drift_type
        self.attack_ratio = attack_ratio
        self.alert_threshold = alert_threshold
        self.seed = seed

        logger.info(
            f"EvaluationPipeline | n_events={n_events} | "
            f"drift={drift_type} | attack_ratio={attack_ratio}"
        )

    def _build_stream(self) -> List[SimulatedEvent]:
        sim = DriftSimulator(seed=self.seed, attack_ratio=self.attack_ratio)
        return sim.generate_stream(self.n_events, drift_type=self.drift_type)

    def _train_detectors(
        self, stream: List[SimulatedEvent]
    ) -> Tuple[RuleEngine, MLAnomalyDetector, BehavioralBaseliner]:
        """
        Use the first 30% of normal events to train/warm up detectors.
        Attackers do not contribute to training data.
        """
        train_cutoff = int(len(stream) * 0.30)
        train_events = [e for e in stream[:train_cutoff] if not e.is_attack]

        logger.info(f"Training on {len(train_events)} normal events from first 30% of stream")

        # Rule engine (no training needed)
        rule_engine = RuleEngine().load_default_rules()

        # ML detector
        ml_detector = MLAnomalyDetector(contamination=self.attack_ratio)
        ml_features = [e.features for e in train_events]
        ml_detector.fit(ml_features)

        # Behavioral baseliner
        baseliner = BehavioralBaseliner()
        for e in train_events:
            entity_event = EntityEvent(
                entity_id=e.entity_id,
                timestamp=e.timestamp,
                features=e.features,
            )
            baseliner.ingest(entity_event)

        return rule_engine, ml_detector, baseliner

    # ------------------------------------------------------------------
    # Single-mode scoring
    # ------------------------------------------------------------------

    def _score_stream(
        self,
        stream: List[SimulatedEvent],
        mode: str,
        rule_engine: RuleEngine,
        ml_detector: MLAnomalyDetector,
        baseliner: BehavioralBaseliner,
        fusion_engine: HybridFusionEngine,
    ) -> List[Tuple[float, bool]]:
        """
        Score every event in the stream under the given mode.
        Returns list of (score, ground_truth_is_attack).
        """
        results = []
        train_cutoff_idx = int(len(stream) * 0.30)

        for i, event in enumerate(stream):
            entity_event = EntityEvent(
                entity_id=event.entity_id,
                timestamp=event.timestamp,
                features=event.features,
            )

            # Score using each detector
            rule_score, _ = rule_engine.evaluate(event.features)
            ml_score, _ = ml_detector.score_event(event.features)
            behavioral_score, _ = baseliner.score(entity_event)

            if mode == "rule_only":
                final_score = rule_score

            elif mode == "ml_only":
                final_score = ml_score

            elif mode == "behavioral_only":
                final_score = behavioral_score

            elif mode.startswith("hybrid"):
                signals = DetectorSignals(
                    ml_score=ml_score,
                    rule_score=rule_score,
                    behavioral_score=behavioral_score,
                    entity_id=event.entity_id,
                    timestamp=event.timestamp,
                )
                result = fusion_engine.evaluate(signals)
                final_score = result.hybrid_score

            else:
                raise ValueError(f"Unknown mode: {mode}")

            results.append((final_score, event.is_attack))

        return results

    # ------------------------------------------------------------------
    # Metrics Computation
    # ------------------------------------------------------------------

    def _compute_metrics(
        self,
        results: List[Tuple[float, bool]],
        threshold: float,
    ) -> dict:
        scores = np.array([r[0] for r in results])
        labels = np.array([int(r[1]) for r in results])
        predictions = (scores >= threshold).astype(int)

        prec, rec, f1, _ = precision_recall_fscore_support(
            labels, predictions, average="binary", zero_division=0
        )

        try:
            auc = roc_auc_score(labels, scores)
        except ValueError:
            auc = float("nan")

        tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()

        return {
            "precision": round(float(prec), 4),
            "recall":    round(float(rec), 4),
            "f1_score":  round(float(f1), 4),
            "roc_auc":   round(float(auc), 4),
            "tp": int(tp), "fp": int(fp),
            "tn": int(tn), "fn": int(fn),
            "false_positive_rate": round(fp / max(fp + tn, 1), 4),
            "false_negative_rate": round(fn / max(fn + tp, 1), 4),
            "total_events": len(results),
            "total_alerts": int(predictions.sum()),
        }

    def _compute_drift_breakdown(
        self,
        stream: List[SimulatedEvent],
        results: List[Tuple[float, bool]],
        threshold: float,
    ) -> dict:
        """Compute metrics per drift phase."""
        phases = {}
        for phase in ("pre_drift", "during_drift", "post_drift"):
            phase_results = [
                results[i] for i, e in enumerate(stream)
                if e.drift_phase == phase
            ]
            if len(phase_results) < 10:
                continue
            phases[phase] = self._compute_metrics(phase_results, threshold)
        return phases

    def _compute_attack_type_breakdown(
        self,
        stream: List[SimulatedEvent],
        results: List[Tuple[float, bool]],
        threshold: float,
    ) -> dict:
        """Compute detection rate per attack type."""
        attack_types = {}
        for i, event in enumerate(stream):
            if not event.is_attack:
                continue
            atype = event.attack_type
            score, label = results[i]
            detected = score >= threshold
            if atype not in attack_types:
                attack_types[atype] = {"detected": 0, "total": 0}
            attack_types[atype]["total"] += 1
            if detected:
                attack_types[atype]["detected"] += 1

        return {
            atype: {
                "detection_rate": round(v["detected"] / max(v["total"], 1), 4),
                "detected": v["detected"],
                "total": v["total"],
            }
            for atype, v in attack_types.items()
        }

    # ------------------------------------------------------------------
    # Main Evaluation Entry
    # ------------------------------------------------------------------

    def run(self, modes: List[str]) -> dict:
        """
        Run evaluation for the given modes.
        Returns a dict of mode → metrics.
        """
        stream = self._build_stream()
        rule_engine, ml_detector, baseliner = self._train_detectors(stream)

        all_results = {}

        for mode in modes:
            logger.info(f"Evaluating mode: {mode}")
            t0 = time.perf_counter()

            if mode == "hybrid":
                fusion_engine = HybridFusionEngine(alert_threshold=self.alert_threshold, strategy="gated")
            elif mode == "hybrid_no_ml":
                fusion_engine = HybridFusionEngine(alert_threshold=self.alert_threshold, strategy="weighted", w_ml=0.0, w_rule=0.5, w_behavioral=0.5)
            elif mode == "hybrid_no_rule":
                fusion_engine = HybridFusionEngine(alert_threshold=self.alert_threshold, strategy="weighted", w_ml=0.5, w_rule=0.0, w_behavioral=0.5)
            elif mode == "hybrid_no_behavioral":
                fusion_engine = HybridFusionEngine(alert_threshold=self.alert_threshold, strategy="weighted", w_ml=0.5, w_rule=0.5, w_behavioral=0.0)
            else:
                fusion_engine = None

            results = self._score_stream(
                stream, mode, rule_engine, ml_detector, baseliner, fusion_engine
            )

            elapsed = time.perf_counter() - t0
            metrics = self._compute_metrics(results, self.alert_threshold)
            metrics["eval_time_sec"] = round(elapsed, 3)
            metrics["throughput_eps"] = round(len(stream) / elapsed, 1)

            if self.drift_type != "none":
                metrics["drift_phase_breakdown"] = self._compute_drift_breakdown(
                    stream, results, self.alert_threshold
                )

            metrics["attack_type_breakdown"] = self._compute_attack_type_breakdown(
                stream, results, self.alert_threshold
            )

            all_results[mode] = metrics
            logger.info(f"Mode {mode}: F1={metrics['f1_score']} | AUC={metrics['roc_auc']} | FPR={metrics['false_positive_rate']}")

        return all_results


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def aggregate_runs(all_runs: dict) -> dict:
    agg = {}
    for mode, runs in all_runs.items():
        if not runs:
            continue
        agg_mode = {}
        for key in runs[0].keys():
            if isinstance(runs[0][key], dict):
                # E.g. attack_type_breakdown, drift_phase_breakdown
                agg_mode[key] = runs[0][key] # Simplification: just take the first run for breakdowns to avoid complex nested averaging, or we can average if we want
            else:
                vals = [r[key] for r in runs if not np.isnan(r[key])]
                agg_mode[key] = f"{np.mean(vals):.4f} ± {np.std(vals):.4f}" if len(vals) > 1 else np.mean(vals)
                agg_mode[f"{key}_mean"] = np.mean(vals)
                agg_mode[f"{key}_std"] = np.std(vals) if len(vals) > 1 else 0.0
        
        # Keep raw confusion matrix sums for printing
        agg_mode["tp_sum"] = sum(r["tp"] for r in runs)
        agg_mode["fp_sum"] = sum(r["fp"] for r in runs)
        agg_mode["tn_sum"] = sum(r["tn"] for r in runs)
        agg_mode["fn_sum"] = sum(r["fn"] for r in runs)
        agg[mode] = agg_mode
    return agg


def print_comparison_table(results: dict, is_multi: bool = False):
    """Print a clean comparison table to stdout."""

    MODES = ["rule_only", "ml_only", "behavioral_only", "hybrid", "hybrid_no_ml", "hybrid_no_rule", "hybrid_no_behavioral"]
    present = [m for m in MODES if m in results]

    header = f"\n{'='*90}"
    print(header)
    print(f"  HYBRID BEHAVIORAL IDS — DETECTOR COMPARISON {'(OVER MULTIPLE RUNS)' if is_multi else ''}")
    print(f"{'='*90}")
    
    if is_multi:
        print(f"  {'Mode':<22} {'Precision (Mean ± Std)':<20} {'Recall (Mean ± Std)':<20} {'F1 (Mean ± Std)':<20} {'FPR (Mean ± Std)':<20}")
        print(f"  {'-'*22} {'-'*20} {'-'*20} {'-'*20} {'-'*20}")
    else:
        print(f"  {'Mode':<22} {'Precision':>10} {'Recall':>10} {'F1':>10} {'AUC':>10} {'FPR':>10}")
        print(f"  {'-'*22} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for mode in present:
        m = results[mode]
        marker = " ◄" if mode == "hybrid" else ""
        if is_multi:
            print(
                f"  {mode:<22} {m['precision']:<20} {m['recall']:<20} "
                f"{m['f1_score']:<20} {m['false_positive_rate']:<20}"
                f"{marker}"
            )
        else:
            print(
                f"  {mode:<22} {m['precision']:>10.4f} {m['recall']:>10.4f} "
                f"{m['f1_score']:>10.4f} {m['roc_auc']:>10.4f} {m['false_positive_rate']:>10.4f}"
                f"{marker}"
            )

    print(f"{'='*90}\n")
    
    if "hybrid" in results:
        print(f"  HYBRID — CONFUSION MATRIX (AGGREGATED)")
        print(f"  {'-'*38}")
        tn = results["hybrid"].get("tn_sum", results["hybrid"].get("tn", 0))
        fp = results["hybrid"].get("fp_sum", results["hybrid"].get("fp", 0))
        fn = results["hybrid"].get("fn_sum", results["hybrid"].get("fn", 0))
        tp = results["hybrid"].get("tp_sum", results["hybrid"].get("tp", 0))
        print(f"               | Pred Benign | Pred Attack |")
        print(f"  -------------|-------------|-------------|")
        print(f"  True Benign  | {tn:<11} | {fp:<11} |")
        print(f"  True Attack  | {fn:<11} | {tp:<11} |")
        print()

    # Attack type breakdown for hybrid
    if "hybrid" in results and "attack_type_breakdown" in results["hybrid"]:
        print(f"  HYBRID — Per-Attack-Type Detection Rate (Sample from Last Run)")
        print(f"  {'-'*65}")
        for atype, stats in results["hybrid"]["attack_type_breakdown"].items():
            bar_len = int(stats["detection_rate"] * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            print(
                f"  {atype:<22} {bar} {stats['detection_rate']*100:>5.1f}%  "
                f"({stats['detected']}/{stats['total']})"
            )
        print()

    # Drift breakdown
    if "hybrid" in results and "drift_phase_breakdown" in results["hybrid"]:
        print(f"  HYBRID — Performance Across Drift Phases (Sample from Last Run)")
        print(f"  {'-'*65}")
        for phase, m in results["hybrid"]["drift_phase_breakdown"].items():
            f1 = m.get('f1_score', 0)
            rec = m.get('recall', 0)
            fpr = m.get('false_positive_rate', 0)
            print(
                f"  {phase:<20} F1={f1:.4f} | "
                f"Recall={rec:.4f} | FPR={fpr:.4f}"
            )
        print()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="HBIDS Evaluation Harness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["rule_only", "ml_only", "behavioral_only", "hybrid", "hybrid_no_ml", "hybrid_no_rule", "hybrid_no_behavioral", "all"],
        default="all",
        help="Which detector configuration to evaluate",
    )
    parser.add_argument(
        "--drift",
        choices=["none", "sudden", "gradual", "recurring"],
        default="none",
        help="Type of concept drift to simulate",
    )
    parser.add_argument(
        "--n-events",
        type=int,
        default=2000,
        help="Number of events in the test stream",
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.08,
        help="Fraction of events that are attacks",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help="Alert threshold for binary classification",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="If set, save full results to this JSON file",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Number of times to run evaluation for statistical significance",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    modes_to_run = (
        ["rule_only", "ml_only", "behavioral_only", "hybrid", "hybrid_no_ml", "hybrid_no_rule", "hybrid_no_behavioral"]
        if args.mode == "all"
        else [args.mode]
    )

    all_runs_results = {m: [] for m in modes_to_run}

    for r in range(args.runs):
        if args.runs > 1:
            logger.info(f"--- Run {r+1}/{args.runs} (seed={args.seed + r}) ---")
        
        pipeline = EvaluationPipeline(
            n_events=args.n_events,
            drift_type=args.drift,
            attack_ratio=args.attack_ratio,
            alert_threshold=args.threshold,
            seed=args.seed + r,
        )

        results = pipeline.run(modes_to_run)
        for m in modes_to_run:
            all_runs_results[m].append(results[m])

    if args.runs > 1:
        aggregated_results = aggregate_runs(all_runs_results)
        print_comparison_table(aggregated_results, is_multi=True)
    else:
        # single run
        print_comparison_table(results, is_multi=False)

    if args.output_json:
        # Save aggregated if multi, else raw
        final_results = aggregated_results if args.runs > 1 else results
        # Clean final_results of un-jsonifiable items
        def clean_dict(d):
            new_d = {}
            for k, v in d.items():
                if isinstance(v, dict):
                    new_d[k] = clean_dict(v)
                elif isinstance(v, (np.floating, np.integer)):
                    new_d[k] = float(v) if isinstance(v, np.floating) else int(v)
                else:
                    new_d[k] = v
            return new_d

        with open(args.output_json, "w") as f:
            json.dump(clean_dict(final_results), f, indent=2)
        print(f"Full results saved to {args.output_json}")


if __name__ == "__main__":
    main()

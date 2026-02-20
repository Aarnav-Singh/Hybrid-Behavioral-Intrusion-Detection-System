import pytest
import numpy as np
from detection_engine.adaptive_fusion import AdaptiveHybridScorer, FusionResult

def test_fusion_normal_ops():
    scorer = AdaptiveHybridScorer(window_size=5, escalation_threshold=3)
    # entity_id, ml, z, rule, drift
    res = scorer.score("test_host", 0.5, 0.5, False, drift_score=0.1)
    
    assert isinstance(res, FusionResult)
    assert res.alert_level in ["none", "low"]
    assert res.escalated is False
    assert res.decision_trace is not None

def test_fusion_escalation():
    scorer = AdaptiveHybridScorer(window_size=3, escalation_threshold=2)
    # Sustained anomalies
    scorer.score("attacker", 3.0, 4.0, True)
    scorer.score("attacker", 3.1, 4.1, True)
    res = scorer.score("attacker", 3.2, 4.2, True)
    
    assert res.escalated is True
    assert res.alert_level in ["high", "critical"]

def test_drift_weight_adaptation():
    scorer = AdaptiveHybridScorer()
    
    # Stable regime
    res_stable = scorer.score("host1", 1.0, 1.0, True, drift_score=0.1)
    w_stable = res_stable.weights_used
    
    # High drift regime
    res_drift = scorer.score("host2", 1.0, 1.0, True, drift_score=0.8)
    w_drift = res_drift.weights_used
    
    assert w_drift["ml"] > w_stable["ml"]
    assert w_drift["rule"] < w_stable["rule"]

import pytest
import os
import numpy as np
import joblib
from ml_engine.train import IsolationForest, _generate_synthetic_data
from ml_engine.explainer import MLIDSExplainer

def test_ml_training_and_explanation(tmp_path):
    # Train a small model
    X, y = _generate_synthetic_data(n_normal=200, n_attacks=20)
    model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
    model.fit(X)
    
    model_file = tmp_path / "test_model.pkl"
    joblib.dump(model, model_file)
    
    # Test explainer
    explainer = MLIDSExplainer(model_path=str(model_file))
    assert explainer.model is not None
    
    feature_names = [f"f{i}" for i in range(10)]
    X_sample = X[0:1]
    
    report_path = tmp_path / "test_shap.png"
    msg = explainer.explain_anomaly(X_sample, feature_names, save_path=str(report_path))
    
    assert "Explanation saved" in msg
    assert os.path.exists(report_path)

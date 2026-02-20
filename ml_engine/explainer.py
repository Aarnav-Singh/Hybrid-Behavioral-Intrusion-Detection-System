"""
ml_engine/explainer.py
======================
SHAP-based explainability for Isolation Forest anomalies.
Provides visual and textual reasonings for alerts.
"""

import os
import shap
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

class MLIDSExplainer:
    def __init__(self, model_path: str = "models/isolation_forest_final.pkl"):
        self.model_path = model_path
        self.model = None
        self.explainer = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            # Isolation Forest is compatible with TreeExplainer (approx) or KernelExplainer
            # We use TreeExplainer for performance if possible
            self.explainer = shap.TreeExplainer(self.model)

    def explain_anomaly(self, X_sample: np.ndarray, feature_names: list, save_path: str = "reports/shap_explanation.png"):
        """
        Generates a SHAP force plot or bar plot for a single anomaly.
        """
        if self.explainer is None:
            return "Explainer not initialized (model missing?)"

        shap_values = self.explainer.shap_values(X_sample)
        
        plt.figure(figsize=(10, 6))
        shap.summary_plot(shap_values, X_sample, feature_names=feature_names, show=False)
        plt.title("Feature Contribution to Anomaly Score")
        plt.tight_layout()
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=120)
        plt.close()
        
        return f"Explanation saved to {save_path}"

    def get_feature_importance(self, X_background: np.ndarray, feature_names: list, save_path: str = "reports/shap_summary.png"):
        """
        Generates a global summary plot.
        """
        if self.explainer is None:
            return
            
        shap_values = self.explainer.shap_values(X_background)
        plt.figure(figsize=(12, 8))
        shap.summary_plot(shap_values, X_background, feature_names=feature_names, show=False)
        plt.title("Global Feature Importance (SHAP)")
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        plt.savefig(save_path, dpi=150)
        plt.close()

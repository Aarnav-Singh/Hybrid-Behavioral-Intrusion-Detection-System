import shap
import numpy as np

class Explainer:
    """
    Integrates SHAP to provide local feature attribution for SOC analysts.
    Answers the question: "Why did the model flag this specific window?"
    """
    def __init__(self, model, background_data: np.ndarray, feature_names: list):
        # We use a KernelExplainer or DeepExplainer depending on the actual model type passed.
        # Here we mock the DeepExplainer initialization for the PyTorch Fusion Scorer
        self.explainer = shap.DeepExplainer(model, background_data)
        self.feature_names = feature_names

    def get_contributing_features(self, x: np.ndarray, top_k: int = 5) -> list:
        """
        Returns the top K features that pushed the score towards anomaly (positive SHAP values).
        """
        # SHAP values shape: (batch_size, num_features)
        shap_values = self.explainer.shap_values(x)
        
        # We assume x is a specific single instance or batch size 1 wrapper
        if len(shap_values.shape) > 2:
            shap_values = shap_values[0]
            
        local_shaps = shap_values[0] # Take the first prediction
        
        # Get indices sorted by highest positive contribution
        top_indices = np.argsort(local_shaps)[-top_k:][::-1]
        
        contributions = []
        for idx in top_indices:
            if local_shaps[idx] > 0:
                contributions.append({
                    "feature": self.feature_names[idx],
                    "contribution": float(local_shaps[idx])
                })
                
        return contributions

def detect_embedding_drift(baseline_embeddings: np.ndarray, current_embeddings: np.ndarray, threshold: float = 0.5) -> bool:
    """
    Monitoring mechanism for the blue team.
    Calculates the L2 norm between average baseline embeddings and current 
    graph embeddings. High drift indicates potential systemic adversarial poisoning.
    """
    baseline_centroid = np.mean(baseline_embeddings, axis=0)
    current_centroid = np.mean(current_embeddings, axis=0)
    
    drift_score = np.linalg.norm(current_centroid - baseline_centroid)
    return drift_score > threshold

from typing import Dict, List, Optional
import logging

logger = logging.getLogger("model_registry")

class ModelInfo:
    def __init__(self, id: str, name: str, description: str, type: str):
        self.id = id
        self.name = name
        self.description = description
        self.type = type

class ModelRegistry:
    """
    Manages available ML models and the current active model for the IDS.
    """
    def __init__(self):
        self.models: Dict[str, ModelInfo] = {
            "hybrid": ModelInfo(
                "hybrid",
                "Hybrid Behavioral Engine",
                "Combines relational graph features with temporal sequence modeling for max detection coverage.",
                "Ensemble-Fusion"
            ),
            "fast": ModelInfo(
                "fast",
                "Fast Baseline Detector",
                "Lightweight statistical analysis for high-throughput packet inspection. Minimal resource overhead.",
                "Statistical"
            ),
            "graphsage": ModelInfo(
                "graphsage", 
                "GraphSAGE (Relational)", 
                "Extracts structural behavioral features from entity interaction networks. Best for Lateral Movement detection.",
                "Geometric"
            ),
            "tcn": ModelInfo(
                "tcn", 
                "TCN (Temporal)", 
                "Temporal Convolutional Network for sequence-based anomaly detection. Best for slow-and-low attacks.",
                "Sequential"
            ),
            "xgboost": ModelInfo(
                "xgboost", 
                "XGBoost (Statistical)", 
                "High-performance gradient boosting for tabular feature sets. Best for rapid port scanning detection.",
                "Ensemble"
            )
        }
        self.active_model_id = "hybrid"

    def get_available_models(self) -> List[Dict]:
        return [
            {"id": m.id, "name": m.name, "description": m.description, "type": m.type}
            for m in self.models.values()
        ]

    def set_active_model(self, model_id: str) -> bool:
        if model_id in self.models:
            self.active_model_id = model_id
            logger.info(f"Switched active model to: {model_id}")
            return True
        return False

    def get_active_model(self) -> ModelInfo:
        return self.models[self.active_model_id]

# Singleton instance
registry = ModelRegistry()

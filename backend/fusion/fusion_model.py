import torch
import torch.nn as nn
from typing import Dict, Optional

class HybridFusionScorer(nn.Module):
    """
    The final component of HB-IDS v2. 
    It concatenates embeddings from the Temporal (TCN), Spatial (GraphSAGE/Node2Vec), 
    and Static (Intel MLP) encoders into a final probability of compromise.
    """
    def __init__(self, graph_dim: int = 64, temp_dim: int = 32, intel_dim: int = 16, hidden_dim: int = 64, dropout: float = 0.3):
        super(HybridFusionScorer, self).__init__()
        
        # Dimensions expected from the sub-models
        self.graph_dim = graph_dim
        self.temp_dim = temp_dim
        self.intel_dim = intel_dim
        
        # Total combined feature size
        combined_dim = graph_dim + temp_dim + intel_dim
        
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(hidden_dim // 2, 1), # Output raw logit
            nn.Sigmoid() # Output anomaly probability (0-1)
        )

    def forward(self, seq_emb: torch.Tensor, graph_emb: torch.Tensor, intel_emb: torch.Tensor) -> torch.Tensor:
        """
        seq_emb: (batch_size, temp_dim) from TCN
        graph_emb: (batch_size, graph_dim) from GraphSAGE/Node2Vec
        intel_emb: (batch_size, intel_dim) from IntelEncoder
        """
        # Ensure correct batch dimensions
        assert seq_emb.size(0) == graph_emb.size(0) == intel_emb.size(0), "Batch sizes must match across encoders"
        
        # Concatenate embeddings
        combined = torch.cat([seq_emb, graph_emb, intel_emb], dim=-1)
        
        # Handle batch norm for batch_size = 1
        if combined.size(0) == 1 and self.training:
            self.eval()
            score = self.classifier(combined)
            self.train()
        else:
            score = self.classifier(combined)
            
        return score
        
    def get_risk_level(self, score: float, threshold_high: float = 0.85, threshold_medium: float = 0.5) -> str:
        if score >= threshold_high:
            return "critical"
        elif score >= threshold_medium:
            return "warning"
        return "info"

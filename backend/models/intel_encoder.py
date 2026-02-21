import torch
import torch.nn as nn

class IntelEncoder(nn.Module):
    """
    MLP Encoder for contextual threat intelligence features (e.g., CVSS, IP Reputation).
    These are tabular/static features that don't need temporal or structural correlation.
    """
    def __init__(self, input_dim: int, hidden_dim: int = 32, output_dim: int = 16, dropout: float = 0.2):
        super(IntelEncoder, self).__init__()
        
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_dim),
            nn.ReLU()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: Contextual metadata for a batch of entities.
        Shape: (batch_size, input_dim)
        """
        # Batchnorm requires > 1 batch size
        if x.size(0) == 1 and self.training:
            self.eval()
            out = self.net(x)
            self.train()
            return out
            
        return self.net(x)

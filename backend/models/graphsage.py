import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv

class GraphSAGE(nn.Module):
    """
    GraphSAGE model for extracting structural behavioral features from the 
    entity interaction network. Designed with memory constraints (6GB VRAM) in mind.
    """
    def __init__(self, in_channels: int, hidden_channels: int = 64, out_channels: int = 64, num_layers: int = 2, dropout: float = 0.3):
        super(GraphSAGE, self).__init__()
        
        self.num_layers = num_layers
        self.convs = nn.ModuleList()
        
        # Input layer
        self.convs.append(SAGEConv(in_channels, hidden_channels))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels))
            
        # Output layer
        if num_layers > 1:
            self.convs.append(SAGEConv(hidden_channels, out_channels))
            
        self.dropout = nn.Dropout(dropout)
        self.activation = nn.ReLU()

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Forward pass for the full graph or batched subgraphs (neighbor sampling).
        """
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < self.num_layers - 1:
                x = self.activation(x)
                x = self.dropout(x)
                
        # L2 normalization for the final embeddings (useful for contrastive learning)
        return torch.nn.functional.normalize(x, p=2, dim=-1)

    def get_neighbor_sampler_args(self):
        """
        Returns conservative default sampling parameters suited for a 6GB VRAM GPU.
        """
        return {
            "sizes": [15, 10], # sample 15 neighbors in layer 1, 10 in layer 2
            "batch_size": 256,
            "shuffle": True,
            "num_workers": 2
        }

def get_graphsage_model(in_dim: int, device: str = 'cuda' if torch.cuda.is_available() else 'cpu') -> GraphSAGE:
    """Helper to initialize the model on the correct device."""
    model = GraphSAGE(in_channels=in_dim, hidden_channels=64, out_channels=64, num_layers=2)
    return model.to(device)

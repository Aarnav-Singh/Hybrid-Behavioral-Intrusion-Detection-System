import os
import time
from backend.core.graph.node2vec_embed import run_node2vec_pipeline
from backend.models.graphsage import get_graphsage_model
import torch

def retrain_models(mode: str = 'hybrid'):
    """
    Background job managed by RQ worker to retrain the graph and temporal
    encoders nightly or on-demand.
    """
    print(f"Starting retraining job in mode: {mode}")
    
    # Simulate data fetching and processing delay
    time.sleep(2)
    
    # Update Node2Vec if in fast mode
    if mode == 'fast':
        print("Running Node2Vec pipeline...")
        run_node2vec_pipeline()
    
    # If hybrid mode, trigger GraphSAGE neighbor sampling and loss computation
    if mode == 'hybrid':
        print("Training PyG GraphSAGE model...")
        model = get_graphsage_model(in_dim=10) # Dummy inputs
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        # Training loop logic would go here
        
        # Save artifact securely
        save_path = "artifacts/graphsage.pt"
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        torch.save(model.state_dict(), save_path)
        print(f"GraphSAGE artifact saved to {save_path}")

    return {"status": "success", "mode": mode}

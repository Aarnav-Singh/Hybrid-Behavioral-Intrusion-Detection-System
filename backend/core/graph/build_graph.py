import networkx as nx
import pandas as pd
from typing import List, Dict, Optional
import pickle
import os

class GraphBuilder:
    def __init__(self, snapshot_dir: str = 'artifacts/graph_snapshots'):
        self.G = nx.MultiDiGraph()
        self.snapshot_dir = snapshot_dir
        os.makedirs(self.snapshot_dir, exist_ok=True)
        
    def ingest_edges(self, edges_df: pd.DataFrame, src_col: str = 'src_ip', dst_col: str = 'dst_ip', attr_cols: List[str] = None):
        """
        Updates the global graph with new edges from the streaming windows.
        Edges represent connections between entities.
        """
        if attr_cols is None:
            attr_cols = []
            
        for _, row in edges_df.iterrows():
            src = row[src_col]
            dst = row[dst_col]
            
            # Extract edge attributes
            attrs = {col: row[col] for col in attr_cols if col in row}
            
            # Add nodes if they don't exist
            if not self.G.has_node(src):
                self.G.add_node(src, type='host')
            if not self.G.has_node(dst):
                # Simple heuristic: if it's not an IP, it might be a domain
                node_type = 'domain' if not dst.replace('.', '').isnumeric() else 'host'
                self.G.add_node(dst, type=node_type)
                
            # Add edge with weight based on connection count if available
            weight = row.get('conn_count', 1.0)
            self.G.add_edge(src, dst, weight=weight, **attrs)
            
    def get_snapshot(self) -> nx.MultiDiGraph:
        """Returns the current state of the graph."""
        return self.G.copy()
        
    def save_snapshot(self, version: str = 'latest') -> str:
        """Persists the graph onto disk for training the GraphSAGE model or Node2Vec."""
        path = os.path.join(self.snapshot_dir, f'graph_{version}.pkl')
        with open(path, 'wb') as f:
            pickle.dump(self.G, f)
        return path
        
    def load_snapshot(self, version: str = 'latest'):
        """Loads a graph snapshot from disk."""
        path = os.path.join(self.snapshot_dir, f'graph_{version}.pkl')
        if os.path.exists(path):
            with open(path, 'rb') as f:
                self.G = pickle.load(f)
        else:
            print(f"No snapshot found at {path}, starting fresh.")
            
def update_graph_from_batch(df: pd.DataFrame) -> GraphBuilder:
    """Helper to maintain the state of the graph given a new batch."""
    builder = GraphBuilder()
    builder.load_snapshot('latest')
    
    # We assume 'src_ip', 'dst_ip' exist. If not mapped, skip.
    if 'src_ip' in df.columns and ('dst_ip' in df.columns or 'domain' in df.columns):
        dst_col = 'dst_ip' if 'dst_ip' in df.columns else 'domain'
        builder.ingest_edges(df, src_col='src_ip', dst_col=dst_col, attr_cols=['bytes_in_sum', 'timestamp'])
        
    builder.save_snapshot('latest')
    return builder

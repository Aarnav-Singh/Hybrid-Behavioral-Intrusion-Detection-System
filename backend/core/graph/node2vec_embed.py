import networkx as nx
from node2vec import Node2Vec
import numpy as np
import os
import pickle

class Embedder:
    def __init__(self, dimensions: int = 64, walk_length: int = 40, num_walks: int = 10, workers: int = 4):
        self.dimensions = dimensions
        self.walk_length = walk_length
        self.num_walks = num_walks
        self.workers = workers
        self.model = None

    def fit(self, graph: nx.Graph, save_path: str = "artifacts/node2vec.model"):
        """
        Trains Node2Vec on the provided graph. Node2Vec uses random walks to capture the local neighborhood
        and computes embeddings.
        """
        if graph.number_of_nodes() == 0:
            print("Graph is empty. Skipping embedding.")
            return

        # Precompute probabilities and generate walks
        node2vec = Node2Vec(
            graph, 
            dimensions=self.dimensions, 
            walk_length=self.walk_length, 
            num_walks=self.num_walks, 
            workers=self.workers,
            quiet=True # Don't print progress bar to stdout
        )
        
        # Embed nodes
        # Using unigram word frequency distribution and hierarchical softmax
        self.model = node2vec.fit(window=5, min_count=1, batch_words=4)
        
        # Ensure directory exists before saving
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        # Save model
        self.model.wv.save_word2vec_format(save_path)
        print(f"Node2Vec model saved to {save_path}")

    def load(self, path: str = "artifacts/node2vec.model"):
        """Loads a pre-trained Word2Vec format Node2Vec model."""
        from gensim.models import KeyedVectors
        self.model = KeyedVectors.load_word2vec_format(path)

    def get_embedding(self, node_id: str) -> np.ndarray:
        """Retrieves the embedding for a specific node, or a zero vector if unknown."""
        node_str = str(node_id)
        if self.model and node_str in self.model:
            return self.model[node_str]
        else:
            return np.zeros(self.dimensions)

def run_node2vec_pipeline(graph_path: str = "artifacts/graph_latest.pkl", save_path: str = "artifacts/node2vec.model"):
    """Pipeline entry function for triggering Node2Vec retraining over RQ worker or CLI."""
    if not os.path.exists(graph_path):
        print(f"Could not find graph snapshot: {graph_path}")
        return

    with open(graph_path, 'rb') as f:
        graph = pickle.load(f)

    embedder = Embedder()
    # It converts directed/multidigraphs to undirected simpler graphs implicitly, which Node2Vec usually requires
    graph_undirected = nx.Graph(graph)
    embedder.fit(graph_undirected, save_path)

"""
evaluation/data_loader.py
=========================
Loader for real-world IDS datasets (CIC-IDS2017, UNSW-NB15).
Provides a consistent interface for benchmark evaluation.
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, Optional

class IDSDataLoader:
    def __init__(self, data_root: str = "data"):
        self.data_root = data_root

    def load_cicids2017(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Loads pre-processed CIC-IDS2017 features.
        Expects a CSV file with features mapping to our 10 behavioral features.
        """
        path = os.path.join(self.data_root, "cicids2017_processed.csv")
        if not os.path.exists(path):
            print(f"  [!] CIC-IDS2017 not found at {path}. Returning synthetic fallback.")
            return self._generate_synthetic_fallback(name="CIC-IDS2017")
        
        df = pd.read_csv(path)
        X = df.drop(columns=["label"]).values
        y = df["label"].values
        return X, y

    def load_unsw_nb15(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Loads pre-processed UNSW-NB15 features.
        """
        path = os.path.join(self.data_root, "unsw_nb15_processed.csv")
        if not os.path.exists(path):
            print(f"  [!] UNSW-NB15 not found at {path}. Returning synthetic fallback.")
            return self._generate_synthetic_fallback(name="UNSW-NB15")

        df = pd.read_csv(path)
        X = df.drop(columns=["label"]).values
        y = df["label"].values
        return X, y

    def _generate_synthetic_fallback(self, name: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generates name-specific synthetic data if real datasets aren't available locally.
        Ensures the evaluation pipeline still runs.
        """
        rng = np.random.default_rng(seed=42 if name == "CIC-IDS2017" else 99)
        n_samples = 2000
        attack_ratio = 0.2
        n_attack = int(n_samples * attack_ratio)
        n_normal = n_samples - n_attack

        # Shift distributions slightly to simulate different dataset characteristics
        shift = 0.1 if name == "CIC-IDS2017" else -0.1
        normal = rng.normal(loc=[0.2 + shift, 0.8, 0.1], scale=[0.3, 0.4, 0.1], size=(n_normal, 3)).clip(0, 1)
        attack = rng.normal(loc=[0.75, 3.2, 0.85], scale=[0.2, 0.5, 0.15], size=(n_attack, 3)).clip(0, 1)

        X = np.vstack([normal, attack])
        y = np.array([0] * n_normal + [1] * n_attack)
        idx = rng.permutation(len(y))
        return X[idx], y[idx]

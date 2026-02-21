import pandas as pd
from typing import Dict

class FeaturePerturbationAttack:
    """
    White-box evasion attack (mimicking PGD or similar methods).
    The attacker knows the feature weights and intentionally clips/modifies flow 
    characteristics to stay beneath the Fusion MLP threshold.
    """
    def __init__(self, target_ip: str, max_perturbation: float = 0.15):
        self.target_ip = target_ip
        self.max_perturbation = max_perturbation

    def inject(self, df: pd.DataFrame) -> pd.DataFrame:
        attack_df = df.copy()
        mask = attack_df['src_ip'] == self.target_ip
        
        if not mask.any():
            return attack_df
            
        columns_to_perturb = ['bytes_in_sum', 'bytes_out_sum', 'dst_port_nunique', 'delta_bytes_in']
        
        # Reduce the observable metrics slightly to drop the anomaly score below decision boundary
        for col in columns_to_perturb:
            if col in attack_df.columns:
                attack_df.loc[mask, col] = attack_df.loc[mask, col] * (1.0 - self.max_perturbation)
                
        # Manually suppress intel scores (assuming attacker changes domains/IPs to clean ones)
        if 'ip_reputation_score' in attack_df.columns:
            attack_df.loc[mask, 'ip_reputation_score'] = 0.0
            
        return attack_df

import pandas as pd
import numpy as np

class BeaconEvasionAttack:
    """
    Simulates a C2 (Command & Control) beaconing behavior where the attacker
    tries to evade detection by keeping connection counts very low, spacing them out,
    and avoiding repetitive port usage to bypass simple temporal models like Isolation Forests.
    """
    def __init__(self, target_ip: str, intensity: float = 1.0):
        self.target_ip = target_ip
        self.intensity = intensity

    def inject(self, df: pd.DataFrame) -> pd.DataFrame:
        attack_df = df.copy()
        mask = attack_df['src_ip'] == self.target_ip
        
        # Inject sparse but anomalous bytes to represent slow beacon pulls
        # This increases the delta_bytes slightly but keeps connection counts artificially constrained
        attack_df.loc[mask, 'bytes_in_sum'] += 500 * self.intensity
        attack_df.loc[mask, 'bytes_out_sum'] += 100 * self.intensity
        
        # Manually lower the entropy of the connection to simulate traffic blending
        attack_df.loc[mask, 'domain_entropy'] = np.clip(attack_df.loc[mask, 'domain_entropy'] - 1.0 * self.intensity, 0, None)
        
        return attack_df

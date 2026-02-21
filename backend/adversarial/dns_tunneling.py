import pandas as pd
import numpy as np

class DNSTunnelingAttack:
    """
    Simulates a low-and-slow DNS tunneling attack.
    Injects high entropy domains and high NXDomain rates into the telemetry.
    """
    def __init__(self, target_ip: str, intensity: float = 1.0):
        self.target_ip = target_ip
        self.intensity = intensity
        
    def inject(self, df: pd.DataFrame) -> pd.DataFrame:
        """Modifies the dataframe to reflect a DNS tunneling attack from the target IP."""
        attack_df = df.copy()
        mask = attack_df['src_ip'] == self.target_ip
        
        if not mask.any():
            print(f"Target IP {self.target_ip} not found in the baseline telemetry.")
            return attack_df
            
        # Increase unique domains and entropy synthetically
        attack_df.loc[mask, 'domain_nunique'] = (attack_df.loc[mask, 'domain_nunique'] + 50 * self.intensity).astype(int)
        attack_df.loc[mask, 'domain_entropy'] = np.clip(attack_df.loc[mask, 'domain_entropy'] + 2.5 * self.intensity, 0, 8.0)
        
        # Increase payload byte counts disproportionately for DNS (UDP/53 usually small)
        attack_df.loc[mask, 'bytes_out_sum'] += 15000 * self.intensity
        
        return attack_df

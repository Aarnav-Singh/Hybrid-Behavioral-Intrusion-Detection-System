import pandas as pd
import random

class GraphPoisoningAttack:
    """
    Simulates an attacker trying to evade GraphSAGE detection by performing 
    Denial of Service (DoS) or random noisy connections to trusted nodes (Google, DNS roots).
    This attempts to blend the attacker's localized graph neighborhood with benign hubs.
    """
    def __init__(self, target_ip: str, trusted_ips: list = None, num_edges: int = 10):
        self.target_ip = target_ip
        self.trusted_ips = trusted_ips or ['8.8.8.8', '1.1.1.1', '192.168.1.1'] # Typical hubs
        self.num_edges = num_edges
        
    def inject(self, df: pd.DataFrame) -> pd.DataFrame:
        attack_df = df.copy()
        
        # We need raw flow data (not just windowed) to inject actual edges
        if 'dst_ip' not in attack_df.columns:
            # If applied to windowed data, we just inflate the connection count
            mask = attack_df['src_ip'] == self.target_ip
            attack_df.loc[mask, 'dst_port_nunique'] += self.num_edges
            return attack_df
            
        # Inject noisy edges
        new_rows = []
        for _ in range(self.num_edges):
            row = attack_df.iloc[0].copy() # copy structure
            row['src_ip'] = self.target_ip
            row['dst_ip'] = random.choice(self.trusted_ips)
            row['bytes_out'] = random.randint(40, 100)
            new_rows.append(row)
            
        attack_df = pd.concat([attack_df, pd.DataFrame(new_rows)], ignore_index=True)
        return attack_df

import pandas as pd
import numpy as np
from typing import List, Dict, Any

class FeatureEngineer:
    def __init__(self, window_size: str = '1T'):
        self.window_size = window_size
        
    def add_entropy(self, data: pd.Series) -> float:
        """Calculate Shannon entropy for a series of values (e.g., domain names)."""
        counts = data.value_counts()
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs + 1e-9))
        return entropy

    def apply_windowing(self, df: pd.DataFrame, ts_col: str = 'timestamp', entity_col: str = 'src_ip') -> pd.DataFrame:
        """
        Group records into sliding windows based on entity and calculate statistical features.
        
        Expected features matching the schema:
        {bytes_in, bytes_out, conn_count, unique_domains, domain_entropy, nx_domain_rate, failed_logins, port_count, fortiguard_hits, ip_reputation_score, max_cvss, vuln_count}
        """
        df[ts_col] = pd.to_datetime(df[ts_col])
        df = df.set_index(ts_col)
        
        # Define aggregations per entity
        aggs = {
            'bytes_in': 'sum',
            'bytes_out': 'sum',
            'dst_port': 'nunique',
            'domain': ['nunique', self.add_entropy],
            'is_nxdomain': 'mean', # Rate of NXDomain responses
            'failed_login': 'sum',
            'fortiguard_hit': 'sum',
            'cvss_score': 'max',
            'is_vuln': 'sum'
        }
        
        # Resample by window size and entity ID
        windowed = df.groupby(entity_col).resample(self.window_size).agg(aggs)
        
        # Flatten MultiIndex columns
        windowed.columns = [f"{col[0]}_{col[1]}" if col[1] != '' else col[0] for col in windowed.columns]
        
        # Calculate deltas (differences from previous window)
        windowed['delta_bytes_in'] = windowed.groupby(entity_col)['bytes_in_sum'].diff().fillna(0)
        windowed['delta_conn_count'] = windowed.groupby(entity_col)['dst_port_nunique'].diff().fillna(0)
        
        windowed = windowed.reset_index()
        return windowed

    def enrich_intel(self, df: pd.DataFrame, entity_col: str = 'src_ip') -> pd.DataFrame:
        """
        Mock enrichment function simulating FortiGuard/IP Reputation APIs.
        In a real scenario, this would query a Redis cache or external API.
        """
        # Simulated reputation score (0-100, where 100 is high risk)
        df['ip_reputation_score'] = np.random.uniform(0, 20, size=len(df))
        return df

def process_batch(raw_events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Main pipeline entry point for processing a batch of events."""
    df = pd.DataFrame(raw_events)
    if df.empty:
        return df
    
    engineer = FeatureEngineer(window_size='1T')
    windowed_df = engineer.apply_windowing(df)
    enriched_df = engineer.enrich_intel(windowed_df)
    
    return enriched_df

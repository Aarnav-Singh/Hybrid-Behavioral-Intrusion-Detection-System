import pandas as pd
import pytest
from backend.core.feature_engineering import FeatureEngineer, process_batch

def test_entropy_calculation():
    engineer = FeatureEngineer()
    
    # Low entropy (all same)
    s1 = pd.Series(['google.com', 'google.com', 'google.com'])
    # High entropy (all different)
    s2 = pd.Series(['google.com', 'yahoo.com', 'bing.com'])
    
    assert engineer.add_entropy(s1) < engineer.add_entropy(s2)

def test_batch_pipeline_empty():
    df = process_batch([])
    assert df.empty
    
def test_batch_pipeline_valid():
    data = [
        {"timestamp": "2024-01-01T12:00:00Z", "src_ip": "10.0.0.1", "dst_port": 443, "domain": "github.com", "bytes_in": 100},
        {"timestamp": "2024-01-01T12:00:30Z", "src_ip": "10.0.0.1", "dst_port": 80, "domain": "example.com", "bytes_in": 200}
    ]
    df = process_batch(data)
    
    assert not df.empty
    assert "bytes_in_sum" in df.columns
    assert df.iloc[0]["bytes_in_sum"] == 300
    assert "ip_reputation_score" in df.columns

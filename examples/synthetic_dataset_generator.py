import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_dataset(num_rows: int = 10000, output_path: str = 'examples/synthetic_dataset.csv'):
    """Generates a synthetic dataset of sliding window network flows."""
    print(f"Generating {num_rows} rows of synthetic network flow telemetry...")
    
    start_time = datetime.now() - timedelta(days=7)
    
    # Common IPs and Domains
    internal_ips = [f"10.0.0.{i}" for i in range(10, 60)]
    external_ips = [f"192.168.1.{i}" for i in range(1, 255)]
    domains = ['google.com', 'microsoft.com', 'amazon.com', 'github.com']
    
    records = []
    
    for i in range(num_rows):
        timestamp = start_time + timedelta(minutes=i)
        is_malicious = random.random() < 0.05 # 5% baseline malicious
        
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
        
        # Base stats
        bytes_in = int(np.random.normal(5000, 1000))
        bytes_out = int(np.random.normal(1500, 500))
        conn_count = random.randint(1, 20)
        domain = random.choice(domains)
        
        if is_malicious:
            # Inject anomaly (e.g. data exfiltration or scanning)
            bytes_out += int(np.random.normal(50000, 10000))
            conn_count += random.randint(50, 200)
            domain = 'unknown-c2-malicious.xyz'
            
        records.append({
            'timestamp': timestamp.isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': random.choice([80, 443, 53, 22, 3389]),
            'domain': domain,
            'bytes_in': max(0, bytes_in),
            'bytes_out': max(0, bytes_out),
            'conn_count': conn_count,
            'is_malicious': int(is_malicious)
        })
        
    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"Saved synthetic dataset to {output_path}")

if __name__ == "__main__":
    generate_dataset()

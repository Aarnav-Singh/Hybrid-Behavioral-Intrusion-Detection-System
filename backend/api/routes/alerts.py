from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict
import datetime
import random

from backend.core.models import registry
from backend.core.threat_intel import ThreatIntelligenceAPI

router = APIRouter()
intel_client = ThreatIntelligenceAPI()

class AlertResponse(BaseModel):
    id: str
    severity: str
    timestamp: str
    score: float
    threat_type: str
    target_ip: str
    datetime: str
    source_ip: str
    shap_values: Dict[str, float]
    threat_intel: dict = None

# A pool of recent suspicious IPs detected by the V1 models to simulate live traffic
SUSPICIOUS_IPS = [
    "185.153.199.117", # The one tested earlier (Clean)
    "104.25.10.12",    # External IP
    "10.0.0.5",        # Internal IP (Should theoretically bypass external intel)
    "8.8.8.8",         # Clean Google DNS
    "45.227.255.190"   # Known malicious scanner
]

@router.get("/alerts", response_model=List[AlertResponse])
async def get_latest_alerts():
    """
    Fetch the latest detection alerts. 
    Here, we simulate the detection engine output and enrich it LIVE using AbuseIPDB.
    """
    active_model = registry.get_active_model()
    
    # 1. Simulate the detection engine flagging recent anomalies
    base_alerts = []
    
    # Select a random subset of suspicious IPs for this "poll" to simulate dynamic flow
    num_ips = random.randint(3, 5)
    selected_ips = random.sample(SUSPICIOUS_IPS, min(num_ips, len(SUSPICIOUS_IPS)))
    
    # Occasionally add a completely new random IP
    if random.random() > 0.7:
        selected_ips.append(f"194.168.{random.randint(1, 255)}.{random.randint(2, 254)}")

    now = datetime.datetime.now()

    for i, ip in enumerate(selected_ips):
        # Add jitter to timestamps so they don't all look identical (0-15s ago)
        alert_time = now - datetime.timedelta(seconds=random.randint(0, 15))
        
        # Base ML Anomaly Score varies based on model type
        if active_model.id == "hybrid":
            # Hybrid balances all features
            base_score = random.uniform(0.65, 0.98) if ("10." in ip or "185." in ip) else random.uniform(0.2, 0.5)
            threat_name = "Multi-Vector Behavioral Anomaly (Hybrid)"
        elif active_model.id == "fast":
            # Fast focuses on statistical volume
            base_score = random.uniform(0.4, 0.8)
            threat_name = "Rapid Traffic Spike (Fast Baseline)"
        elif active_model.id == "graphsage":
            base_score = random.uniform(0.6, 0.95) if "10." in ip else random.uniform(0.3, 0.6)
            threat_name = "Structural Anomaly (GraphSAGE)"
        elif active_model.id == "tcn":
            base_score = random.uniform(0.5, 0.9)
            threat_name = "Temporal Pattern Match (TCN)"
        else: # xgboost / default
            base_score = random.uniform(0.4, 0.85)
            threat_name = "Statistical Outlier (XGBoost)"
            
        alert = {
            "id": f"ALRT-{1000 + i + random.randint(100, 999)}", 
            "severity": "medium",
            "timestamp": alert_time.strftime("%H:%M:%S"),
            "datetime": alert_time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": base_score,
            "threat_type": threat_name,
            "source_ip": ip,
            "target_ip": "192.168.1.100",
            "shap_values": {
                "packet_size_std": random.uniform(0.1, 0.5),
                "conn_duration": random.uniform(0.05, 0.3),
                "graph_auth_fails": random.uniform(0.0, 0.8) if active_model.id == "graphsage" else random.uniform(0.0, 0.2)
            }
        }
        
        # 2. ENRICHMENT PHASE: Call the Threat Intel API (AbuseIPDB)
        intel_data = await intel_client.check_ip(ip)
        
        if intel_data:
            alert["threat_intel"] = intel_data
            if intel_data["malicious"]:
                alert["score"] = min(base_score + 0.3, 0.99)
                alert["threat_type"] = f"{threat_name} + Intel Match"
            else:
                if intel_data["confidence"] == 0 and not ip.startswith("10."):
                    alert["score"] = max(base_score - 0.3, 0.1)
        
        # 3. Final Thresholding
        if alert["score"] >= 0.85:
            alert["severity"] = "critical"
        elif alert["score"] >= 0.60:
            alert["severity"] = "high"
        else:
            alert["severity"] = "medium"
            
        base_alerts.append(alert)
        
    # Sort by score for the dashboard view
    base_alerts.sort(key=lambda x: x["score"], reverse=True)
    return base_alerts

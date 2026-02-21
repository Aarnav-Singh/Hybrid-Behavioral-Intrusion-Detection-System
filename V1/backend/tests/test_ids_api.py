import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from server import app

# We'll mock the database connections or rely on the fact that TestClient triggers lifespan 
# which will try to connect. If Mongo isn't running, tests might fail. 
# We'll skip tests if they fail due to connection issues.

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ONLINE"

def test_get_alerts():
    response = client.get("/api/alerts?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_get_alert_stats():
    response = client.get("/api/alerts/stats")
    assert response.status_code == 200
    data = response.json()
    assert "stats" in data
    assert "total" in data

def test_get_packets():
    response = client.get("/api/packets?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_get_system():
    response = client.get("/api/system")
    assert response.status_code == 200
    data = response.json()
    assert "elasticsearch" in data

def test_get_traffic():
    response = client.get("/api/traffic")
    assert response.status_code == 200
    data = response.json()
    assert "history" in data

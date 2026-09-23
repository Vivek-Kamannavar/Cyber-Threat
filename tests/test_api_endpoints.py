"""
Phase 5 Test Suite: API & WebSocket Resilience
Tests WebSocket connection lifecycle, file upload routes, simulation triggers,
and live topology endpoints.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.main import app

client = TestClient(app)


def test_health_and_status_endpoints():
    """Verifies GET /api/health and GET /api/detection/status."""
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["status"] == "healthy"
    assert "diode_mode" in health_data

    status_res = client.get("/api/detection/status")
    assert status_res.status_code == 200
    assert "auto_detection_enabled" in status_res.json()


def test_simulation_endpoints():
    """Verifies POST /api/simulate/{threat_type} for valid and invalid threats."""
    valid_threats = ['ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration']

    for threat in valid_threats:
        res = client.post(f"/api/simulate/{threat}")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "threat_injected"
        assert data["flows_processed"] > 0
        assert data["alerts_raised"] >= 1

    # Invalid threat returns 400
    invalid_res = client.post("/api/simulate/invalid_worm_type")
    assert invalid_res.status_code == 400


def test_topology_endpoint():
    """Verifies GET /api/topology extracts live communicating nodes and edges."""
    res = client.get("/api/topology")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert "total_active_flows" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


def test_websocket_snapshot():
    """Verifies that WebSocket connection receives initial snapshot on connect."""
    with client.websocket_connect("/ws/alerts") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert "stats" in msg
        assert "recent_alerts" in msg

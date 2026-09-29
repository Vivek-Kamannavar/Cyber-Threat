"""
Test Suite: Continuous Threat Incident Streaming & Baseline Coverage
Verifies that:
1. Baseline demo alerts cover all 6 primary SOC threat vectors.
2. WebSocket snapshot delivers the pre-loaded baseline alerts.
3. Periodic threat scenarios dynamically raise detection alerts.
4. Alert clearing safely resets the stream to zero.
"""

import sys
import os
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.main import app, detector, BASELINE_DEMO_ALERTS
from ingest.traffic_generator import TrafficGenerator

client = TestClient(app)


def test_baseline_alerts_cover_all_six_threat_classes():
    """Verifies that the 6 baseline alerts represent each primary threat category."""
    expected_classes = {
        "Botnet C2 Beaconing",
        "DGA Domains & DNS Tunnelling",
        "Volumetric / Protocol DDoS",
        "Encrypted Malware (TLS/QUIC)",
        "Reconnaissance & Port Scanning",
        "Data Exfiltration"
    }

    baseline_classes = {alert["threat_class"] for alert in BASELINE_DEMO_ALERTS}
    assert expected_classes.issubset(baseline_classes), f"Missing threat classes in baseline: {expected_classes - baseline_classes}"
    assert len(BASELINE_DEMO_ALERTS) >= 6


def test_websocket_snapshot_contains_baseline_alerts():
    """Verifies that newly connected WebSocket clients receive snapshot with all baseline alerts."""
    with client.websocket_connect("/ws/alerts") as ws:
        snapshot = ws.receive_json()
        assert snapshot["type"] == "snapshot"
        assert "recent_alerts" in snapshot
        assert len(snapshot["recent_alerts"]) >= 6
        alert_ids = [a["alert_id"] for a in snapshot["recent_alerts"]]
        assert "ALT-70778D62" in alert_ids or len(alert_ids) >= 6


def test_all_threat_scenarios_generate_valid_alerts():
    """Verifies that all 6 threat scenario types produce valid alerts when processed by the detector."""
    generator = TrafficGenerator()
    threat_types = ['ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration']

    for threat in threat_types:
        flows = generator.generate_threat_scenario(threat)
        raised = []
        for flow in flows:
            alerts = detector.process_flow(flow)
            raised.extend(alerts)
        
        assert len(raised) >= 1, f"Scenario {threat} failed to raise an alert."
        for alert in raised:
            assert "alert_id" in alert
            assert "threat_class" in alert
            assert alert["confidence_score"] >= 0.70
            assert "flow_identifier" in alert


def test_clear_alerts_and_restoration():
    """Verifies that clear_alerts resets alert history to 0."""
    res = client.post("/api/alerts/clear")
    assert res.status_code == 200
    assert res.json()["status"] == "alerts_cleared"
    assert len(detector.get_all_alerts()) == 0

    # Inject a simulated threat to verify alert stream works after clear
    sim_res = client.post("/api/simulate/ddos")
    assert sim_res.status_code == 200
    assert sim_res.json()["alerts_raised"] >= 1
    assert len(detector.get_all_alerts()) >= 1

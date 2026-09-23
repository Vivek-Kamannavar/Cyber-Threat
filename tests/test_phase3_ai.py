"""
Phase 3 Test Suite: Free Groq AI Incident Copilot & Natural Language Explanations
Tests Groq client integration, deterministic offline fallbacks, response schema compliance,
and SQLite response caching.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.groq_service import GroqCopilotService
from backend.database import save_alert, init_db, clear_alerts
from backend.main import app

client = TestClient(app)


def test_offline_fallback_schema_compliance():
    """Verifies that the offline rule-based analyzer generates valid structured JSON with all required keys."""
    service = GroqCopilotService(api_key="")  # Force offline fallback
    mock_alert = {
        "alert_id": "ALT-TEST-001",
        "threat_class": "Data Exfiltration",
        "confidence_score": 0.96,
        "flow_identifier": {
            "src_ip": "192.168.10.15",
            "src_port": 50123,
            "dst_ip": "45.142.214.8",
            "dst_port": 443,
            "protocol": "TCP"
        },
        "supporting_evidence_feature": {
            "megabytes_exfiltrated": 18.45,
            "asymmetry_ratio": 1475.88,
            "reason": "Extreme outbound data flow"
        }
    }

    analysis = service.analyze_alert(mock_alert)

    # Check required schema keys
    assert "summary" in analysis
    assert "severity_rating" in analysis
    assert "attack_vector_breakdown" in analysis
    assert "potential_business_impact" in analysis
    assert "recommended_remediation_steps" in analysis
    assert "firewall_mitigation_rule" in analysis

    assert analysis["severity_rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert isinstance(analysis["recommended_remediation_steps"], list)
    assert len(analysis["recommended_remediation_steps"]) >= 2
    assert "iptables" in analysis["firewall_mitigation_rule"]
    assert "192.168.10.15" in analysis["firewall_mitigation_rule"]


def test_ai_analyze_alert_endpoint_and_sqlite_caching(tmp_path):
    """Verifies POST /api/ai/analyze-alert/{id} and subsequent SQLite cached retrieval."""
    test_db = str(tmp_path / "test_ai_cache.db")
    init_db(test_db)
    clear_alerts(test_db)

    # Seed an alert
    sample_alert = {
        "alert_id": "ALT-AI-999",
        "timestamp": "2026-09-23T12:00:00Z",
        "threat_class": "Botnet C2 Beaconing",
        "confidence_score": 0.94,
        "flow_identifier": {
            "src_ip": "192.168.10.22",
            "src_port": 49120,
            "dst_ip": "91.215.102.14",
            "dst_port": 8443,
            "protocol": "TCP"
        },
        "supporting_evidence_feature": {
            "coefficient_of_variation": 0.012,
            "reason": "Periodic beaconing"
        }
    }
    save_alert(sample_alert)

    # First call: Should compute and cache (cached: False)
    res1 = client.post("/api/ai/analyze-alert/ALT-AI-999")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["alert_id"] == "ALT-AI-999"
    assert data1["cached"] is False
    assert "analysis" in data1
    assert data1["analysis"]["severity_rating"] in ("CRITICAL", "HIGH")

    # Second call: Should return from SQLite cache (cached: True)
    res2 = client.post("/api/ai/analyze-alert/ALT-AI-999")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["alert_id"] == "ALT-AI-999"
    assert data2["cached"] is True
    assert data2["analysis"] == data1["analysis"]


def test_ai_chat_endpoint():
    """Verifies POST /api/ai/chat returns actionable response with context."""
    chat_payload = {
        "message": "How do I block this host using iptables?",
        "alert_context": {
            "threat_class": "Data Exfiltration",
            "flow_identifier": {
                "src_ip": "192.168.10.45",
                "dst_ip": "45.142.214.8"
            }
        }
    }

    res = client.post("/api/ai/chat", json=chat_payload)
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "iptables" in data["reply"]
    assert "192.168.10.45" in data["reply"]

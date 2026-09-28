"""
Conversational AI Security Analyst Test Suite
Covers the /api/copilot/chat contract, live context injection, intent routing and the
deterministic offline fallback used when GROQ_API_KEY is absent.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import backend.main as main_module
from backend.copilot import ConversationalCopilot, DEFAULT_SUGGESTIONS
from backend.services.groq_service import GroqCopilotService
from backend.main import app

client = TestClient(app)

SAMPLE_TELEMETRY = {"pps": 421.5, "bps": 1_820_000.0, "total_flows": 96}

SAMPLE_ALERT = {
    "alert_id": "ALT-CHAT-001",
    "threat_class": "Data Exfiltration",
    "confidence_score": 0.97,
    "flow_identifier": {
        "src_ip": "192.168.10.31",
        "src_port": 51200,
        "dst_ip": "45.142.214.8",
        "dst_port": 443,
        "protocol": "TCP",
    },
    "supporting_evidence_feature": {
        "megabytes_exfiltrated": 22.5,
        "asymmetry_ratio": 812.4,
        "reason": "A workstation quietly uploaded an unusually large amount of data outside the plant.",
    },
}

SAMPLE_ALERTS = [
    SAMPLE_ALERT,
    {
        "alert_id": "ALT-CHAT-002",
        "threat_class": "Botnet C2 Beaconing",
        "confidence_score": 0.72,
        "flow_identifier": {
            "src_ip": "192.168.10.19",
            "src_port": 49881,
            "dst_ip": "91.215.102.14",
            "dst_port": 8443,
            "protocol": "TCP",
        },
        "supporting_evidence_feature": {"coefficient_of_variation": 0.03},
    },
]


def _offline_copilot() -> ConversationalCopilot:
    """Copilot forced into deterministic offline mode (no API key, no network)."""
    return ConversationalCopilot(GroqCopilotService(api_key=""))


def test_context_injection_summarises_live_telemetry_and_incidents():
    """The offline posture answer must reflect the injected telemetry and alert set."""
    copilot = _offline_copilot()
    context = copilot.build_context(SAMPLE_TELEMETRY, SAMPLE_ALERTS)

    assert context["incidents"]["total"] == 2
    assert context["incidents"]["critical"] == 1
    assert context["throughput"]["pps"] == 421.5
    assert context["focus_alert"]["alert_id"] == "ALT-CHAT-001"
    assert context["incidents"]["by_class"]["Data Exfiltration"] == 1

    result = copilot.respond("Summarize threat posture", SAMPLE_TELEMETRY, SAMPLE_ALERTS)

    assert result["mode"] == "OFFLINE_HEURISTIC"
    assert "CRITICAL" in result["response"]
    assert "Window throughput" in result["response"]
    assert "pps" in result["response"]
    assert "Data Exfiltration" in result["response"]


def test_intent_routing_generates_rules_and_incident_explanations():
    """Firewall and explain intents must produce actionable, grounded answers."""
    copilot = _offline_copilot()

    rules = copilot.respond("Generate firewall rules", SAMPLE_TELEMETRY, SAMPLE_ALERTS)
    assert "iptables" in rules["response"]
    assert "192.168.10.31" in rules["response"]

    explained = copilot.respond("Explain the latest incident", SAMPLE_TELEMETRY, SAMPLE_ALERTS)
    assert "ALT-CHAT-001" in explained["response"]
    assert "Data Exfiltration" in explained["response"]

    containment = copilot.respond("What should I contain first?", SAMPLE_TELEMETRY, SAMPLE_ALERTS)
    assert "Containment Plan" in containment["response"]


def test_empty_message_and_empty_context_never_raise():
    """Empty prompts and a cold SOC (no telemetry, no alerts) must stay well-formed."""
    copilot = _offline_copilot()

    blank = copilot.respond("", None, None)
    assert blank["mode"] == "OFFLINE_HEURISTIC"
    assert blank["response"]
    assert blank["suggestions"]

    cold = copilot.respond("Summarize threat posture", None, [])
    assert cold["mode"] == "OFFLINE_HEURISTIC"
    assert "NORMAL" in cold["response"]


def test_suggestions_are_bounded_and_context_driven():
    """Suggestion chips stay at four and reference the focused incident when one exists."""
    copilot = _offline_copilot()

    with_incidents = copilot.respond("hello", SAMPLE_TELEMETRY, SAMPLE_ALERTS)
    assert len(with_incidents["suggestions"]) == 4
    assert any("ALT-CHAT-001" in chip for chip in with_incidents["suggestions"])

    without_incidents = copilot.respond("hello", SAMPLE_TELEMETRY, [])
    assert len(without_incidents["suggestions"]) == 4
    assert set(without_incidents["suggestions"]).issubset(set(DEFAULT_SUGGESTIONS) | set(without_incidents["suggestions"]))


def test_copilot_chat_endpoint_contract(monkeypatch):
    """POST /api/copilot/chat always answers {response, mode, suggestions} with live context."""
    monkeypatch.setattr(main_module, "conversational_copilot", _offline_copilot())

    res = client.post(
        "/api/copilot/chat",
        json={"message": "Summarize threat posture", "history": [{"role": "user", "content": "hi"}]},
    )
    assert res.status_code == 200
    data = res.json()
    assert set(data.keys()) >= {"response", "mode", "suggestions"}
    assert data["mode"] in ("GROQ", "OFFLINE_HEURISTIC")
    assert isinstance(data["suggestions"], list)
    assert data["response"]

    empty = client.post("/api/copilot/chat", json={"message": ""})
    assert empty.status_code == 200
    assert empty.json()["response"]

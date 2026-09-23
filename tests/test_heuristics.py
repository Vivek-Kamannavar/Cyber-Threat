"""
Phase 5 Test Suite: Detection Heuristic Boundaries & False-Positive Hardening
Tests exact threshold boundary transitions (DDoS, C2, Exfiltration) and asserts
zero false-positive alerts across 1,000 continuous benign flows.
"""

import sys
import os
import time
import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.models.heuristic_rules import ThreatHeuristics
from engine.threat_detector import ThreatDetector
from ingest.traffic_generator import TrafficGenerator
from backend.config import Config


def test_ddos_rate_threshold_boundary():
    """
    Tests DDoS boundary: 24 flows (no trigger) vs 25 flows with low entropy (trigger).
    """
    now = time.time()
    # 24 single-source flows (just below Config.DDOS_RATE_THRESHOLD = 25)
    flows_24 = [
        {
            "flow_identifier": {"src_ip": "10.0.0.99", "dst_ip": "10.0.0.1", "src_port": 10000 + i, "dst_port": 80},
            "timestamp": now + i * 0.1,
            "tcp_flags": "S"
        }
        for i in range(24)
    ]
    # Under 25 flows, evaluate_ddos should return None (syn_count <= 20 condition also kept in mind)
    # Give tcp_flags without 'S' so syn_count won't bypass
    for f in flows_24:
        f["tcp_flags"] = ""

    alert_24 = ThreatHeuristics.evaluate_ddos(flows_24)
    assert alert_24 is None, "DDoS should NOT trigger at 24 flows"

    # Add 1 more flow -> 25 flows with low source IP entropy (single source IP -> H = 0.0 < 1.5)
    flows_25 = list(flows_24) + [{
        "flow_identifier": {"src_ip": "10.0.0.99", "dst_ip": "10.0.0.1", "src_port": 10025, "dst_port": 80},
        "timestamp": now + 2.5,
        "tcp_flags": ""
    }]
    alert_25 = ThreatHeuristics.evaluate_ddos(flows_25)
    assert alert_25 is not None, "DDoS SHOULD trigger at 25 flows with low entropy"
    assert alert_25["threat_class"] == "Volumetric / Protocol DDoS"


def test_c2_beaconing_cv_threshold_boundary():
    """
    Tests C2 beaconing boundary: CV < 0.22 (trigger) vs CV >= 0.22 (no trigger).
    """
    now = time.time()
    dst_ip = "91.215.102.14"

    # Strict periodic timestamps: intervals = [10.0, 10.0, 10.0, 10.0, 10.0] -> std = 0, CV = 0.0 < 0.22
    periodic_flows = [
        {
            "flow_identifier": {"src_ip": "192.168.10.15", "dst_ip": dst_ip, "src_port": 50000 + i, "dst_port": 443},
            "timestamp": now + (i * 10.0)
        }
        for i in range(6)
    ]
    alert_periodic = ThreatHeuristics.evaluate_c2_beaconing(periodic_flows)
    assert alert_periodic is not None, "Periodic beaconing (CV ~ 0.0) must trigger C2 alert"

    # Jittered timestamps with wide variance: intervals = [1.0, 30.0, 2.0, 50.0, 5.0] -> high CV > 0.50
    jittered_delays = [0.0, 1.0, 31.0, 33.0, 83.0, 88.0]
    jittered_flows = [
        {
            "flow_identifier": {"src_ip": "192.168.10.15", "dst_ip": dst_ip, "src_port": 50000 + i, "dst_port": 443},
            "timestamp": now + jittered_delays[i]
        }
        for i in range(len(jittered_delays))
    ]
    alert_jittered = ThreatHeuristics.evaluate_c2_beaconing(jittered_flows)
    assert alert_jittered is None, "Irregular jittered traffic (CV >= 0.22) must NOT trigger C2 beaconing alert"


def test_data_exfiltration_bytes_boundary():
    """
    Tests exfiltration byte threshold: 4,999,999 bytes (no trigger) vs 5,000,001 bytes (trigger).
    """
    flow_below = {
        "flow_identifier": {"src_ip": "192.168.10.10", "dst_ip": "45.142.214.8", "src_port": 49123, "dst_port": 443},
        "bytes_sent": 4_999_999,
        "bytes_received": 100
    }
    assert ThreatHeuristics.evaluate_data_exfiltration(flow_below) is None

    flow_above = {
        "flow_identifier": {"src_ip": "192.168.10.10", "dst_ip": "45.142.214.8", "src_port": 49123, "dst_port": 443},
        "bytes_sent": 5_000_001,
        "bytes_received": 100
    }
    alert = ThreatHeuristics.evaluate_data_exfiltration(flow_above)
    assert alert is not None
    assert alert["threat_class"] == "Data Exfiltration"


def test_zero_false_positives_on_benign_traffic():
    """
    Verifies that continuous benign traffic does NOT trigger false heuristic alerts.
    Processes 1,000 normal flows through ThreatDetector.
    """
    detector = ThreatDetector(window_size_seconds=60.0, load_persisted_alerts=False)
    generator = TrafficGenerator()

    rule_alerts = []
    for _ in range(1000):
        flow = generator.generate_benign_flow()
        alerts = detector.process_flow(flow)
        # Filter for rule heuristics (ignore unsupervised ML anomaly if any statistical outlier occurs)
        heuristic_alerts = [a for a in alerts if a["threat_class"] != "Unsupervised Volumetric Anomaly"]
        rule_alerts.extend(heuristic_alerts)

    assert len(rule_alerts) == 0, f"Expected 0 rule-based false positives on benign traffic, got: {len(rule_alerts)}"

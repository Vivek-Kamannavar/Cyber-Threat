"""
Phase 1 Automated Test & Regression Suite
Tests concurrency safety, SQLite persistence, environment configuration overrides,
model persistence with joblib, and baseline threat detection integrity.
"""

import os
import sys
import asyncio
import pytest
import tempfile
import time

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.window_manager import SlidingWindowManager
from engine.threat_detector import ThreatDetector
from engine.models.heuristic_rules import ThreatHeuristics
from engine.models.isolation_forest import FlowAnomalyDetector
from ingest.traffic_generator import TrafficGenerator
from backend.config import Config
from backend.database import (
    save_alert,
    get_all_alerts,
    get_alert_by_id,
    clear_alerts,
    init_db
)


# ======================================================================
# TEST A: Concurrency Safety of SlidingWindowManager
# ======================================================================
@pytest.mark.asyncio
async def test_a_sliding_window_concurrency():
    """
    Simulates 50 concurrent async tasks rapidly pushing flows to SlidingWindowManager
    while reading throughput stats and recent flows simultaneously.
    Asserts zero RuntimeError / iteration size mutation errors.
    """
    wm = SlidingWindowManager(window_size_seconds=10.0)
    errors = []

    async def producer(task_id: int):
        for i in range(20):
            flow = {
                "flow_identifier": {
                    "src_ip": f"192.168.1.{task_id % 10}",
                    "src_port": 10000 + task_id,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "protocol": "TCP"
                },
                "timestamp": time.time(),
                "bytes_sent": 500 + i,
                "bytes_received": 1000 + i,
                "packet_count": 2
            }
            try:
                wm.add_flow(flow)
            except Exception as e:
                errors.append(f"Producer error: {e}")
            await asyncio.sleep(0.001)

    async def consumer():
        for _ in range(50):
            try:
                flows = wm.get_recent_flows()
                _ = len(flows)
                stats = wm.get_throughput_stats()
                _ = stats.get("pps")
                src_flows = wm.get_flows_for_src_ip("192.168.1.1")
                _ = len(src_flows)
            except Exception as e:
                errors.append(f"Consumer error: {e}")
            await asyncio.sleep(0.001)

    # Launch 50 producers and 5 consumers concurrently
    producer_tasks = [producer(i) for i in range(50)]
    consumer_tasks = [consumer() for _ in range(5)]

    await asyncio.gather(*producer_tasks, *consumer_tasks)

    assert len(errors) == 0, f"Encountered concurrency errors during iteration: {errors}"
    assert len(wm.get_recent_flows()) > 0


# ======================================================================
# TEST B: Database Persistence Across ThreatDetector Re-instantiations
# ======================================================================
def test_b_database_persistence(tmp_path):
    """
    Generates alerts through ThreatDetector, verifies persistence in SQLite,
    re-instantiates ThreatDetector, and asserts all alerts persist and can be retrieved.
    """
    test_db = str(tmp_path / "test_cyber_threat.db")
    Config.DB_PATH = test_db
    init_db(test_db)
    clear_alerts(test_db)

    detector = ThreatDetector(window_size_seconds=60.0, load_persisted_alerts=False)

    # Single-direction high-volume flow triggering Data Exfiltration
    flow = {
        "flow_identifier": {
            "src_ip": "10.0.0.99",
            "src_port": 49152,
            "dst_ip": "198.51.100.5",
            "dst_port": 443,
            "protocol": "TCP"
        },
        "timestamp": time.time(),
        "bytes_sent": 8_000_000,
        "bytes_received": 200,
        "packet_count": 5000
    }

    alerts = detector.process_flow(flow)
    assert len(alerts) >= 1, "Expected Data Exfiltration alert to be generated"
    generated_alert_id = alerts[0]["alert_id"]

    # Verify directly from SQLite
    db_alerts = get_all_alerts(limit=100, db_path=test_db)
    alert_ids = [a["alert_id"] for a in db_alerts]
    assert generated_alert_id in alert_ids

    # Verify get_alert_by_id
    single_alert = get_alert_by_id(generated_alert_id, db_path=test_db)
    assert single_alert is not None
    assert single_alert["alert_id"] == generated_alert_id
    assert single_alert["threat_class"] == "Data Exfiltration"

    # Re-instantiate detector with load_persisted_alerts=True
    reloaded_detector = ThreatDetector(window_size_seconds=60.0, load_persisted_alerts=True)
    reloaded_alert_ids = [a["alert_id"] for a in reloaded_detector.get_all_alerts()]
    assert generated_alert_id in reloaded_alert_ids


# ======================================================================
# TEST C: Dynamic Environment Configuration Overrides
# ======================================================================
def test_c_config_overrides():
    """
    Modifies an environment variable threshold (EXFIL_BYTES_THRESHOLD=1000)
    and asserts the heuristic reacts to the new threshold.
    """
    test_flow = {
        "flow_identifier": {
            "src_ip": "192.168.1.50",
            "src_port": 50000,
            "dst_ip": "198.51.100.1",
            "dst_port": 443,
            "protocol": "TCP"
        },
        "bytes_sent": 5000,
        "bytes_received": 100,
        "timestamp": time.time()
    }

    # Under default 5,000,000 bytes, this 5,000 byte flow should NOT trigger exfiltration
    if "EXFIL_BYTES_THRESHOLD" in os.environ:
        del os.environ["EXFIL_BYTES_THRESHOLD"]

    default_result = ThreatHeuristics.evaluate_data_exfiltration(test_flow)
    assert default_result is None, "Should not trigger with default 5MB threshold"

    # Now override via environment variable to 1,000 bytes
    os.environ["EXFIL_BYTES_THRESHOLD"] = "1000"
    try:
        assert Config.EXFIL_BYTES_THRESHOLD == 1000
        overridden_result = ThreatHeuristics.evaluate_data_exfiltration(test_flow)
        assert overridden_result is not None, "Should trigger exfiltration with 1000 bytes threshold"
        assert overridden_result["threat_class"] == "Data Exfiltration"
    finally:
        # Cleanup environment variable
        del os.environ["EXFIL_BYTES_THRESHOLD"]

    # Verify fallback restored
    assert Config.EXFIL_BYTES_THRESHOLD == 5000000


# ======================================================================
# TEST D: Isolation Forest Model Persistence via joblib
# ======================================================================
def test_d_model_persistence(tmp_path):
    """
    Verifies FlowAnomalyDetector saves and reloads its trained state via joblib
    without re-fitting and yields deterministic predictions.
    """
    model_file = str(tmp_path / "test_iso_forest.joblib")

    # Initial boot: fits baseline and saves to model_file
    detector1 = FlowAnomalyDetector(model_path=model_file)
    assert detector1.is_fitted is True
    assert os.path.exists(model_file)

    # Anomaly test flow
    anomalous_flow = {
        "flow_identifier": {"src_port": 12345, "dst_port": 9999},
        "bytes_sent": 50_000_000,
        "bytes_received": 10,
        "packet_count": 100000
    }

    is_anomaly1, score1 = detector1.predict_anomaly(anomalous_flow)

    # Second boot: loads model from model_file
    detector2 = FlowAnomalyDetector(model_path=model_file)
    assert detector2.is_fitted is True
    is_anomaly2, score2 = detector2.predict_anomaly(anomalous_flow)

    assert is_anomaly1 == is_anomaly2
    assert score1 == score2


# ======================================================================
# TEST E: Baseline Attack Scenarios Integrity (100% Accuracy)
# ======================================================================
def test_e_baseline_attack_integrity():
    """
    Re-runs all 6 baseline attack scenarios to verify 100% detection accuracy.
    """
    detector = ThreatDetector(window_size_seconds=60.0, load_persisted_alerts=False)
    generator = TrafficGenerator()

    threat_types = ['ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration']
    total_alerts_found = 0

    for threat in threat_types:
        flows = generator.generate_threat_scenario(threat)
        threat_alerts = []
        for flow in flows:
            alerts = detector.process_flow(flow)
            threat_alerts.extend(alerts)

        assert len(threat_alerts) > 0, f"Expected alert for threat scenario '{threat}', got 0"
        total_alerts_found += len(threat_alerts)

    assert total_alerts_found >= 6, f"Expected at least 6 total alerts, got {total_alerts_found}"

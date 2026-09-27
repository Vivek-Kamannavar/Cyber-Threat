"""
Robustness & Failure-Mode Test Matrix
Six critical edge cases for the data-diode pipeline:

1. Concurrency burst (100 simultaneous packets).
2. Shannon entropy stability on zero-byte / single-byte payloads.
3. Corrupted packet recovery.
4. Offline AI fallback when API keys are absent.
5. SQLite concurrent write safety.
6. WebSocket broadcast reconnect resilience.
"""

import asyncio
import os
import sys
import threading
import time

import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.features import calculate_dns_ngram_score, calculate_iat_stats, calculate_shannon_entropy
from engine.window_manager import SlidingWindowManager
from ingest.adapter_bridge import DedupeWindow, ingest_stream_batch, normalize_event
from ingest.parser import FlowNormalizer, ZeekLogParser
from backend.copilot import ConversationalCopilot
from backend.services.groq_service import GroqCopilotService
from backend.database import clear_alerts, get_all_alerts, init_db, save_alert


def _flow(index: int, when: float, window_marker: str = "10.0.0.1") -> dict:
    return {
        "timestamp": when,
        "flow_identifier": {
            "src_ip": f"192.168.10.{index % 40 + 10}",
            "src_port": 40000 + index,
            "dst_ip": window_marker,
            "dst_port": 443,
            "protocol": "TCP",
        },
        "bytes_sent": 512 + index,
        "bytes_received": 1024,
        "packet_count": 2,
        "tcp_flags": "SF",
        "dns": None,
        "tls": None,
    }


# ----------------------------------------------------------------------
# 1. Concurrency burst
# ----------------------------------------------------------------------
def test_concurrency_burst_of_100_packets_is_thread_safe():
    """100 simultaneous writers must be fully accounted for without losing or corrupting state."""
    manager = SlidingWindowManager(window_size_seconds=60.0)
    now = time.time()
    errors = []
    barrier = threading.Barrier(20)

    def writer(chunk: int):
        try:
            barrier.wait(timeout=5)
            for offset in range(5):
                manager.add_flow(_flow(chunk * 5 + offset, now))
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert len(manager.get_recent_flows()) == 100
    stats = manager.get_throughput_stats()
    assert stats["total_flows"] == 100
    assert stats["pps"] > 0


def test_window_pruning_stays_bounded_under_burst():
    """Flows older than the window must be evicted so memory stays bounded."""
    manager = SlidingWindowManager(window_size_seconds=5.0)
    now = time.time()

    for index in range(50):
        manager.add_flow(_flow(index, now - 30.0))  # already stale
    for index in range(50):
        manager.add_flow(_flow(index, now))

    assert len(manager.get_recent_flows()) == 50
    assert all(flow["timestamp"] >= now - 5.0 for flow in manager.get_recent_flows())


# ----------------------------------------------------------------------
# 2. Shannon entropy math stability
# ----------------------------------------------------------------------
@pytest.mark.parametrize("payload", ["", b"", b"\x00", "A", b"\x00" * 64, "aaaa"])
def test_entropy_handles_degenerate_payloads(payload):
    """Zero-byte and single-symbol payloads must return 0.0 instead of raising."""
    entropy = calculate_shannon_entropy(payload)
    assert isinstance(entropy, float)
    assert abs(entropy) < 1e-9


def test_entropy_and_iat_helpers_handle_empty_input():
    assert calculate_shannon_entropy(None) == 0.0
    assert calculate_shannon_entropy("ab" * 40) >= 1.0

    empty_dns = calculate_dns_ngram_score("")
    assert empty_dns == {"length": 0, "entropy": 0.0, "ngram_rarity": 0.0}

    single_char = calculate_dns_ngram_score("x")
    assert single_char["length"] == 1 and single_char["ngram_rarity"] == 0.0

    empty_iat = calculate_iat_stats([])
    assert empty_iat["cv_iat"] == 1.0 and empty_iat["sample_count"] == 0

    # A perfect zero-variance sample has a zero mean IAT; the guarded CV stays neutral,
    # never NaN or ZeroDivisionError.
    flat_iat = calculate_iat_stats([5.0, 5.0, 5.0])
    assert flat_iat["cv_iat"] == 1.0
    assert flat_iat["sample_count"] == 3


# ----------------------------------------------------------------------
# 3. Corrupted packet recovery
# ----------------------------------------------------------------------
def test_corrupted_zeek_lines_are_skipped_not_fatal():
    corrupted_lines = [
        "",
        "#separator \\x09",
        "{ truncated json",
        "1.5\tC2\t192.168.10.10\t50821",   # too few TSV fields
        "not-a-tsv-line",
    ]
    assert all(ZeekLogParser.parse_log_line(line) is None for line in corrupted_lines)

    valid = '1.5\tC3\t192.168.10.10\t50821\t45.142.214.8\t443\ttcp\t\t\t2048\t512'
    parsed = ZeekLogParser.parse_log_line(valid)
    assert parsed is not None and parsed["id.resp_h"] == "45.142.214.8"


def test_corrupted_flow_records_normalize_to_safe_defaults():
    """A structurally broken record must normalize into a usable flow, never raise."""
    flow = FlowNormalizer.normalize({})
    assert flow["flow_identifier"]["src_ip"] == "0.0.0.0"
    assert flow["flow_identifier"]["dst_ip"] == "0.0.0.0"
    assert flow["bytes_sent"] == 0
    assert flow["packet_count"] >= 1

    partial = FlowNormalizer.normalize({"id.orig_h": "192.168.10.10", "id.resp_p": "not-a-port"})
    assert partial["flow_identifier"]["src_ip"] == "192.168.10.10"
    assert partial["flow_identifier"]["dst_port"] == 0


def test_malformed_batch_is_absorbed_by_the_ingest_loop():
    """A worst-case batch must not raise out of the collector ingestion path."""
    class Detector:
        def __init__(self):
            self.flows = []

        def process_flow(self, flow):
            self.flows.append(flow)
            return []

    detector = Detector()
    summary = ingest_stream_batch(
        detector,
        [None, "garbage", {}, {"src_ip": "x", "dst_ip": "y"}, {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}],
        dedupe=DedupeWindow(),
    )

    assert summary["accepted"] == 1
    assert summary["rejected"] == 4
    assert summary["duplicates"] == 0
    assert detector.flows[0]["flow_identifier"]["src_ip"] == "10.0.0.1"


def test_dedupe_window_bounds_memory_during_flood():
    window = DedupeWindow(max_keys=10, ttl_seconds=1.0)
    now = 500.0
    for index in range(1000):
        window.is_duplicate({"timestamp": index, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, now=now)
    assert len(window._seen) <= 10


# ----------------------------------------------------------------------
# 4. Offline AI fallback
# ----------------------------------------------------------------------
def test_offline_ai_fallback_without_api_key(monkeypatch):
    """With no GROQ_API_KEY the analyst must answer deterministically, never error."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    service = GroqCopilotService()
    assert service.client is None

    copilot = ConversationalCopilot(service)
    result = copilot.respond(
        "Summarize threat posture",
        telemetry={"pps": 12.0, "bps": 2048.0, "total_flows": 3},
        alerts=[_flow(1, time.time()) | {"alert_id": "ALT-ROB-1", "threat_class": "DDoS", "confidence_score": 0.91}],
    )

    assert result["mode"] == "OFFLINE_HEURISTIC"
    assert result["response"]
    assert len(result["suggestions"]) == 4

    analysis = service.analyze_alert({"threat_class": "Data Exfiltration", "confidence_score": 0.93,
                                      "flow_identifier": {"src_ip": "192.168.10.10", "dst_ip": "45.142.214.8"}})
    assert analysis["firewall_mitigation_rule"].startswith("iptables")


def test_offline_ai_fallback_survives_broken_service_client():
    """A client that raises on every call must still yield a deterministic offline answer."""
    class ExplodingClient:
        class chat:  # noqa: N801 - emulates the Groq SDK attribute shape
            class completions:  # noqa: N801
                @staticmethod
                def create(**_kwargs):
                    raise RuntimeError("network down")

    service = GroqCopilotService(api_key="")
    service.client = ExplodingClient()

    copilot = ConversationalCopilot(service)
    result = copilot.respond("Explain the latest incident", alerts=[{"alert_id": "ALT-1", "threat_class": "Botnet C2 Beaconing",
                                                                    "confidence_score": 0.88,
                                                                    "flow_identifier": {"src_ip": "10.0.0.5", "dst_ip": "1.2.3.4"}}])

    assert result["mode"] == "OFFLINE_HEURISTIC"
    assert "ALT-1" in result["response"]


# ----------------------------------------------------------------------
# 5. SQLite concurrent write safety
# ----------------------------------------------------------------------
def test_sqlite_concurrent_writes_are_not_lost(tmp_path):
    db_path = str(tmp_path / "concurrency.db")
    init_db(db_path)
    clear_alerts(db_path)

    writers, per_writer = 8, 10
    errors = []

    def write_batch(writer_index: int):
        try:
            for offset in range(per_writer):
                alert_id = f"ALT-{writer_index:02d}{offset:03d}"
                assert save_alert(
                    {
                        "alert_id": alert_id,
                        "timestamp": "2026-09-27T12:00:00Z",
                        "threat_class": "Concurrency Probe",
                        "confidence_score": 0.5,
                        "flow_identifier": {
                            "src_ip": f"192.168.10.{writer_index + 10}",
                            "src_port": 50000 + offset,
                            "dst_ip": "45.142.214.8",
                            "dst_port": 443,
                            "protocol": "TCP",
                        },
                        "supporting_evidence_feature": {"reason": "concurrency probe"},
                    },
                    db_path,
                )
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=write_batch, args=(index,)) for index in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert errors == []
    stored = get_all_alerts(limit=writers * per_writer + 10, db_path=db_path)
    assert len(stored) == writers * per_writer


# ----------------------------------------------------------------------
# 6. WebSocket broadcast resilience
# ----------------------------------------------------------------------
def test_websocket_reconnect_cycle_delivers_snapshots():
    """Each reconnect must receive a fresh snapshot after the previous socket closed."""
    from backend.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        for _ in range(3):
            with client.websocket_connect("/ws/alerts") as ws:
                snapshot = ws.receive_json()
                assert snapshot["type"] == "snapshot"
                assert "stats" in snapshot
                assert "recent_alerts" in snapshot


def test_broadcast_prunes_dead_connections_without_raising():
    from backend.main import ConnectionManager

    manager = ConnectionManager()

    class DeadSocket:
        async def send_json(self, _message):
            raise RuntimeError("client vanished")

    class LiveSocket:
        def __init__(self):
            self.received = []

        async def send_json(self, message):
            self.received.append(message)

    dead, live = DeadSocket(), LiveSocket()
    manager.active_connections = [dead, live]

    asyncio.run(manager.broadcast({"type": "telemetry", "data": {"pps": 1.0}}))

    assert dead not in manager.active_connections
    assert live in manager.active_connections
    assert live.received[0]["type"] == "telemetry"

    manager.active_connections = []
    asyncio.run(manager.broadcast({"type": "noop"}))  # zero clients is a no-op


def test_broadcast_survives_connection_removed_mid_flight():
    from backend.main import ConnectionManager, manager

    class FlakySocket:
        def __init__(self):
            self.calls = 0

        async def send_json(self, _message):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("reset by peer")

    original = list(manager.active_connections)
    manager.active_connections = [FlakySocket()]
    try:
        asyncio.run(manager.broadcast({"type": "alert", "data": {"alert_id": "ALT-1"}}))
        assert manager.active_connections == []
    finally:
        manager.active_connections = original

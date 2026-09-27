"""
Ingestion Bridge Test Suite
Covers adapter-record normalization, store parsing with corrupted lines, indicator
deduplication, collector stream normalization and batch ingestion semantics.
"""

import json
import os
import sys
import time

import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ingest.adapter_bridge import (
    MAX_INDICATORS,
    AdapterFeedBridge,
    DedupeWindow,
    classify_indicator,
    dedupe_indicators,
    discover_adapters,
    ingest_stream_batch,
    load_store_records,
    normalize_event,
    normalize_record,
)


class RecordingDetector:
    """Minimal detector double that records flows and echoes one alert per flow."""

    def __init__(self, raise_on=None):
        self.flows = []
        self.raise_on = raise_on

    def process_flow(self, flow):
        if self.raise_on and self.raise_on(flow):
            raise ValueError("engine rejected flow")
        self.flows.append(flow)
        # Emulate the engine: high-volume flows raise an alert.
        return [{"alert_id": f"ALT-{len(self.flows)}", "threat_class": "Test"}] if flow["bytes_sent"] > 200 else []


# ----------------------------------------------------------------------
# Record normalization
# ----------------------------------------------------------------------
def test_classify_indicator_recognises_and_rejects():
    assert classify_indicator("185.220.101.5") == "ipv4"
    assert classify_indicator("999.1.1.1") is None
    assert classify_indicator("malware-c2.example.com") == "domain"
    assert classify_indicator("https://exfil-drop.net/payload") == "url"
    assert classify_indicator("a" * 64) == "sha256"
    assert classify_indicator("not an indicator") is None
    assert classify_indicator(None) is None


def test_normalize_record_extracts_indicator_and_severity():
    record = {
        "id": "feed.example:1",
        "source_host": "feed.example",
        "source_url": "https://feed.example/iocs/1",
        "fetched_at": "2026-09-25T10:00:00Z",
        "fields": {"ip": "203.0.113.9", "severity": 0.95, "title": "Known C2 node"},
    }

    indicator = normalize_record(record)
    assert indicator is not None
    assert indicator["indicator"] == "203.0.113.9"
    assert indicator["indicator_type"] == "ipv4"
    assert indicator["severity"] == "CRITICAL"
    assert indicator["source_host"] == "feed.example"

    assert normalize_record({"fields": {"title": "no indicator here"}}) is None
    assert normalize_record("not a record") is None


def test_load_store_records_is_last_write_wins_and_survives_corruption(tmp_path):
    store = tmp_path / "feed.example.jsonl"
    store.write_text(
        "\n".join(
            [
                json.dumps({"id": "1", "fields": {"ip": "10.0.0.1"}}),
                "{ this line is truncated",       # malformed JSON
                json.dumps(["not", "a", "dict"]),  # valid JSON, wrong shape
                json.dumps({"id": "1", "fields": {"ip": "10.0.0.2"}}),  # revision of id 1
                json.dumps({"id": "2", "fields": {"ip": "10.0.0.3"}}),
            ]
        ),
        encoding="utf-8",
    )

    records, malformed = load_store_records(str(store))
    by_id = {record["id"]: record for record in records}

    assert malformed == 2
    assert len(records) == 2
    assert by_id["1"]["fields"]["ip"] == "10.0.0.2"

    missing, missing_malformed = load_store_records(str(tmp_path / "nope.jsonl"))
    assert missing == [] and missing_malformed == 0


def test_dedupe_indicators_keeps_highest_severity_and_stays_bounded():
    indicators = [
        {"indicator": "1.1.1.1", "indicator_type": "ipv4", "severity": "LOW"},
        {"indicator": "1.1.1.1", "indicator_type": "ipv4", "severity": "CRITICAL"},
        {"indicator": "bad.example.com", "indicator_type": "domain", "severity": "MEDIUM"},
    ]
    deduped = dedupe_indicators(indicators)

    assert len(deduped) == 2
    lookup = {item["indicator"]: item["severity"] for item in deduped}
    assert lookup["1.1.1.1"] == "CRITICAL"

    bounded = dedupe_indicators(
        [{"indicator": f"10.0.{i // 250}.{i % 250}", "indicator_type": "ipv4", "severity": "HIGH"} for i in range(MAX_INDICATORS + 250)]
    )
    assert len(bounded) <= MAX_INDICATORS


# ----------------------------------------------------------------------
# Collector stream normalization
# ----------------------------------------------------------------------
def test_normalize_event_builds_engine_flow_schema():
    flow = normalize_event(
        {
            "timestamp": 1_760_000_000,
            "src_ip": "192.168.10.14",
            "src_port": "50123",
            "dst_ip": "91.215.102.14",
            "dst_port": 8443,
            "bytes": "2048",
            "packet_count": 4,
            "flags": "SF",
            "entropy": 7.42,
            "dns_query": "c2.example.com",
        }
    )

    assert flow["timestamp"] == 1_760_000_000
    assert flow["flow_identifier"]["src_ip"] == "192.168.10.14"
    assert flow["flow_identifier"]["src_port"] == 50123
    assert flow["flow_identifier"]["dst_port"] == 8443
    assert flow["bytes_sent"] == 2048
    assert flow["packet_count"] == 4
    assert flow["payload_entropy"] == pytest.approx(7.42)
    assert flow["dns"]["query"] == "c2.example.com"


@pytest.mark.parametrize(
    "raw",
    [None, "packet", {}, {"src_ip": "192.168.10.14"}, {"src_ip": "not-an-ip", "dst_ip": "10.0.0.1"}],
)
def test_normalize_event_rejects_unusable_payloads(raw):
    """Corrupted collector events are dropped instead of raising."""
    assert normalize_event(raw) is None


def test_normalize_event_coerces_corrupted_field_types():
    """Garbage timestamps and byte counters degrade to safe defaults."""
    flow = normalize_event(
        {"src_ip": "192.168.10.14", "dst_ip": "10.0.0.1", "timestamp": "whenever", "bytes": "lots"}
    )
    assert flow is not None
    assert flow["timestamp"] > 0
    assert flow["bytes_sent"] == 0
    assert flow["packet_count"] == 1


def test_ingest_stream_batch_counts_accepted_rejected_and_duplicates():
    detector = RecordingDetector()
    events = [
        {"timestamp": 1, "src_ip": "192.168.10.10", "dst_ip": "45.142.214.8", "bytes": 100},
        {"timestamp": 1, "src_ip": "192.168.10.10", "dst_ip": "45.142.214.8", "bytes": 100},  # duplicate
        {"timestamp": 2, "src_ip": "bad-ip", "dst_ip": "45.142.214.8"},                        # rejected
        {"timestamp": 3, "src_ip": "192.168.10.11", "dst_ip": "91.215.102.14", "bytes": 250},  # accepted + alert
    ]

    summary = ingest_stream_batch(detector, events)

    assert summary["accepted"] == 2
    assert summary["rejected"] == 1
    assert summary["duplicates"] == 1
    assert summary["alerts_raised"] == 1
    assert len(detector.flows) == 2


def test_ingest_stream_batch_survives_engine_failure_and_bad_batch():
    detector = RecordingDetector(raise_on=lambda flow: flow["flow_identifier"]["dst_ip"] == "10.0.0.9")
    events = [
        {"timestamp": 1, "src_ip": "192.168.10.10", "dst_ip": "10.0.0.9"},
        {"timestamp": 2, "src_ip": "192.168.10.10", "dst_ip": "10.0.0.8"},
    ]

    summary = ingest_stream_batch(detector, events)
    assert summary["accepted"] == 1
    assert summary["rejected"] == 1

    assert ingest_stream_batch(detector, None)["accepted"] == 0


def test_dedupe_window_evicts_expired_and_bounded_entries():
    window = DedupeWindow(max_keys=3, ttl_seconds=5.0)
    event = {"timestamp": 1, "src_ip": "10.1.1.1", "dst_ip": "10.1.1.2"}

    assert window.is_duplicate(event, now=100.0) is False
    assert window.is_duplicate(event, now=100.5) is True
    assert window.is_duplicate(event, now=200.0) is False  # TTL expired

    for index in range(6):
        window.is_duplicate({"timestamp": index, "src_ip": "10.2.2.2", "dst_ip": "10.2.2.3"}, now=300.0)
    assert len(window._seen) <= 3


# ----------------------------------------------------------------------
# Adapter feed bridge (package directory + local cache)
# ----------------------------------------------------------------------
def _scaffold_package(tmp_path):
    """Creates a minimal adapter-ingestion package layout with one adapter + store."""
    package_dir = tmp_path / "adapter-ingestion"
    (package_dir / "adapters").mkdir(parents=True)
    (package_dir / "src").mkdir()
    (package_dir / "src" / "run.mjs").write_text("// runner stub", encoding="utf-8")

    adapter = {
        "version": 1,
        "host": "threatfeed.example",
        "access": {"tier": 0, "kind": "json-api", "url": "https://threatfeed.example/feed"},
        "records_path": "results",
        "map": {"source_id": {"path": "id"}},
    }
    (package_dir / "adapters" / "threatfeed.example.adapter.json").write_text(json.dumps(adapter), encoding="utf-8")

    (package_dir / "store").mkdir()
    (package_dir / "store" / "threatfeed.example.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"id": "threatfeed.example:1", "source_host": "threatfeed.example",
                            "fetched_at": "2026-09-25T10:00:00Z",
                            "fields": {"ip": "203.0.113.77", "severity": "HIGH", "title": "Scanner node"}}),
                json.dumps({"id": "threatfeed.example:2", "source_host": "threatfeed.example",
                            "fields": {"domain": "dga-rotator.example.net", "severity": "MEDIUM"}}),
                "{ truncated line",
            ]
        ),
        encoding="utf-8",
    )
    return package_dir


def test_bridge_discovers_adapters_and_builds_local_indicator_cache(tmp_path):
    package_dir = _scaffold_package(tmp_path)
    cache_path = tmp_path / "backend" / "data" / "threat_intel.json"
    bridge = AdapterFeedBridge(package_dir=str(package_dir), cache_path=str(cache_path))

    assert bridge.available() is True
    assert [src["host"] for src in discover_adapters(str(package_dir))] == ["threatfeed.example"]

    indicators = bridge.reload()
    assert len(indicators) == 2
    assert cache_path.is_file()

    status = bridge.status()
    assert status["available"] is True
    assert status["indicator_count"] == 2
    assert status["by_severity"].get("HIGH") == 1
    assert status["sources"][0]["records"] == 2
    assert "zero live lookups" in status["compliance"]


def test_bridge_refresh_reports_unavailable_without_runner(tmp_path):
    """A missing node binary degrades to an explicit status instead of raising."""
    package_dir = _scaffold_package(tmp_path)
    bridge = AdapterFeedBridge(
        package_dir=str(package_dir),
        cache_path=str(tmp_path / "cache.json"),
        node_bin="definitely-not-node-xyz",
    )

    result = bridge.refresh()
    assert result["status"] in ("degraded", "refreshed")
    assert result["sources"][0]["outcome"] == "unavailable"

    missing = AdapterFeedBridge(package_dir=str(tmp_path / "absent"), cache_path=str(tmp_path / "c.json"))
    assert missing.refresh()["status"] == "unavailable"
    assert missing.status()["available"] is False
    assert missing.indicators() == []


def test_bridge_matches_flows_against_cached_indicators(tmp_path):
    package_dir = _scaffold_package(tmp_path)
    bridge = AdapterFeedBridge(package_dir=str(package_dir), cache_path=str(tmp_path / "cache.json"))
    bridge.reload()

    ip_match = bridge.match_flow({"flow_identifier": {"src_ip": "192.168.10.20", "dst_ip": "203.0.113.77"}})
    assert len(ip_match) == 1
    assert ip_match[0]["severity"] == "HIGH"

    domain_match = bridge.match_flow({"flow_identifier": {"dst_ip": "8.8.8.8"}, "dns": {"query": "DGA-Rotator.example.net."}})
    assert len(domain_match) == 1

    assert bridge.match_flow({"flow_identifier": {"dst_ip": "8.8.8.8"}}) == []


def test_bridge_intel_matches_surface_through_stream_batch(tmp_path):
    package_dir = _scaffold_package(tmp_path)
    bridge = AdapterFeedBridge(package_dir=str(package_dir), cache_path=str(tmp_path / "cache.json"))
    bridge.reload()

    detector = RecordingDetector()
    summary = ingest_stream_batch(
        detector,
        [{"timestamp": time.time(), "src_ip": "192.168.10.20", "dst_ip": "203.0.113.77", "bytes": 512}],
        bridge=bridge,
    )

    assert summary["accepted"] == 1
    assert len(summary["intel_matches"]) == 1
    assert summary["intel_matches"][0]["indicator"] == "203.0.113.77"

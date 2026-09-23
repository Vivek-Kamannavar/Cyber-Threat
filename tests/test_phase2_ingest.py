"""
Phase 2 Test Suite: Real-World PCAP & Zeek Multi-Log Ingestion Pipeline
Tests Scapy PCAP streaming reader, Zeek UID correlation, and ingestion upload/control APIs.
"""

import os
import sys
import pytest
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ingest.pcap_loader import PcapStreamLoader
from ingest.parser import ZeekMultiLogCorrelator, ZeekLogParser, FlowNormalizer
from backend.main import app

client = TestClient(app)


def test_pcap_streaming_loader(tmp_path):
    """Verifies that PcapStreamLoader streams packets without loading whole file into memory."""
    pcap_path = str(tmp_path / "test_capture.pcap")

    # Generate sample test packets
    pkts = [
        Ether() / IP(src="192.168.10.15", dst="45.142.214.8") / TCP(sport=54321, dport=443, flags="S"),
        Ether() / IP(src="192.168.10.15", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious-exfil.xyz")),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"
    ]
    wrpcap(pcap_path, pkts)

    flows = list(PcapStreamLoader.stream_flows(pcap_path))
    assert len(flows) == 3, f"Expected 3 flows from PCAP, got {len(flows)}"

    # Check TCP flow
    tcp_flow = flows[0]
    assert tcp_flow["flow_identifier"]["src_ip"] == "192.168.10.15"
    assert tcp_flow["flow_identifier"]["dst_ip"] == "45.142.214.8"
    assert tcp_flow["flow_identifier"]["protocol"] == "TCP"
    assert tcp_flow["flow_identifier"]["dst_port"] == 443
    assert "S" in tcp_flow["tcp_flags"]

    # Check DNS flow
    dns_flow = flows[1]
    assert dns_flow["flow_identifier"]["protocol"] == "UDP"
    assert dns_flow["dns"] is not None
    assert "malicious-exfil.xyz" in dns_flow["dns"]["query"]


def test_zeek_multi_log_correlation(tmp_path):
    """Verifies ZeekMultiLogCorrelator merges conn.log with dns.log and ssl.log by UID."""
    conn_log = tmp_path / "conn.log"
    dns_log = tmp_path / "dns.log"
    ssl_log = tmp_path / "ssl.log"

    # Write synthetic conn.log TSV lines
    conn_log.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n"
        "1700000001.000\tC_UID_001\t192.168.10.20\t49152\t1.1.1.1\t53\tudp\tdns\t0.01\t64\t128\n"
        "1700000002.000\tC_UID_002\t192.168.10.30\t51234\t91.215.102.14\t443\ttcp\tssl\t1.50\t15000\t800\n",
        encoding="utf-8"
    )

    # Write synthetic dns.log matching C_UID_001
    dns_log.write_text(
        "{\n"
        '  "ts": 1700000001.000,\n'
        '  "uid": "C_UID_001",\n'
        '  "query": "super-secret-tunnelling-domain-381928310.biz",\n'
        '  "qtype_name": "TXT"\n'
        "}\n",
        encoding="utf-8"
    )

    # Write synthetic ssl.log matching C_UID_002
    ssl_log.write_text(
        "{\n"
        '  "ts": 1700000002.000,\n'
        '  "uid": "C_UID_002",\n'
        '  "server_name": "darknet-c2.xyz",\n'
        '  "ja3": "a0e42d24b9c7c4b0959f676e939da290"\n'
        "}\n",
        encoding="utf-8"
    )

    correlator = ZeekMultiLogCorrelator()
    flows = list(correlator.stream_correlated_flows(str(conn_log)))
    assert len(flows) == 2

    # Verify flow 1 was enriched with DNS query
    f1 = flows[0]
    assert f1["flow_identifier"]["src_ip"] == "192.168.10.20"
    assert f1["dns"] is not None
    assert f1["dns"]["query"] == "super-secret-tunnelling-domain-381928310.biz"
    assert f1["dns"]["qtype"] == "TXT"

    # Verify flow 2 was enriched with SSL JA3 hash
    f2 = flows[1]
    assert f2["flow_identifier"]["src_ip"] == "192.168.10.30"
    assert f2["tls"] is not None
    assert f2["tls"]["ja3"] == "a0e42d24b9c7c4b0959f676e939da290"
    assert f2["tls"]["sni"] == "darknet-c2.xyz"


def test_ingest_api_upload_and_status(tmp_path):
    """Verifies file upload API /api/ingest/upload and status inspection."""
    test_log = tmp_path / "conn.log"
    test_log.write_text(
        "1700000010.000\tC_TEST_999\t10.0.0.100\t55555\t10.0.0.1\t80\ttcp\thttp\t0.05\t500\t1200\n",
        encoding="utf-8"
    )

    with open(test_log, "rb") as f:
        res = client.post(
            "/api/ingest/upload?playback_speed=instant",
            files={"file": ("conn.log", f, "text/plain")}
        )

    assert res.status_code == 200
    data = res.json()
    assert "filename" in data
    assert data["filename"] == "conn.log"

    # Check status endpoint
    status_res = client.get("/api/ingest/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["status"] in ("completed", "replaying", "idle")

    # Stop API
    stop_res = client.post("/api/ingest/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "stopped"

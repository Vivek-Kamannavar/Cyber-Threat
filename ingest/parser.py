"""
Unidirectional IP Traffic Parser
Strictly read-only network flow ingestion module for Data Diode environments.
Parses Zeek logs (conn.log, dns.log, ssl.log), Scapy PCAP captures, and raw flow streams.
Includes device and website domain mapping for IP address resolution.
"""

import json
import time
from typing import Dict, Any, Generator, List, Optional
import os

IP_RESOLVER_MAP = {
    # Benign Infrastructure & Websites
    "8.8.8.8": "Google Public DNS (dns.google)",
    "1.1.1.1": "Cloudflare DNS (one.one.one.one)",
    "142.250.190.46": "Google Services (google.com)",
    "13.107.42.14": "Microsoft Azure / Windows Update",
    "151.101.1.69": "GitHub / Fastly CDN (github.com)",

    # Malicious External C2 & Drop Nodes
    "185.220.101.5": "Tor / Darknet C2 Server (darknet-c2.xyz)",
    "91.215.102.14": "Cobalt Strike Command & Control Node",
    "45.142.214.8": "High-Volume Data Drop Server (exfil-drop.net)",
    "10.200.1.15": "External Botnet Attacker Host"
}


def get_ip_identity_label(ip: str) -> str:
    """Resolves IP address to friendly device name or website identity."""
    if ip in IP_RESOLVER_MAP:
        return IP_RESOLVER_MAP[ip]
    if ip.startswith("192.168.10."):
        node_id = ip.split(".")[-1]
        return f"Internal SCADA Workstation #{node_id}"
    if ip.startswith("10.") or ip.startswith("172.16."):
        return f"Internal Network Host ({ip})"
    return f"External Host ({ip})"


class ZeekLogParser:
    """Parses Zeek TSV and JSON log formats (conn.log, dns.log, ssl.log) in read-only mode."""

    @staticmethod
    def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        if line.startswith('{') and line.endswith('}'):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                return None
        
        parts = line.split('\t')
        if len(parts) >= 10:
            return {
                "ts": float(parts[0]) if parts[0] != '-' else time.time(),
                "uid": parts[1],
                "id.orig_h": parts[2],
                "id.orig_p": int(parts[3]) if parts[3].isdigit() else 0,
                "id.resp_h": parts[4],
                "id.resp_p": int(parts[5]) if parts[5].isdigit() else 0,
                "proto": parts[6],
                "orig_bytes": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                "resp_bytes": int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0,
            }
        return None


class FlowNormalizer:
    """Normalizes heterogeneous input formats into a standardized Unidirectional Flow record."""

    @staticmethod
    def normalize(raw_record: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = raw_record.get('ts') or raw_record.get('timestamp') or time.time()
        
        src_ip = raw_record.get('id.orig_h') or raw_record.get('src_ip') or '0.0.0.0'
        src_port = int(raw_record.get('id.orig_p') or raw_record.get('src_port') or 0)
        dst_ip = raw_record.get('id.resp_h') or raw_record.get('dst_ip') or '0.0.0.0'
        dst_port = int(raw_record.get('id.resp_p') or raw_record.get('dst_port') or 0)
        protocol = (raw_record.get('proto') or raw_record.get('protocol') or 'TCP').upper()

        orig_bytes = int(raw_record.get('orig_bytes') or raw_record.get('bytes_sent') or raw_record.get('orig_ip_bytes') or 0)
        resp_bytes = int(raw_record.get('resp_bytes') or raw_record.get('bytes_received') or raw_record.get('resp_ip_bytes') or 0)

        dns_query = raw_record.get('query') or raw_record.get('dns_query')
        qtype_name = raw_record.get('qtype_name') or raw_record.get('dns_qtype')
        
        ja3_hash = raw_record.get('ja3') or raw_record.get('ja3_hash')
        ja4_hash = raw_record.get('ja4') or raw_record.get('ja4_hash')
        sni = raw_record.get('server_name') or raw_record.get('sni')
        cipher = raw_record.get('cipher')

        tcp_flags = raw_record.get('conn_state') or raw_record.get('tcp_flags') or ''
        packet_count = int(raw_record.get('orig_pkts', 0)) + int(raw_record.get('resp_pkts', 0)) or raw_record.get('packet_count', 1)

        src_label = get_ip_identity_label(src_ip)
        dst_label = get_ip_identity_label(dst_ip)

        return {
            "timestamp": timestamp,
            "flow_identifier": {
                "src_ip": src_ip,
                "src_port": src_port,
                "src_label": src_label,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "dst_label": dst_label,
                "protocol": protocol
            },
            "bytes_sent": orig_bytes,
            "bytes_received": resp_bytes,
            "packet_count": packet_count,
            "tcp_flags": tcp_flags,
            "dns": {
                "query": dns_query,
                "qtype": qtype_name
            } if dns_query else None,
            "tls": {
                "ja3": ja3_hash,
                "ja4": ja4_hash,
                "sni": sni,
                "cipher": cipher
            } if (ja3_hash or sni or cipher) else None
        }

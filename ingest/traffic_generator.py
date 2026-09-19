"""
Synthetic Flow & PCAP Stream Generator for Unidirectional Data Diode Simulation
Generates realistic baseline critical-infrastructure network traffic and streams configurable threat vectors.
Includes IP resolution labels for device and website identification.
"""

import time
import random
import string
from typing import Dict, Any, List
from ingest.parser import get_ip_identity_label

class TrafficGenerator:
    """Generates continuous streaming network flows with configurable threat injection."""

    BENIGN_INTERNAL_IPS = [f"192.168.10.{i}" for i in range(10, 50)]
    BENIGN_EXTERNAL_SERVERS = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "13.107.42.14", "151.101.1.69"]
    COMMON_PORTS = [80, 443, 53, 123, 22, 4430]

    BENIGN_JA3_HASHES = [
        "771fd359987056501a35567c9c0b1e98",  # Chrome standard
        "b32309a26951912be7dba376398abc3b",  # Firefox standard
        "3b6376336cca036c14ae67343f700c92",  # Python requests default
    ]

    def __init__(self):
        self.beacon_counter = 0

    def _build_flow(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str,
                    bytes_sent: int, bytes_recv: int, pkts: int, tcp_flags: str = "SF",
                    dns: Any = None, tls: Any = None) -> Dict[str, Any]:
        return {
            "timestamp": time.time(),
            "flow_identifier": {
                "src_ip": src_ip,
                "src_port": src_port,
                "src_label": get_ip_identity_label(src_ip),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "dst_label": get_ip_identity_label(dst_ip),
                "protocol": protocol
            },
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "packet_count": pkts,
            "tcp_flags": tcp_flags,
            "dns": dns,
            "tls": tls
        }

    def generate_benign_flow(self) -> Dict[str, Any]:
        """Generates a normal background flow record."""
        src_ip = random.choice(self.BENIGN_INTERNAL_IPS)
        dst_ip = random.choice(self.BENIGN_EXTERNAL_SERVERS)
        dst_port = random.choice(self.COMMON_PORTS)
        src_port = random.randint(32768, 65535)
        protocol = "UDP" if dst_port in [53, 123] else "TCP"

        dns_data = None
        if dst_port == 53:
            benign_domains = ["update.windows.com", "api.github.com", "google.com", "pypi.org", "internal-scada.local"]
            dns_data = {"query": random.choice(benign_domains), "qtype": "A"}

        tls_data = None
        if dst_port == 443:
            tls_data = {
                "ja3": random.choice(self.BENIGN_JA3_HASHES),
                "ja4": "t13d151600_8da5_9b09930f36",
                "sni": "secure-gateway.corp.internal",
                "cipher": "TLS_AES_256_GCM_SHA384"
            }

        return self._build_flow(
            src_ip, src_port, dst_ip, dst_port, protocol,
            bytes_sent=random.randint(100, 1500),
            bytes_recv=random.randint(500, 10000),
            pkts=random.randint(3, 15),
            dns=dns_data,
            tls=tls_data
        )

    def generate_threat_scenario(self, threat_type: str) -> List[Dict[str, Any]]:
        """Generates a batch of flows simulating a specific attack scenario."""
        flows = []
        now = time.time()

        if threat_type == "ddos":
            target_ip = "192.168.10.50"
            attacker_ip = "10.200.1.15"
            for i in range(40):
                f = self._build_flow(attacker_ip, random.randint(10000, 60000), target_ip, 80, "TCP",
                                     bytes_sent=64, bytes_recv=0, pkts=1, tcp_flags="S")
                f['timestamp'] = now + (i * 0.05)
                flows.append(f)

        elif threat_type == "c2_beacon":
            bot_ip = "192.168.10.22"
            c2_ip = "185.220.101.5"
            for i in range(8):
                tls_data = {
                    "ja3": "a0e42d24b9c7c4b0959f676e939da290",
                    "ja4": "t13d151600_a0e4_c2beacon",
                    "sni": "c2-checkin.darknet.xyz",
                    "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA"
                }
                f = self._build_flow(bot_ip, 49200 + i, c2_ip, 8443, "TCP",
                                     bytes_sent=256, bytes_recv=128, pkts=4, tls=tls_data)
                f['timestamp'] = now - (35.0 - (i * 5.0))
                flows.append(f)

        elif threat_type == "dga_dns":
            infected_host = "192.168.10.18"
            dns_server = "8.8.8.8"
            for i in range(12):
                random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=28))
                dga_domain = f"{random_string}.exfil-tunnel.badactor.top"
                dns_data = {"query": dga_domain, "qtype": "TXT" if i % 2 == 0 else "NULL"}
                f = self._build_flow(infected_host, 53000 + i, dns_server, 53, "UDP",
                                     bytes_sent=350, bytes_recv=120, pkts=2, tcp_flags="", dns=dns_data)
                f['timestamp'] = now + (i * 0.2)
                flows.append(f)

        elif threat_type == "encrypted_malware":
            victim = "192.168.10.30"
            malware_c2 = "91.215.102.14"
            tls_data = {
                "ja3": "a0e42d24b9c7c4b0959f676e939da290",
                "ja4": "t13d151600_a0e4_badmalware",
                "sni": "update-service-raw.xyz",
                "cipher": "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
            }
            f = self._build_flow(victim, 51234, malware_c2, 4444, "TCP",
                                 bytes_sent=1024, bytes_recv=512, pkts=8, tls=tls_data)
            f['timestamp'] = now
            flows.append(f)

        elif threat_type == "port_scan":
            scanner_ip = "192.168.10.99"
            target_ip = "10.0.0.1"
            for p in range(20, 55):
                f = self._build_flow(scanner_ip, 58000 + p, target_ip, p, "TCP",
                                     bytes_sent=44, bytes_recv=0, pkts=1, tcp_flags="S")
                f['timestamp'] = now + ((p - 20) * 0.05)
                flows.append(f)

        elif threat_type == "data_exfiltration":
            exfil_host = "192.168.10.15"
            drop_ip = "45.142.214.8"
            tls_data = {
                "ja3": "771fd359987056501a35567c9c0b1e98",
                "ja4": "t13d151600_8da5_exfil",
                "sni": "cloud-storage-drop.net",
                "cipher": "TLS_AES_256_GCM_SHA384"
            }
            f = self._build_flow(exfil_host, 59120, drop_ip, 443, "TCP",
                                 bytes_sent=18450000, bytes_recv=12500, pkts=1250, tls=tls_data)
            f['timestamp'] = now
            flows.append(f)

        return flows

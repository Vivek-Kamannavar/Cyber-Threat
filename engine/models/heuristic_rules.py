"""
Threat Heuristics & Statistical Rule Classifier Engine
Implements domain-specific detection algorithms for all 6 threat categories:
1. Volumetric / Protocol DDoS
2. Botnet C2 Beaconing
3. DGA Domains & DNS Tunnelling
4. Encrypted Malware (TLS/QUIC)
5. Reconnaissance & Port Scanning
6. Data Exfiltration
"""

from typing import List, Dict, Any, Optional
from engine.features import (
    calculate_shannon_entropy,
    calculate_iat_stats,
    calculate_dns_ngram_score,
    analyze_fanout_networkx,
    calculate_byte_asymmetry
)


class ThreatHeuristics:
    """Evaluates network flows against statistical rules and heuristics."""

    MALICIOUS_JA3 = {
        "a0e42d24b9c7c4b0959f676e939da290": "Cobalt Strike Beacon",
        "51c64c77e60f3980eea4f87b32d51586": "TrickBot Malware",
        "0cce74b724b07724393692df17d0af3e": "Metasploit HTTPS Stager"
    }

    @classmethod
    def evaluate_ddos(cls, flows_in_window: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Module 1: Volumetric / Protocol DDoS
        Evaluates source IP entropy and packet rates.
        Low IP entropy + high flow rate indicates single-source or target flood.
        """
        if len(flows_in_window) < 15:
            return None

        src_ips = [f['flow_identifier']['src_ip'] for f in flows_in_window]
        ip_entropy = calculate_shannon_entropy(src_ips)
        syn_count = sum(1 for f in flows_in_window if 'S' in f.get('tcp_flags', ''))

        # If high rate and low source IP entropy (single or few sources attacking)
        if (len(flows_in_window) >= 25 and ip_entropy < 1.5) or (syn_count > 20):
            most_common_src = max(set(src_ips), key=src_ips.count)
            target_ip = flows_in_window[0]['flow_identifier']['dst_ip']
            confidence = min(0.98, round(0.75 + (0.01 * syn_count), 2))

            return {
                "threat_class": "Volumetric / Protocol DDoS",
                "confidence_score": confidence,
                "flow_identifier": flows_in_window[-1]['flow_identifier'],
                "supporting_evidence_feature": {
                    "source_ip_entropy": ip_entropy,
                    "flow_rate_in_window": len(flows_in_window),
                    "syn_packet_count": syn_count,
                    "primary_attacker_ip": most_common_src,
                    "target_ip": target_ip,
                    "technical_reason": f"Low Source-IP Shannon Entropy ({ip_entropy}) with high flow burst ({len(flows_in_window)} flows/window).",
                    "reason": "A huge crowd of robot computers is shouting at our server all at once so nobody else can get in — just like 100 people trying to push through a tiny classroom door at the exact same second!"
                }
            }
        return None

    @classmethod
    def evaluate_c2_beaconing(cls, src_ip_flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Module 2: Botnet C2 Beaconing
        Analyzes Inter-Arrival Time (IAT) statistics over repeating flows to specific destination.
        """
        if len(src_ip_flows) < 5:
            return None

        # Group by dst_ip
        dst_groups = {}
        for f in src_ip_flows:
            dst = f['flow_identifier']['dst_ip']
            dst_groups.setdefault(dst, []).append(f)

        for dst_ip, flows in dst_groups.items():
            if len(flows) >= 5:
                timestamps = [f['timestamp'] for f in flows]
                iat_stats = calculate_iat_stats(timestamps)
                cv = iat_stats['cv_iat']

                # Low CV (< 0.20) indicates tight, periodic beaconing intervals
                if cv < 0.22 and iat_stats['mean_iat'] > 0.5:
                    confidence = round(max(0.80, 1.0 - cv), 2)
                    sample_flow = flows[-1]

                    return {
                        "threat_class": "Botnet C2 Beaconing",
                        "confidence_score": confidence,
                        "flow_identifier": sample_flow['flow_identifier'],
                        "supporting_evidence_feature": {
                            "destination_c2_ip": dst_ip,
                            "iat_mean_seconds": iat_stats['mean_iat'],
                            "iat_std_seconds": iat_stats['std_iat'],
                            "coefficient_of_variation": cv,
                            "connection_count": iat_stats['sample_count'],
                            "technical_reason": f"Strict periodic inter-arrival time detected (Mean IAT: {iat_stats['mean_iat']}s, CV: {cv}).",
                            "reason": "A secret bad program hiding inside is quietly whispering to a hacker's computer on a timer like a ticking clock, waiting for secret evil instructions."
                        }
                    }
        return None

    @classmethod
    def evaluate_dga_dns(cls, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Module 3: DGA Domains & DNS Tunnelling
        Runs Shannon entropy, n-gram rarity score, length check, and unusual record type analysis.
        """
        dns = flow.get('dns')
        if not dns or not dns.get('query'):
            return None

        query = dns['query']
        qtype = dns.get('qtype', 'A')
        scores = calculate_dns_ngram_score(query)

        # High entropy (> 3.8), long query (> 25), or TXT/NULL record query
        is_high_entropy = scores['entropy'] > 3.7 and scores['length'] > 20
        is_unusual_qtype = qtype in ['TXT', 'NULL', 'CNAME'] and scores['entropy'] > 3.4

        if is_high_entropy or is_unusual_qtype:
            confidence = min(0.96, round(0.65 + (scores['entropy'] / 10.0) + (0.10 if is_unusual_qtype else 0.0), 2))
            
            return {
                "threat_class": "DGA Domains & DNS Tunnelling",
                "confidence_score": confidence,
                "flow_identifier": flow['flow_identifier'],
                "supporting_evidence_feature": {
                    "dns_query": query,
                    "query_length": scores['length'],
                    "shannon_entropy": scores['entropy'],
                    "ngram_rarity_score": scores['ngram_rarity'],
                    "record_type": qtype,
                    "technical_reason": f"High Shannon Entropy ({scores['entropy']}) and elevated n-gram rarity score ({scores['ngram_rarity']}) in DNS query.",
                    "reason": "The computer is asking for weird scrambled secret-code website names (like 'x9z8q7w6'), which hackers use to sneak stolen secrets out without anyone noticing."
                }
            }
        return None

    @classmethod
    def evaluate_tls_malware(cls, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Module 4: Encrypted Malware (TLS/QUIC)
        Detects anomalies via metadata fingerprints (JA3/JA4) and suspicious TLS port/cipher parameters without payload decryption.
        """
        tls = flow.get('tls')
        if not tls:
            return None

        ja3 = tls.get('ja3')
        dst_port = flow['flow_identifier']['dst_port']
        sni = tls.get('sni', '')

        # 1. Known malicious JA3 hash lookup
        if ja3 in cls.MALICIOUS_JA3:
            malware_name = cls.MALICIOUS_JA3[ja3]
            return {
                "threat_class": "Encrypted Malware (TLS/QUIC)",
                "confidence_score": 0.98,
                "flow_identifier": flow['flow_identifier'],
                "supporting_evidence_feature": {
                    "ja3_fingerprint": ja3,
                    "ja4_fingerprint": tls.get('ja4', 'N/A'),
                    "signature_match": malware_name,
                    "sni": sni,
                    "technical_reason": f"Exact match for known malicious TLS JA3 fingerprint signature ({malware_name}).",
                    "reason": "A dangerous computer virus was caught trying to wear a fake disguise to sneak past the security guards."
                }
            }

        # 2. Non-standard port TLS or suspicious SNI
        if dst_port not in [443, 8443] and (ja3 or sni):
            return {
                "threat_class": "Encrypted Malware (TLS/QUIC)",
                "confidence_score": 0.82,
                "flow_identifier": flow['flow_identifier'],
                "supporting_evidence_feature": {
                    "ja3_fingerprint": ja3,
                    "non_standard_port": dst_port,
                    "sni": sni,
                    "technical_reason": f"TLS session established over non-standard destination port {dst_port} with metadata fingerprinting.",
                    "reason": "A suspicious program tried to enter through an unusual back window instead of using the front door."
                }
            }

        return None

    @classmethod
    def evaluate_recon_scan(cls, flows_in_window: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Module 5: Reconnaissance & Port Scanning
        Identifies single source IP fan-out targeting numerous ports or destination hosts using NetworkX topology metrics.
        """
        if len(flows_in_window) < 10:
            return None

        fanout_map = analyze_fanout_networkx(flows_in_window)

        for src_ip, metrics in fanout_map.items():
            if metrics['unique_dst_ports'] >= 15 or metrics['unique_dst_ips'] >= 20:
                confidence = min(0.95, round(0.70 + (metrics['unique_dst_ports'] * 0.01), 2))
                sample_flow = [f for f in flows_in_window if f['flow_identifier']['src_ip'] == src_ip][-1]

                return {
                    "threat_class": "Reconnaissance & Port Scanning",
                    "confidence_score": confidence,
                    "flow_identifier": sample_flow['flow_identifier'],
                    "supporting_evidence_feature": {
                        "scanner_src_ip": src_ip,
                        "unique_dst_ports_visited": metrics['unique_dst_ports'],
                        "unique_dst_hosts_visited": metrics['unique_dst_ips'],
                        "graph_out_degree": metrics['out_degree'],
                        "technical_reason": f"High source fan-out detected (scanned {metrics['unique_dst_ports']} distinct ports across {metrics['unique_dst_ips']} hosts).",
                        "reason": "A sneaky stranger is walking around trying to wiggle every single doorknob and window on our house to see if any door was left unlocked."
                    }
                }
        return None

    @classmethod
    def evaluate_data_exfiltration(cls, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Module 6: Data Exfiltration
        Tracks asymmetric outbound-to-inbound byte ratio spikes and large outbound data transfers.
        """
        bytes_sent = flow.get('bytes_sent', 0)
        bytes_recv = flow.get('bytes_received', 0)

        ratio = calculate_byte_asymmetry(bytes_sent, bytes_recv)

        # High outbound asymmetry: ratio > 10.0 and sent bytes > 5 MB
        if ratio > 10.0 and bytes_sent > 5_000_000:
            confidence = min(0.96, round(0.75 + (ratio / 100.0), 2))
            
            return {
                "threat_class": "Data Exfiltration",
                "confidence_score": confidence,
                "flow_identifier": flow['flow_identifier'],
                "supporting_evidence_feature": {
                    "bytes_sent_outbound": bytes_sent,
                    "bytes_received_inbound": bytes_recv,
                    "asymmetry_ratio": ratio,
                    "megabytes_exfiltrated": round(bytes_sent / 1_000_000, 2),
                    "technical_reason": f"Extreme asymmetric outbound byte flow detected ({round(bytes_sent / 1_000_000, 2)} MB sent, Ratio: {ratio}).",
                    "reason": "Someone is sneaking out a giant backpack stuffed with private files and secret photos through the back door!"
                }
            }
        return None

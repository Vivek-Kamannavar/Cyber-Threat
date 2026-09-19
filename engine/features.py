"""
Feature Engineering Pipeline for Unidirectional Threat Detection
Calculates Shannon Entropy, Inter-Arrival Time (IAT) statistics, DNS N-Gram scores,
and NetworkX Fan-out graph topology metrics.
"""

import math
from collections import Counter
from typing import List, Dict, Any, Tuple
import networkx as nx
import numpy as np


def calculate_shannon_entropy(data: Any) -> float:
    """
    Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
    Works on strings (e.g. DNS domain names) or lists (e.g. Source IP distribution).
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        tokens = list(data)
    else:
        tokens = list(data)

    total_count = len(tokens)
    if total_count == 0:
        return 0.0

    counts = Counter(tokens)
    entropy = 0.0
    for count in counts.values():
        p = count / total_count
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_iat_stats(timestamps: List[float]) -> Dict[str, float]:
    """
    Calculates Inter-Arrival Time (IAT) statistics:
    Mean (mu), Standard Deviation (sigma), and Coefficient of Variation (CV = sigma / mu).
    Low CV (< 0.20) indicates periodic beaconing activity.
    """
    if len(timestamps) < 2:
        return {"mean_iat": 0.0, "std_iat": 0.0, "cv_iat": 1.0, "sample_count": len(timestamps)}

    sorted_ts = sorted(timestamps)
    iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

    mean_iat = float(np.mean(iats))
    std_iat = float(np.std(iats))
    cv_iat = float(std_iat / mean_iat) if mean_iat > 1e-6 else 1.0

    return {
        "mean_iat": round(mean_iat, 4),
        "std_iat": round(std_iat, 4),
        "cv_iat": round(cv_iat, 4),
        "sample_count": len(timestamps)
    }


# Standard English/DNS bi-gram frequency baseline (normalized frequencies)
COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd', 'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
    'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea'
}

def calculate_dns_ngram_score(domain: str) -> Dict[str, Any]:
    """
    Calculates DNS query length, Shannon entropy, and N-gram rarity score.
    Higher rarity score and higher entropy strongly indicate DGA (Domain Generation Algorithms) or DNS Tunnelling.
    """
    if not domain:
        return {"length": 0, "entropy": 0.0, "ngram_rarity": 0.0}

    # Clean domain (strip trailing dot or subdomain tld)
    domain_clean = domain.lower().split('.')[0]
    length = len(domain_clean)
    entropy = calculate_shannon_entropy(domain_clean)

    if length < 2:
        return {"length": length, "entropy": entropy, "ngram_rarity": 0.0}

    bigrams = [domain_clean[i:i+2] for i in range(length - 1)]
    common_count = sum(1 for bg in bigrams if bg in COMMON_BIGRAMS)
    ngram_rarity = round(1.0 - (common_count / len(bigrams)), 4)

    return {
        "length": length,
        "entropy": entropy,
        "ngram_rarity": ngram_rarity
    }


def analyze_fanout_networkx(flows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Uses NetworkX to build a directed graph G = (V, E) of IP & Port interactions.
    Computes out-degree, unique destination IPs, and unique destination ports per source IP.
    """
    G = nx.DiGraph()

    for f in flows:
        fid = f.get('flow_identifier', {})
        src = fid.get('src_ip')
        dst = fid.get('dst_ip')
        dport = fid.get('dst_port')

        if src and dst:
            G.add_node(src, type='source')
            G.add_node(dst, type='destination')
            G.add_edge(src, dst, port=dport)

    fanout_results = {}
    for node in G.nodes():
        if G.nodes[node].get('type') == 'source' or G.out_degree(node) > 0:
            neighbors = list(G.successors(node))
            unique_ports = set()
            for neighbor in neighbors:
                edge_data = G.get_edge_data(node, neighbor)
                if edge_data and 'port' in edge_data:
                    unique_ports.add(edge_data['port'])

            fanout_results[node] = {
                "out_degree": G.out_degree(node),
                "unique_dst_ips": len(neighbors),
                "unique_dst_ports": len(unique_ports)
            }

    return fanout_results


def calculate_byte_asymmetry(bytes_sent: int, bytes_received: int) -> float:
    """Calculates outbound to inbound byte asymmetry ratio."""
    return round(float(bytes_sent) / float(bytes_received + 1.0), 2)

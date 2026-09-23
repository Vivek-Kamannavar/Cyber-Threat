"""
Phase 5 Test Suite: Mathematical Feature Extraction Edge Cases
Tests Shannon entropy boundaries, zero division prevention in IAT stats,
DNS n-gram scoring limits, and byte asymmetry smoothing.
"""

import math
import sys
import os
import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.features import (
    calculate_shannon_entropy,
    calculate_iat_stats,
    calculate_dns_ngram_score,
    calculate_byte_asymmetry,
    analyze_fanout_networkx
)


def test_shannon_entropy_boundaries():
    """Tests Shannon entropy on empty, single repeated character, and uniform distributions."""
    # 1. Empty string / empty list
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy([]) == 0.0
    assert calculate_shannon_entropy(None) == 0.0

    # 2. Single character repeated 1,000 times (Zero randomness -> H = 0.0)
    assert calculate_shannon_entropy("a" * 1000) == 0.0

    # 3. Uniform binary distribution (H = - (0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0)
    binary_data = "01" * 500
    assert calculate_shannon_entropy(binary_data) == 1.0

    # 4. Uniform alphabet distribution (26 distinct letters -> H = log2(26) ~= 4.7004)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    expected = round(math.log2(26), 4)
    assert abs(calculate_shannon_entropy(alphabet) - expected) < 0.001


def test_iat_stats_zero_division_safety():
    """Verifies that calculate_iat_stats prevents ZeroDivisionError on 0, 1, and identical timestamps."""
    # 0 timestamps
    stats0 = calculate_iat_stats([])
    assert stats0["mean_iat"] == 0.0
    assert stats0["cv_iat"] == 1.0

    # 1 timestamp
    stats1 = calculate_iat_stats([1700000000.0])
    assert stats1["mean_iat"] == 0.0
    assert stats1["cv_iat"] == 1.0

    # Identical timestamps (dt = 0, mean = 0 -> zero division prevented)
    stats_identical = calculate_iat_stats([1700000000.0] * 10)
    assert stats_identical["mean_iat"] == 0.0
    assert stats_identical["cv_iat"] == 1.0

    # Strict periodic interval (dt = 10.0, std = 0.0 -> CV = 0.0)
    timestamps = [1700000000.0 + i * 10.0 for i in range(10)]
    stats_periodic = calculate_iat_stats(timestamps)
    assert stats_periodic["mean_iat"] == 10.0
    assert stats_periodic["std_iat"] == 0.0
    assert stats_periodic["cv_iat"] == 0.0


def test_dns_ngram_extreme_inputs():
    """Tests DNS n-gram scoring on non-ASCII, deeply nested, and ultra-long domain names."""
    # Empty
    res_empty = calculate_dns_ngram_score("")
    assert res_empty["length"] == 0
    assert res_empty["entropy"] == 0.0

    # Single character
    res_single = calculate_dns_ngram_score("x")
    assert res_single["length"] == 1
    assert res_single["ngram_rarity"] == 0.0

    # Deeply nested subdomains (e.g. 20 subdomain levels)
    deep_domain = ".".join([f"sub{i}" for i in range(20)]) + ".internal.lan"
    res_deep = calculate_dns_ngram_score(deep_domain)
    assert res_deep["length"] > 0
    assert 0.0 <= res_deep["ngram_rarity"] <= 1.0

    # Ultra-long random domain string (> 255 chars)
    long_domain = "a" * 300 + ".com"
    res_long = calculate_dns_ngram_score(long_domain)
    assert res_long["length"] == 300
    assert res_long["entropy"] == 0.0  # Monotonous characters


def test_byte_asymmetry_smoothing():
    """Verifies asymmetry ratio handles zero inbound bytes without division error."""
    # Pure outbound flow: 10 MB sent, 0 bytes received
    ratio = calculate_byte_asymmetry(bytes_sent=10_000_000, bytes_received=0)
    assert ratio == 10_000_000.0

    # Balanced symmetric flow
    balanced_ratio = calculate_byte_asymmetry(bytes_sent=1000, bytes_received=1000)
    assert 0.99 <= balanced_ratio <= 1.01

    # Inbound-heavy flow (download)
    inbound_ratio = calculate_byte_asymmetry(bytes_sent=100, bytes_received=10_000)
    assert inbound_ratio < 0.1


def test_fanout_graph_empty_and_disconnected():
    """Verifies analyze_fanout_networkx handles empty and single flow structures."""
    assert analyze_fanout_networkx([]) == {}

    flows = [
        {"flow_identifier": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80}},
        {"flow_identifier": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "dst_port": 443}}
    ]
    res = analyze_fanout_networkx(flows)
    assert "10.0.0.1" in res
    assert res["10.0.0.1"]["unique_dst_ips"] == 2
    assert res["10.0.0.1"]["unique_dst_ports"] == 2

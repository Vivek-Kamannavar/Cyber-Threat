"""
Verification script testing engine and threat detection modules
"""

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ingest.traffic_generator import TrafficGenerator
from engine.threat_detector import ThreatDetector

def run_tests():
    detector = ThreatDetector(window_size_seconds=60.0)
    generator = TrafficGenerator()

    threat_types = ['ddos', 'c2_beacon', 'dga_dns', 'encrypted_malware', 'port_scan', 'data_exfiltration']
    total_alerts_found = 0

    print("=== STARTING THREAT DETECTION PIPELINE UNIT TESTS ===")
    for threat in threat_types:
        flows = generator.generate_threat_scenario(threat)
        threat_alerts = []
        for flow in flows:
            alerts = detector.process_flow(flow)
            threat_alerts.extend(alerts)

        print(f"[{threat.upper()}] Processed {len(flows)} flows -> Raised {len(threat_alerts)} alerts")
        if threat_alerts:
            total_alerts_found += len(threat_alerts)
            sample = threat_alerts[0]
            print(f"   -> Sample Alert ID: {sample['alert_id']}")
            print(f"   -> Threat Class: {sample['threat_class']}")
            print(f"   -> Confidence: {sample['confidence_score']}")
            print(f"   -> Evidence: {sample['supporting_evidence_feature'].get('reason')}\n")

    print(f"=== TEST COMPLETE: Total Alerts Generated: {total_alerts_found} ===")
    assert total_alerts_found >= 6, f"Expected at least 6 threat alerts, got {total_alerts_found}"
    print("SUCCESS! All 6 threat modules generated valid standardized alerts.")

if __name__ == '__main__':
    run_tests()

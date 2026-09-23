"""
Unified Threat Detection Engine for Unidirectional IP Traffic
Orchestrates ML Isolation Forest, Heuristics Rules, Sliding Window Manager, and standardizes alert outputs.
Persists alerts to SQLite database and supports configurable detection parameters.
"""

import time
import uuid
from typing import List, Dict, Any, Optional
from engine.window_manager import SlidingWindowManager
from engine.models.isolation_forest import FlowAnomalyDetector
from engine.models.heuristic_rules import ThreatHeuristics
from backend.config import Config
from backend.database import save_alert, get_all_alerts, clear_alerts as db_clear_alerts


class ThreatDetector:
    """Main orchestration engine for analyzing incoming unidirectional flow streams."""

    def __init__(self, window_size_seconds: Optional[float] = None, load_persisted_alerts: bool = True):
        ws = window_size_seconds if window_size_seconds is not None else Config.WINDOW_SIZE_SECONDS
        self.window_manager = SlidingWindowManager(window_size_seconds=ws)
        self.ml_detector = FlowAnomalyDetector()
        self.alerts_history: List[Dict[str, Any]] = []
        self.last_alert_time: Dict[str, float] = {}

        if load_persisted_alerts:
            try:
                # Load existing persisted alerts from SQLite
                persisted = get_all_alerts(limit=500)
                # Stored most-recent first in DB; reverse so in-memory history is chronological
                self.alerts_history = list(reversed(persisted))
            except Exception as e:
                print(f"Notice: Could not load historical alerts from database: {e}")

    def process_flow(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Processes a single flow through the detection pipeline.
        Returns a list of standardized Alert JSON records raised by this flow.
        """
        # 1. Add flow to sliding window
        self.window_manager.add_flow(flow)

        alerts = []
        recent_flows = self.window_manager.get_recent_flows()
        src_ip = flow['flow_identifier']['src_ip']
        src_flows = self.window_manager.get_flows_for_src_ip(src_ip)

        cooldown = Config.ALERT_COOLDOWN_SECONDS

        # 2. Check Rule-based Heuristics for all 6 threat classes

        # Module 1: Volumetric DDoS
        ddos_alert = ThreatHeuristics.evaluate_ddos(recent_flows)
        if ddos_alert and self._should_raise_alert("DDoS", ddos_alert['supporting_evidence_feature']['primary_attacker_ip'], cooldown):
            alerts.append(self._format_alert(ddos_alert))

        # Module 2: Botnet C2 Beaconing
        c2_alert = ThreatHeuristics.evaluate_c2_beaconing(src_flows)
        if c2_alert and self._should_raise_alert("C2_Beacon", src_ip, cooldown):
            alerts.append(self._format_alert(c2_alert))

        # Module 3: DGA Domains & DNS Tunnelling
        dga_alert = ThreatHeuristics.evaluate_dga_dns(flow)
        if dga_alert and self._should_raise_alert("DGA", flow['flow_identifier']['src_ip'], cooldown):
            alerts.append(self._format_alert(dga_alert))

        # Module 4: Encrypted Malware (TLS/QUIC)
        tls_alert = ThreatHeuristics.evaluate_tls_malware(flow)
        if tls_alert and self._should_raise_alert("TLS_Malware", flow['flow_identifier']['src_ip'], cooldown):
            alerts.append(self._format_alert(tls_alert))

        # Module 5: Reconnaissance & Port Scanning
        recon_alert = ThreatHeuristics.evaluate_recon_scan(recent_flows)
        if recon_alert and self._should_raise_alert("Recon_Scan", recon_alert['supporting_evidence_feature']['scanner_src_ip'], cooldown):
            alerts.append(self._format_alert(recon_alert))

        # Module 6: Data Exfiltration
        exfil_alert = ThreatHeuristics.evaluate_data_exfiltration(flow)
        if exfil_alert and self._should_raise_alert("Exfiltration", src_ip, cooldown):
            alerts.append(self._format_alert(exfil_alert))

        # 3. Unsupervised ML Isolation Forest check
        is_ml_anomaly, ml_score = self.ml_detector.predict_anomaly(flow)
        if is_ml_anomaly and not alerts and self._should_raise_alert("ML_Anomaly", src_ip, cooldown):
            ml_alert = {
                "threat_class": "Unsupervised Volumetric Anomaly",
                "confidence_score": ml_score,
                "flow_identifier": flow['flow_identifier'],
                "supporting_evidence_feature": {
                    "isolation_forest_score": ml_score,
                    "bytes_sent": flow.get('bytes_sent', 0),
                    "bytes_received": flow.get('bytes_received', 0),
                    "packet_count": flow.get('packet_count', 1),
                    "technical_reason": f"Isolation Forest detected multi-variate statistical anomaly score of {ml_score}.",
                    "reason": "This computer suddenly started acting very weirdly and doing things it has never done before!"
                }
            }
            alerts.append(self._format_alert(ml_alert))

        # 4. Record to in-memory history and persist to SQLite
        for alert in alerts:
            self.alerts_history.append(alert)
            try:
                save_alert(alert)
            except Exception as e:
                print(f"Warning: Failed to persist alert {alert.get('alert_id')} to database: {e}")

        return alerts

    def _should_raise_alert(self, alert_key: str, entity: str, cooldown_seconds: Optional[float] = None) -> bool:
        """Deduplicates frequent repetitive alerts within cooldown period."""
        if cooldown_seconds is None:
            cooldown_seconds = Config.ALERT_COOLDOWN_SECONDS
        key = f"{alert_key}:{entity}"
        now = time.time()
        last_time = self.last_alert_time.get(key, 0)
        if now - last_time >= cooldown_seconds:
            self.last_alert_time[key] = now
            return True
        return False

    def _format_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Formats alert into standard JSON schema."""
        return {
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "flow_identifier": alert_data["flow_identifier"],
            "threat_class": alert_data["threat_class"],
            "confidence_score": alert_data["confidence_score"],
            "supporting_evidence_feature": alert_data["supporting_evidence_feature"]
        }

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Returns historical alert list."""
        return self.alerts_history

    def clear_alerts(self, clear_db: bool = True):
        """Clears all historical alerts from memory, database, and cooldown trackers."""
        self.alerts_history = []
        self.last_alert_time.clear()
        if clear_db:
            try:
                db_clear_alerts()
            except Exception as e:
                print(f"Warning: Failed to clear database alerts: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Returns overall detection stats and throughput metrics."""
        tp = self.window_manager.get_throughput_stats()
        return {
            "throughput": tp,
            "total_alerts_raised": len(self.alerts_history),
            "window_size_seconds": self.window_manager.window_size
        }

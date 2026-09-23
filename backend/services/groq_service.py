"""
Free Groq AI Incident Copilot & Natural Language Explanations
Uses Groq SDK with llama-3.3-70b-versatile / llama-3.1-8b-instant models.
Includes 100% deterministic offline fallback when GROQ_API_KEY is not set or network is unavailable.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from backend.config import Config

logger = logging.getLogger("groq_service")

# Default Groq model
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
FALLBACK_MODEL = "llama-3.1-8b-instant"


class GroqCopilotService:
    """Provides AI-driven incident analysis, remediation checklists, and threat chat."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.client = None
        if self.api_key:
            try:
                from groq import Groq
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Groq client: {e}")
                self.client = None

    def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates structured executive incident analysis, impact assessment,
        remediation checklist, and copyable firewall rules.
        """
        if self.client:
            try:
                return self._call_groq_analysis(alert)
            except Exception as e:
                logger.warning(f"Groq API error ({e}). Using deterministic offline fallback.")
                return self._generate_offline_analysis(alert)
        return self._generate_offline_analysis(alert)

    def _call_groq_analysis(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Calls Groq API with structured JSON output instructions."""
        threat_class = alert.get("threat_class", "Unknown Threat")
        confidence = alert.get("confidence_score", 0.0)
        fid = alert.get("flow_identifier", {})
        evidence = alert.get("supporting_evidence_feature", {})

        system_prompt = (
            "You are an elite Industrial Cybersecurity (ICS/SCADA) and Data Diode Incident Responder. "
            "Analyze the following threat alert and output STRICTLY valid JSON with these exact keys:\n"
            "{\n"
            '  "summary": "Plain English description of what occurred",\n'
            '  "severity_rating": "CRITICAL | HIGH | MEDIUM | LOW",\n'
            '  "attack_vector_breakdown": "Explanation of the protocol/methodology used",\n'
            '  "potential_business_impact": "Operational risks for the air-gapped facility",\n'
            '  "recommended_remediation_steps": ["Step 1", "Step 2", "Step 3"],\n'
            '  "firewall_mitigation_rule": "iptables command to block the threat"\n'
            "}"
        )

        user_content = (
            f"Alert Details:\n"
            f"- Threat Category: {threat_class}\n"
            f"- Confidence: {confidence}\n"
            f"- Source IP: {fid.get('src_ip')}:{fid.get('src_port')}\n"
            f"- Destination IP: {fid.get('dst_ip')}:{fid.get('dst_port')}\n"
            f"- Protocol: {fid.get('protocol')}\n"
            f"- Evidence: {json.dumps(evidence)}\n"
        )

        response = self.client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )

        raw_json = response.choices[0].message.content
        return json.loads(raw_json)

    def _generate_offline_analysis(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic offline rule-based incident analysis generator."""
        threat_class = alert.get("threat_class", "Suspicious Activity")
        confidence = alert.get("confidence_score", 0.85)
        fid = alert.get("flow_identifier", {})
        src_ip = fid.get("src_ip", "0.0.0.0")
        dst_ip = fid.get("dst_ip", "0.0.0.0")
        dst_port = fid.get("dst_port", 0)
        protocol = fid.get("protocol", "TCP")
        evidence = alert.get("supporting_evidence_feature", {})

        severity = "HIGH"
        if confidence >= 0.95 or "DDoS" in threat_class or "Exfiltration" in threat_class:
            severity = "CRITICAL"
        elif confidence < 0.80:
            severity = "MEDIUM"

        if "Data Exfiltration" in threat_class:
            mbs = evidence.get("megabytes_exfiltrated", "multiple")
            ratio = evidence.get("asymmetry_ratio", "high")
            summary = (
                f"Data exfiltration alert: Host {src_ip} transferred an abnormal volume of data "
                f"({mbs} MB, asymmetry ratio: {ratio}) to external destination {dst_ip}:{dst_port}."
            )
            impact = "Potential loss of proprietary industrial intellectual property, blueprints, or critical control configurations."
            steps = [
                f"Immediately sever network link for internal workstation {src_ip}.",
                f"Check active processes on {src_ip} for unauthorized file compression or staging utilities.",
                f"Inspect external destination {dst_ip} against threat intelligence feeds.",
                "Review data diode optical mirror taps to verify no other hosts are transmitting to this target."
            ]
            rule = f"iptables -A FORWARD -s {src_ip} -d {dst_ip} -j DROP"

        elif "Botnet C2" in threat_class:
            summary = (
                f"Periodic Command & Control beaconing detected from {src_ip} to external node {dst_ip}. "
                f"Connection frequency displays strict robotic periodicity (low Inter-Arrival Time variance)."
            )
            impact = "Malware presence inside the facility awaiting remote activation or execution instructions."
            steps = [
                f"Isolate host {src_ip} from the internal subnet.",
                "Capture memory dump of the infected workstation to identify injected DLLs or rootkits.",
                f"Block outbound destination IP {dst_ip} at the gateway firewall.",
                "Conduct full forensic scan of all adjacent controllers sharing credentials."
            ]
            rule = f"iptables -A OUTPUT -d {dst_ip} -p {protocol.lower()} --dport {dst_port} -j DROP"

        elif "DGA" in threat_class:
            query = evidence.get("dns_query", "unknown domain")
            summary = (
                f"Domain Generation Algorithm (DGA) query or DNS tunnelling pattern detected: "
                f"Host {src_ip} queried suspicious high-entropy domain '{query}'."
            )
            impact = "Covert communications channel bypassing perimeter firewalls through DNS query smuggling."
            steps = [
                f"Sinkhole DNS resolution for '{query}' on internal DNS resolvers.",
                f"Audit endpoint DNS client logs on {src_ip} to identify the requesting PID.",
                "Inspect internal DNS logs for similar high-entropy subdomains."
            ]
            rule = f"iptables -A FORWARD -s {src_ip} -p udp --dport 53 -j REJECT"

        elif "Encrypted Malware" in threat_class:
            match = evidence.get("signature_match", "Malicious TLS Signature")
            summary = (
                f"Encrypted malware fingerprint matched: Host {src_ip} established TLS session matching "
                f"known signature '{match}' without payload decryption."
            )
            impact = "Active compromise by known threat actors or offensive security frameworks (e.g. Cobalt Strike, TrickBot)."
            steps = [
                f"Emergency containment: Disconnect physical Ethernet interface of {src_ip}.",
                "Initiate incident response triage for Cobalt Strike / C2 beacon payloads.",
                "Search network logs for other hosts exhibiting identical JA3 fingerprints."
            ]
            rule = f"iptables -A FORWARD -s {src_ip} -j DROP"

        elif "Reconnaissance" in threat_class:
            ports = evidence.get("unique_dst_ports_visited", 0)
            summary = (
                f"Port scanning / reconnaissance activity detected: Host {src_ip} rapidly targeted "
                f"{ports} distinct ports/services across the network."
            )
            impact = "Adversary or automated worm mapping industrial attack surface prior to lateral exploitation."
            steps = [
                f"Block scanning host {src_ip} at the local switch level (port security / 802.1X).",
                "Verify whether {src_ip} is an authorized vulnerability scanner or rogue device.",
                "Verify integrity of targeted industrial controllers (PLCs/RTUs)."
            ]
            rule = f"iptables -A INPUT -s {src_ip} -j DROP"

        elif "DDoS" in threat_class or "Volumetric" in threat_class:
            summary = (
                f"Volumetric flood anomaly detected targeting {dst_ip}. "
                f"Abnormal traffic volume or low-entropy source distribution indicates flood conditions."
            )
            impact = "Network bandwidth saturation leading to dropped telemetry and loss of real-time SCADA visibility."
            steps = [
                f"Rate-limit incoming packets from source subnet at upstream perimeter switch.",
                "Enable SYN flood protection and TCP cookies on target servers.",
                "Inspect switch port metrics to ensure optical diode link is not dropping legitimate frames."
            ]
            rule = f"iptables -A INPUT -s {src_ip} -p {protocol.lower()} --dport {dst_port} -m limit --limit 25/minute -j ACCEPT"

        else:
            summary = f"Anomalous flow activity detected from {src_ip} to {dst_ip}:{dst_port}."
            impact = "Potential deviation from industrial traffic baseline."
            steps = [
                f"Review connection history for host {src_ip}.",
                "Inspect device logs for unauthorized configuration changes."
            ]
            rule = f"iptables -A FORWARD -s {src_ip} -j DROP"

        return {
            "summary": summary,
            "severity_rating": severity,
            "attack_vector_breakdown": f"Observed over {protocol} protocol via port {dst_port}. Evaluated against {threat_class} behavioral rules.",
            "potential_business_impact": impact,
            "recommended_remediation_steps": steps,
            "firewall_mitigation_rule": rule
        }

    def chat_response(self, message: str, alert_context: Optional[Dict[str, Any]] = None, history: Optional[List[Dict[str, str]]] = None) -> str:
        """Processes analyst chat inquiries regarding threats and air-gapped security."""
        if self.client:
            try:
                system_content = (
                    "You are the AI Incident Copilot for a high-security Data Diode Critical Infrastructure SOC. "
                    "Provide concise, expert, actionable guidance tailored to air-gapped environments. "
                    "Never suggest actions requiring active reverse network connections if traffic is unidirectional."
                )
                messages = [{"role": "system", "content": system_content}]
                if alert_context:
                    messages.append({
                        "role": "system",
                        "content": f"Active Alert Context: {json.dumps(alert_context)}"
                    })
                if history:
                    messages.extend(history[-6:])
                messages.append({"role": "user", "content": message})

                res = self.client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=600
                )
                return res.choices[0].message.content
            except Exception as e:
                logger.warning(f"Groq chat API error: {e}. Fallback to offline assistant.")

        # Offline deterministic assistant
        msg_lower = message.lower()
        if "block" in msg_lower or "firewall" in msg_lower or "iptables" in msg_lower:
            src = alert_context.get("flow_identifier", {}).get("src_ip", "<SOURCE_IP>") if alert_context else "<SOURCE_IP>"
            return (
                f"### Recommended Firewall Containment\n\n"
                f"To block the compromised host, execute the following command at the internal gateway:\n\n"
                f"```bash\n"
                f"iptables -A INPUT -s {src} -j DROP\n"
                f"iptables -A FORWARD -s {src} -j DROP\n"
                f"```\n\n"
                f"**Note:** In a physical Data Diode network, ensure you apply this rule on the internal side of the diode to prevent internal lateral movement."
            )
        elif "verify" in msg_lower or "investigate" in msg_lower or "how to" in msg_lower:
            return (
                "### Investigation Checklist for Air-Gapped Networks\n\n"
                "1. **Host Isolation:** Physically disconnect the suspect machine from the LAN switch.\n"
                "2. **Process Auditing:** Run `netstat -ano` (Windows) or `ss -tulpn` (Linux) to find the process ID maintaining the session.\n"
                "3. **Memory Capture:** Extract RAM dump using WinPmem or LiME before rebooting to preserve volatility.\n"
                "4. **Log Review:** Check event logs for unexpected service installations, scheduled tasks, or USB storage insertions."
            )
        else:
            return (
                f"### SOC Incident Copilot (Offline Mode)\n\n"
                f"Analysis for query: *\"{message}\"*\n\n"
                f"The active environment operates under strict hardware data diode constraints. "
                f"All threat telemetry is ingested passively with zero return path. "
                f"To contain threats safely without interrupting industrial processes, isolate endpoints at switch ports "
                f"rather than rebooting industrial controllers."
            )

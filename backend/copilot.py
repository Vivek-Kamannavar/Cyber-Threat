"""
Conversational AI Security Analyst.

Wraps the existing :class:`~backend.services.groq_service.GroqCopilotService` with a
context-aware conversational layer: the analyst's question is answered against the live
telemetry snapshot and the current alert set, not in isolation.

Every response is a deterministic contract:

    {"response": str, "mode": "GROQ" | "OFFLINE_HEURISTIC", "suggestions": list[str]}

When ``GROQ_API_KEY`` is missing, the network is unreachable, or the model call fails for
any reason, the layer degrades to rule-based offline heuristics (reusing the service's own
deterministic generators) instead of returning an error.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from backend.services.groq_service import GROQ_MODEL, GroqCopilotService

logger = logging.getLogger("copilot")

# Bounded context (RULE 2.1): only the newest alerts ever enter the prompt.
MAX_CONTEXT_ALERTS = 10
MAX_HISTORY_TURNS = 6

DEFAULT_SUGGESTIONS = [
    "Summarize threat posture",
    "Generate firewall rules",
    "Explain the latest incident",
    "What should I contain first?",
]


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class ConversationalCopilot:
    """Context-aware SOC analyst chat with deterministic offline fallback."""

    def __init__(self, service: Optional[GroqCopilotService] = None):
        self.service = service or GroqCopilotService()

    # -- context assembly ---------------------------------------------
    def build_context(
        self,
        telemetry: Optional[Dict[str, Any]] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        alert_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Builds the sliding-window + incident snapshot injected into every prompt."""
        clean_alerts = [alert for alert in (alerts or []) if isinstance(alert, dict)]
        metrics = telemetry if isinstance(telemetry, dict) else {}

        by_class: Dict[str, int] = {}
        for alert in clean_alerts:
            threat_class = str(alert.get("threat_class") or "Unknown")
            by_class[threat_class] = by_class.get(threat_class, 0) + 1

        highest = max((_coerce_float(a.get("confidence_score")) for a in clean_alerts), default=0.0)
        critical = sum(1 for alert in clean_alerts if _coerce_float(alert.get("confidence_score")) >= 0.9)

        return {
            "generated_at": _iso_now(),
            "facility_status": "CRITICAL" if critical else ("ELEVATED" if clean_alerts else "NORMAL"),
            "diode": "Unidirectional read-only (zero return path)",
            "throughput": {
                "pps": _coerce_float(metrics.get("pps")),
                "bps": _coerce_float(metrics.get("bps")),
                "total_flows": int(_coerce_float(metrics.get("total_flows"))),
            },
            "incidents": {
                "total": len(clean_alerts),
                "critical": critical,
                "highest_confidence": round(highest, 4),
                "by_class": by_class,
            },
            "focus_alert": self._select_alert(clean_alerts, alert_id),
        }

    @staticmethod
    def _select_alert(alerts: List[Dict[str, Any]], alert_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not alerts:
            return None
        if alert_id:
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    return alert
        return max(alerts, key=lambda alert: _coerce_float(alert.get("confidence_score")))

    # -- main entry ----------------------------------------------------
    def respond(
        self,
        message: str,
        telemetry: Optional[Dict[str, Any]] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        alert_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Answers an analyst question with live SOC context and never raises."""
        prompt = (message or "").strip()
        context = self.build_context(telemetry, alerts, alert_id)

        if not prompt:
            return {
                "response": (
                    "I did not receive a question. Ask me to summarise the current threat posture, "
                    "explain the highest-confidence incident, or propose containment rules."
                ),
                "mode": "OFFLINE_HEURISTIC",
                "suggestions": list(DEFAULT_SUGGESTIONS),
            }

        if self.service.client is not None:
            try:
                return {
                    "response": self._call_groq(prompt, context, history or []),
                    "mode": "GROQ",
                    "suggestions": self._suggestions(context, prompt),
                }
            except Exception as exc:
                logger.warning("Groq chat failed (%s). Falling back to offline heuristics.", exc)

        return {
            "response": self._offline_response(prompt, context),
            "mode": "OFFLINE_HEURISTIC",
            "suggestions": self._suggestions(context, prompt),
        }

    def _call_groq(self, prompt: str, context: Dict[str, Any], history: List[Dict[str, str]]) -> str:
        system_prompt = (
            "You are the AI Security Analyst embedded in a Data Diode SOC for critical industrial "
            "infrastructure. Answer with precise, actionable analysis. Always ground your answer in the "
            "provided live telemetry and incident context. Remember the operational constraints: traffic "
            "is unidirectional (no reverse connections are possible), payloads are never decrypted, and "
            "containment must not interrupt industrial processes. Prefer short markdown sections and exact "
            "commands only where they are safe to run on the internal side of the diode."
        )
        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "system", "content": f"Live SOC context JSON: {json.dumps(self._trim_context(context))}"},
        ]
        for turn in history[-MAX_HISTORY_TURNS:]:
            if isinstance(turn, dict) and turn.get("role") in ("user", "assistant") and turn.get("content"):
                messages.append({"role": turn["role"], "content": str(turn["content"])[:2000]})
        messages.append({"role": "user", "content": prompt})

        response = self.service.client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=0.3,
            max_tokens=700,
        )
        return response.choices[0].message.content

    @staticmethod
    def _trim_context(context: Dict[str, Any]) -> Dict[str, Any]:
        """Keeps the injected prompt small: summary counts plus one focused alert."""
        focus = context.get("focus_alert")
        trimmed_focus = None
        if focus:
            trimmed_focus = {
                "alert_id": focus.get("alert_id"),
                "threat_class": focus.get("threat_class"),
                "confidence_score": focus.get("confidence_score"),
                "flow_identifier": focus.get("flow_identifier"),
                "evidence": focus.get("supporting_evidence_feature"),
            }
        return {
            "generated_at": context.get("generated_at"),
            "facility_status": context.get("facility_status"),
            "throughput": context.get("throughput"),
            "incidents": context.get("incidents"),
            "focus_alert": trimmed_focus,
        }

    # -- offline heuristics -------------------------------------------
    def _offline_response(self, message: str, context: Dict[str, Any]) -> str:
        lower = message.lower()

        if any(token in lower for token in ("posture", "status", "summary", "summarize", "summarise", "overview")):
            return self._posture_summary(context)

        if any(token in lower for token in ("firewall", "iptables", "block", "rule")):
            return self._firewall_rules(context)

        if any(token in lower for token in ("explain", "what happened", "incident", "alert", "detail")):
            return self._explain_incident(context)

        if any(token in lower for token in ("contain", "remediat", "respond", "fix", "mitigat")):
            return self._containment_plan(context)

        # Unknown intent: reuse the service's own deterministic assistant for a coherent reply.
        reply = self.service.chat_response(message, context.get("focus_alert"))
        return f"{reply}\n\n_Offline heuristic mode — no GROQ_API_KEY configured._"

    def _posture_summary(self, context: Dict[str, Any]) -> str:
        incidents = context.get("incidents", {})
        throughput = context.get("throughput", {})
        by_class = incidents.get("by_class") or {}

        lines = [
            "### Threat Posture Summary",
            f"- **Facility status:** {context.get('facility_status', 'NORMAL')}",
            f"- **Active incidents:** {incidents.get('total', 0)} ({incidents.get('critical', 0)} critical)",
            f"- **Peak anomaly confidence:** {round(_coerce_float(incidents.get('highest_confidence')) * 100)}%",
            f"- **Window throughput:** {round(_coerce_float(throughput.get('pps')))} pps · "
            f"{round(_coerce_float(throughput.get('bps')) / 1000, 1)} Kbps across {throughput.get('total_flows', 0)} flows",
        ]

        if by_class:
            lines.append("- **Detections by class:**")
            for threat_class, count in sorted(by_class.items(), key=lambda item: item[1], reverse=True):
                lines.append(f"  - {threat_class}: {count}")
        else:
            lines.append("- No heuristic or isolation-forest anomalies are present in the current window.")

        lines.append(
            "\nAll telemetry crossed a unidirectional diode, so no reverse channel exists for an "
            "adversary to command a compromised host once it is isolated at the switch port."
        )
        return "\n".join(lines)

    def _firewall_rules(self, context: Dict[str, Any]) -> str:
        focus = context.get("focus_alert")
        if not focus:
            return (
                "### Firewall Containment\n\nNo active incident is available to derive a rule from. "
                "Once an alert is raised I can emit an exact internal-side rule."
            )

        analysis = self.service._generate_offline_analysis(focus)
        flow = focus.get("flow_identifier") or {}
        return (
            f"### Firewall Containment — {focus.get('threat_class')}\n\n"
            f"Target flow: `{flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}` "
            f"({flow.get('protocol')})\n\n"
            f"```bash\n{analysis['firewall_mitigation_rule']}\n```\n\n"
            f"**Apply this on the internal side of the diode.** The optical link is one-way, so egress "
            f"suppression is what actually severs the compromised host from its control channel."
        )

    def _explain_incident(self, context: Dict[str, Any]) -> str:
        focus = context.get("focus_alert")
        if not focus:
            return "### Incident Explanation\n\nNo incident is currently logged, so there is nothing to explain."

        analysis = self.service._generate_offline_analysis(focus)
        flow = focus.get("flow_identifier") or {}
        evidence = focus.get("supporting_evidence_feature") or {}

        return (
            f"### Incident {focus.get('alert_id')} — {focus.get('threat_class')}\n\n"
            f"- **Severity:** {analysis['severity_rating']} "
            f"({round(_coerce_float(focus.get('confidence_score')) * 100)}% confidence)\n"
            f"- **Flow:** `{flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}`"
            f" over {flow.get('protocol')}\n"
            f"- **What happened:** {analysis['summary']}\n"
            f"- **Method:** {analysis['attack_vector_breakdown']}\n"
            f"- **Business impact:** {analysis['potential_business_impact']}\n"
            f"- **Analogy for operators:** {evidence.get('reason', 'Not provided')}"
        )

    def _containment_plan(self, context: Dict[str, Any]) -> str:
        focus = context.get("focus_alert")
        if not focus:
            return (
                "### Containment Plan\n\nNothing is currently flagged. Maintain passive monitoring — the "
                "diode already prevents inbound command traffic."
            )

        analysis = self.service._generate_offline_analysis(focus)
        steps = analysis.get("recommended_remediation_steps") or []
        lines = [f"### Containment Plan — {focus.get('threat_class')}", ""]
        for index, step in enumerate(steps, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")
        lines.append("Never reboot industrial controllers to contain a threat; isolate at the network edge instead.")
        return "\n".join(lines)

    def _suggestions(self, context: Dict[str, Any], message: str) -> List[str]:
        """Next-question chips derived from the live context."""
        focus = context.get("focus_alert") or {}
        incidents = context.get("incidents", {})

        suggestions: List[str] = []
        if incidents.get("total"):
            label = focus.get("alert_id") or "the latest incident"
            suggestions.append(f"Explain incident {label}")
            suggestions.append("What should I contain first?")
            suggestions.append("Generate firewall rules")
        else:
            suggestions.append("Summarize threat posture")
            suggestions.append("How does the data diode constrain an attacker?")

        if incidents.get("by_class"):
            top_class = max(incidents["by_class"].items(), key=lambda item: item[1])[0]
            suggestions.append(f"Why was {top_class} flagged?")

        for fallback in DEFAULT_SUGGESTIONS:
            if len(suggestions) >= 4:
                break
            if fallback not in suggestions:
                suggestions.append(fallback)

        return suggestions[:4]

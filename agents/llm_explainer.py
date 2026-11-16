from datetime import datetime, timezone
import json
import logging
import httpx

from config.settings import get_config

logger = logging.getLogger(__name__)


class LLMExplainer:
    """Provides natural-language cybersecurity explanations for detected incidents.

    Communicates with a local Ollama instance on-demand, translating technical
    telemetry, rule triggers, and Isolation Forest anomaly feature vectors into
    accessible, executive- and analyst-friendly plain English.
    """

    def __init__(self, config=None):
        raw_config = config if config is not None else get_config()
        llm_cfg = raw_config.get("llm", {})

        self.provider = llm_cfg.get("provider", "ollama")
        self.model = llm_cfg.get("model", "llama3.2")
        self.base_url = llm_cfg.get("base_url", "http://127.0.0.1:11434").rstrip("/")
        self.timeout_seconds = float(llm_cfg.get("timeout_seconds", 30))

    def explain_incident(
        self,
        incident: dict,
        analysis: dict | None = None,
        decision: dict | None = None,
        model_override: str | None = None
    ) -> dict:
        """Generate a structured, plain-English explanation of an incident.

        Attempts to call the local Ollama LLM. If Ollama is unreachable,
        the model is still downloading, or a timeout occurs, seamlessly falls
        back to high-quality deterministic explanation templates.
        """
        model_to_use = model_override or self.model
        context = self._build_incident_context(incident, analysis, decision)

        try:
            explanation = self._call_ollama(context, model_to_use)
            explanation["source"] = "ollama"
            explanation["model"] = model_to_use
            explanation["generated_at"] = datetime.now(timezone.utc).isoformat()
            return explanation
        except Exception as error:
            logger.warning(
                "Ollama call failed or timed out (%s). Falling back to template explainer.",
                error
            )
            fallback = self._generate_fallback_explanation(incident, analysis, decision, context)
            fallback["source"] = "fallback_engine"
            fallback["model"] = f"deterministic_template (Ollama offline: {error.__class__.__name__})"
            fallback["generated_at"] = datetime.now(timezone.utc).isoformat()
            return fallback

    def _build_incident_context(
        self,
        incident: dict,
        analysis: dict | None,
        decision: dict | None
    ) -> dict:
        """Extract relevant security metrics and features for the prompt."""
        incident_type = incident.get("incident_type", "UNKNOWN_INCIDENT")
        severity = incident.get("severity", "MEDIUM")
        confidence = incident.get("confidence", 0.8)
        sources = incident.get("sources", [])
        targets = incident.get("targets", [])
        detection_methods = incident.get("detection_methods", [])

        # Extract underlying alerts and isolation forest features if present
        payload = incident.get("payload", {})
        alerts = payload.get("alerts", [])
        if not alerts and "alerts" in incident:
            alerts = incident.get("alerts", [])

        anomaly_features = {}
        anomaly_score = None
        has_isolation_forest = False
        rule_reasons = []

        for alert in alerts:
            alert_payload = alert.get("payload", {}) if isinstance(alert, dict) else {}
            method = alert.get("detection_method") or alert_payload.get("detection_method")
            if method == "ISOLATION_FOREST":
                has_isolation_forest = True
                anomaly_score = alert.get("anomaly_score") or alert_payload.get("anomaly_score")
                features = alert.get("features") or alert_payload.get("features", {})
                if features:
                    anomaly_features = features
            elif method == "RULE_BASED":
                reason = alert.get("reason") or alert_payload.get("reason") or alert.get("alert_type")
                if reason:
                    rule_reasons.append(str(reason))

        recommended_action = "MONITOR"
        decision_reason = "No automated action recorded yet."
        if decision:
            recommended_action = decision.get("recommended_action", recommended_action)
            decision_reason = decision.get("reason", decision_reason)

        return {
            "incident_id": incident.get("incident_id"),
            "incident_type": incident_type,
            "severity": severity,
            "confidence": confidence,
            "sources": sources,
            "targets": targets,
            "detection_methods": detection_methods,
            "has_isolation_forest": has_isolation_forest,
            "anomaly_score": anomaly_score,
            "anomaly_features": anomaly_features,
            "rule_reasons": rule_reasons,
            "recommended_action": recommended_action,
            "decision_reason": decision_reason,
            "risk_score": analysis.get("risk_score") if analysis else None,
            "key_findings": analysis.get("key_findings", []) if analysis else []
        }

    def _call_ollama(self, context: dict, model_name: str) -> dict:
        """Query Ollama /api/chat with strict JSON schema instructions."""
        prompt = (
            "You are an expert Security Operations Center (SOC) incident analyst assistant. "
            "Analyze the following security detection telemetry and explain it in clear, "
            "accessible plain English for both technical and non-technical stakeholders.\n\n"
            f"INCIDENT TELEMETRY CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
            "Respond ONLY with a valid JSON object matching this structure (do not wrap in markdown or extra text):\n"
            "{\n"
            '  "summary": "<2-3 sentence plain English overview of what happened>",\n'
            '  "root_cause": "<Clear explanation of the attacker behavior or system anomaly that caused this incident>",\n'
            '  "why_flagged": {\n'
            '    "primary_detector": "<ISOLATION_FOREST, RULE_BASED, or HYBRID>",\n'
            '    "plain_explanation": "<Detailed explanation of why the detector triggered. If Isolation Forest, explain which metrics/distributions diverged from normal baselines. If Rule-based, explain which threshold or signature was crossed>",\n'
            '    "key_signals": ["<Signal 1>", "<Signal 2>", "<Signal 3>"]\n'
            "  },\n"
            '  "why_response_chosen": "<Plain English explanation of why the defensive response action was selected and how it neutralizes the threat>",\n'
            '  "recommended_measures": [\n'
            '    "<Specific mitigation or preventive action 1>",\n'
            '    "<Specific mitigation or preventive action 2>",\n'
            '    "<Specific mitigation or preventive action 3>"\n'
            "  ]\n"
            "}"
        )

        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity AI analyst. Output strictly valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "stream": False,
            "format": "json"
        }

        timeout = httpx.Timeout(self.timeout_seconds, connect=3.0)
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        content = data.get("message", {}).get("content", "").strip()
        parsed = json.loads(content)

        required_keys = ["summary", "root_cause", "why_flagged", "why_response_chosen", "recommended_measures"]
        for key in required_keys:
            if key not in parsed:
                raise ValueError(f"Missing required key '{key}' in Ollama response")

        return parsed

    def _generate_fallback_explanation(
        self,
        incident: dict,
        analysis: dict | None,
        decision: dict | None,
        context: dict
    ) -> dict:
        """Deterministic, rich plain-English explanation used when LLM is unavailable."""
        incident_type = context["incident_type"]
        sources = ", ".join(context["sources"]) or "Unknown source"
        targets = ", ".join(context["targets"]) or "Target system"
        action = context["recommended_action"]
        methods = context["detection_methods"]
        has_ai = context["has_isolation_forest"]
        features = context["anomaly_features"]
        score = context["anomaly_score"]

        # 1. Summary
        if "BRUTE_FORCE" in incident_type:
            summary = (
                f"Repeated unauthorized authentication attempts were detected originating from {sources} "
                f"targeting {targets}. The event frequency indicates an automated credential-guessing attack."
            )
            root_cause = (
                f"An external or unauthorized client at {sources} attempted to gain entry by systematically "
                f"testing credentials against authentication services on {targets}."
            )
        elif "DDOS" in incident_type:
            summary = (
                f"A distributed surge of HTTP traffic was detected from multiple sources ({sources}) "
                f"directed at {targets}, threatening service availability."
            )
            root_cause = (
                "Multiple coordinated endpoints sent an abnormal volume of simultaneous requests "
                "intended to saturate bandwidth and compute capacity."
            )
        elif "PORT_SCAN" in incident_type:
            summary = (
                f"Reconnaissance port probing was detected from {sources} against {targets}. "
                "The source surveyed multiple network ports in rapid succession to discover exposed services."
            )
            root_cause = (
                f"The host {sources} initiated systematic connection requests across varied ports to map out "
                "vulnerabilities and available daemon services."
            )
        elif "PROCESS" in incident_type:
            summary = (
                f"Suspicious host-level process execution was observed on {targets}. "
                "The command line characteristics and process lineage deviate from standard administrative activity."
            )
            root_cause = (
                "A process with unusual arguments or elevated execution privileges was launched, "
                "which may signify unauthorized tooling or lateral movement."
            )
        else:
            summary = (
                f"Anomalous cybersecurity activity ({incident_type}) was identified between {sources} and {targets}. "
                "The security telemetry diverged from established operational baselines."
            )
            root_cause = "Observed telemetry exhibited non-standard behavior patterns inconsistent with normal baseline traffic."

        # 2. Why Flagged
        key_signals = []
        if has_ai:
            primary_detector = "HYBRID" if "RULE_BASED" in methods else "ISOLATION_FOREST"
            score_str = f"score: {score}" if score is not None else "negative anomaly score"
            plain_explanation = (
                f"The Isolation Forest machine-learning model flagged this event window ({score_str}) "
                "because multiple operational metrics sharply diverged from the baseline learned from normal activity."
            )
            if features.get("failed_logins", 0) > 0:
                key_signals.append(f"Failed logins count: {features.get('failed_logins')} (baseline norm is near 0)")
            if features.get("max_failed_logins_per_user", 0) > 0:
                key_signals.append(f"High failure concentration per user: {features.get('max_failed_logins_per_user')}")
            if features.get("http_requests", 0) > 0:
                key_signals.append(f"Spike in HTTP request volume: {features.get('http_requests')}")
            if features.get("unique_destination_ports", 0) > 1:
                key_signals.append(f"Unusual port diversity: {features.get('unique_destination_ports')} distinct ports")
            if features.get("max_command_line_length", 0) > 50:
                key_signals.append(f"Long command line length: {features.get('max_command_line_length')} characters")
            if not key_signals:
                key_signals.append(f"Multivariate feature vector was isolated with an anomaly score of {score}")
        else:
            primary_detector = "RULE_BASED"
            plain_explanation = (
                "Deterministic rule detectors triggered because traffic attributes exceeded predefined safety "
                "thresholds (e.g., attempt counts, connection rates, or suspicious binaries)."
            )
            for reason in context.get("rule_reasons", []):
                key_signals.append(reason)
            if not key_signals:
                key_signals.append(f"Threshold exceeded for {incident_type}")

        # 3. Why Response Chosen
        response_map = {
            "BLOCK_IP": (
                f"The system recommended blocking source IP(s) ({sources}) to immediately sever inbound "
                "malicious traffic, preventing credential compromise and protecting system availability."
            ),
            "RATE_LIMIT_IP": (
                f"Rate limiting was chosen for {sources} to throttle excessive requests while avoiding "
                "hard drops in case of partial legitimate traffic."
            ),
            "TERMINATE_PROCESS": (
                "The suspicious process was slated for termination to halt potential payload execution and "
                "prevent persistence or privilege escalation."
            ),
            "REQUIRE_MFA": (
                "Forced Multi-Factor Authentication was recommended to ensure that credential attempts "
                "cannot succeed without secondary verification."
            ),
            "ISOLATE_HOST": (
                f"Host isolation was recommended for {targets} to quarantine the machine and contain potential "
                "lateral movement across the internal subnet."
            ),
            "MONITOR": (
                "The incident is flagged for close monitoring because current indicators do not yet meet the "
                "confidence threshold required for disruptive automated containment."
            )
        }
        why_response_chosen = response_map.get(
            action,
            f"The action '{action}' was recommended based on incident severity ({context['severity']}) and policy rules."
        )

        # 4. Recommended Measures
        if "BRUTE_FORCE" in incident_type:
            measures = [
                f"Temporarily ban or blacklist source IP {sources} at edge firewalls.",
                "Enforce multi-factor authentication (MFA) and account lockout policies for targeted users.",
                "Audit recent authentication logs to confirm no unauthorized session was established."
            ]
        elif "DDOS" in incident_type:
            measures = [
                "Activate Web Application Firewall (WAF) rate-limiting and DDoS mitigation rules.",
                "Inspect upstream routing to filter suspicious IP subnets before reaching backend servers.",
                "Verify service capacity and autoscaling health on target endpoints."
            ]
        elif "PORT_SCAN" in incident_type:
            measures = [
                f"Block {sources} from scanning internal subnet ranges.",
                "Review perimeter firewall rules to ensure only essential services (e.g., 443, 22) are exposed.",
                "Inspect host logs on scanned ports for unauthorized connection attempts."
            ]
        elif "PROCESS" in incident_type:
            measures = [
                "Isolate the affected workstation/server from the local network.",
                "Inspect memory, persistence mechanisms (scheduled tasks, run keys), and file hashes.",
                "Collect forensic artifact logs and verify integrity of administrative binaries."
            ]
        else:
            measures = [
                "Review correlated alerts and verify whether this behavior matches known maintenance schedules.",
                "Apply progressive access controls to the identified source addresses.",
                "Update baseline anomaly detection thresholds if this activity represents legitimate business traffic."
            ]

        return {
            "summary": summary,
            "root_cause": root_cause,
            "why_flagged": {
                "primary_detector": primary_detector,
                "plain_explanation": plain_explanation,
                "key_signals": key_signals
            },
            "why_response_chosen": why_response_chosen,
            "recommended_measures": measures
        }

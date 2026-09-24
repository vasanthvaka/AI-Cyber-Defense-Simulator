from collections import deque

from agents.analysis_schema import (
    IncidentAnalysis
)

from agents.base_agent import BaseAgent


SEVERITY_BASE_SCORES = {
    "UNKNOWN": 10,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 95
}


class AnalysisAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="ANALYSIS_AGENT"
        )

        self.analysis_history = deque(
            maxlen=1000
        )

        self.analyzed_incident_count = 0

    def handle_message(self, message):

        if message.message_type not in {
            "INCIDENT_CREATED",
            "INCIDENT_UPDATED"
        }:
            raise ValueError(
                "Analysis Agent only accepts "
                "incident messages"
            )

        incident = message.payload.get(
            "incident"
        )

        self._validate_incident(incident)

        analysis = self._analyze_incident(
            incident
        )

        self.analysis_history.append(
            analysis
        )

        self.analyzed_incident_count += 1

        priority = self._priority_from_risk(
            analysis.risk_score
        )

        return self.create_message(
            message_type="ANALYSIS_COMPLETED",
            recipient="DECISION_AGENT",
            payload={
                "analysis": analysis.to_dict(),
                "incident": incident
            },
            correlation_id=(
                incident["incident_id"]
            ),
            priority=priority,
            parent_message_id=message.message_id
        )

    def _analyze_incident(self, incident):

        severity = incident["severity"]
        confidence = incident["confidence"]
        alerts = incident["alerts"]

        detection_methods = sorted(
            set(
                incident.get(
                    "detection_methods",
                    []
                )
            )
        )

        evidence_count = len(alerts)

        risk_score = self._calculate_risk_score(
            severity=severity,
            confidence=confidence,
            evidence_count=evidence_count,
            detection_methods=detection_methods
        )

        key_findings = self._build_findings(
            incident=incident,
            evidence_count=evidence_count,
            detection_methods=detection_methods
        )

        requires_human_review = (
            self._requires_human_review(
                incident=incident,
                confidence=confidence,
                detection_methods=detection_methods
            )
        )

        recommended_escalation = (
            self._recommend_escalation(
                risk_score
            )
        )

        return IncidentAnalysis(
            incident_id=incident[
                "incident_id"
            ],
            incident_type=incident[
                "incident_type"
            ],
            risk_score=risk_score,
            confidence=confidence,
            severity=severity,
            evidence_count=evidence_count,
            detection_methods=(
                detection_methods
            ),
            key_findings=key_findings,
            requires_human_review=(
                requires_human_review
            ),
            recommended_escalation=(
                recommended_escalation
            )
        )

    @staticmethod
    def _calculate_risk_score(
        severity,
        confidence,
        evidence_count,
        detection_methods
    ):

        severity_score = (
            SEVERITY_BASE_SCORES[severity]
        )

        weighted_severity = (
            severity_score * 0.6
        )

        confidence_score = (
            confidence * 30
        )

        evidence_bonus = min(
            max(evidence_count - 1, 0) * 5,
            10
        )

        method_bonus = 0

        if len(detection_methods) > 1:
            method_bonus = 10

        risk_score = (
            weighted_severity
            + confidence_score
            + evidence_bonus
            + method_bonus
        )

        return round(
            min(risk_score, 100),
            2
        )

    @staticmethod
    def _build_findings(
        incident,
        evidence_count,
        detection_methods
    ):

        findings = [
            (
                f"{evidence_count} alert(s) "
                f"support this incident."
            ),
            (
                "Detection methods: "
                + ", ".join(
                    detection_methods
                )
            )
        ]

        source_count = len(
            incident.get(
                "sources",
                []
            )
        )

        target_count = len(
            incident.get(
                "targets",
                []
            )
        )

        findings.append(
            f"{source_count} source entity or "
            f"entities identified."
        )

        findings.append(
            f"{target_count} target entity or "
            f"entities identified."
        )

        if (
            "ISOLATION_FOREST"
            in detection_methods
        ):
            findings.append(
                "Machine-learning anomaly "
                "evidence is present."
            )

        if (
            "RULE_BASED"
            in detection_methods
        ):
            findings.append(
                "A known security rule "
                "matched the activity."
            )

        return findings

    @staticmethod
    def _requires_human_review(
        incident,
        confidence,
        detection_methods
    ):

        ai_only = (
            detection_methods
            == [
                "ISOLATION_FOREST"
            ]
        )

        uncertain_attack_type = (
            incident["incident_type"]
            == "ANOMALOUS_BEHAVIOR"
        )

        low_confidence = confidence < 0.7

        return (
            ai_only
            or uncertain_attack_type
            or low_confidence
        )

    @staticmethod
    def _recommend_escalation(
        risk_score
    ):

        if risk_score >= 85:
            return "IMMEDIATE_RESPONSE"

        if risk_score >= 60:
            return "RESPOND"

        if risk_score >= 35:
            return "INVESTIGATE"

        return "MONITOR"

    @staticmethod
    def _priority_from_risk(risk_score):

        if risk_score >= 85:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 35:
            return "NORMAL"

        return "LOW"

    @staticmethod
    def _validate_incident(incident):

        if not isinstance(incident, dict):
            raise TypeError(
                "Incident payload must be "
                "a dictionary"
            )

        required_fields = {
            "incident_id",
            "incident_type",
            "severity",
            "confidence",
            "alerts",
            "sources",
            "targets"
        }

        missing_fields = (
            required_fields
            - incident.keys()
        )

        if missing_fields:
            missing_names = ", ".join(
                sorted(missing_fields)
            )

            raise ValueError(
                "Incident is missing required "
                f"fields: {missing_names}"
            )

        severity = incident["severity"]

        if severity not in SEVERITY_BASE_SCORES:
            raise ValueError(
                f"Invalid incident severity: "
                f"{severity}"
            )

        confidence = incident["confidence"]

        if not isinstance(
            confidence,
            (int, float)
        ):
            raise TypeError(
                "Incident confidence must "
                "be numeric"
            )

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "Incident confidence must be "
                "between 0 and 1"
            )

        if not isinstance(
            incident["alerts"],
            list
        ):
            raise TypeError(
                "Incident alerts must be a list"
            )

        if not incident["alerts"]:
            raise ValueError(
                "Incident must contain at least "
                "one alert"
            )

        if not isinstance(
            incident["sources"],
            list
        ):
            raise TypeError(
                "Incident sources must be a list"
            )

        if not isinstance(
            incident["targets"],
            list
        ):
            raise TypeError(
                "Incident targets must be a list"
            )
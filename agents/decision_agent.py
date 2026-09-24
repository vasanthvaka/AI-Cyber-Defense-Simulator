from collections import deque

from agents.base_agent import BaseAgent

def decide_response(alert):

    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary")

    attack_type = alert.get("attack_type")
    severity = alert.get("severity", "UNKNOWN")

    if not attack_type:
        raise ValueError(
            "Alert must contain an attack_type"
        )

    if attack_type == "BRUTE_FORCE":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IP",
            "target_type": "IP_ADDRESS",
            "targets": [alert["source_ip"]],
            "automatic": True,
            "reason": (
                "Repeated failed logins were detected "
                "from one source IP."
            )
        }

    if attack_type == "DISTRIBUTED_BRUTE_FORCE":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IPS",
            "target_type": "IP_ADDRESS",
            "targets": alert["source_ips"],
            "automatic": True,
            "reason": (
                "Multiple source IPs are attacking "
                "the same user account."
            )
        }

    if attack_type == "DDOS":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "RATE_LIMIT_IPS",
            "target_type": "IP_ADDRESS",
            "targets": alert["source_ips"],
            "automatic": True,
            "reason": (
                "A high-volume request flood was "
                "detected from multiple sources."
            )
        }

    if attack_type == "PORT_SCAN":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IP",
            "target_type": "IP_ADDRESS",
            "targets": [alert["source_ip"]],
            "automatic": True,
            "reason": (
                "One source IP contacted an unusual "
                "number of destination ports."
            )
        }

    if attack_type == "SUSPICIOUS_PROCESS":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "QUARANTINE_PROCESS",
            "target_type": "PROCESS_ID",
            "targets": [alert["process_id"]],
            "automatic": True,
            "reason": (
                "The process displayed multiple "
                "suspicious execution indicators."
            )
        }

    if attack_type == "ANOMALOUS_BEHAVIOR":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "FLAG_FOR_INVESTIGATION",
            "target_type": "EVENT_WINDOW",
            "targets": alert.get("source_ips", []),
            "automatic": False,
            "reason": (
                "The event window differs from normal "
                "behavior, but the exact attack is unknown."
            )
        }

    return {
        "attack_type": attack_type,
        "severity": severity,
        "recommended_action": "CONTINUE_MONITORING",
        "target_type": "UNKNOWN",
        "targets": [],
        "automatic": False,
        "reason": (
            "No response policy exists for this alert type."
        )
    }

INCIDENT_RESPONSE_POLICIES = {
    "BRUTE_FORCE": {
        "action": "BLOCK_IP",
        "target_entity_type": "IP_ADDRESS",
        "target_type": "IP_ADDRESS"
    },
    "DISTRIBUTED_BRUTE_FORCE": {
        "action": "BLOCK_IPS",
        "target_entity_type": "IP_ADDRESS",
        "target_type": "IP_ADDRESS"
    },
    "DDOS": {
        "action": "RATE_LIMIT_IPS",
        "target_entity_type": "IP_ADDRESS",
        "target_type": "IP_ADDRESS"
    },
    "PORT_SCAN": {
        "action": "BLOCK_IP",
        "target_entity_type": "IP_ADDRESS",
        "target_type": "IP_ADDRESS"
    },
    "SUSPICIOUS_PROCESS": {
        "action": "QUARANTINE_PROCESS",
        "target_entity_type": "PROCESS_ID",
        "target_type": "PROCESS_ID"
    }
}


class DecisionAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="DECISION_AGENT"
        )

        self.decision_history = deque(
            maxlen=1000
        )

        self.decision_count = 0

    def handle_message(self, message):

        if (
            message.message_type
            != "ANALYSIS_COMPLETED"
        ):
            raise ValueError(
                "Decision Agent only accepts "
                "ANALYSIS_COMPLETED messages"
            )

        analysis = message.payload.get(
            "analysis"
        )

        incident = message.payload.get(
            "incident"
        )

        self._validate_analysis(analysis)
        self._validate_incident(incident)

        decision = self._make_decision(
            analysis=analysis,
            incident=incident
        )

        self.decision_history.append(
            decision
        )

        self.decision_count += 1

        return self.create_message(
            message_type="DECISION_CREATED",
            recipient="RESPONSE_AGENT",
            payload={
                "decision": decision,
                "analysis": analysis,
                "incident": incident
            },
            correlation_id=(
                incident["incident_id"]
            ),
            priority=message.priority,
            parent_message_id=message.message_id
        )

    def _make_decision(
        self,
        analysis,
        incident
    ):

        incident_type = incident[
            "incident_type"
        ]

        escalation = analysis[
            "recommended_escalation"
        ]

        requires_human_review = analysis[
            "requires_human_review"
        ]

        confidence = analysis["confidence"]
        risk_score = analysis["risk_score"]

        if escalation == "MONITOR":

            return self._build_decision(
                incident=incident,
                analysis=analysis,
                action="CONTINUE_MONITORING",
                target_type="INCIDENT",
                targets=[],
                automatic=False,
                reason=(
                    "The analysed incident is "
                    "currently below the response "
                    "threshold."
                )
            )

        if (
            escalation == "INVESTIGATE"
            or requires_human_review
        ):

            targets = self._all_source_values(
                incident
            )

            return self._build_decision(
                incident=incident,
                analysis=analysis,
                action="FLAG_FOR_INVESTIGATION",
                target_type="INCIDENT",
                targets=targets,
                automatic=False,
                reason=(
                    "The incident requires analyst "
                    "review before containment."
                )
            )

        policy = INCIDENT_RESPONSE_POLICIES.get(
            incident_type
        )

        if policy is None:

            return self._build_decision(
                incident=incident,
                analysis=analysis,
                action="CONTINUE_MONITORING",
                target_type="INCIDENT",
                targets=[],
                automatic=False,
                reason=(
                    "No automated response policy "
                    "exists for this incident type."
                )
            )

        targets = self._entity_values(
            entities=incident["sources"],
            required_entity_type=(
                policy[
                    "target_entity_type"
                ]
            )
        )

        if not targets:

            return self._build_decision(
                incident=incident,
                analysis=analysis,
                action="FLAG_FOR_INVESTIGATION",
                target_type="INCIDENT",
                targets=[],
                automatic=False,
                reason=(
                    "The incident does not contain "
                    "the target information required "
                    "for an automatic response."
                )
            )

        automatic = confidence >= 0.7

        return self._build_decision(
            incident=incident,
            analysis=analysis,
            action=policy["action"],
            target_type=policy[
                "target_type"
            ],
            targets=targets,
            automatic=automatic,
            reason=(
                f"The analysed {incident_type} "
                f"incident has a risk score of "
                f"{risk_score} and meets the "
                f"configured response policy."
            )
        )

    @staticmethod
    def _build_decision(
        incident,
        analysis,
        action,
        target_type,
        targets,
        automatic,
        reason
    ):

        return {
            "incident_id": incident[
                "incident_id"
            ],
            "attack_type": incident[
                "incident_type"
            ],
            "severity": analysis[
                "severity"
            ],
            "risk_score": analysis[
                "risk_score"
            ],
            "confidence": analysis[
                "confidence"
            ],
            "recommended_action": action,
            "target_type": target_type,
            "targets": list(targets),
            "automatic": automatic,
            "requires_human_review": analysis[
                "requires_human_review"
            ],
            "reason": reason
        }

    @staticmethod
    def _entity_values(
        entities,
        required_entity_type
    ):

        values = []

        for entity in entities:

            if not isinstance(entity, dict):
                continue

            if (
                entity.get("entity_type")
                == required_entity_type
            ):
                value = entity.get("value")

                if (
                    value is not None
                    and value not in values
                ):
                    values.append(value)

        return values

    @staticmethod
    def _all_source_values(incident):

        values = []

        for entity in incident["sources"]:

            if not isinstance(entity, dict):
                continue

            value = entity.get("value")

            if (
                value is not None
                and value not in values
            ):
                values.append(value)

        return values

    @staticmethod
    def _validate_analysis(analysis):

        if not isinstance(analysis, dict):
            raise TypeError(
                "Analysis payload must be "
                "a dictionary"
            )

        required_fields = {
            "risk_score",
            "confidence",
            "severity",
            "requires_human_review",
            "recommended_escalation"
        }

        missing_fields = (
            required_fields
            - analysis.keys()
        )

        if missing_fields:
            missing_names = ", ".join(
                sorted(missing_fields)
            )

            raise ValueError(
                "Analysis is missing required "
                f"fields: {missing_names}"
            )

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
            "sources"
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

        if not isinstance(
            incident["sources"],
            list
        ):
            raise TypeError(
                "Incident sources must be a list"
            )
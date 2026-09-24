import unittest

from agents.analysis_agent import AnalysisAgent
from agents.message_schema import AgentMessage


class TestAnalysisAgent(unittest.TestCase):

    def create_incident(
        self,
        incident_type="PORT_SCAN",
        severity="MEDIUM",
        confidence=1.0,
        alert_count=1,
        detection_methods=None
    ):

        if detection_methods is None:
            detection_methods = [
                "RULE_BASED"
            ]

        alerts = [
            {
                "alert_id":
                    f"alert-{index}",
                "attack_type":
                    incident_type,
                "detection_method":
                    detection_methods[
                        index
                        % len(detection_methods)
                    ]
            }
            for index in range(alert_count)
        ]

        return {
            "incident_id": "incident-123",
            "incident_type": incident_type,
            "severity": severity,
            "confidence": confidence,
            "alerts": alerts,
            "sources": [
                {
                    "entity_type":
                        "IP_ADDRESS",
                    "value":
                        "10.0.2.50"
                }
            ],
            "targets": [
                {
                    "entity_type":
                        "IP_ADDRESS",
                    "value":
                        "192.168.1.100"
                }
            ],
            "detection_methods":
                detection_methods,
            "status": "OPEN"
        }

    def create_incident_message(
        self,
        incident,
        message_type="INCIDENT_CREATED"
    ):

        return AgentMessage(
            message_type=message_type,
            sender="MONITORING_AGENT",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident": incident
            },
            correlation_id=(
                incident.get(
                    "incident_id"
                )
            ),
            priority="HIGH"
        )

    def test_rule_incident_is_analyzed(self):

        agent = AnalysisAgent()

        incident = self.create_incident()

        message = self.create_incident_message(
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            reply.message_type,
            "ANALYSIS_COMPLETED"
        )

        self.assertEqual(
            reply.recipient,
            "DECISION_AGENT"
        )

        self.assertEqual(
            reply.correlation_id,
            "incident-123"
        )

        self.assertEqual(
            reply.parent_message_id,
            message.message_id
        )

        analysis = reply.payload["analysis"]

        self.assertEqual(
            analysis["incident_type"],
            "PORT_SCAN"
        )

        self.assertEqual(
            analysis["risk_score"],
            60.0
        )

        self.assertEqual(
            analysis[
                "recommended_escalation"
            ],
            "RESPOND"
        )

        self.assertFalse(
            analysis[
                "requires_human_review"
            ]
        )

        self.assertEqual(
            reply.priority,
            "HIGH"
        )

        self.assertEqual(
            agent.analyzed_incident_count,
            1
        )

        self.assertEqual(
            len(agent.analysis_history),
            1
        )

    def test_hybrid_detection_increases_risk(self):

        agent = AnalysisAgent()

        incident = self.create_incident(
            alert_count=2,
            detection_methods=[
                "RULE_BASED",
                "ISOLATION_FOREST"
            ]
        )

        message = self.create_incident_message(
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        analysis = reply.payload["analysis"]

        self.assertEqual(
            analysis["risk_score"],
            75.0
        )

        self.assertEqual(
            analysis["evidence_count"],
            2
        )

        self.assertIn(
            "Machine-learning anomaly "
            "evidence is present.",
            analysis["key_findings"]
        )

        self.assertIn(
            "A known security rule "
            "matched the activity.",
            analysis["key_findings"]
        )

    def test_ai_only_incident_requires_review(self):

        agent = AnalysisAgent()

        incident = self.create_incident(
            incident_type=(
                "ANOMALOUS_BEHAVIOR"
            ),
            severity="MEDIUM",
            confidence=0.5,
            detection_methods=[
                "ISOLATION_FOREST"
            ]
        )

        message = self.create_incident_message(
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        analysis = reply.payload["analysis"]

        self.assertEqual(
            analysis["risk_score"],
            45.0
        )

        self.assertTrue(
            analysis[
                "requires_human_review"
            ]
        )

        self.assertEqual(
            analysis[
                "recommended_escalation"
            ],
            "INVESTIGATE"
        )

        self.assertEqual(
            reply.priority,
            "NORMAL"
        )

    def test_critical_incident_requires_immediate_response(
        self
    ):

        agent = AnalysisAgent()

        incident = self.create_incident(
            severity="CRITICAL",
            confidence=1.0
        )

        message = self.create_incident_message(
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        analysis = reply.payload["analysis"]

        self.assertEqual(
            analysis["risk_score"],
            87.0
        )

        self.assertEqual(
            analysis[
                "recommended_escalation"
            ],
            "IMMEDIATE_RESPONSE"
        )

        self.assertEqual(
            reply.priority,
            "CRITICAL"
        )

    def test_low_risk_incident_is_monitored(self):

        agent = AnalysisAgent()

        incident = self.create_incident(
            severity="LOW",
            confidence=0.5
        )

        message = self.create_incident_message(
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        analysis = reply.payload["analysis"]

        self.assertEqual(
            analysis["risk_score"],
            30.0
        )

        self.assertEqual(
            analysis[
                "recommended_escalation"
            ],
            "MONITOR"
        )

        self.assertEqual(
            reply.priority,
            "LOW"
        )

    def test_incident_updated_message_is_accepted(self):

        agent = AnalysisAgent()

        incident = self.create_incident(
            alert_count=2
        )

        message = self.create_incident_message(
            incident=incident,
            message_type="INCIDENT_UPDATED"
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            reply.message_type,
            "ANALYSIS_COMPLETED"
        )

        self.assertEqual(
            reply.payload[
                "analysis"
            ][
                "evidence_count"
            ],
            2
        )

    def test_wrong_message_type_is_rejected(self):

        agent = AnalysisAgent()

        message = AgentMessage(
            message_type="EVENT_OBSERVED",
            sender="COORDINATOR",
            recipient="ANALYSIS_AGENT",
            payload={
                "event": {}
            }
        )

        agent.receive(message)

        with self.assertRaises(ValueError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_non_dictionary_incident_is_rejected(self):

        agent = AnalysisAgent()

        message = AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident":
                    "not-a-dictionary"
            }
        )

        agent.receive(message)

        with self.assertRaises(TypeError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_missing_incident_fields_are_rejected(self):

        agent = AnalysisAgent()

        message = AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident": {
                    "incident_id":
                        "incident-123"
                }
            }
        )

        agent.receive(message)

        with self.assertRaises(ValueError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )


if __name__ == "__main__":
    unittest.main()
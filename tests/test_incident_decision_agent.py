import unittest

from agents.decision_agent import DecisionAgent
from agents.message_schema import AgentMessage


class TestIncidentDecisionAgent(
    unittest.TestCase
):

    def create_analysis(
        self,
        risk_score=75,
        confidence=0.9,
        severity="HIGH",
        requires_human_review=False,
        recommended_escalation="RESPOND"
    ):

        return {
            "analysis_id": "analysis-123",
            "incident_id": "incident-123",
            "incident_type": "PORT_SCAN",
            "risk_score": risk_score,
            "confidence": confidence,
            "severity": severity,
            "evidence_count": 2,
            "detection_methods": [
                "RULE_BASED",
                "ISOLATION_FOREST"
            ],
            "key_findings": [],
            "requires_human_review":
                requires_human_review,
            "recommended_escalation":
                recommended_escalation,
            "analysis_method":
                "DETERMINISTIC",
            "llm_enrichment": None
        }

    def create_incident(
        self,
        incident_type="PORT_SCAN",
        entity_type="IP_ADDRESS",
        entity_value="10.0.2.50"
    ):

        sources = []

        if entity_type is not None:
            sources.append(
                {
                    "entity_type": entity_type,
                    "value": entity_value
                }
            )

        return {
            "incident_id": "incident-123",
            "incident_type": incident_type,
            "severity": "HIGH",
            "confidence": 0.9,
            "sources": sources,
            "targets": [],
            "alerts": [
                {
                    "alert_id": "alert-123"
                }
            ]
        }

    def create_analysis_message(
        self,
        analysis,
        incident
    ):

        return AgentMessage(
            message_type="ANALYSIS_COMPLETED",
            sender="ANALYSIS_AGENT",
            recipient="DECISION_AGENT",
            payload={
                "analysis": analysis,
                "incident": incident
            },
            correlation_id="incident-123",
            priority="HIGH"
        )

    def test_known_incidents_map_to_actions(self):

        scenarios = [
            (
                "BRUTE_FORCE",
                "IP_ADDRESS",
                "10.0.0.50",
                "BLOCK_IP"
            ),
            (
                "DISTRIBUTED_BRUTE_FORCE",
                "IP_ADDRESS",
                "10.0.0.51",
                "BLOCK_IPS"
            ),
            (
                "DDOS",
                "IP_ADDRESS",
                "10.0.1.1",
                "RATE_LIMIT_IPS"
            ),
            (
                "PORT_SCAN",
                "IP_ADDRESS",
                "10.0.2.50",
                "BLOCK_IP"
            ),
            (
                "SUSPICIOUS_PROCESS",
                "PROCESS_ID",
                4321,
                "QUARANTINE_PROCESS"
            )
        ]

        for (
            incident_type,
            entity_type,
            entity_value,
            expected_action
        ) in scenarios:

            with self.subTest(
                incident_type=incident_type
            ):

                agent = DecisionAgent()

                analysis = (
                    self.create_analysis()
                )

                incident = (
                    self.create_incident(
                        incident_type=(
                            incident_type
                        ),
                        entity_type=entity_type,
                        entity_value=entity_value
                    )
                )

                message = (
                    self.create_analysis_message(
                        analysis,
                        incident
                    )
                )

                agent.receive(message)
                reply = agent.process_next()

                decision = reply.payload[
                    "decision"
                ]

                self.assertEqual(
                    decision[
                        "recommended_action"
                    ],
                    expected_action
                )

                self.assertEqual(
                    decision["targets"],
                    [
                        entity_value
                    ]
                )

                self.assertTrue(
                    decision["automatic"]
                )

                self.assertEqual(
                    reply.message_type,
                    "DECISION_CREATED"
                )

                self.assertEqual(
                    reply.recipient,
                    "RESPONSE_AGENT"
                )

    def test_monitor_escalation_continues_monitoring(
        self
    ):

        agent = DecisionAgent()

        analysis = self.create_analysis(
            risk_score=25,
            confidence=0.5,
            severity="LOW",
            recommended_escalation="MONITOR"
        )

        incident = self.create_incident()

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        decision = reply.payload["decision"]

        self.assertEqual(
            decision["recommended_action"],
            "CONTINUE_MONITORING"
        )

        self.assertFalse(
            decision["automatic"]
        )

        self.assertEqual(
            decision["targets"],
            []
        )

    def test_investigation_escalation_is_manual(
        self
    ):

        agent = DecisionAgent()

        analysis = self.create_analysis(
            risk_score=45,
            confidence=0.5,
            severity="MEDIUM",
            requires_human_review=True,
            recommended_escalation=(
                "INVESTIGATE"
            )
        )

        incident = self.create_incident(
            incident_type=(
                "ANOMALOUS_BEHAVIOR"
            )
        )

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        decision = reply.payload["decision"]

        self.assertEqual(
            decision["recommended_action"],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertFalse(
            decision["automatic"]
        )

    def test_human_review_overrides_response(
        self
    ):

        agent = DecisionAgent()

        analysis = self.create_analysis(
            risk_score=75,
            confidence=0.9,
            requires_human_review=True,
            recommended_escalation="RESPOND"
        )

        incident = self.create_incident()

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        decision = reply.payload["decision"]

        self.assertEqual(
            decision["recommended_action"],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertFalse(
            decision["automatic"]
        )

    def test_missing_response_target_requires_review(
        self
    ):

        agent = DecisionAgent()

        analysis = self.create_analysis()

        incident = self.create_incident(
            entity_type=None
        )

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        decision = reply.payload["decision"]

        self.assertEqual(
            decision["recommended_action"],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertEqual(
            decision["targets"],
            []
        )

    def test_unknown_incident_is_monitored(self):

        agent = DecisionAgent()

        analysis = self.create_analysis()

        incident = self.create_incident(
            incident_type="UNKNOWN_ACTIVITY"
        )

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        decision = reply.payload["decision"]

        self.assertEqual(
            decision["recommended_action"],
            "CONTINUE_MONITORING"
        )

        self.assertFalse(
            decision["automatic"]
        )

    def test_decision_history_is_updated(self):

        agent = DecisionAgent()

        analysis = self.create_analysis()
        incident = self.create_incident()

        message = self.create_analysis_message(
            analysis,
            incident
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            agent.decision_count,
            1
        )

        self.assertEqual(
            len(agent.decision_history),
            1
        )

        self.assertEqual(
            agent.decision_history[0],
            reply.payload["decision"]
        )

        self.assertEqual(
            reply.parent_message_id,
            message.message_id
        )

    def test_wrong_message_type_is_rejected(self):

        agent = DecisionAgent()

        message = AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="DECISION_AGENT",
            payload={
                "incident": {}
            }
        )

        agent.receive(message)

        with self.assertRaises(ValueError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_invalid_payloads_are_rejected(self):

        agent = DecisionAgent()

        invalid_analysis_message = AgentMessage(
            message_type="ANALYSIS_COMPLETED",
            sender="ANALYSIS_AGENT",
            recipient="DECISION_AGENT",
            payload={
                "analysis": "invalid",
                "incident": {}
            }
        )

        agent.receive(
            invalid_analysis_message
        )

        with self.assertRaises(TypeError):
            agent.process_next()

        invalid_incident_message = AgentMessage(
            message_type="ANALYSIS_COMPLETED",
            sender="ANALYSIS_AGENT",
            recipient="DECISION_AGENT",
            payload={
                "analysis":
                    self.create_analysis(),
                "incident": "invalid"
            }
        )

        agent.receive(
            invalid_incident_message
        )

        with self.assertRaises(TypeError):
            agent.process_next()


if __name__ == "__main__":
    unittest.main()
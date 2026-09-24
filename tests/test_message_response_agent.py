import unittest

from agents.message_schema import AgentMessage
from agents.response_agent import ResponseAgent


class TestMessageResponseAgent(
    unittest.TestCase
):

    def create_decision(
        self,
        action="BLOCK_IP",
        targets=None,
        automatic=True
    ):

        if targets is None:
            targets = [
                "10.0.2.50"
            ]

        return {
            "incident_id": "incident-123",
            "attack_type": "PORT_SCAN",
            "severity": "HIGH",
            "risk_score": 75,
            "confidence": 0.9,
            "recommended_action": action,
            "target_type": "IP_ADDRESS",
            "targets": targets,
            "automatic": automatic,
            "requires_human_review": (
                not automatic
            ),
            "reason": (
                "The incident meets the "
                "response policy."
            )
        }

    def create_decision_message(
        self,
        decision
    ):

        return AgentMessage(
            message_type="DECISION_CREATED",
            sender="DECISION_AGENT",
            recipient="RESPONSE_AGENT",
            payload={
                "decision": decision
            },
            correlation_id="incident-123",
            priority="HIGH"
        )

    def test_decision_message_executes_response(self):

        agent = ResponseAgent()

        decision = self.create_decision()
        message = self.create_decision_message(
            decision
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            reply.message_type,
            "RESPONSE_EXECUTED"
        )

        self.assertEqual(
            reply.recipient,
            "COORDINATOR"
        )

        self.assertEqual(
            reply.correlation_id,
            "incident-123"
        )

        self.assertEqual(
            reply.parent_message_id,
            message.message_id
        )

        response = reply.payload["response"]

        self.assertEqual(
            response["incident_id"],
            "incident-123"
        )

        self.assertEqual(
            response["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            response["status"],
            "SIMULATED_SUCCESS"
        )

        self.assertIn(
            "10.0.2.50",
            agent.blocked_ips
        )

        self.assertEqual(
            agent.response_message_count,
            1
        )

    def test_investigation_is_queued(self):

        agent = ResponseAgent()

        decision = self.create_decision(
            action="FLAG_FOR_INVESTIGATION",
            automatic=False
        )

        message = self.create_decision_message(
            decision
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            len(agent.investigation_queue),
            1
        )

        investigation = (
            agent.investigation_queue[0]
        )

        self.assertEqual(
            investigation["incident_id"],
            "incident-123"
        )

        self.assertEqual(
            investigation["risk_score"],
            75
        )

        self.assertEqual(
            reply.payload[
                "response"
            ][
                "action"
            ],
            "FLAG_FOR_INVESTIGATION"
        )

    def test_continue_monitoring_changes_no_state(
        self
    ):

        agent = ResponseAgent()

        decision = self.create_decision(
            action="CONTINUE_MONITORING",
            targets=[],
            automatic=False
        )

        message = self.create_decision_message(
            decision
        )

        agent.receive(message)
        reply = agent.process_next()

        response = reply.payload["response"]

        self.assertEqual(
            response["new_targets"],
            []
        )

        self.assertEqual(
            len(agent.blocked_ips),
            0
        )

        self.assertEqual(
            len(agent.rate_limited_ips),
            0
        )

        self.assertEqual(
            len(agent.quarantined_processes),
            0
        )

    def test_duplicate_target_is_not_added_twice(
        self
    ):

        agent = ResponseAgent()

        first_message = (
            self.create_decision_message(
                self.create_decision()
            )
        )

        second_message = (
            self.create_decision_message(
                self.create_decision()
            )
        )

        agent.receive(first_message)
        first_reply = agent.process_next()

        agent.receive(second_message)
        second_reply = agent.process_next()

        self.assertEqual(
            first_reply.payload[
                "response"
            ][
                "new_targets"
            ],
            [
                "10.0.2.50"
            ]
        )

        self.assertEqual(
            second_reply.payload[
                "response"
            ][
                "new_targets"
            ],
            []
        )

        self.assertEqual(
            len(agent.blocked_ips),
            1
        )

    def test_wrong_message_type_is_rejected(self):

        agent = ResponseAgent()

        message = AgentMessage(
            message_type="ANALYSIS_COMPLETED",
            sender="ANALYSIS_AGENT",
            recipient="RESPONSE_AGENT",
            payload={}
        )

        agent.receive(message)

        with self.assertRaises(ValueError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_invalid_decision_payload_is_rejected(
        self
    ):

        agent = ResponseAgent()

        message = AgentMessage(
            message_type="DECISION_CREATED",
            sender="DECISION_AGENT",
            recipient="RESPONSE_AGENT",
            payload={
                "decision": "invalid"
            }
        )

        agent.receive(message)

        with self.assertRaises(TypeError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )


if __name__ == "__main__":
    unittest.main()
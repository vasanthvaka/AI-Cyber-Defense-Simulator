import unittest

from agents.base_agent import BaseAgent
from agents.message_schema import AgentMessage


class EchoAnalysisAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="ANALYSIS_AGENT"
        )

    def handle_message(self, message):

        if message.payload.get("raise_error"):
            raise RuntimeError(
                "Simulated processing failure"
            )

        if message.payload.get("no_reply"):
            return None

        return self.create_message(
            message_type="ANALYSIS_COMPLETED",
            recipient="COORDINATOR",
            payload={
                "received_value":
                    message.payload.get("value")
            },
            correlation_id=message.correlation_id,
            priority=message.priority,
            parent_message_id=message.message_id
        )


class InvalidReturnAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="ANALYSIS_AGENT"
        )

    def handle_message(self, message):

        return {
            "invalid": "reply"
        }


class TestBaseAgent(unittest.TestCase):

    def create_message(
        self,
        value=1,
        **extra_payload
    ):

        payload = {
            "value": value,
            **extra_payload
        }

        return AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="ANALYSIS_AGENT",
            payload=payload,
            correlation_id="incident-123",
            priority="HIGH"
        )

    def test_invalid_agent_name_is_rejected(self):

        with self.assertRaises(ValueError):
            EchoAnalysisAgentWithInvalidName()

    def test_base_agent_cannot_be_created_directly(self):

        with self.assertRaises(TypeError):
            BaseAgent(
                agent_name="ANALYSIS_AGENT"
            )

    def test_non_message_is_rejected(self):

        agent = EchoAnalysisAgent()

        with self.assertRaises(TypeError):
            agent.receive(
                {
                    "message_type":
                        "INCIDENT_CREATED"
                }
            )

    def test_wrong_recipient_is_rejected(self):

        agent = EchoAnalysisAgent()

        message = AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="DECISION_AGENT",
            payload={}
        )

        with self.assertRaises(ValueError):
            agent.receive(message)

    def test_receive_adds_message_to_inbox(self):

        agent = EchoAnalysisAgent()
        message = self.create_message()

        agent.receive(message)

        self.assertEqual(
            len(agent.inbox),
            1
        )

        self.assertEqual(
            message.status,
            "DELIVERED"
        )

    def test_process_message_creates_reply(self):

        agent = EchoAnalysisAgent()
        message = self.create_message(value=25)

        agent.receive(message)
        reply = agent.process_next()

        self.assertEqual(
            message.status,
            "PROCESSED"
        )

        self.assertEqual(
            agent.processed_message_count,
            1
        )

        self.assertEqual(
            reply.message_type,
            "ANALYSIS_COMPLETED"
        )

        self.assertEqual(
            reply.payload["received_value"],
            25
        )

        self.assertEqual(
            reply.parent_message_id,
            message.message_id
        )

        self.assertEqual(
            reply.correlation_id,
            message.correlation_id
        )

        self.assertEqual(
            len(agent.outbox),
            1
        )

    def test_process_all_preserves_fifo_order(self):

        agent = EchoAnalysisAgent()

        first_message = self.create_message(
            value=1
        )

        second_message = self.create_message(
            value=2
        )

        agent.receive(first_message)
        agent.receive(second_message)

        replies = agent.process_all()

        reply_values = [
            reply.payload["received_value"]
            for reply in replies
        ]

        self.assertEqual(
            reply_values,
            [
                1,
                2
            ]
        )

        self.assertEqual(
            agent.processed_message_count,
            2
        )

        self.assertEqual(
            len(agent.inbox),
            0
        )

    def test_empty_inbox_returns_none(self):

        agent = EchoAnalysisAgent()

        self.assertIsNone(
            agent.process_next()
        )

    def test_take_outgoing_message(self):

        agent = EchoAnalysisAgent()
        message = self.create_message()

        agent.receive(message)
        expected_reply = agent.process_next()

        outgoing_message = (
            agent.take_next_outgoing_message()
        )

        self.assertIs(
            outgoing_message,
            expected_reply
        )

        self.assertIsNone(
            agent.take_next_outgoing_message()
        )

    def test_handler_can_return_no_reply(self):

        agent = EchoAnalysisAgent()

        message = self.create_message(
            no_reply=True
        )

        agent.receive(message)
        reply = agent.process_next()

        self.assertIsNone(reply)

        self.assertEqual(
            message.status,
            "PROCESSED"
        )

        self.assertEqual(
            agent.processed_message_count,
            1
        )

        self.assertEqual(
            len(agent.outbox),
            0
        )

    def test_processing_failure_is_recorded(self):

        agent = EchoAnalysisAgent()

        message = self.create_message(
            raise_error=True
        )

        agent.receive(message)

        with self.assertRaises(RuntimeError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

        self.assertEqual(
            agent.failed_message_count,
            1
        )

        self.assertEqual(
            agent.processed_message_count,
            0
        )

    def test_invalid_handler_reply_is_rejected(self):

        agent = InvalidReturnAgent()
        message = self.create_message()

        agent.receive(message)

        with self.assertRaises(TypeError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

        self.assertEqual(
            agent.failed_message_count,
            1
        )


class EchoAnalysisAgentWithInvalidName(
    EchoAnalysisAgent
):

    def __init__(self):

        BaseAgent.__init__(
            self,
            agent_name="UNKNOWN_AGENT"
        )


if __name__ == "__main__":
    unittest.main()
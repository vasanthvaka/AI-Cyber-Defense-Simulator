import unittest

from agents.base_agent import BaseAgent
from agents.message_schema import AgentMessage


class MultipleReplyAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="MONITORING_AGENT"
        )

    def handle_message(self, message):

        first_reply = self.create_message(
            message_type="INCIDENT_CREATED",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident_id": "incident-1"
            },
            correlation_id="incident-1",
            parent_message_id=message.message_id
        )

        second_reply = self.create_message(
            message_type="INCIDENT_UPDATED",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident_id": "incident-2"
            },
            correlation_id="incident-2",
            parent_message_id=message.message_id
        )

        return [
            first_reply,
            second_reply
        ]


class InvalidMultipleReplyAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="MONITORING_AGENT"
        )

    def handle_message(self, message):

        valid_reply = self.create_message(
            message_type="INCIDENT_CREATED",
            recipient="ANALYSIS_AGENT",
            payload={}
        )

        return [
            valid_reply,
            {
                "invalid": "reply"
            }
        ]


class TestBaseAgentMultipleReplies(
    unittest.TestCase
):

    def create_event_message(self):

        return AgentMessage(
            message_type="EVENT_OBSERVED",
            sender="COORDINATOR",
            recipient="MONITORING_AGENT",
            payload={
                "event": {
                    "event_type":
                        "NETWORK_CONNECTION"
                }
            }
        )

    def test_agent_can_return_multiple_messages(self):

        agent = MultipleReplyAgent()
        message = self.create_event_message()

        agent.receive(message)
        replies = agent.process_next()

        self.assertEqual(
            len(replies),
            2
        )

        self.assertEqual(
            len(agent.outbox),
            2
        )

        self.assertEqual(
            message.status,
            "PROCESSED"
        )

        self.assertEqual(
            replies[0].message_type,
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            replies[1].message_type,
            "INCIDENT_UPDATED"
        )

    def test_invalid_item_in_reply_list_fails(self):

        agent = InvalidMultipleReplyAgent()
        message = self.create_event_message()

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

        self.assertEqual(
            len(agent.outbox),
            0
        )


if __name__ == "__main__":
    unittest.main()
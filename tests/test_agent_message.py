import unittest

from agents.message_schema import AgentMessage


class TestAgentMessage(unittest.TestCase):

    def create_valid_message(self):

        return AgentMessage(
            message_type="INCIDENT_CREATED",
            sender="MONITORING_AGENT",
            recipient="ANALYSIS_AGENT",
            payload={
                "incident_id": "incident-123",
                "incident_type": "PORT_SCAN"
            },
            correlation_id="incident-123",
            priority="HIGH"
        )

    def test_create_valid_message(self):

        message = self.create_valid_message()

        self.assertEqual(
            message.message_type,
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            message.sender,
            "MONITORING_AGENT"
        )

        self.assertEqual(
            message.recipient,
            "ANALYSIS_AGENT"
        )

        self.assertEqual(
            message.status,
            "CREATED"
        )

        self.assertTrue(
            message.message_id.startswith(
                "message-"
            )
        )

    def test_message_ids_are_unique(self):

        first_message = self.create_valid_message()
        second_message = self.create_valid_message()

        self.assertNotEqual(
            first_message.message_id,
            second_message.message_id
        )

    def test_invalid_message_type_is_rejected(self):

        with self.assertRaises(ValueError):
            AgentMessage(
                message_type="UNKNOWN_MESSAGE",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={}
            )

    def test_invalid_sender_is_rejected(self):

        with self.assertRaises(ValueError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="UNKNOWN_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={}
            )

    def test_invalid_recipient_is_rejected(self):

        with self.assertRaises(ValueError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="UNKNOWN_AGENT",
                payload={}
            )

    def test_non_dictionary_payload_is_rejected(self):

        with self.assertRaises(TypeError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload=[
                    "incident-123"
                ]
            )

    def test_invalid_priority_is_rejected(self):

        with self.assertRaises(ValueError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={},
                priority="URGENT"
            )

    def test_invalid_status_is_rejected(self):

        with self.assertRaises(ValueError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={},
                status="UNKNOWN"
            )

    def test_message_status_lifecycle(self):

        message = self.create_valid_message()

        message.mark_delivered()

        self.assertEqual(
            message.status,
            "DELIVERED"
        )

        message.mark_processed()

        self.assertEqual(
            message.status,
            "PROCESSED"
        )

        message.mark_failed()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_create_reply_links_messages(self):

        original_message = (
            self.create_valid_message()
        )

        reply = original_message.create_reply(
            message_type="ANALYSIS_COMPLETED",
            sender="ANALYSIS_AGENT",
            recipient="COORDINATOR",
            payload={
                "risk_score": 80
            }
        )

        self.assertEqual(
            reply.correlation_id,
            original_message.correlation_id
        )

        self.assertEqual(
            reply.parent_message_id,
            original_message.message_id
        )

        self.assertEqual(
            reply.priority,
            original_message.priority
        )

        self.assertNotEqual(
            reply.message_id,
            original_message.message_id
        )

    def test_message_converts_to_dictionary(self):

        message = self.create_valid_message()

        message_dictionary = message.to_dict()

        self.assertEqual(
            message_dictionary["message_type"],
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            message_dictionary["correlation_id"],
            "incident-123"
        )

        self.assertEqual(
            message_dictionary["payload"],
            {
                "incident_id": "incident-123",
                "incident_type": "PORT_SCAN"
            }
        )

    def test_invalid_optional_ids_are_rejected(self):

        with self.assertRaises(TypeError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={},
                correlation_id=123
            )

        with self.assertRaises(TypeError):
            AgentMessage(
                message_type="INCIDENT_CREATED",
                sender="MONITORING_AGENT",
                recipient="ANALYSIS_AGENT",
                payload={},
                parent_message_id=123
            )


if __name__ == "__main__":
    unittest.main()
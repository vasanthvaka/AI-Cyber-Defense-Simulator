import unittest
from unittest.mock import patch

from agents.response_agent import ResponseAgent
from monitor import event_monitor


class TestResponsePipeline(unittest.TestCase):

    def setUp(self):

        self.response_agent = ResponseAgent()

    def test_rule_alert_produces_automatic_response(self):

        alert = {
            "attack_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "source_ip": "10.0.2.50"
        }

        with (
            patch.object(
                event_monitor,
                "RESPONSE_AGENT",
                self.response_agent
            ),
            patch.object(
                event_monitor,
                "display_alert"
            ),
            patch.object(
                event_monitor,
                "display_response"
            )
        ):
            result = event_monitor.handle_alert(alert)

        self.assertEqual(
            result["action"],
            "BLOCK_IP"
        )
        self.assertTrue(result["automatic"])
        self.assertIn(
            "10.0.2.50",
            self.response_agent.blocked_ips
        )
        self.assertEqual(
            len(self.response_agent.action_history),
            1
        )

    def test_ai_alert_is_queued_for_investigation(self):

        alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "severity": "MEDIUM",
            "source_ips": [
                "10.0.1.1",
                "192.168.1.20"
            ]
        }

        with (
            patch.object(
                event_monitor,
                "RESPONSE_AGENT",
                self.response_agent
            ),
            patch.object(
                event_monitor,
                "display_alert"
            ),
            patch.object(
                event_monitor,
                "display_response"
            )
        ):
            result = event_monitor.handle_alert(alert)

        self.assertEqual(
            result["action"],
            "FLAG_FOR_INVESTIGATION"
        )
        self.assertFalse(result["automatic"])
        self.assertEqual(
            len(self.response_agent.investigation_queue),
            1
        )
        self.assertEqual(
            self.response_agent.blocked_ips,
            set()
        )
        self.assertEqual(
            self.response_agent.rate_limited_ips,
            set()
        )


if __name__ == "__main__":
    unittest.main()
import unittest
from unittest.mock import patch

from agents.response_agent import ResponseAgent
from alerting.alert_schema import SecurityAlert
from monitor import event_monitor


class TestNormalizedAlertPipeline(unittest.TestCase):

    def setUp(self):

        # Preserve the real shared response agent
        self.original_response_agent = (
            event_monitor.RESPONSE_AGENT
        )

        # Use a fresh response agent for each test
        event_monitor.RESPONSE_AGENT = ResponseAgent()

        # Remove alerts left by earlier tests
        event_monitor.NORMALIZED_ALERTS.clear()

    def tearDown(self):

        # Restore the original response agent
        event_monitor.RESPONSE_AGENT = (
            self.original_response_agent
        )

        event_monitor.NORMALIZED_ALERTS.clear()

    @patch(
        "monitor.event_monitor.display_response"
    )
    @patch(
        "monitor.event_monitor.display_alert"
    )
    def test_rule_alert_enters_normalized_pipeline(
        self,
        mock_display_alert,
        mock_display_response
    ):

        raw_alert = {
            "attack_type": "PORT_SCAN",
            "source_ip": "10.0.2.50",
            "target_ip": "192.168.1.100",
            "ports_scanned": [
                21,
                22,
                80,
                443
            ],
            "unique_port_count": 4,
            "time_window": 10,
            "severity": "MEDIUM"
        }

        response = event_monitor.handle_alert(
            raw_alert
        )

        self.assertEqual(
            len(event_monitor.NORMALIZED_ALERTS),
            1
        )

        normalized_alert = (
            event_monitor.NORMALIZED_ALERTS[0]
        )

        self.assertIsInstance(
            normalized_alert,
            SecurityAlert
        )

        self.assertEqual(
            normalized_alert.attack_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            normalized_alert.detection_method,
            "RULE_BASED"
        )

        self.assertEqual(
            normalized_alert.sources[0].value,
            "10.0.2.50"
        )

        self.assertEqual(
            normalized_alert.targets[0].value,
            "192.168.1.100"
        )

        self.assertEqual(
            response["action"],
            "BLOCK_IP"
        )

        self.assertIn(
            "10.0.2.50",
            event_monitor.RESPONSE_AGENT.blocked_ips
        )

        mock_display_alert.assert_called_once_with(
            raw_alert
        )

        mock_display_response.assert_called_once()


if __name__ == "__main__":
    unittest.main()
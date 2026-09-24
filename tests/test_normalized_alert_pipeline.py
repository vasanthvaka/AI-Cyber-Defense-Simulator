import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent
from alerting.alert_schema import SecurityAlert


class EmptyAIWindowCollector:

    def add_event(self, event):

        return None

    def flush(self):

        return None


class TestNormalizedAlertPipeline(
    unittest.TestCase
):

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_alert_is_normalized(
        self,
        mock_detect_port_scan
    ):

        mock_detect_port_scan.return_value = {
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

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                EmptyAIWindowCollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        responses = coordinator.submit_event(
            {
                "event_type":
                    "NETWORK_CONNECTION"
            }
        )

        self.assertEqual(
            len(
                monitoring_agent
                .normalized_alerts
            ),
            1
        )

        normalized_alert = (
            monitoring_agent
            .normalized_alerts[0]
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
            responses[0]
            .payload["response"]["action"],
            "BLOCK_IP"
        )


if __name__ == "__main__":
    unittest.main()
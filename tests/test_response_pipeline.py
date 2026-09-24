import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent


class FakeAIWindowCollector:

    def __init__(self, alert=None):

        self.alert = alert

    def add_event(self, event):

        return self.alert

    def flush(self):

        return None


class TestResponsePipeline(unittest.TestCase):

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_alert_produces_automatic_response(
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
                FakeAIWindowCollector()
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
            len(responses),
            1
        )

        result = responses[0].payload[
            "response"
        ]

        self.assertEqual(
            result["action"],
            "BLOCK_IP"
        )

        self.assertIn(
            "10.0.2.50",
            coordinator
            .response_agent
            .blocked_ips
        )

    def test_ai_alert_requires_investigation(self):

        ai_alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "detection_method": "ISOLATION_FOREST",
            "severity": "MEDIUM",
            "anomaly_score": -0.06,
            "event_count": 10,
            "source_ips": [
                "10.0.2.50"
            ],
            "features": {}
        }

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector(
                    alert=ai_alert
                )
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        responses = coordinator.submit_event(
            {
                "event_type":
                    "UNKNOWN_EVENT"
            }
        )

        result = responses[0].payload[
            "response"
        ]

        self.assertEqual(
            result["action"],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertEqual(
            len(
                coordinator
                .response_agent
                .investigation_queue
            ),
            1
        )

        self.assertEqual(
            len(
                coordinator
                .response_agent
                .blocked_ips
            ),
            0
        )


if __name__ == "__main__":
    unittest.main()
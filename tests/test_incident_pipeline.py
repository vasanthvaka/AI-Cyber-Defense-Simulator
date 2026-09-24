import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent


class AIAlertCollector:

    def __init__(self, alert):

        self.alert = alert

    def add_event(self, event):

        return self.alert

    def flush(self):

        return None


class TestIncidentPipeline(unittest.TestCase):

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_and_ai_alerts_share_incident(
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

        ai_alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "detection_method": "ISOLATION_FOREST",
            "severity": "MEDIUM",
            "anomaly_score": -0.06,
            "event_count": 10,
            "source_ips": [
                "10.0.2.50"
            ],
            "features": {
                "network_connections": 10,
                "unique_destination_ports": 8
            }
        }

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                AIAlertCollector(ai_alert)
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
            len(monitoring_agent.incidents),
            1
        )

        incident = (
            monitoring_agent.incidents[0]
        )

        self.assertEqual(
            incident.incident_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            len(incident.alerts),
            2
        )

        self.assertEqual(
            incident.detection_methods,
            [
                "ISOLATION_FOREST",
                "RULE_BASED"
            ]
        )

        self.assertEqual(
            len(responses),
            2
        )

        self.assertEqual(
            responses[0].correlation_id,
            responses[1].correlation_id
        )

        self.assertEqual(
            responses[0]
            .payload["response"]["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            responses[1]
            .payload["response"]["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            responses[1]
            .payload["response"]["new_targets"],
            []
        )


if __name__ == "__main__":
    unittest.main()
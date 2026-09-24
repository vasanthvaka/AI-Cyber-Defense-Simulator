import unittest
from unittest.mock import patch

from agents.response_agent import ResponseAgent
from alerting.alert_correlator import AlertCorrelator
from monitor import event_monitor


class TestIncidentPipeline(unittest.TestCase):

    def setUp(self):

        # Preserve the shared production objects
        self.original_response_agent = (
            event_monitor.RESPONSE_AGENT
        )

        self.original_correlator = (
            event_monitor.INCIDENT_CORRELATOR
        )

        # Give this test isolated state
        event_monitor.RESPONSE_AGENT = ResponseAgent()

        event_monitor.INCIDENT_CORRELATOR = (
            AlertCorrelator(
                correlation_window=30
            )
        )

        event_monitor.NORMALIZED_ALERTS.clear()

    def tearDown(self):

        # Restore the production objects
        event_monitor.RESPONSE_AGENT = (
            self.original_response_agent
        )

        event_monitor.INCIDENT_CORRELATOR = (
            self.original_correlator
        )

        event_monitor.NORMALIZED_ALERTS.clear()

    @patch(
        "monitor.event_monitor.display_response"
    )
    @patch(
        "monitor.event_monitor.display_alert"
    )
    def test_rule_and_ai_alert_create_one_incident(
        self,
        mock_display_alert,
        mock_display_response
    ):

        rule_alert = {
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

        event_monitor.handle_alert(rule_alert)
        event_monitor.handle_alert(ai_alert)

        incidents = (
            event_monitor
            .INCIDENT_CORRELATOR
            .incidents
        )

        self.assertEqual(
            len(event_monitor.NORMALIZED_ALERTS),
            2
        )

        self.assertEqual(
            len(incidents),
            1
        )

        incident = incidents[0]

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
            incident.sources[0].value,
            "10.0.2.50"
        )

        self.assertIn(
            "10.0.2.50",
            event_monitor.RESPONSE_AGENT.blocked_ips
        )

        self.assertEqual(
            len(
                event_monitor
                .RESPONSE_AGENT
                .investigation_queue
            ),
            1
        )

        self.assertEqual(
            mock_display_alert.call_count,
            2
        )

        self.assertEqual(
            mock_display_response.call_count,
            2
        )


if __name__ == "__main__":
    unittest.main()
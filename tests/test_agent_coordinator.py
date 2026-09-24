import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent


class FakeAIWindowCollector:

    def __init__(
        self,
        add_event_alert=None,
        flush_alert=None
    ):

        self.add_event_alert = add_event_alert
        self.flush_alert = flush_alert

    def add_event(self, event):

        return self.add_event_alert

    def flush(self):

        return self.flush_alert


class TestAgentCoordinator(unittest.TestCase):

    def create_ai_alert(self):

        return {
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

    def create_port_scan_alert(self):

        return {
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

    def test_ai_incident_runs_complete_pipeline(
        self
    ):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector(
                    add_event_alert=(
                        self.create_ai_alert()
                    )
                )
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        event = {
            "event_type": "UNKNOWN_EVENT"
        }

        responses = coordinator.submit_event(
            event
        )

        self.assertEqual(
            len(responses),
            1
        )

        response_message = responses[0]
        response = response_message.payload[
            "response"
        ]

        self.assertEqual(
            response[
                "action"
            ],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertFalse(
            response["automatic"]
        )

        self.assertEqual(
            len(
                coordinator
                .response_agent
                .investigation_queue
            ),
            1
        )

        incident_id = (
            response_message.correlation_id
        )

        trace = coordinator.get_message_trace(
            incident_id
        )

        self.assertEqual(
            [
                message.message_type
                for message in trace
            ],
            [
                "INCIDENT_CREATED",
                "ANALYSIS_COMPLETED",
                "DECISION_CREATED",
                "RESPONSE_EXECUTED"
            ]
        )

        self.assertEqual(
            trace[1].parent_message_id,
            trace[0].message_id
        )

        self.assertEqual(
            trace[2].parent_message_id,
            trace[1].message_id
        )

        self.assertEqual(
            trace[3].parent_message_id,
            trace[2].message_id
        )

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_incident_runs_automatic_response(
        self,
        mock_detect_port_scan
    ):

        mock_detect_port_scan.return_value = (
            self.create_port_scan_alert()
        )

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        event = {
            "event_type":
                "NETWORK_CONNECTION"
        }

        responses = coordinator.submit_event(
            event
        )

        self.assertEqual(
            len(responses),
            1
        )

        response = responses[0].payload[
            "response"
        ]

        self.assertEqual(
            response["action"],
            "BLOCK_IP"
        )

        self.assertTrue(
            response["automatic"]
        )

        self.assertIn(
            "10.0.2.50",
            coordinator
            .response_agent
            .blocked_ips
        )

    def test_normal_event_produces_no_response(self):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        event = {
            "event_type": "UNKNOWN_EVENT"
        }

        responses = coordinator.submit_event(
            event
        )

        self.assertEqual(
            responses,
            []
        )

        self.assertEqual(
            coordinator.submitted_event_count,
            1
        )

        self.assertEqual(
            coordinator.routed_message_count,
            1
        )

        self.assertEqual(
            len(coordinator.message_queue),
            0
        )

        self.assertEqual(
            coordinator
            .message_history[0]
            .status,
            "PROCESSED"
        )

    def test_flush_routes_final_ai_alert(self):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector(
                    flush_alert=(
                        self.create_ai_alert()
                    )
                )
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        responses = (
            coordinator.flush_ai_window()
        )

        self.assertEqual(
            len(responses),
            1
        )

        self.assertEqual(
            responses[0]
            .payload["response"]["action"],
            "FLAG_FOR_INVESTIGATION"
        )

    def test_unknown_trace_is_empty(self):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        self.assertEqual(
            coordinator.get_message_trace(
                "incident-does-not-exist"
            ),
            []
        )

    def test_invalid_event_is_rejected(self):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        with self.assertRaises(TypeError):
            coordinator.submit_event(
                "invalid-event"
            )

    def test_processing_failure_is_recorded(self):

        malformed_alert = {
            "severity": "HIGH"
        }

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector(
                    add_event_alert=(
                        malformed_alert
                    )
                )
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        with self.assertRaises(ValueError):
            coordinator.submit_event(
                {
                    "event_type":
                        "UNKNOWN_EVENT"
                }
            )

        self.assertEqual(
            len(coordinator.failed_messages),
            1
        )

        self.assertIn(
            "attack_type",
            coordinator
            .failed_messages[0]["error"]
        )

    def test_invalid_message_limit_is_rejected(
        self
    ):

        with self.assertRaises(TypeError):
            AgentCoordinator(
                max_messages_per_run="100"
            )

        with self.assertRaises(ValueError):
            AgentCoordinator(
                max_messages_per_run=0
            )


if __name__ == "__main__":
    unittest.main()
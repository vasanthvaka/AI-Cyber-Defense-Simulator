import unittest
from unittest.mock import patch

from agents.message_schema import AgentMessage
from agents.monitoring_agent import MonitoringAgent


class FakeAIWindowCollector:

    def __init__(
        self,
        add_event_alert=None,
        flush_alert=None
    ):

        self.add_event_alert = add_event_alert
        self.flush_alert = flush_alert
        self.received_events = []

    def add_event(self, event):

        self.received_events.append(event)
        return self.add_event_alert

    def flush(self):

        return self.flush_alert


class TestMonitoringAgent(unittest.TestCase):

    def create_event_message(self, event):

        return AgentMessage(
            message_type="EVENT_OBSERVED",
            sender="COORDINATOR",
            recipient="MONITORING_AGENT",
            payload={
                "event": event
            }
        )

    def create_port_scan_alert(
        self,
        severity="MEDIUM"
    ):

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
            "severity": severity
        }

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

    def test_normal_event_is_observed_and_logged(self):

        logged_events = []

        fake_collector = FakeAIWindowCollector()

        agent = MonitoringAgent(
            ai_window_collector=fake_collector,
            event_logger=logged_events.append
        )

        event = {
            "event_type": "UNKNOWN_EVENT",
            "value": 1
        }

        message = self.create_event_message(
            event
        )

        agent.receive(message)
        result = agent.process_next()

        self.assertIsNone(result)

        self.assertEqual(
            agent.observed_event_count,
            1
        )

        self.assertEqual(
            logged_events,
            [
                event
            ]
        )

        self.assertEqual(
            fake_collector.received_events,
            [
                event
            ]
        )

        self.assertEqual(
            len(agent.incidents),
            0
        )

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_alert_creates_incident_message(
        self,
        mock_detect_port_scan
    ):

        mock_detect_port_scan.return_value = (
            self.create_port_scan_alert(
                severity="HIGH"
            )
        )

        agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        event = {
            "event_type":
                "NETWORK_CONNECTION"
        }

        incoming_message = (
            self.create_event_message(event)
        )

        agent.receive(incoming_message)
        replies = agent.process_next()

        self.assertEqual(
            len(replies),
            1
        )

        reply = replies[0]

        self.assertEqual(
            reply.message_type,
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            reply.recipient,
            "ANALYSIS_AGENT"
        )

        self.assertEqual(
            reply.priority,
            "HIGH"
        )

        self.assertEqual(
            reply.parent_message_id,
            incoming_message.message_id
        )

        self.assertEqual(
            reply.payload[
                "incident"
            ][
                "incident_type"
            ],
            "PORT_SCAN"
        )

        self.assertEqual(
            len(agent.raw_alerts),
            1
        )

        self.assertEqual(
            len(agent.normalized_alerts),
            1
        )

        self.assertEqual(
            len(agent.incidents),
            1
        )

    def test_ai_alert_creates_incident_message(self):

        fake_collector = FakeAIWindowCollector(
            add_event_alert=(
                self.create_ai_alert()
            )
        )

        agent = MonitoringAgent(
            ai_window_collector=fake_collector
        )

        event = {
            "event_type": "UNKNOWN_EVENT"
        }

        message = self.create_event_message(
            event
        )

        agent.receive(message)
        replies = agent.process_next()

        self.assertEqual(
            len(replies),
            1
        )

        reply = replies[0]

        self.assertEqual(
            reply.message_type,
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            reply.payload[
                "incident"
            ][
                "incident_type"
            ],
            "ANOMALOUS_BEHAVIOR"
        )

        self.assertEqual(
            reply.correlation_id,
            agent.incidents[0].incident_id
        )

    @patch(
        "agents.monitoring_agent.detect_port_scan"
    )
    def test_rule_and_ai_alerts_are_correlated(
        self,
        mock_detect_port_scan
    ):

        mock_detect_port_scan.return_value = (
            self.create_port_scan_alert()
        )

        fake_collector = FakeAIWindowCollector(
            add_event_alert=(
                self.create_ai_alert()
            )
        )

        agent = MonitoringAgent(
            ai_window_collector=fake_collector
        )

        event = {
            "event_type":
                "NETWORK_CONNECTION"
        }

        message = self.create_event_message(
            event
        )

        agent.receive(message)
        replies = agent.process_next()

        self.assertEqual(
            len(replies),
            2
        )

        self.assertEqual(
            replies[0].message_type,
            "INCIDENT_CREATED"
        )

        self.assertEqual(
            replies[1].message_type,
            "INCIDENT_UPDATED"
        )

        self.assertEqual(
            replies[0].correlation_id,
            replies[1].correlation_id
        )

        self.assertEqual(
            len(agent.incidents),
            1
        )

        incident = agent.incidents[0]

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
            len(agent.outbox),
            2
        )

    def test_flush_creates_ai_incident_message(self):

        fake_collector = FakeAIWindowCollector(
            flush_alert=self.create_ai_alert()
        )

        agent = MonitoringAgent(
            ai_window_collector=fake_collector
        )

        replies = agent.flush_ai_window()

        self.assertEqual(
            len(replies),
            1
        )

        self.assertEqual(
            replies[0].message_type,
            "INCIDENT_CREATED"
        )

        self.assertIsNone(
            replies[0].parent_message_id
        )

        self.assertEqual(
            len(agent.outbox),
            1
        )

        self.assertEqual(
            len(agent.incidents),
            1
        )

    def test_empty_flush_returns_no_messages(self):

        agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        replies = agent.flush_ai_window()

        self.assertEqual(
            replies,
            []
        )

        self.assertEqual(
            len(agent.outbox),
            0
        )

    def test_wrong_message_type_is_rejected(self):

        agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        message = AgentMessage(
            message_type="ALERT_CREATED",
            sender="COORDINATOR",
            recipient="MONITORING_AGENT",
            payload={}
        )

        agent.receive(message)

        with self.assertRaises(ValueError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )

    def test_missing_event_dictionary_is_rejected(self):

        agent = MonitoringAgent(
            ai_window_collector=(
                FakeAIWindowCollector()
            )
        )

        message = AgentMessage(
            message_type="EVENT_OBSERVED",
            sender="COORDINATOR",
            recipient="MONITORING_AGENT",
            payload={
                "event": "not-a-dictionary"
            }
        )

        agent.receive(message)

        with self.assertRaises(TypeError):
            agent.process_next()

        self.assertEqual(
            message.status,
            "FAILED"
        )


if __name__ == "__main__":
    unittest.main()
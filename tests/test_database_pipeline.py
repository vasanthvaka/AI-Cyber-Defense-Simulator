import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent
from storage.database import SecurityDatabase


class EmptyAIWindowCollector:

    def add_event(self, event):

        return None

    def flush(self):

        return None


class TestDatabasePipeline(unittest.TestCase):

    def setUp(self):

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        database_path = (
            Path(self.temp_directory.name)
            / "pipeline_test.db"
        )

        self.database = SecurityDatabase(
            database_path
        )

        self.monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                EmptyAIWindowCollector()
            )
        )

        self.coordinator = AgentCoordinator(
            monitoring_agent=(
                self.monitoring_agent
            ),
            database=self.database
        )

    def tearDown(self):

        self.temp_directory.cleanup()

    @patch(
        "agents.monitoring_agent."
        "detect_port_scan"
    )
    def test_completed_pipeline_is_persisted(
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

        event = {
            "event_type": (
                "NETWORK_CONNECTION"
            ),
            "timestamp": "10:00:00",
            "source_ip": "10.0.2.50",
            "target_ip": "192.168.1.100",
            "destination_port": 443,
            "protocol": "TCP",
            "connection_status": "OPEN"
        }

        responses = (
            self.coordinator.submit_event(
                event
            )
        )

        self.assertEqual(
            len(responses),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "events"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "alerts"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "incidents"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "analyses"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "decisions"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "responses"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "audit_records"
            ),
            1
        )

        response_payload = (
            responses[0].payload
        )

        incident_id = response_payload[
            "incident"
        ]["incident_id"]

        stored_incident = (
            self.database.get_record(
                "incidents",
                incident_id
            )
        )

        self.assertEqual(
            stored_incident[
                "incident_type"
            ],
            "PORT_SCAN"
        )

        self.assertEqual(
            stored_incident[
                "payload"
            ]["incident_id"],
            incident_id
        )

        stored_responses = (
            self.database.get_records(
                "responses"
            )
        )

        self.assertEqual(
            stored_responses[0]["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            stored_responses[0][
                "payload"
            ]["policy_status"],
            "ALLOWED"
        )

    def test_event_without_alert_is_still_persisted(
        self
    ):

        event = {
            "event_type": "UNKNOWN_EVENT",
            "timestamp": "10:00:00"
        }

        responses = (
            self.coordinator.submit_event(
                event
            )
        )

        self.assertEqual(
            responses,
            []
        )

        self.assertEqual(
            self.database.count_records(
                "events"
            ),
            1
        )

        self.assertEqual(
            self.database.count_records(
                "incidents"
            ),
            0
        )

        self.assertEqual(
            self.database.count_records(
                "responses"
            ),
            0
        )


if __name__ == "__main__":
    unittest.main()
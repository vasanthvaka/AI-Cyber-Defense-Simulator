import json
import tempfile
import unittest
from pathlib import Path

from detector.dataset_builder import (
    load_events,
    build_feature_dataset
)


class TestDatasetBuilder(unittest.TestCase):

    def test_load_events(self):

        sample_events = [
            {
                "timestamp": "10:00:00",
                "event_type": "LOGIN_ATTEMPT",
                "source_ip": "192.168.1.10",
                "status": "SUCCESS"
            },
            {
                "timestamp": "10:00:01",
                "event_type": "HTTP_REQUEST",
                "source_ip": "192.168.1.20",
                "endpoint": "/home"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_directory:

            log_file = Path(temp_directory) / "events.jsonl"

            with open(log_file, "w", encoding="utf-8") as file:
                for event in sample_events:
                    file.write(json.dumps(event) + "\n")

            loaded_events = load_events(log_file)

        self.assertEqual(loaded_events, sample_events)

    def test_build_feature_dataset(self):

        events = [
            {
                "timestamp": "10:00:00",
                "event_type": "LOGIN_ATTEMPT",
                "source_ip": "192.168.1.10",
                "status": "FAILED"
            },
            {
                "timestamp": "10:00:01",
                "event_type": "HTTP_REQUEST",
                "source_ip": "192.168.1.20",
                "endpoint": "/login"
            },
            {
                "timestamp": "10:00:05",
                "event_type": "NETWORK_CONNECTION",
                "source_ip": "192.168.1.30",
                "destination_port": 80
            }
        ]

        dataset = build_feature_dataset(
            events,
            window_size=5
        )

        expected_dataset = [
            [
                2,  # total_events
                1,  # login_attempts
                1,  # failed_logins
                2,  # unique_source_ips
                1,  # http_requests
                1,  # unique_http_endpoints
                0,  # network_connections
                0,  # unique_destination_ports
                0,  # process_activities
                0   # unique_process_names
            ],
            [
                1,  # total_events
                0,  # login_attempts
                0,  # failed_logins
                1,  # unique_source_ips
                0,  # http_requests
                0,  # unique_http_endpoints
                1,  # network_connections
                1,  # unique_destination_ports
                0,  # process_activities
                0   # unique_process_names
            ]
        ]

        self.assertEqual(dataset, expected_dataset)


if __name__ == "__main__":
    unittest.main()
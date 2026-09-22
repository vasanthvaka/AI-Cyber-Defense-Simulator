import unittest

from detector.feature_extractor import (
    extract_window_features,
    features_to_vector
)


class TestFeatureExtractor(unittest.TestCase):

    def test_extract_window_features(self):

        events = [
            {
                "event_type": "LOGIN_ATTEMPT",
                "source_ip": "192.168.1.10",
                "username": "admin",
                "status": "FAILED"
            },
            {
                "event_type": "LOGIN_ATTEMPT",
                "source_ip": "192.168.1.10",
                "username": "admin",
                "status": "SUCCESS"
            },
            {
                "event_type": "HTTP_REQUEST",
                "source_ip": "192.168.1.20",
                "target_service": "web-server",
                "endpoint": "/login",
                "method": "GET"
            },
            {
                "event_type": "NETWORK_CONNECTION",
                "source_ip": "10.0.2.50",
                "destination_port": 80
            },
            {
                "event_type": "NETWORK_CONNECTION",
                "source_ip": "10.0.2.50",
                "destination_port": 443
            },
            {
                "event_type": "PROCESS_ACTIVITY",
                "process_name": "chrome.exe"
            },
            {
                "event_type": "PROCESS_ACTIVITY",
                "process_name": "chrome.exe"
            }
        ]

        features = extract_window_features(events)

        expected_features = {
            "total_events": 7,
            "login_attempts": 2,
            "failed_logins": 1,
            "unique_source_ips": 3,
            "http_requests": 1,
            "unique_http_endpoints": 1,
            "network_connections": 2,
            "unique_destination_ports": 2,
            "process_activities": 2,
            "unique_process_names": 1,
            "max_failed_logins_per_user": 1,
            "max_http_requests_per_source_ip": 1,
            "max_http_requests_per_target_service": 1,
            "max_http_requests_per_endpoint": 1,
            "max_ports_per_source_ip": 2,
            "max_command_line_length": 0
        }

        self.assertEqual(
            features,
            expected_features
        )

        feature_vector = features_to_vector(features)

        expected_vector = [
            7,  # total_events
            2,  # login_attempts
            1,  # failed_logins
            3,  # unique_source_ips
            1,  # http_requests
            1,  # unique_http_endpoints
            2,  # network_connections
            2,  # unique_destination_ports
            2,  # process_activities
            1,  # unique_process_names
            1,  # max_failed_logins_per_user
            1,  # max_http_requests_per_source_ip
            1,  # max_http_requests_per_target_service
            1,  # max_http_requests_per_endpoint
            2,  # max_ports_per_source_ip
            0   # max_command_line_length
        ]

        self.assertEqual(
            feature_vector,
            expected_vector
        )


if __name__ == "__main__":
    unittest.main()
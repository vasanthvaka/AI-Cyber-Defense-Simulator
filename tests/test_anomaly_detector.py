import unittest
from unittest.mock import Mock, patch

from detector.anomaly_detector import detect_anomaly


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):

        self.events = [
            {
                "event_type": "LOGIN_ATTEMPT",
                "timestamp": "10:00:00",
                "source_ip": "10.0.0.50",
                "username": "admin",
                "status": "FAILED"
            },
            {
                "event_type": "LOGIN_ATTEMPT",
                "timestamp": "10:00:01",
                "source_ip": "10.0.0.51",
                "username": "admin",
                "status": "FAILED"
            }
        ]

    @patch(
        "detector.anomaly_detector.load_anomaly_model"
    )
    def test_anomalous_window_returns_alert(
        self,
        mock_load_model
    ):

        mock_model = Mock()

        mock_model.predict.return_value = [-1]

        mock_model.decision_function.return_value = [
            -0.12345
        ]

        mock_load_model.return_value = {
            "model": mock_model
        }

        alert = detect_anomaly(self.events)

        self.assertIsNotNone(alert)

        self.assertEqual(
            alert["attack_type"],
            "ANOMALOUS_BEHAVIOR"
        )

        self.assertEqual(
            alert["detection_method"],
            "ISOLATION_FOREST"
        )

        self.assertEqual(
            alert["anomaly_score"],
            -0.1235
        )

        self.assertEqual(
            alert["event_count"],
            2
        )

        self.assertEqual(
            alert["source_ips"],
            ["10.0.0.50", "10.0.0.51"]
        )

    @patch(
        "detector.anomaly_detector.load_anomaly_model"
    )
    def test_normal_window_returns_none(
        self,
        mock_load_model
    ):

        mock_model = Mock()

        mock_model.predict.return_value = [1]

        mock_model.decision_function.return_value = [
            0.1523
        ]

        mock_load_model.return_value = {
            "model": mock_model
        }

        alert = detect_anomaly(self.events)

        self.assertIsNone(alert)

    def test_empty_window_returns_none(self):

        alert = detect_anomaly([])

        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
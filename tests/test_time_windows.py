import unittest
from unittest.mock import patch

from detector import brute_force_detector
from detector import ddos_detector
from detector import port_scan_detector


class TestTimeWindowsAndCooldowns(unittest.TestCase):

    def setUp(self):

        brute_force_detector.failed_attempts_by_ip.clear()
        brute_force_detector.failed_attempts_by_username.clear()
        brute_force_detector.flagged_ips.clear()
        brute_force_detector.flagged_usernames.clear()

        ddos_detector.requests_by_target.clear()
        ddos_detector.flagged_targets.clear()

        port_scan_detector.connection_attempts.clear()
        port_scan_detector.flagged_scanners.clear()

    def create_login_event(self):

        return {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "12:00:00",
            "source_ip": "10.0.0.50",
            "username": "admin",
            "status": "FAILED"
        }

    def create_http_event(self, ip):

        return {
            "event_type": "HTTP_REQUEST",
            "timestamp": "12:00:00",
            "source_ip": ip,
            "target_service": "web-server",
            "endpoint": "/login",
            "method": "GET"
        }

    def create_connection_event(self, port):

        return {
            "event_type": "NETWORK_CONNECTION",
            "timestamp": "12:00:00",
            "source_ip": "10.0.2.50",
            "target_ip": "192.168.1.100",
            "destination_port": port,
            "protocol": "TCP",
            "connection_status": "CLOSED"
        }

    def test_slow_login_failures_do_not_trigger_alert(self):

        timestamps = [
            0,
            3,
            6,
            9,
            12
        ]

        with patch.object(
            brute_force_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            alert = None

            for _ in range(5):
                event = self.create_login_event()

                alert = (
                    brute_force_detector.detect_brute_force(
                        event
                    )
                )

        self.assertIsNone(alert)

    def test_brute_force_alerts_again_after_cooldown(self):

        timestamps = [
            0, 1, 2, 3, 4,
            20, 21, 22, 23, 24
        ]

        with patch.object(
            brute_force_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            first_alert = None
            second_alert = None

            for i in range(10):
                event = self.create_login_event()

                alert = (
                    brute_force_detector.detect_brute_force(
                        event
                    )
                )

                if i == 4:
                    first_alert = alert

                if i == 9:
                    second_alert = alert

        self.assertIsNotNone(first_alert)
        self.assertIsNotNone(second_alert)
        self.assertEqual(
            first_alert["attack_type"],
            "BRUTE_FORCE"
        )
        self.assertEqual(
            second_alert["attack_type"],
            "BRUTE_FORCE"
        )

    def test_slow_http_requests_do_not_trigger_alert(self):

        timestamps = [
            i * 0.25
            for i in range(15)
        ]

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        with patch.object(
            ddos_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            alert = None

            for i in range(15):
                event = self.create_http_event(
                    source_ips[i % len(source_ips)]
                )

                alert = ddos_detector.detect_ddos(event)

        self.assertIsNone(alert)

    def test_ddos_alerts_again_after_cooldown(self):

        first_burst = [
            i * 0.05
            for i in range(15)
        ]

        second_burst = [
            20 + (i * 0.05)
            for i in range(15)
        ]

        timestamps = first_burst + second_burst

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        with patch.object(
            ddos_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            first_alert = None
            second_alert = None

            for i in range(30):
                event = self.create_http_event(
                    source_ips[i % len(source_ips)]
                )

                alert = ddos_detector.detect_ddos(event)

                if i == 14:
                    first_alert = alert

                if i == 29:
                    second_alert = alert

        self.assertIsNotNone(first_alert)
        self.assertIsNotNone(second_alert)
        self.assertEqual(
            first_alert["attack_type"],
            "DDOS"
        )
        self.assertEqual(
            second_alert["attack_type"],
            "DDOS"
        )

    def test_slow_port_attempts_do_not_trigger_alert(self):

        timestamps = list(range(10))

        with patch.object(
            port_scan_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            alert = None

            for port in range(20, 30):
                event = self.create_connection_event(port)

                alert = port_scan_detector.detect_port_scan(
                    event
                )

        self.assertIsNone(alert)

    def test_port_scan_alerts_again_after_cooldown(self):

        first_scan = [
            i * 0.1
            for i in range(10)
        ]

        second_scan = [
            20 + (i * 0.1)
            for i in range(10)
        ]

        timestamps = first_scan + second_scan

        with patch.object(
            port_scan_detector,
            "datetime"
        ) as mock_datetime:

            mock_datetime.now.return_value.timestamp.side_effect = (
                timestamps
            )

            first_alert = None
            second_alert = None

            for i in range(20):

                port = 20 + (i % 10)

                event = self.create_connection_event(port)

                alert = port_scan_detector.detect_port_scan(
                    event
                )

                if i == 9:
                    first_alert = alert

                if i == 19:
                    second_alert = alert

        self.assertIsNotNone(first_alert)
        self.assertIsNotNone(second_alert)
        self.assertEqual(
            first_alert["attack_type"],
            "PORT_SCAN"
        )
        self.assertEqual(
            second_alert["attack_type"],
            "PORT_SCAN"
        )


if __name__ == "__main__":
    unittest.main()
import unittest

from detector import port_scan_detector as detector


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):

        detector.connection_attempts.clear()
        detector.flagged_scanners.clear()

    def create_event(
        self,
        port,
        source_ip="10.0.2.50",
        target_ip="192.168.1.100"
    ):

        return {
            "event_type": "NETWORK_CONNECTION",
            "timestamp": "12:00:00",
            "source_ip": source_ip,
            "target_ip": target_ip,
            "destination_port": port,
            "protocol": "TCP",
            "connection_status": "CLOSED"
        }

    def test_nine_unique_ports_do_not_trigger_alert(self):

        alert = None

        for port in range(20, 29):
            event = self.create_event(port)
            alert = detector.detect_port_scan(event)

        self.assertIsNone(alert)

    def test_ten_unique_ports_trigger_alert(self):

        alert = None

        for port in range(20, 30):
            event = self.create_event(port)
            alert = detector.detect_port_scan(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["attack_type"],
            "PORT_SCAN"
        )
        self.assertEqual(
            alert["source_ip"],
            "10.0.2.50"
        )
        self.assertEqual(
            alert["target_ip"],
            "192.168.1.100"
        )
        self.assertEqual(
            alert["unique_port_count"],
            10
        )

    def test_repeated_same_port_does_not_trigger_alert(self):

        alert = None

        for _ in range(15):
            event = self.create_event(port=443)
            alert = detector.detect_port_scan(event)

        self.assertIsNone(alert)

    def test_different_targets_are_tracked_separately(self):

        alert = None

        for port in range(20, 25):

            first_target_event = self.create_event(
                port=port,
                target_ip="192.168.1.100"
            )

            second_target_event = self.create_event(
                port=port,
                target_ip="192.168.1.101"
            )

            first_alert = detector.detect_port_scan(
                first_target_event
            )

            second_alert = detector.detect_port_scan(
                second_target_event
            )

            if first_alert:
                alert = first_alert

            if second_alert:
                alert = second_alert

        self.assertIsNone(alert)

    def test_duplicate_alert_is_suppressed_during_cooldown(self):

        first_alert = None

        for port in range(20, 30):
            event = self.create_event(port)
            first_alert = detector.detect_port_scan(event)

        repeated_event = self.create_event(port=30)

        repeated_alert = detector.detect_port_scan(
            repeated_event
        )

        self.assertIsNotNone(first_alert)
        self.assertIsNone(repeated_alert)


if __name__ == "__main__":
    unittest.main()
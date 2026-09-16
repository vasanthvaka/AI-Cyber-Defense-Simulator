import unittest

from detector import ddos_detector as detector


class TestDDoSDetector(unittest.TestCase):

    def setUp(self):

        detector.requests_by_target.clear()
        detector.flagged_targets.clear()

    def create_event(
        self,
        ip="10.0.1.1",
        endpoint="/login"
    ):

        return {
            "event_type": "HTTP_REQUEST",
            "timestamp": "12:00:00",
            "source_ip": ip,
            "target_service": "web-server",
            "endpoint": endpoint,
            "method": "GET"
        }

    def test_fourteen_requests_do_not_trigger_alert(self):

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        alert = None

        for i in range(14):
            event = self.create_event(
                ip=source_ips[i % len(source_ips)]
            )
            alert = detector.detect_ddos(event)

        self.assertIsNone(alert)

    def test_fifteen_requests_trigger_ddos_alert(self):

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        alert = None

        for i in range(15):
            event = self.create_event(
                ip=source_ips[i % len(source_ips)]
            )
            alert = detector.detect_ddos(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["attack_type"],
            "DDOS"
        )
        self.assertEqual(
            alert["request_count"],
            15
        )
        self.assertEqual(
            alert["unique_ip_count"],
            5
        )
        self.assertEqual(
            alert["endpoint"],
            "/login"
        )

    def test_four_unique_ips_do_not_trigger_alert(self):

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4"
        ]

        alert = None

        for i in range(15):
            event = self.create_event(
                ip=source_ips[i % len(source_ips)]
            )
            alert = detector.detect_ddos(event)

        self.assertIsNone(alert)

    def test_different_endpoints_are_tracked_separately(self):

        alert = None

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        for i in range(8):
            login_event = self.create_event(
                ip=source_ips[i % len(source_ips)],
                endpoint="/login"
            )

            products_event = self.create_event(
                ip=source_ips[i % len(source_ips)],
                endpoint="/products"
            )

            login_alert = detector.detect_ddos(
                login_event
            )

            products_alert = detector.detect_ddos(
                products_event
            )

            if login_alert:
                alert = login_alert

            if products_alert:
                alert = products_alert

        self.assertIsNone(alert)

    def test_duplicate_alert_is_suppressed_during_cooldown(self):

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        first_alert = None

        for i in range(15):
            event = self.create_event(
                ip=source_ips[i % len(source_ips)]
            )
            first_alert = detector.detect_ddos(event)

        repeated_event = self.create_event(
            ip="10.0.1.1"
        )

        repeated_alert = detector.detect_ddos(
            repeated_event
        )

        self.assertIsNotNone(first_alert)
        self.assertIsNone(repeated_alert)


if __name__ == "__main__":
    unittest.main()
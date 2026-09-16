import unittest

from detector import brute_force_detector as detector


class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):

        detector.failed_attempts_by_ip.clear()
        detector.failed_attempts_by_username.clear()
        detector.flagged_ips.clear()
        detector.flagged_usernames.clear()

    def create_event(
        self,
        ip="10.0.0.50",
        username="admin",
        status="FAILED"
    ):

        return {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "12:00:00",
            "source_ip": ip,
            "username": username,
            "status": status
        }

    def test_successful_login_does_not_trigger_alert(self):

        event = self.create_event(status="SUCCESS")

        alert = detector.detect_brute_force(event)

        self.assertIsNone(alert)

    def test_four_failures_do_not_trigger_alert(self):

        alert = None

        for _ in range(4):
            event = self.create_event()
            alert = detector.detect_brute_force(event)

        self.assertIsNone(alert)

    def test_five_failures_trigger_brute_force_alert(self):

        alert = None

        for _ in range(5):
            event = self.create_event()
            alert = detector.detect_brute_force(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["attack_type"],
            "BRUTE_FORCE"
        )
        self.assertEqual(
            alert["source_ip"],
            "10.0.0.50"
        )
        self.assertEqual(
            alert["failed_attempts"],
            5
        )

    def test_two_ips_do_not_trigger_distributed_alert(self):

        source_ips = [
            "10.0.0.51",
            "10.0.0.52",
            "10.0.0.51",
            "10.0.0.52",
            "10.0.0.51"
        ]

        alert = None

        for ip in source_ips:
            event = self.create_event(ip=ip)
            alert = detector.detect_brute_force(event)

        self.assertIsNone(alert)

    def test_three_ips_trigger_distributed_alert(self):

        source_ips = [
            "10.0.0.51",
            "10.0.0.52",
            "10.0.0.53",
            "10.0.0.51",
            "10.0.0.52"
        ]

        alert = None

        for ip in source_ips:
            event = self.create_event(ip=ip)
            alert = detector.detect_brute_force(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["attack_type"],
            "DISTRIBUTED_BRUTE_FORCE"
        )
        self.assertEqual(
            alert["target_user"],
            "admin"
        )
        self.assertEqual(
            alert["unique_ip_count"],
            3
        )

    def test_duplicate_alert_is_suppressed_during_cooldown(self):

        first_alert = None

        for _ in range(5):
            event = self.create_event()
            first_alert = detector.detect_brute_force(event)

        repeated_event = self.create_event()
        repeated_alert = detector.detect_brute_force(
            repeated_event
        )

        self.assertIsNotNone(first_alert)
        self.assertIsNone(repeated_alert)


if __name__ == "__main__":
    unittest.main()
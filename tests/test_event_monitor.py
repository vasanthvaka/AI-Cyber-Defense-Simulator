import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from monitor import event_monitor as monitor


class TestEventMonitor(unittest.TestCase):

    def test_login_event_routes_to_brute_force_detector(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "status": "SUCCESS"
        }

        with (
            patch.object(monitor, "log_event"),
            patch.object(
                monitor,
                "detect_brute_force",
                return_value=None
            ) as brute_detector,
            patch.object(
                monitor,
                "detect_ddos",
                return_value=None
            ) as ddos_detector,
            patch.object(
                monitor,
                "detect_port_scan",
                return_value=None
            ) as port_detector,
            patch.object(
                monitor,
                "detect_suspicious_process",
                return_value=None
            ) as process_detector,
            patch("builtins.print")
        ):
            monitor.process_event(event)

        brute_detector.assert_called_once_with(event)
        ddos_detector.assert_not_called()
        port_detector.assert_not_called()
        process_detector.assert_not_called()

    def test_http_event_routes_to_ddos_detector(self):

        event = {
            "event_type": "HTTP_REQUEST"
        }

        with (
            patch.object(monitor, "log_event"),
            patch.object(
                monitor,
                "detect_brute_force",
                return_value=None
            ) as brute_detector,
            patch.object(
                monitor,
                "detect_ddos",
                return_value=None
            ) as ddos_detector,
            patch.object(
                monitor,
                "detect_port_scan",
                return_value=None
            ) as port_detector,
            patch.object(
                monitor,
                "detect_suspicious_process",
                return_value=None
            ) as process_detector,
            patch("builtins.print")
        ):
            monitor.process_event(event)

        brute_detector.assert_not_called()
        ddos_detector.assert_called_once_with(event)
        port_detector.assert_not_called()
        process_detector.assert_not_called()

    def test_network_event_routes_to_port_scan_detector(self):

        event = {
            "event_type": "NETWORK_CONNECTION"
        }

        with (
            patch.object(monitor, "log_event"),
            patch.object(
                monitor,
                "detect_brute_force",
                return_value=None
            ) as brute_detector,
            patch.object(
                monitor,
                "detect_ddos",
                return_value=None
            ) as ddos_detector,
            patch.object(
                monitor,
                "detect_port_scan",
                return_value=None
            ) as port_detector,
            patch.object(
                monitor,
                "detect_suspicious_process",
                return_value=None
            ) as process_detector,
            patch("builtins.print")
        ):
            monitor.process_event(event)

        brute_detector.assert_not_called()
        ddos_detector.assert_not_called()
        port_detector.assert_called_once_with(event)
        process_detector.assert_not_called()

    def test_process_event_routes_to_process_detector(self):

        event = {
            "event_type": "PROCESS_ACTIVITY"
        }

        with (
            patch.object(monitor, "log_event"),
            patch.object(
                monitor,
                "detect_brute_force",
                return_value=None
            ) as brute_detector,
            patch.object(
                monitor,
                "detect_ddos",
                return_value=None
            ) as ddos_detector,
            patch.object(
                monitor,
                "detect_port_scan",
                return_value=None
            ) as port_detector,
            patch.object(
                monitor,
                "detect_suspicious_process",
                return_value=None
            ) as process_detector,
            patch("builtins.print")
        ):
            monitor.process_event(event)

        brute_detector.assert_not_called()
        ddos_detector.assert_not_called()
        port_detector.assert_not_called()
        process_detector.assert_called_once_with(event)

    def test_unknown_event_is_logged_but_not_detected(self):

        event = {
            "event_type": "UNKNOWN_EVENT"
        }

        with (
            patch.object(monitor, "log_event") as log_event,
            patch.object(
                monitor,
                "detect_brute_force",
                return_value=None
            ) as brute_detector,
            patch.object(
                monitor,
                "detect_ddos",
                return_value=None
            ) as ddos_detector,
            patch.object(
                monitor,
                "detect_port_scan",
                return_value=None
            ) as port_detector,
            patch.object(
                monitor,
                "detect_suspicious_process",
                return_value=None
            ) as process_detector,
            patch("builtins.print")
        ):
            monitor.process_event(event)

        log_event.assert_called_once_with(event)
        brute_detector.assert_not_called()
        ddos_detector.assert_not_called()
        port_detector.assert_not_called()
        process_detector.assert_not_called()

    def test_log_event_creates_valid_jsonl(self):

        events = [
            {
                "event_type": "LOGIN_ATTEMPT",
                "status": "SUCCESS"
            },
            {
                "event_type": "HTTP_REQUEST",
                "method": "GET"
            }
        ]

        with TemporaryDirectory() as directory:

            temporary_log = (
                Path(directory) / "security_events.jsonl"
            )

            with patch.object(
                monitor,
                "LOG_FILE",
                temporary_log
            ):
                for event in events:
                    monitor.log_event(event)

            with open(
                temporary_log,
                "r",
                encoding="utf-8"
            ) as file:
                lines = file.readlines()

        self.assertEqual(len(lines), 2)

        first_event = json.loads(lines[0])
        second_event = json.loads(lines[1])

        self.assertEqual(first_event, events[0])
        self.assertEqual(second_event, events[1])


if __name__ == "__main__":
    unittest.main()
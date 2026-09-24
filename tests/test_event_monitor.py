import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from monitor import event_monitor


class TestEventMonitor(unittest.TestCase):

    @patch("builtins.print")
    def test_process_event_submits_to_coordinator(
        self,
        mock_print
    ):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "status": "FAILED"
        }

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            return_value=[]
        ) as submit_event:

            result = event_monitor.process_event(
                event
            )

        submit_event.assert_called_once_with(
            event
        )

        self.assertEqual(
            result,
            []
        )

        mock_print.assert_called_once_with(
            event
        )

    @patch("builtins.print")
    @patch(
        "monitor.event_monitor.display_agent_result"
    )
    def test_process_event_displays_every_response(
        self,
        mock_display_agent_result,
        mock_print
    ):

        event = {
            "event_type":
                "NETWORK_CONNECTION"
        }

        first_response = object()
        second_response = object()

        responses = [
            first_response,
            second_response
        ]

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            return_value=responses
        ):

            result = event_monitor.process_event(
                event
            )

        self.assertEqual(
            result,
            responses
        )

        self.assertEqual(
            mock_display_agent_result.call_count,
            2
        )

        mock_display_agent_result.assert_any_call(
            first_response
        )

        mock_display_agent_result.assert_any_call(
            second_response
        )

    @patch("builtins.print")
    @patch(
        "monitor.event_monitor.display_agent_result"
    )
    def test_normal_event_displays_no_result(
        self,
        mock_display_agent_result,
        mock_print
    ):

        event = {
            "event_type": "UNKNOWN_EVENT"
        }

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            return_value=[]
        ):

            result = event_monitor.process_event(
                event
            )

        self.assertEqual(
            result,
            []
        )

        mock_display_agent_result.assert_not_called()

    @patch(
        "monitor.event_monitor.display_agent_result"
    )
    def test_flush_uses_coordinator(
        self,
        mock_display_agent_result
    ):

        first_response = object()
        second_response = object()

        responses = [
            first_response,
            second_response
        ]

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "flush_ai_window",
            return_value=responses
        ) as flush_ai_window:

            result = (
                event_monitor.flush_ai_window()
            )

        flush_ai_window.assert_called_once_with()

        self.assertEqual(
            result,
            responses
        )

        self.assertEqual(
            mock_display_agent_result.call_count,
            2
        )

    def test_log_event_writes_json_line(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "status": "FAILED"
        }

        with tempfile.TemporaryDirectory() as directory:

            temporary_log_file = (
                Path(directory)
                / "security_events.jsonl"
            )

            with patch.object(
                event_monitor,
                "LOG_FILE",
                temporary_log_file
            ):

                event_monitor.log_event(event)

            with open(
                temporary_log_file,
                "r",
                encoding="utf-8"
            ) as file:

                stored_event = json.loads(
                    file.readline()
                )

        self.assertEqual(
            stored_event,
            event
        )


if __name__ == "__main__":
    unittest.main()
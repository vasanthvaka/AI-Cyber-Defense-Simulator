import unittest
from unittest.mock import patch

from monitor import event_monitor


class TestEventMonitorValidation(unittest.TestCase):

    def test_valid_event_reaches_coordinator(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "192.168.1.10",
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

        self.assertEqual(result, [])

    def test_invalid_event_does_not_reach_coordinator(
        self
    ):

        invalid_event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin"
        }

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            return_value=[]
        ) as submit_event:

            result = event_monitor.process_event(
                invalid_event
            )

        submit_event.assert_not_called()
        self.assertEqual(result, [])

    def test_non_dictionary_event_is_rejected(self):

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            return_value=[]
        ) as submit_event:

            result = event_monitor.process_event(
                "invalid event"
            )

        submit_event.assert_not_called()
        self.assertEqual(result, [])

    @patch("builtins.print")
    def test_pipeline_failure_is_contained(
        self,
        mock_print
    ):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "status": "FAILED"
        }

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "submit_event",
            side_effect=[
                RuntimeError(
                    "Simulated detector failure"
                ),
                []
            ]
        ) as submit_event:

            first_result = (
                event_monitor.process_event(
                    event
                )
            )

            second_result = (
                event_monitor.process_event(
                    event
                )
            )

        self.assertEqual(first_result, [])
        self.assertEqual(second_result, [])

        self.assertEqual(
            submit_event.call_count,
            2
        )

    @patch("builtins.print")
    def test_ai_flush_failure_is_contained(
        self,
        mock_print
    ):

        with patch.object(
            event_monitor.AGENT_COORDINATOR,
            "flush_ai_window",
            side_effect=RuntimeError(
                "Simulated model failure"
            )
        ) as flush_ai_window:

            result = (
                event_monitor.flush_ai_window()
            )

        flush_ai_window.assert_called_once_with()

        self.assertEqual(result, [])
        
if __name__ == "__main__":
    unittest.main()
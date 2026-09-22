import unittest

from monitor.ai_window_collector import AIWindowCollector


class TestAIWindowCollector(unittest.TestCase):

    def setUp(self):

        self.analyzed_windows = []

        def mock_anomaly_detector(events):

            self.analyzed_windows.append(events)

            return {
                "attack_type": "ANOMALOUS_BEHAVIOR",
                "event_count": len(events)
            }

        self.collector = AIWindowCollector(
            window_size=5,
            minimum_flush_events=1,
            anomaly_detector=mock_anomaly_detector
        )

    def create_event(self, timestamp, source_ip="192.168.1.10"):

        return {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": timestamp,
            "source_ip": source_ip,
            "username": "user",
            "status": "SUCCESS"
        }

    def test_events_inside_five_seconds_remain_in_same_window(self):

        self.collector.add_event(
            self.create_event("10:00:00")
        )
        self.collector.add_event(
            self.create_event("10:00:02")
        )
        alert = self.collector.add_event(
            self.create_event("10:00:04")
        )

        self.assertIsNone(alert)
        self.assertEqual(
            len(self.analyzed_windows),
            0
        )
        self.assertEqual(
            len(self.collector.current_window),
            3
        )

    def test_event_at_five_seconds_closes_window(self):

        first_event = self.create_event("10:00:00")
        second_event = self.create_event("10:00:04")
        boundary_event = self.create_event("10:00:05")

        self.collector.add_event(first_event)
        self.collector.add_event(second_event)
        alert = self.collector.add_event(boundary_event)

        self.assertEqual(
            self.analyzed_windows,
            [[first_event, second_event]]
        )
        self.assertEqual(
            self.collector.current_window,
            [boundary_event]
        )
        self.assertEqual(
            alert["event_count"],
            2
        )

    def test_flush_analyzes_final_window(self):

        first_event = self.create_event("10:00:00")
        second_event = self.create_event("10:00:03")

        self.collector.add_event(first_event)
        self.collector.add_event(second_event)

        alert = self.collector.flush()

        self.assertEqual(
            self.analyzed_windows,
            [[first_event, second_event]]
        )
        self.assertEqual(
            alert["event_count"],
            2
        )
        self.assertEqual(
            self.collector.current_window,
            []
        )
        self.assertIsNone(
            self.collector.window_start
        )

    def test_empty_flush_does_not_call_detector(self):

        alert = self.collector.flush()

        self.assertIsNone(alert)
        self.assertEqual(
            self.analyzed_windows,
            []
        )

    def test_missing_timestamp_is_ignored(self):

        alert = self.collector.add_event({
            "event_type": "LOGIN_ATTEMPT",
            "source_ip": "192.168.1.10"
        })

        self.assertIsNone(alert)
        self.assertEqual(
            self.collector.current_window,
            []
        )
        self.assertEqual(
            self.analyzed_windows,
            []
        )

    def test_midnight_rollover_keeps_correct_window(self):

        first_event = self.create_event("23:59:58")
        second_event = self.create_event("00:00:01")
        boundary_event = self.create_event("00:00:03")

        self.collector.add_event(first_event)
        self.collector.add_event(second_event)
        alert = self.collector.add_event(boundary_event)

        self.assertEqual(
            self.analyzed_windows,
            [[first_event, second_event]]
        )
        self.assertEqual(
            self.collector.current_window,
            [boundary_event]
        )
        self.assertEqual(
            alert["event_count"],
            2
        )

    def test_invalid_window_size_raises_error(self):

        with self.assertRaises(ValueError):
            AIWindowCollector(window_size=0)

    def test_flush_ignores_window_with_too_few_events(self):

        analyzed_windows = []

        def mock_anomaly_detector(events):
            analyzed_windows.append(events)
            return {"event_count": len(events)}

        collector = AIWindowCollector(
            window_size=5,
            minimum_flush_events=5,
            anomaly_detector=mock_anomaly_detector
        )

        collector.add_event(
            self.create_event("10:00:00")
        )

        alert = collector.flush()

        self.assertIsNone(alert)
        self.assertEqual(analyzed_windows, [])
        self.assertEqual(
            collector.current_window,
            []
        )
        
if __name__ == "__main__":
    unittest.main()
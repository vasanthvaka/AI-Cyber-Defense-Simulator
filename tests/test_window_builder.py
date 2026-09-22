import unittest

from detector.window_builder import (
    build_time_windows,
    timestamp_to_seconds
)


class TestWindowBuilder(unittest.TestCase):

    def test_timestamp_to_seconds(self):

        result = timestamp_to_seconds("01:02:03")

        self.assertEqual(result, 3723)

    def test_build_five_second_windows(self):

        events = [
            {"timestamp": "10:00:00", "event_type": "LOGIN_ATTEMPT"},
            {"timestamp": "10:00:02", "event_type": "HTTP_REQUEST"},
            {"timestamp": "10:00:04", "event_type": "PROCESS_ACTIVITY"},
            {"timestamp": "10:00:05", "event_type": "LOGIN_ATTEMPT"},
            {"timestamp": "10:00:09", "event_type": "HTTP_REQUEST"},
            {"timestamp": "10:00:10", "event_type": "NETWORK_CONNECTION"}
        ]

        windows = build_time_windows(events, window_size=5)

        self.assertEqual(len(windows), 3)
        self.assertEqual(len(windows[0]), 3)
        self.assertEqual(len(windows[1]), 2)
        self.assertEqual(len(windows[2]), 1)

    def test_midnight_rollover(self):

        events = [
            {"timestamp": "23:59:58", "event_type": "LOGIN_ATTEMPT"},
            {"timestamp": "23:59:59", "event_type": "HTTP_REQUEST"},
            {"timestamp": "00:00:00", "event_type": "PROCESS_ACTIVITY"},
            {"timestamp": "00:00:03", "event_type": "NETWORK_CONNECTION"}
        ]

        windows = build_time_windows(events, window_size=5)

        self.assertEqual(len(windows), 2)
        self.assertEqual(len(windows[0]), 3)
        self.assertEqual(len(windows[1]), 1)


if __name__ == "__main__":
    unittest.main()
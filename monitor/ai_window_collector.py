from detector.anomaly_detector import detect_anomaly

from detector.window_builder import (
    SECONDS_PER_DAY,
    timestamp_to_seconds
)

from config.settings import get_config


class AIWindowCollector:

    def __init__(
        self,
        window_size=None,
        minimum_flush_events=None,
        anomaly_detector=detect_anomaly
    ):

        ai_config = get_config()["ai_window"]

        if window_size is None:
            window_size = ai_config[
                "window_size_seconds"
            ]

        if minimum_flush_events is None:
            minimum_flush_events = ai_config[
                "minimum_flush_events"
            ]

        if window_size <= 0:
            raise ValueError(
                "Window size must be greater than zero"
            )

        if minimum_flush_events <= 0:
            raise ValueError(
                "Minimum flush events must be greater than zero"
            )

        self.window_size = window_size

        self.minimum_flush_events = (
            minimum_flush_events
        )

        self.anomaly_detector = anomaly_detector

        self.current_window = []
        self.window_start = None
        self.previous_time = None
        self.day_offset = 0

    def add_event(self, event):

        timestamp = event.get("timestamp")

        # Match the offline window builder:
        # events without timestamps cannot enter AI windows.
        if timestamp is None:
            return None

        event_time = timestamp_to_seconds(timestamp)

        # Handle a simulation crossing midnight.
        if (
            self.previous_time is not None
            and event_time < self.previous_time
        ):
            self.day_offset += SECONDS_PER_DAY

        absolute_event_time = (
            event_time + self.day_offset
        )

        self.previous_time = event_time

        if self.window_start is None:
            self.window_start = absolute_event_time

        window_complete = (
            absolute_event_time - self.window_start
            >= self.window_size
        )

        if window_complete:

            completed_window = self.current_window

            # The boundary event begins the next window.
            self.current_window = [event]
            self.window_start = absolute_event_time

            return self.anomaly_detector(
                completed_window
            )

        self.current_window.append(event)

        return None

    def flush(self):

        if not self.current_window:
            return None

        completed_window = self.current_window

        # Reset all state so the collector can be reused.
        self.current_window = []
        self.window_start = None
        self.previous_time = None
        self.day_offset = 0

        # Very small partial windows do not contain enough
        # evidence and differ from the model's training windows.
        if (
            len(completed_window)
            < self.minimum_flush_events
        ):
            return None

        return self.anomaly_detector(
            completed_window
        )
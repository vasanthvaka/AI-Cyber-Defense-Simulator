SECONDS_PER_DAY = 24 * 60 * 60


def timestamp_to_seconds(timestamp):

    hours, minutes, seconds = map(int, timestamp.split(":"))

    return (
        hours * 3600
        + minutes * 60
        + seconds
    )


def build_time_windows(events, window_size=5):

    if window_size <= 0:
        raise ValueError("Window size must be greater than zero")

    windows = []
    current_window = []

    window_start = None
    previous_time = None
    day_offset = 0

    for event in events:

        timestamp = event.get("timestamp")

        if timestamp is None:
            continue

        event_time = timestamp_to_seconds(timestamp)

        # Handle a simulation crossing midnight
        if (
            previous_time is not None
            and event_time < previous_time
        ):
            day_offset += SECONDS_PER_DAY

        absolute_event_time = event_time + day_offset
        previous_time = event_time

        if window_start is None:
            window_start = absolute_event_time

        if absolute_event_time - window_start >= window_size:

            if current_window:
                windows.append(current_window)

            current_window = [event]
            window_start = absolute_event_time

        else:
            current_window.append(event)

    if current_window:
        windows.append(current_window)

    return windows
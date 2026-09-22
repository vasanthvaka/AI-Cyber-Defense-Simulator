import json

from detector.feature_extractor import (
    extract_window_features,
    features_to_vector
)
from detector.window_builder import build_time_windows


def load_events(log_file):

    events = []

    with open(log_file, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)

            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from error

    return events


def build_feature_dataset(events, window_size=5):

    windows = build_time_windows(
        events,
        window_size=window_size
    )

    dataset = []

    for window in windows:

        features = extract_window_features(window)
        feature_vector = features_to_vector(features)

        dataset.append(feature_vector)

    return dataset
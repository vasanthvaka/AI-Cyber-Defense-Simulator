from pathlib import Path
from statistics import mean

from detector.dataset_builder import (
    load_events,
    build_feature_dataset
)
from detector.feature_extractor import FEATURE_NAMES


PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAINING_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "normal_training_events.jsonl"
)


def inspect_feature_ranges():

    events = load_events(TRAINING_LOG_FILE)

    dataset = build_feature_dataset(
        events,
        window_size=5
    )

    print("\nNormal training feature ranges:\n")

    for index, feature_name in enumerate(FEATURE_NAMES):

        values = [
            row[index]
            for row in dataset
        ]

        print(
            f"{feature_name:35} "
            f"min={min(values):6.2f}  "
            f"max={max(values):6.2f}  "
            f"mean={mean(values):6.2f}"
        )


if __name__ == "__main__":
    inspect_feature_ranges()
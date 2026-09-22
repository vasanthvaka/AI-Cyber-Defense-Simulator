import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from simulator.main import generate_mixed_normal_event


PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAINING_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "normal_training_events.jsonl"
)


def generate_normal_training_data(
    window_count=200,
    window_size=5
):

    starting_time = datetime.now().replace(microsecond=0)
    generated_event_count = 0

    with open(
        TRAINING_LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        for window_index in range(window_count):

            window_start = (
                starting_time
                + timedelta(
                    seconds=window_index * window_size
                )
            )

            event_count = random.randint(5, 15)

            event_offsets = [0]

            event_offsets.extend(
                sorted(
                    random.randint(0, window_size - 1)
                    for _ in range(event_count - 1)
                )
            )

            for event_offset in event_offsets:

                event = generate_mixed_normal_event()

                event_time = (
                    window_start
                    + timedelta(seconds=event_offset)
                )

                event["timestamp"] = event_time.strftime(
                    "%H:%M:%S"
                )

                file.write(json.dumps(event) + "\n")

                generated_event_count += 1

    print(
        f"Generated {generated_event_count} normal events "
        f"across {window_count} time windows."
    )

    print(f"Training events saved to: {TRAINING_LOG_FILE}")


def main():

    parser = argparse.ArgumentParser(
        description="Generate normal events for anomaly-model training"
    )

    parser.add_argument(
        "--windows",
        type=int,
        default=200,
        help="Number of normal time windows to generate"
    )

    args = parser.parse_args()

    if args.windows <= 0:
        raise ValueError(
            "Number of windows must be greater than zero"
        )

    generate_normal_training_data(
        window_count=args.windows
    )


if __name__ == "__main__":
    main()
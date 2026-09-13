import json
from pathlib import Path

from detector.brute_force_detector import detect_brute_force


# Get the main project folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Location where security events will be stored
LOG_FILE = PROJECT_ROOT / "data" / "security_events.jsonl"


def log_event(event):

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def process_event(event):

    # Store every event
    log_event(event)

    # Display it for now
    print(event)

    # Send event to detector
    alert = detect_brute_force(event)

    if alert:
        print("\n⚠ SECURITY ALERT")
        print(f"Attack Type: {alert['attack_type']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Target User: {alert['target_user']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"Severity: {alert['severity']}")
        print()
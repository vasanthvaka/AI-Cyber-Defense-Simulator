import json
from pathlib import Path

from detector.brute_force_detector import detect_brute_force
from detector.ddos_detector import detect_ddos


# Get the main project folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Location where security events will be stored
LOG_FILE = PROJECT_ROOT / "data" / "security_events.jsonl"


def log_event(event):

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def display_alert(alert):

    print("\n⚠ SECURITY ALERT")
    print(f"Attack Type: {alert['attack_type']}")

    if "source_ips" in alert:
        print(f"Source IPs: {', '.join(alert['source_ips'])}")
        print(f"Unique IP Count: {alert['unique_ip_count']}")
    else:
        print(f"Source IP: {alert['source_ip']}")

    if alert["attack_type"] in [
        "BRUTE_FORCE",
        "DISTRIBUTED_BRUTE_FORCE"
    ]:
        print(f"Target User: {alert['target_user']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")

    elif alert["attack_type"] == "DDOS":
        print(f"Target Service: {alert['target_service']}")
        print(f"Endpoint: {alert['endpoint']}")
        print(f"Request Count: {alert['request_count']}")
        print(f"Time Window: {alert['time_window']} seconds")

    print(f"Severity: {alert['severity']}")
    print()


def process_event(event):

    # Store every event
    log_event(event)

    # Display the event
    print(event)

    # No detector selected initially
    alert = None

    # Route login events to the brute-force detector
    if event.get("event_type") == "LOGIN_ATTEMPT":
        alert = detect_brute_force(event)

    # Route HTTP events to the DDoS detector
    elif event.get("event_type") == "HTTP_REQUEST":
        alert = detect_ddos(event)

    if alert:
        display_alert(alert)
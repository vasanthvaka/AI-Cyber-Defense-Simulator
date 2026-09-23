import json
from pathlib import Path

from agents.decision_agent import decide_response
from agents.response_agent import ResponseAgent
from detector.brute_force_detector import detect_brute_force
from detector.ddos_detector import detect_ddos
from detector.port_scan_detector import detect_port_scan
from detector.process_detector import detect_suspicious_process
from monitor.ai_window_collector import AIWindowCollector
from collections import deque

from alerting.alert_normalizer import normalize_alert

# Get the main project folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Location where security events will be stored
LOG_FILE = PROJECT_ROOT / "data" / "security_events.jsonl"

# Collect events into five-second windows for AI analysis
AI_WINDOW_COLLECTOR = AIWindowCollector(window_size=5)

# Maintain simulated defensive state
RESPONSE_AGENT = ResponseAgent()
# Temporarily retain normalized alerts for future correlation
NORMALIZED_ALERTS = deque(maxlen=1000)

def log_event(event):

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def display_alert(alert):

    print("\n⚠ SECURITY ALERT")
    print(f"Attack Type: {alert['attack_type']}")

    if alert["attack_type"] == "BRUTE_FORCE":
        print(f"Source IP: {alert['source_ip']}")
        print(f"Target User: {alert['target_user']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")

    elif alert["attack_type"] == "DISTRIBUTED_BRUTE_FORCE":
        print(f"Source IPs: {', '.join(alert['source_ips'])}")
        print(f"Unique IP Count: {alert['unique_ip_count']}")
        print(f"Target User: {alert['target_user']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")

    elif alert["attack_type"] == "DDOS":
        print(f"Source IPs: {', '.join(alert['source_ips'])}")
        print(f"Unique IP Count: {alert['unique_ip_count']}")
        print(f"Target Service: {alert['target_service']}")
        print(f"Endpoint: {alert['endpoint']}")
        print(f"Request Count: {alert['request_count']}")
        print(f"Time Window: {alert['time_window']} seconds")

    elif alert["attack_type"] == "PORT_SCAN":
        print(f"Source IP: {alert['source_ip']}")
        print(f"Target IP: {alert['target_ip']}")

        ports = ", ".join(
            str(port)
            for port in alert["ports_scanned"]
        )

        print(f"Ports Scanned: {ports}")
        print(f"Unique Port Count: {alert['unique_port_count']}")
        print(f"Time Window: {alert['time_window']} seconds")

    elif alert["attack_type"] == "SUSPICIOUS_PROCESS":
        print(f"Process Name: {alert['process_name']}")
        print(f"Process ID: {alert['process_id']}")
        print(f"Parent Process: {alert['parent_process']}")
        print(f"User: {alert['user']}")
        print(f"Executable Path: {alert['executable_path']}")
        print(f"Command Line: {alert['command_line']}")
        print(f"Risk Score: {alert['risk_score']}")

        print("Indicators:")

        for indicator in alert["indicators"]:
            print(f"  - {indicator}")

    elif alert["attack_type"] == "ANOMALOUS_BEHAVIOR":
        source_ips = ", ".join(
            alert["source_ips"]
        )

        print(
            f"Detection Method: "
            f"{alert['detection_method']}"
        )
        print(f"Anomaly Score: {alert['anomaly_score']}")
        print(f"Event Count: {alert['event_count']}")
        print(
            f"Source IPs: "
            f"{source_ips if source_ips else 'None'}"
        )

    print(f"Severity: {alert['severity']}")
    print()


def display_response(result):

    targets = ", ".join(
        str(target)
        for target in result["targets"]
    )

    new_targets = ", ".join(
        str(target)
        for target in result["new_targets"]
    )

    print("🛡 SIMULATED RESPONSE")
    print(f"Action: {result['action']}")
    print(f"Status: {result['status']}")
    print(
        f"Targets: "
        f"{targets if targets else 'None'}"
    )
    print(
        f"New Targets: "
        f"{new_targets if new_targets else 'None'}"
    )
    print(f"Automatic: {result['automatic']}")
    print()


def handle_alert(alert):

    # Convert the detector-specific alert into
    # the common SecurityAlert format
    normalized_alert = normalize_alert(alert)

    # Make the normalized alert available to
    # the future correlation and analysis layer
    NORMALIZED_ALERTS.append(normalized_alert)

    # Continue displaying the original alert for now
    display_alert(alert)

    # Keep the existing response pipeline working
    decision = decide_response(alert)
    result = RESPONSE_AGENT.execute(decision)

    display_response(result)

    return result


def process_event(event):

    # Store every event
    log_event(event)

    # Display the event
    print(event)

    # No rule-based alert selected initially
    rule_alert = None

    # Route login events to the brute-force detector
    if event.get("event_type") == "LOGIN_ATTEMPT":
        rule_alert = detect_brute_force(event)

    # Route HTTP events to the DDoS detector
    elif event.get("event_type") == "HTTP_REQUEST":
        rule_alert = detect_ddos(event)

    # Route network events to the port-scan detector
    elif event.get("event_type") == "NETWORK_CONNECTION":
        rule_alert = detect_port_scan(event)

    # Route process events to the process detector
    elif event.get("event_type") == "PROCESS_ACTIVITY":
        rule_alert = detect_suspicious_process(event)

    # Process a rule-based alert immediately
    if rule_alert:
        handle_alert(rule_alert)

    # Independently add the event to the AI window
    ai_alert = AI_WINDOW_COLLECTOR.add_event(event)

    # Process an alert from the completed AI window
    if ai_alert:
        handle_alert(ai_alert)


def flush_ai_window():

    ai_alert = AI_WINDOW_COLLECTOR.flush()

    if ai_alert:
        return handle_alert(ai_alert)

    return None
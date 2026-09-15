from datetime import datetime


connection_attempts = {}
flagged_scanners = {}


PORT_THRESHOLD = 10
TIME_WINDOW = 5
ALERT_COOLDOWN = 15


def detect_port_scan(event):

    current_time = datetime.now().timestamp()

    source_ip = event["source_ip"]
    target_ip = event["target_ip"]
    destination_port = event["destination_port"]

    scanner_target = (source_ip, target_ip)

    if scanner_target not in connection_attempts:
        connection_attempts[scanner_target] = []

    # Store attempt time and destination port
    connection_attempts[scanner_target].append(
        (current_time, destination_port)
    )

    # Keep only attempts inside the time window
    connection_attempts[scanner_target] = [
        attempt
        for attempt in connection_attempts[scanner_target]
        if current_time - attempt[0] <= TIME_WINDOW
    ]

    recent_attempts = connection_attempts[scanner_target]

    unique_ports = {
        port
        for _, port in recent_attempts
    }

    if (
        len(unique_ports) >= PORT_THRESHOLD
        and (
            scanner_target not in flagged_scanners
            or (
                current_time - flagged_scanners[scanner_target]
                >= ALERT_COOLDOWN
            )
        )
    ):
        flagged_scanners[scanner_target] = current_time

        return {
            "attack_type": "PORT_SCAN",
            "source_ip": source_ip,
            "target_ip": target_ip,
            "ports_scanned": sorted(unique_ports),
            "unique_port_count": len(unique_ports),
            "time_window": TIME_WINDOW,
            "severity": "MEDIUM"
        }

    return None
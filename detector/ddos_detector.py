from datetime import datetime


requests_by_target = {}
flagged_targets = set()


REQUEST_THRESHOLD = 15
UNIQUE_IP_THRESHOLD = 5
TIME_WINDOW = 2


def detect_ddos(event):

    current_time = datetime.now().timestamp()

    target_service = event["target_service"]
    endpoint = event["endpoint"]

    # A tuple identifies the exact target
    target = (target_service, endpoint)

    if target not in requests_by_target:
        requests_by_target[target] = []

    # Store the time and source of the current request
    requests_by_target[target].append(
        (current_time, event["source_ip"])
    )

    # Remove requests outside the time window
    requests_by_target[target] = [
        request
        for request in requests_by_target[target]
        if current_time - request[0] <= TIME_WINDOW
    ]

    recent_requests = requests_by_target[target]

    # Extract the unique source IPs
    unique_ips = {
        source_ip
        for _, source_ip in recent_requests
    }

    if (
        len(recent_requests) >= REQUEST_THRESHOLD
        and len(unique_ips) >= UNIQUE_IP_THRESHOLD
        and target not in flagged_targets
    ):
        flagged_targets.add(target)

        return {
            "attack_type": "DDOS",
            "source_ips": sorted(unique_ips),
            "target_service": target_service,
            "endpoint": endpoint,
            "request_count": len(recent_requests),
            "unique_ip_count": len(unique_ips),
            "time_window": TIME_WINDOW,
            "severity": "HIGH"
        }

    return None
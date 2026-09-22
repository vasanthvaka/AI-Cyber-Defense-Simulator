FEATURE_NAMES = [
    "total_events",
    "login_attempts",
    "failed_logins",
    "unique_source_ips",
    "http_requests",
    "unique_http_endpoints",
    "network_connections",
    "unique_destination_ports",
    "process_activities",
    "unique_process_names"
]


def extract_window_features(events):

    source_ips = set()
    http_endpoints = set()
    destination_ports = set()
    process_names = set()

    login_attempts = 0
    failed_logins = 0
    http_requests = 0
    network_connections = 0
    process_activities = 0

    for event in events:

        event_type = event.get("event_type")

        source_ip = event.get("source_ip")

        if source_ip:
            source_ips.add(source_ip)

        if event_type == "LOGIN_ATTEMPT":
            login_attempts += 1

            if event.get("status") == "FAILED":
                failed_logins += 1

        elif event_type == "HTTP_REQUEST":
            http_requests += 1

            endpoint = event.get("endpoint")

            if endpoint:
                http_endpoints.add(endpoint)

        elif event_type == "NETWORK_CONNECTION":
            network_connections += 1

            destination_port = event.get("destination_port")

            if destination_port is not None:
                destination_ports.add(destination_port)

        elif event_type == "PROCESS_ACTIVITY":
            process_activities += 1

            process_name = event.get("process_name")

            if process_name:
                process_names.add(process_name)

    features = {
        "total_events": len(events),
        "login_attempts": login_attempts,
        "failed_logins": failed_logins,
        "unique_source_ips": len(source_ips),
        "http_requests": http_requests,
        "unique_http_endpoints": len(http_endpoints),
        "network_connections": network_connections,
        "unique_destination_ports": len(destination_ports),
        "process_activities": process_activities,
        "unique_process_names": len(process_names)
    }

    return features
def features_to_vector(features):

    return [
        features[feature_name]
        for feature_name in FEATURE_NAMES
    ]
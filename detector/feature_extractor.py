from collections import defaultdict


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
    "unique_process_names",
    "max_failed_logins_per_user",
    "max_http_requests_per_source_ip",
    "max_http_requests_per_target_service",
    "max_http_requests_per_endpoint",
    "max_ports_per_source_ip",
    "max_command_line_length"
]


def extract_window_features(events):

    source_ips = set()
    http_endpoints = set()
    destination_ports = set()
    process_names = set()

    failed_logins_per_user = defaultdict(int)
    http_requests_per_source_ip = defaultdict(int)
    http_requests_per_target_service = defaultdict(int)
    http_requests_per_endpoint = defaultdict(int)
    ports_per_source_ip = defaultdict(set)

    login_attempts = 0
    failed_logins = 0
    http_requests = 0
    network_connections = 0
    process_activities = 0
    max_command_line_length = 0

    for event in events:

        event_type = event.get("event_type")
        source_ip = event.get("source_ip")

        if source_ip:
            source_ips.add(source_ip)

        if event_type == "LOGIN_ATTEMPT":

            login_attempts += 1

            if event.get("status") == "FAILED":

                failed_logins += 1

                username = event.get("username")

                if username:
                    failed_logins_per_user[username] += 1

        elif event_type == "HTTP_REQUEST":

            http_requests += 1

            endpoint = event.get("endpoint")
            target_service = event.get("target_service")

            if endpoint:

                http_endpoints.add(endpoint)

                http_requests_per_endpoint[
                    endpoint
                ] += 1

            if source_ip:
                http_requests_per_source_ip[
                    source_ip
                ] += 1

            if target_service:
                http_requests_per_target_service[
                    target_service
                ] += 1

        elif event_type == "NETWORK_CONNECTION":

            network_connections += 1

            destination_port = event.get(
                "destination_port"
            )

            if destination_port is not None:

                destination_ports.add(
                    destination_port
                )

                if source_ip:
                    ports_per_source_ip[
                        source_ip
                    ].add(destination_port)

        elif event_type == "PROCESS_ACTIVITY":

            process_activities += 1

            process_name = event.get("process_name")

            if process_name:
                process_names.add(process_name)

            command_line = event.get(
                "command_line",
                ""
            )

            max_command_line_length = max(
                max_command_line_length,
                len(command_line)
            )

    max_failed_logins_per_user = max(
        failed_logins_per_user.values(),
        default=0
    )

    max_http_requests_per_source_ip = max(
        http_requests_per_source_ip.values(),
        default=0
    )

    max_http_requests_per_target_service = max(
        http_requests_per_target_service.values(),
        default=0
    )

    max_http_requests_per_endpoint = max(
        http_requests_per_endpoint.values(),
        default=0
    )

    max_ports_per_source_ip = max(
        (
            len(ports)
            for ports in ports_per_source_ip.values()
        ),
        default=0
    )

    return {
        "total_events": len(events),
        "login_attempts": login_attempts,
        "failed_logins": failed_logins,
        "unique_source_ips": len(source_ips),
        "http_requests": http_requests,
        "unique_http_endpoints": len(
            http_endpoints
        ),
        "network_connections": network_connections,
        "unique_destination_ports": len(
            destination_ports
        ),
        "process_activities": process_activities,
        "unique_process_names": len(
            process_names
        ),
        "max_failed_logins_per_user":
            max_failed_logins_per_user,
        "max_http_requests_per_source_ip":
            max_http_requests_per_source_ip,
        "max_http_requests_per_target_service":
            max_http_requests_per_target_service,
        "max_http_requests_per_endpoint":
            max_http_requests_per_endpoint,
        "max_ports_per_source_ip":
            max_ports_per_source_ip,
        "max_command_line_length":
            max_command_line_length
    }


def features_to_vector(features):

    return [
        features[feature_name]
        for feature_name in FEATURE_NAMES
    ]
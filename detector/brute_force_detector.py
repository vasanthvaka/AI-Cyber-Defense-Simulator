from datetime import datetime


failed_attempts_by_ip = {}
failed_attempts_by_username = {}

flagged_ips = {}
flagged_usernames = {}


THRESHOLD = 5
TIME_WINDOW = 10
DISTRIBUTED_IP_THRESHOLD = 3
ALERT_COOLDOWN = 15


def detect_brute_force(event):

    if event["status"] != "FAILED":
        return None

    ip = event["source_ip"]
    username = event["username"]
    current_time = datetime.now().timestamp()

    # Track failures by source IP
    if ip not in failed_attempts_by_ip:
        failed_attempts_by_ip[ip] = []

    failed_attempts_by_ip[ip].append(current_time)

    failed_attempts_by_ip[ip] = [
        timestamp
        for timestamp in failed_attempts_by_ip[ip]
        if current_time - timestamp <= TIME_WINDOW
    ]

    # Track failures by target username
    if username not in failed_attempts_by_username:
        failed_attempts_by_username[username] = []

    failed_attempts_by_username[username].append(
        (current_time, ip)
    )

    failed_attempts_by_username[username] = [
        attempt
        for attempt in failed_attempts_by_username[username]
        if current_time - attempt[0] <= TIME_WINDOW
    ]

    # Detect traditional single-IP brute force
    if (
        len(failed_attempts_by_ip[ip]) >= THRESHOLD
        and (
            ip not in flagged_ips
            or current_time - flagged_ips[ip] >= ALERT_COOLDOWN
        )
    ):
        flagged_ips[ip] = current_time

        return {
            "attack_type": "BRUTE_FORCE",
            "source_ip": ip,
            "target_user": username,
            "failed_attempts": len(failed_attempts_by_ip[ip]),
            "severity": "HIGH"
        }

    # Detect distributed brute force
    username_attempts = failed_attempts_by_username[username]

    unique_ips = {
        attempt_ip
        for _, attempt_ip in username_attempts
    }

    if (
        len(username_attempts) >= THRESHOLD
        and len(unique_ips) >= DISTRIBUTED_IP_THRESHOLD
        and (
            username not in flagged_usernames
            or (
                current_time - flagged_usernames[username]
                >= ALERT_COOLDOWN
            )
        )
    ):
        flagged_usernames[username] = current_time

        return {
            "attack_type": "DISTRIBUTED_BRUTE_FORCE",
            "source_ip": ip,
            "source_ips": sorted(unique_ips),
            "target_user": username,
            "failed_attempts": len(username_attempts),
            "unique_ip_count": len(unique_ips),
            "severity": "HIGH"
        }

    return None
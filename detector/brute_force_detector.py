from datetime import datetime

failed_attempts = {}
flagged_ips = set()

THRESHOLD = 5
TIME_WINDOW = 10


def detect_brute_force(event):

    if event["status"] != "FAILED":
        return None

    ip = event["source_ip"]
    username = event["username"]
    current_time = datetime.now().timestamp()

    if ip not in failed_attempts:
        failed_attempts[ip] = []

    failed_attempts[ip].append(current_time)

    # Keep only failures inside the time window
    failed_attempts[ip] = [
        timestamp
        for timestamp in failed_attempts[ip]
        if current_time - timestamp <= TIME_WINDOW
    ]

    if (
        len(failed_attempts[ip]) >= THRESHOLD
        and ip not in flagged_ips
    ):
        flagged_ips.add(ip)

        return {
            "attack_type": "BRUTE_FORCE",
            "source_ip": ip,
            "target_user": username,
            "failed_attempts": len(failed_attempts[ip]),
            "severity": "HIGH"
        }

    return None
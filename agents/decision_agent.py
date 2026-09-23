def decide_response(alert):

    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary")

    attack_type = alert.get("attack_type")
    severity = alert.get("severity", "UNKNOWN")

    if not attack_type:
        raise ValueError(
            "Alert must contain an attack_type"
        )

    if attack_type == "BRUTE_FORCE":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IP",
            "target_type": "IP_ADDRESS",
            "targets": [alert["source_ip"]],
            "automatic": True,
            "reason": (
                "Repeated failed logins were detected "
                "from one source IP."
            )
        }

    if attack_type == "DISTRIBUTED_BRUTE_FORCE":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IPS",
            "target_type": "IP_ADDRESS",
            "targets": alert["source_ips"],
            "automatic": True,
            "reason": (
                "Multiple source IPs are attacking "
                "the same user account."
            )
        }

    if attack_type == "DDOS":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "RATE_LIMIT_IPS",
            "target_type": "IP_ADDRESS",
            "targets": alert["source_ips"],
            "automatic": True,
            "reason": (
                "A high-volume request flood was "
                "detected from multiple sources."
            )
        }

    if attack_type == "PORT_SCAN":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "BLOCK_IP",
            "target_type": "IP_ADDRESS",
            "targets": [alert["source_ip"]],
            "automatic": True,
            "reason": (
                "One source IP contacted an unusual "
                "number of destination ports."
            )
        }

    if attack_type == "SUSPICIOUS_PROCESS":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "QUARANTINE_PROCESS",
            "target_type": "PROCESS_ID",
            "targets": [alert["process_id"]],
            "automatic": True,
            "reason": (
                "The process displayed multiple "
                "suspicious execution indicators."
            )
        }

    if attack_type == "ANOMALOUS_BEHAVIOR":
        return {
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": "FLAG_FOR_INVESTIGATION",
            "target_type": "EVENT_WINDOW",
            "targets": alert.get("source_ips", []),
            "automatic": False,
            "reason": (
                "The event window differs from normal "
                "behavior, but the exact attack is unknown."
            )
        }

    return {
        "attack_type": attack_type,
        "severity": severity,
        "recommended_action": "CONTINUE_MONITORING",
        "target_type": "UNKNOWN",
        "targets": [],
        "automatic": False,
        "reason": (
            "No response policy exists for this alert type."
        )
    }
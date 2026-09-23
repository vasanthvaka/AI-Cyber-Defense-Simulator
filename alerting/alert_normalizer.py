from alerting.alert_schema import (
    EntityReference,
    SecurityAlert
)


RULE_DETECTORS = {
    "BRUTE_FORCE": "brute_force_detector",
    "DISTRIBUTED_BRUTE_FORCE": "brute_force_detector",
    "DDOS": "ddos_detector",
    "PORT_SCAN": "port_scan_detector",
    "SUSPICIOUS_PROCESS": "process_detector"
}


def normalize_alert(raw_alert):

    if not isinstance(raw_alert, dict):
        raise TypeError(
            "Raw alert must be a dictionary"
        )

    attack_type = raw_alert.get("attack_type")

    if not attack_type:
        raise ValueError(
            "Raw alert must contain an attack_type"
        )

    if attack_type == "BRUTE_FORCE":
        return normalize_brute_force(raw_alert)

    if attack_type == "DISTRIBUTED_BRUTE_FORCE":
        return normalize_distributed_brute_force(
            raw_alert
        )

    if attack_type == "DDOS":
        return normalize_ddos(raw_alert)

    if attack_type == "PORT_SCAN":
        return normalize_port_scan(raw_alert)

    if attack_type == "SUSPICIOUS_PROCESS":
        return normalize_suspicious_process(
            raw_alert
        )

    if attack_type == "ANOMALOUS_BEHAVIOR":
        return normalize_anomaly(raw_alert)

    return normalize_unknown_alert(raw_alert)


def normalize_brute_force(raw_alert):

    return create_rule_alert(
        raw_alert=raw_alert,
        sources=[
            create_entity(
                "IP_ADDRESS",
                raw_alert,
                "source_ip"
            )
        ],
        targets=[
            create_entity(
                "USER_ACCOUNT",
                raw_alert,
                "target_user"
            )
        ]
    )


def normalize_distributed_brute_force(raw_alert):

    source_ips = require_list(
        raw_alert,
        "source_ips"
    )

    sources = [
        EntityReference(
            entity_type="IP_ADDRESS",
            value=source_ip
        )
        for source_ip in source_ips
    ]

    return create_rule_alert(
        raw_alert=raw_alert,
        sources=sources,
        targets=[
            create_entity(
                "USER_ACCOUNT",
                raw_alert,
                "target_user"
            )
        ]
    )


def normalize_ddos(raw_alert):

    source_ips = require_list(
        raw_alert,
        "source_ips"
    )

    sources = [
        EntityReference(
            entity_type="IP_ADDRESS",
            value=source_ip
        )
        for source_ip in source_ips
    ]

    targets = [
        create_entity(
            "SERVICE",
            raw_alert,
            "target_service"
        ),
        create_entity(
            "HTTP_ENDPOINT",
            raw_alert,
            "endpoint"
        )
    ]

    return create_rule_alert(
        raw_alert=raw_alert,
        sources=sources,
        targets=targets
    )


def normalize_port_scan(raw_alert):

    return create_rule_alert(
        raw_alert=raw_alert,
        sources=[
            create_entity(
                "IP_ADDRESS",
                raw_alert,
                "source_ip"
            )
        ],
        targets=[
            create_entity(
                "IP_ADDRESS",
                raw_alert,
                "target_ip"
            )
        ]
    )


def normalize_suspicious_process(raw_alert):

    return create_rule_alert(
        raw_alert=raw_alert,
        sources=[
            create_entity(
                "PROCESS_ID",
                raw_alert,
                "process_id"
            ),
            create_entity(
                "PROCESS_NAME",
                raw_alert,
                "process_name"
            )
        ],
        targets=[
            create_entity(
                "USER_ACCOUNT",
                raw_alert,
                "user"
            )
        ]
    )


def normalize_anomaly(raw_alert):

    source_ips = raw_alert.get(
        "source_ips",
        []
    )

    if not isinstance(source_ips, list):
        raise TypeError(
            "source_ips must be a list"
        )

    sources = [
        EntityReference(
            entity_type="IP_ADDRESS",
            value=source_ip
        )
        for source_ip in source_ips
    ]

    return SecurityAlert(
        attack_type="ANOMALOUS_BEHAVIOR",
        detection_method=raw_alert.get(
            "detection_method",
            "ISOLATION_FOREST"
        ),
        detector_name="anomaly_detector",
        sources=sources,
        targets=[],
        severity=raw_alert.get(
            "severity",
            "UNKNOWN"
        ),
        confidence=0.5,
        anomaly_score=raw_alert.get(
            "anomaly_score"
        ),
        evidence=create_evidence(raw_alert)
    )


def normalize_unknown_alert(raw_alert):

    return SecurityAlert(
        attack_type=raw_alert["attack_type"],
        detection_method=raw_alert.get(
            "detection_method",
            "UNKNOWN"
        ),
        detector_name="unknown_detector",
        sources=[],
        targets=[],
        severity=raw_alert.get(
            "severity",
            "UNKNOWN"
        ),
        confidence=0.0,
        evidence=create_evidence(raw_alert)
    )


def create_rule_alert(
    raw_alert,
    sources,
    targets
):

    attack_type = raw_alert["attack_type"]

    return SecurityAlert(
        attack_type=attack_type,
        detection_method="RULE_BASED",
        detector_name=RULE_DETECTORS[
            attack_type
        ],
        sources=sources,
        targets=targets,
        severity=raw_alert.get(
            "severity",
            "UNKNOWN"
        ),
        confidence=1.0,
        evidence=create_evidence(raw_alert)
    )


def create_entity(
    entity_type,
    raw_alert,
    field_name
):

    if field_name not in raw_alert:
        raise ValueError(
            f"Raw alert must contain {field_name}"
        )

    return EntityReference(
        entity_type=entity_type,
        value=raw_alert[field_name]
    )


def require_list(
    raw_alert,
    field_name
):

    if field_name not in raw_alert:
        raise ValueError(
            f"Raw alert must contain {field_name}"
        )

    value = raw_alert[field_name]

    if not isinstance(value, list):
        raise TypeError(
            f"{field_name} must be a list"
        )

    return value


def create_evidence(raw_alert):

    excluded_fields = {
        "attack_type",
        "severity",
        "detection_method"
    }

    return {
        key: value
        for key, value in raw_alert.items()
        if key not in excluded_fields
    }
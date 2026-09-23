from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    "UNKNOWN"
}

VALID_STATUSES = {
    "NEW",
    "ANALYZING",
    "CORRELATED",
    "RESOLVED",
    "DISMISSED"
}


def generate_alert_id():

    return f"alert-{uuid4()}"


def current_utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


@dataclass(frozen=True)
class EntityReference:

    entity_type: str
    value: Any

    def __post_init__(self):

        if not isinstance(self.entity_type, str):
            raise TypeError(
                "Entity type must be a string"
            )

        if not self.entity_type.strip():
            raise ValueError(
                "Entity type cannot be empty"
            )

        if self.value is None:
            raise ValueError(
                "Entity value cannot be None"
            )


@dataclass
class SecurityAlert:

    attack_type: str
    detection_method: str
    detector_name: str

    sources: list[EntityReference]
    targets: list[EntityReference]

    severity: str
    confidence: float
    evidence: dict

    anomaly_score: float | None = None

    related_event_ids: list[str] = field(
        default_factory=list
    )

    status: str = "NEW"
    schema_version: str = "1.0"

    alert_id: str = field(
        default_factory=generate_alert_id
    )

    timestamp: str = field(
        default_factory=current_utc_timestamp
    )

    def __post_init__(self):

        self._validate_required_string(
            self.attack_type,
            "Attack type"
        )

        self._validate_required_string(
            self.detection_method,
            "Detection method"
        )

        self._validate_required_string(
            self.detector_name,
            "Detector name"
        )

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {self.severity}"
            )

        if not isinstance(
            self.confidence,
            (int, float)
        ):
            raise TypeError(
                "Confidence must be numeric"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Confidence must be between 0 and 1"
            )

        if not isinstance(self.sources, list):
            raise TypeError(
                "Sources must be a list"
            )

        if not all(
            isinstance(source, EntityReference)
            for source in self.sources
        ):
            raise TypeError(
                "Every source must be an EntityReference"
            )

        if not isinstance(self.targets, list):
            raise TypeError(
                "Targets must be a list"
            )

        if not all(
            isinstance(target, EntityReference)
            for target in self.targets
        ):
            raise TypeError(
                "Every target must be an EntityReference"
            )

        if not isinstance(self.evidence, dict):
            raise TypeError(
                "Evidence must be a dictionary"
            )

        if self.anomaly_score is not None:

            if not isinstance(
                self.anomaly_score,
                (int, float)
            ):
                raise TypeError(
                    "Anomaly score must be numeric or None"
                )

        if not isinstance(
            self.related_event_ids,
            list
        ):
            raise TypeError(
                "Related event IDs must be a list"
            )

        if not all(
            isinstance(event_id, str)
            for event_id in self.related_event_ids
        ):
            raise TypeError(
                "Every related event ID must be a string"
            )

        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid alert status: {self.status}"
            )

        self._validate_required_string(
            self.schema_version,
            "Schema version"
        )

        self._validate_required_string(
            self.alert_id,
            "Alert ID"
        )

        self._validate_required_string(
            self.timestamp,
            "Timestamp"
        )

    @staticmethod
    def _validate_required_string(
        value,
        field_name
    ):

        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        if not value.strip():
            raise ValueError(
                f"{field_name} cannot be empty"
            )

    def to_dict(self):

        return asdict(self)
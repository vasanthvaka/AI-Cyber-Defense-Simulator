from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from alerting.alert_schema import (
    EntityReference,
    SecurityAlert,
    VALID_SEVERITIES
)


VALID_INCIDENT_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "DISMISSED"
}


def generate_incident_id():

    return f"incident-{uuid4()}"


def current_utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


@dataclass
class SecurityIncident:

    incident_type: str
    severity: str
    confidence: float
    alerts: list[SecurityAlert]
    sources: list[EntityReference]
    targets: list[EntityReference]

    status: str = "OPEN"

    incident_id: str = field(
        default_factory=generate_incident_id
    )

    created_at: str = field(
        default_factory=current_utc_timestamp
    )

    updated_at: str = field(
        default_factory=current_utc_timestamp
    )

    def __post_init__(self):

        self._validate_required_string(
            self.incident_type,
            "Incident type"
        )

        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid incident severity: "
                f"{self.severity}"
            )

        if not isinstance(
            self.confidence,
            (int, float)
        ):
            raise TypeError(
                "Incident confidence must be numeric"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Incident confidence must be "
                "between 0 and 1"
            )

        if not isinstance(self.alerts, list):
            raise TypeError(
                "Incident alerts must be a list"
            )

        if not self.alerts:
            raise ValueError(
                "An incident must contain at "
                "least one alert"
            )

        if not all(
            isinstance(alert, SecurityAlert)
            for alert in self.alerts
        ):
            raise TypeError(
                "Every incident alert must be "
                "a SecurityAlert"
            )

        self._validate_entities(
            self.sources,
            "sources"
        )

        self._validate_entities(
            self.targets,
            "targets"
        )

        if self.status not in VALID_INCIDENT_STATUSES:
            raise ValueError(
                f"Invalid incident status: "
                f"{self.status}"
            )

        self._validate_required_string(
            self.incident_id,
            "Incident ID"
        )

        self._validate_required_string(
            self.created_at,
            "Created timestamp"
        )

        self._validate_required_string(
            self.updated_at,
            "Updated timestamp"
        )

    @property
    def alert_ids(self):

        return [
            alert.alert_id
            for alert in self.alerts
        ]

    @property
    def detection_methods(self):

        return sorted({
            alert.detection_method
            for alert in self.alerts
        })

    def to_dict(self):

        incident_dictionary = asdict(self)

        incident_dictionary["alert_ids"] = (
            self.alert_ids
        )

        incident_dictionary[
            "detection_methods"
        ] = self.detection_methods

        return incident_dictionary

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

    @staticmethod
    def _validate_entities(
        entities,
        field_name
    ):

        if not isinstance(entities, list):
            raise TypeError(
                f"Incident {field_name} must "
                f"be a list"
            )

        if not all(
            isinstance(entity, EntityReference)
            for entity in entities
        ):
            raise TypeError(
                f"Every incident {field_name[:-1]} "
                f"must be an EntityReference"
            )
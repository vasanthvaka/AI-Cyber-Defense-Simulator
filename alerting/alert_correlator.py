from datetime import datetime, timezone

from alerting.alert_schema import (
    EntityReference,
    SecurityAlert
)

from alerting.incident_schema import (
    SecurityIncident
)


SEVERITY_RANKS = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


class AlertCorrelator:

    def __init__(self, correlation_window=30):

        if not isinstance(
            correlation_window,
            (int, float)
        ):
            raise TypeError(
                "Correlation window must be numeric"
            )

        if correlation_window <= 0:
            raise ValueError(
                "Correlation window must be greater "
                "than zero"
            )

        self.correlation_window = correlation_window
        self.incidents = []

    def correlate(self, alert):

        if not isinstance(alert, SecurityAlert):
            raise TypeError(
                "Alert must be a SecurityAlert"
            )

        matching_incident = (
            self._find_matching_incident(alert)
        )

        if matching_incident is None:
            incident = self._create_incident(alert)
            self.incidents.append(incident)
            return incident

        self._add_alert_to_incident(
            matching_incident,
            alert
        )

        return matching_incident

    def _find_matching_incident(self, alert):

        for incident in reversed(self.incidents):

            if incident.status not in {
                "OPEN",
                "INVESTIGATING"
            }:
                continue

            if not self._within_time_window(
                incident,
                alert
            ):
                continue

            if not self._has_shared_entities(
                incident,
                alert
            ):
                continue

            if not self._attack_types_are_related(
                incident,
                alert
            ):
                continue

            return incident

        return None

    def _create_incident(self, alert):

        return SecurityIncident(
            incident_type=alert.attack_type,
            severity=alert.severity,
            confidence=alert.confidence,
            alerts=[
                alert
            ],
            sources=list(alert.sources),
            targets=list(alert.targets),
            created_at=alert.timestamp,
            updated_at=alert.timestamp
        )

    def _add_alert_to_incident(
        self,
        incident,
        alert
    ):

        if alert.alert_id in incident.alert_ids:
            return

        incident.alerts.append(alert)

        incident.sources = self._merge_entities(
            incident.sources,
            alert.sources
        )

        incident.targets = self._merge_entities(
            incident.targets,
            alert.targets
        )

        incident.severity = self._higher_severity(
            incident.severity,
            alert.severity
        )

        incident.confidence = max(
            incident.confidence,
            alert.confidence
        )

        if (
            incident.incident_type
            == "ANOMALOUS_BEHAVIOR"
            and alert.attack_type
            != "ANOMALOUS_BEHAVIOR"
        ):
            incident.incident_type = (
                alert.attack_type
            )

        incident.updated_at = alert.timestamp

    def _within_time_window(
        self,
        incident,
        alert
    ):

        incident_time = self._parse_timestamp(
            incident.updated_at
        )

        alert_time = self._parse_timestamp(
            alert.timestamp
        )

        time_difference = abs(
            (
                alert_time - incident_time
            ).total_seconds()
        )

        return (
            time_difference
            <= self.correlation_window
        )

    @staticmethod
    def _has_shared_entities(
        incident,
        alert
    ):

        shared_source = (
            AlertCorrelator._entities_overlap(
                incident.sources,
                alert.sources
            )
        )

        shared_target = (
            AlertCorrelator._entities_overlap(
                incident.targets,
                alert.targets
            )
        )

        return shared_source or shared_target

    @staticmethod
    def _attack_types_are_related(
        incident,
        alert
    ):

        if (
            incident.incident_type
            == alert.attack_type
        ):
            return True

        return (
            incident.incident_type
            == "ANOMALOUS_BEHAVIOR"
            or alert.attack_type
            == "ANOMALOUS_BEHAVIOR"
        )

    @staticmethod
    def _entities_overlap(
        first_entities,
        second_entities
    ):

        return any(
            first_entity == second_entity
            for first_entity in first_entities
            for second_entity in second_entities
        )

    @staticmethod
    def _merge_entities(
        existing_entities,
        new_entities
    ):

        merged_entities = list(
            existing_entities
        )

        for entity in new_entities:

            if entity not in merged_entities:
                merged_entities.append(entity)

        return merged_entities

    @staticmethod
    def _higher_severity(
        first_severity,
        second_severity
    ):

        if (
            SEVERITY_RANKS[second_severity]
            > SEVERITY_RANKS[first_severity]
        ):
            return second_severity

        return first_severity

    @staticmethod
    def _parse_timestamp(timestamp):

        if not isinstance(timestamp, str):
            raise TypeError(
                "Alert timestamp must be a string"
            )

        try:
            parsed_timestamp = (
                datetime.fromisoformat(
                    timestamp.replace(
                        "Z",
                        "+00:00"
                    )
                )
            )
        except ValueError as error:
            raise ValueError(
                "Alert timestamp must use "
                "ISO 8601 format"
            ) from error

        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = (
                parsed_timestamp.replace(
                    tzinfo=timezone.utc
                )
            )

        return parsed_timestamp
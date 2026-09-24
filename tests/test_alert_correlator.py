import unittest

from alerting.alert_correlator import AlertCorrelator
from alerting.alert_schema import (
    EntityReference,
    SecurityAlert
)


class TestAlertCorrelator(unittest.TestCase):

    def create_alert(
        self,
        attack_type="PORT_SCAN",
        detection_method="RULE_BASED",
        source_ip="10.0.2.50",
        target_ip="192.168.1.100",
        timestamp="2026-09-24T10:00:00+00:00",
        severity="MEDIUM",
        confidence=0.8
    ):

        targets = []

        if target_ip is not None:
            targets.append(
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value=target_ip
                )
            )

        detector_name = "port_scan_detector"

        if detection_method == "ISOLATION_FOREST":
            detector_name = "anomaly_detector"

        return SecurityAlert(
            attack_type=attack_type,
            detection_method=detection_method,
            detector_name=detector_name,
            sources=[
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value=source_ip
                )
            ],
            targets=targets,
            severity=severity,
            confidence=confidence,
            evidence={},
            timestamp=timestamp
        )

    def test_first_alert_creates_incident(self):

        correlator = AlertCorrelator()
        alert = self.create_alert()

        incident = correlator.correlate(alert)

        self.assertEqual(
            len(correlator.incidents),
            1
        )

        self.assertEqual(
            incident.incident_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            incident.alerts,
            [alert]
        )

    def test_related_rule_alerts_are_correlated(self):

        correlator = AlertCorrelator()

        first_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:00+00:00"
            )
        )

        second_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:15+00:00"
            )
        )

        first_incident = correlator.correlate(
            first_alert
        )

        second_incident = correlator.correlate(
            second_alert
        )

        self.assertIs(
            first_incident,
            second_incident
        )

        self.assertEqual(
            len(correlator.incidents),
            1
        )

        self.assertEqual(
            len(first_incident.alerts),
            2
        )

    def test_ai_alert_supports_rule_incident(self):

        correlator = AlertCorrelator()

        rule_alert = self.create_alert()

        ai_alert = self.create_alert(
            attack_type="ANOMALOUS_BEHAVIOR",
            detection_method="ISOLATION_FOREST",
            target_ip=None,
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            ),
            confidence=0.5
        )

        incident = correlator.correlate(
            rule_alert
        )

        correlated_incident = correlator.correlate(
            ai_alert
        )

        self.assertIs(
            incident,
            correlated_incident
        )

        self.assertEqual(
            incident.incident_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            incident.detection_methods,
            [
                "ISOLATION_FOREST",
                "RULE_BASED"
            ]
        )

    def test_rule_alert_promotes_ai_incident(self):

        correlator = AlertCorrelator()

        ai_alert = self.create_alert(
            attack_type="ANOMALOUS_BEHAVIOR",
            detection_method="ISOLATION_FOREST",
            target_ip=None,
            confidence=0.5
        )

        rule_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            )
        )

        incident = correlator.correlate(
            ai_alert
        )

        correlator.correlate(rule_alert)

        self.assertEqual(
            len(correlator.incidents),
            1
        )

        self.assertEqual(
            incident.incident_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            len(incident.alerts),
            2
        )

    def test_alert_outside_time_window_creates_incident(self):

        correlator = AlertCorrelator(
            correlation_window=30
        )

        first_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:00+00:00"
            )
        )

        second_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:31+00:00"
            )
        )

        correlator.correlate(first_alert)
        correlator.correlate(second_alert)

        self.assertEqual(
            len(correlator.incidents),
            2
        )

    def test_alert_without_shared_entity_creates_incident(self):

        correlator = AlertCorrelator()

        first_alert = self.create_alert(
            source_ip="10.0.2.50",
            target_ip="192.168.1.100"
        )

        second_alert = self.create_alert(
            source_ip="10.0.2.99",
            target_ip="192.168.1.200",
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            )
        )

        correlator.correlate(first_alert)
        correlator.correlate(second_alert)

        self.assertEqual(
            len(correlator.incidents),
            2
        )

    def test_unrelated_attack_types_are_not_correlated(self):

        correlator = AlertCorrelator()

        port_scan_alert = self.create_alert(
            attack_type="PORT_SCAN"
        )

        brute_force_alert = self.create_alert(
            attack_type="BRUTE_FORCE",
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            )
        )

        correlator.correlate(port_scan_alert)
        correlator.correlate(brute_force_alert)

        self.assertEqual(
            len(correlator.incidents),
            2
        )

    def test_duplicate_alert_is_not_added_twice(self):

        correlator = AlertCorrelator()
        alert = self.create_alert()

        incident = correlator.correlate(alert)
        correlator.correlate(alert)

        self.assertEqual(
            len(correlator.incidents),
            1
        )

        self.assertEqual(
            len(incident.alerts),
            1
        )

    def test_incident_severity_and_confidence_are_updated(self):

        correlator = AlertCorrelator()

        first_alert = self.create_alert(
            severity="MEDIUM",
            confidence=0.6
        )

        second_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            ),
            severity="HIGH",
            confidence=0.9
        )

        incident = correlator.correlate(
            first_alert
        )

        correlator.correlate(second_alert)

        self.assertEqual(
            incident.severity,
            "HIGH"
        )

        self.assertEqual(
            incident.confidence,
            0.9
        )

    def test_resolved_incident_is_not_reopened(self):

        correlator = AlertCorrelator()

        first_alert = self.create_alert()

        incident = correlator.correlate(
            first_alert
        )

        incident.status = "RESOLVED"

        second_alert = self.create_alert(
            timestamp=(
                "2026-09-24T10:00:10+00:00"
            )
        )

        new_incident = correlator.correlate(
            second_alert
        )

        self.assertEqual(
            len(correlator.incidents),
            2
        )

        self.assertIsNot(
            incident,
            new_incident
        )

    def test_invalid_inputs_are_rejected(self):

        with self.assertRaises(ValueError):
            AlertCorrelator(
                correlation_window=0
            )

        with self.assertRaises(TypeError):
            AlertCorrelator(
                correlation_window="30"
            )

        correlator = AlertCorrelator()

        with self.assertRaises(TypeError):
            correlator.correlate(
                {
                    "attack_type": "PORT_SCAN"
                }
            )


if __name__ == "__main__":
    unittest.main()
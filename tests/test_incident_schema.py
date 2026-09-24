import unittest

from alerting.alert_schema import (
    EntityReference,
    SecurityAlert
)

from alerting.incident_schema import (
    SecurityIncident
)


class TestSecurityIncident(unittest.TestCase):

    def create_rule_alert(self):

        return SecurityAlert(
            attack_type="PORT_SCAN",
            detection_method="RULE_BASED",
            detector_name="port_scan_detector",
            sources=[
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value="10.0.2.50"
                )
            ],
            targets=[
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value="192.168.1.100"
                )
            ],
            severity="MEDIUM",
            confidence=1.0,
            evidence={
                "ports_scanned": [
                    21,
                    22,
                    80,
                    443
                ]
            }
        )

    def create_ai_alert(self):

        return SecurityAlert(
            attack_type="ANOMALOUS_BEHAVIOR",
            detection_method="ISOLATION_FOREST",
            detector_name="anomaly_detector",
            sources=[
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value="10.0.2.50"
                )
            ],
            targets=[],
            severity="MEDIUM",
            confidence=0.5,
            anomaly_score=-0.06,
            evidence={
                "event_count": 10
            }
        )

    def create_valid_incident(self):

        rule_alert = self.create_rule_alert()

        return SecurityIncident(
            incident_type="PORT_SCAN",
            severity="MEDIUM",
            confidence=1.0,
            alerts=[
                rule_alert
            ],
            sources=list(
                rule_alert.sources
            ),
            targets=list(
                rule_alert.targets
            )
        )

    def test_create_valid_incident(self):

        incident = self.create_valid_incident()

        self.assertEqual(
            incident.incident_type,
            "PORT_SCAN"
        )

        self.assertEqual(
            incident.status,
            "OPEN"
        )

        self.assertEqual(
            len(incident.alerts),
            1
        )

        self.assertTrue(
            incident.incident_id.startswith(
                "incident-"
            )
        )

    def test_incident_ids_are_unique(self):

        first_incident = self.create_valid_incident()
        second_incident = self.create_valid_incident()

        self.assertNotEqual(
            first_incident.incident_id,
            second_incident.incident_id
        )

    def test_derived_alert_information(self):

        rule_alert = self.create_rule_alert()
        ai_alert = self.create_ai_alert()

        incident = SecurityIncident(
            incident_type="PORT_SCAN",
            severity="HIGH",
            confidence=1.0,
            alerts=[
                rule_alert,
                ai_alert
            ],
            sources=list(
                rule_alert.sources
            ),
            targets=list(
                rule_alert.targets
            )
        )

        self.assertEqual(
            incident.alert_ids,
            [
                rule_alert.alert_id,
                ai_alert.alert_id
            ]
        )

        self.assertEqual(
            incident.detection_methods,
            [
                "ISOLATION_FOREST",
                "RULE_BASED"
            ]
        )

    def test_incident_converts_to_dictionary(self):

        incident = self.create_valid_incident()

        incident_dictionary = incident.to_dict()

        self.assertEqual(
            incident_dictionary[
                "incident_type"
            ],
            "PORT_SCAN"
        )

        self.assertEqual(
            incident_dictionary[
                "alert_ids"
            ],
            incident.alert_ids
        )

        self.assertEqual(
            incident_dictionary[
                "detection_methods"
            ],
            [
                "RULE_BASED"
            ]
        )

        self.assertEqual(
            incident_dictionary[
                "sources"
            ][0],
            {
                "entity_type": "IP_ADDRESS",
                "value": "10.0.2.50"
            }
        )

    def test_empty_alert_list_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="MEDIUM",
                confidence=1.0,
                alerts=[],
                sources=[],
                targets=[]
            )

    def test_invalid_alert_is_rejected(self):

        with self.assertRaises(TypeError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="MEDIUM",
                confidence=1.0,
                alerts=[
                    {
                        "attack_type": "PORT_SCAN"
                    }
                ],
                sources=[],
                targets=[]
            )

    def test_invalid_severity_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="EXTREME",
                confidence=1.0,
                alerts=[
                    self.create_rule_alert()
                ],
                sources=[],
                targets=[]
            )

    def test_invalid_confidence_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="MEDIUM",
                confidence=1.5,
                alerts=[
                    self.create_rule_alert()
                ],
                sources=[],
                targets=[]
            )

    def test_invalid_status_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="MEDIUM",
                confidence=1.0,
                alerts=[
                    self.create_rule_alert()
                ],
                sources=[],
                targets=[],
                status="IGNORED"
            )

    def test_invalid_source_entity_is_rejected(self):

        with self.assertRaises(TypeError):
            SecurityIncident(
                incident_type="PORT_SCAN",
                severity="MEDIUM",
                confidence=1.0,
                alerts=[
                    self.create_rule_alert()
                ],
                sources=[
                    "10.0.2.50"
                ],
                targets=[]
            )


if __name__ == "__main__":
    unittest.main()
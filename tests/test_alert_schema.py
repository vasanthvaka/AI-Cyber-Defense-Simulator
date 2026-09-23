import unittest

from alerting.alert_schema import (
    EntityReference,
    SecurityAlert
)


class TestEntityReference(unittest.TestCase):

    def test_create_valid_entity_reference(self):

        entity = EntityReference(
            entity_type="IP_ADDRESS",
            value="10.0.0.50"
        )

        self.assertEqual(
            entity.entity_type,
            "IP_ADDRESS"
        )

        self.assertEqual(
            entity.value,
            "10.0.0.50"
        )

    def test_empty_entity_type_is_rejected(self):

        with self.assertRaises(ValueError):
            EntityReference(
                entity_type="",
                value="10.0.0.50"
            )

    def test_none_entity_value_is_rejected(self):

        with self.assertRaises(ValueError):
            EntityReference(
                entity_type="IP_ADDRESS",
                value=None
            )


class TestSecurityAlert(unittest.TestCase):

    def create_valid_alert(self):

        return SecurityAlert(
            attack_type="BRUTE_FORCE",
            detection_method="RULE_BASED",
            detector_name="brute_force_detector",
            sources=[
                EntityReference(
                    entity_type="IP_ADDRESS",
                    value="10.0.0.50"
                )
            ],
            targets=[
                EntityReference(
                    entity_type="USER_ACCOUNT",
                    value="admin"
                )
            ],
            severity="HIGH",
            confidence=1.0,
            evidence={
                "failed_attempts": 5
            }
        )

    def test_create_valid_security_alert(self):

        alert = self.create_valid_alert()

        self.assertEqual(
            alert.attack_type,
            "BRUTE_FORCE"
        )

        self.assertEqual(
            alert.detection_method,
            "RULE_BASED"
        )

        self.assertEqual(
            alert.severity,
            "HIGH"
        )

        self.assertEqual(
            alert.status,
            "NEW"
        )

        self.assertTrue(
            alert.alert_id.startswith("alert-")
        )

        self.assertIsNotNone(
            alert.timestamp
        )

    def test_alert_ids_are_unique(self):

        first_alert = self.create_valid_alert()
        second_alert = self.create_valid_alert()

        self.assertNotEqual(
            first_alert.alert_id,
            second_alert.alert_id
        )

    def test_invalid_severity_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityAlert(
                attack_type="BRUTE_FORCE",
                detection_method="RULE_BASED",
                detector_name="brute_force_detector",
                sources=[],
                targets=[],
                severity="EXTREME",
                confidence=1.0,
                evidence={}
            )

    def test_confidence_above_one_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityAlert(
                attack_type="BRUTE_FORCE",
                detection_method="RULE_BASED",
                detector_name="brute_force_detector",
                sources=[],
                targets=[],
                severity="HIGH",
                confidence=1.5,
                evidence={}
            )

    def test_confidence_below_zero_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityAlert(
                attack_type="BRUTE_FORCE",
                detection_method="RULE_BASED",
                detector_name="brute_force_detector",
                sources=[],
                targets=[],
                severity="HIGH",
                confidence=-0.1,
                evidence={}
            )

    def test_invalid_source_is_rejected(self):

        with self.assertRaises(TypeError):
            SecurityAlert(
                attack_type="BRUTE_FORCE",
                detection_method="RULE_BASED",
                detector_name="brute_force_detector",
                sources=["10.0.0.50"],
                targets=[],
                severity="HIGH",
                confidence=1.0,
                evidence={}
            )

    def test_invalid_status_is_rejected(self):

        with self.assertRaises(ValueError):
            SecurityAlert(
                attack_type="BRUTE_FORCE",
                detection_method="RULE_BASED",
                detector_name="brute_force_detector",
                sources=[],
                targets=[],
                severity="HIGH",
                confidence=1.0,
                evidence={},
                status="IGNORED"
            )

    def test_alert_converts_to_dictionary(self):

        alert = self.create_valid_alert()

        alert_dictionary = alert.to_dict()

        self.assertEqual(
            alert_dictionary["attack_type"],
            "BRUTE_FORCE"
        )

        self.assertEqual(
            alert_dictionary["sources"][0],
            {
                "entity_type": "IP_ADDRESS",
                "value": "10.0.0.50"
            }
        )

        self.assertEqual(
            alert_dictionary["targets"][0],
            {
                "entity_type": "USER_ACCOUNT",
                "value": "admin"
            }
        )

        self.assertEqual(
            alert_dictionary["evidence"],
            {
                "failed_attempts": 5
            }
        )


if __name__ == "__main__":
    unittest.main()
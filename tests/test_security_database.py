import tempfile
import unittest
from pathlib import Path

from storage.database import SecurityDatabase


class TestSecurityDatabase(unittest.TestCase):

    def setUp(self):

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        database_path = (
            Path(self.temp_directory.name)
            / "test_security.db"
        )

        self.database = SecurityDatabase(
            database_path
        )

    def tearDown(self):

        self.temp_directory.cleanup()

    def test_database_creates_required_tables(self):

        expected_tables = {
            "events",
            "alerts",
            "incidents",
            "analyses",
            "decisions",
            "responses",
            "audit_records"
        }

        with self.database.connect() as connection:

            rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()

        created_tables = {
            row["name"]
            for row in rows
        }

        self.assertTrue(
            expected_tables.issubset(
                created_tables
            )
        )

    def test_save_and_read_event(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "status": "FAILED"
        }

        event_id = self.database.save_event(
            event
        )

        stored_event = self.database.get_record(
            "events",
            event_id
        )

        self.assertEqual(
            stored_event["event_type"],
            "LOGIN_ATTEMPT"
        )

        self.assertEqual(
            stored_event["payload"],
            event
        )

    def test_save_and_update_alert(self):

        alert = {
            "alert_id": "alert-test",
            "attack_type": "BRUTE_FORCE",
            "detection_method": "RULE_BASED",
            "severity": "HIGH",
            "confidence": 1.0,
            "status": "NEW",
            "timestamp": (
                "2026-09-24T10:00:00+00:00"
            )
        }

        self.database.save_alert(alert)

        alert["status"] = "CORRELATED"

        self.database.save_alert(alert)

        stored_alert = self.database.get_record(
            "alerts",
            "alert-test"
        )

        self.assertEqual(
            self.database.count_records(
                "alerts"
            ),
            1
        )

        self.assertEqual(
            stored_alert["status"],
            "CORRELATED"
        )

    def test_incident_is_updated_not_duplicated(self):

        incident = {
            "incident_id": "incident-test",
            "incident_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "confidence": 1.0,
            "status": "OPEN",
            "created_at": (
                "2026-09-24T10:00:00+00:00"
            ),
            "updated_at": (
                "2026-09-24T10:00:00+00:00"
            ),
            "alerts": []
        }

        self.database.save_incident(
            incident
        )

        incident["severity"] = "HIGH"
        incident["updated_at"] = (
            "2026-09-24T10:01:00+00:00"
        )

        self.database.save_incident(
            incident
        )

        stored_incident = (
            self.database.get_record(
                "incidents",
                "incident-test"
            )
        )

        self.assertEqual(
            self.database.count_records(
                "incidents"
            ),
            1
        )

        self.assertEqual(
            stored_incident["severity"],
            "HIGH"
        )

    def test_save_analysis(self):

        analysis = {
            "analysis_id": "analysis-test",
            "incident_id": "incident-test",
            "risk_score": 90,
            "confidence": 0.95,
            "severity": "HIGH",
            "requires_human_review": False,
            "recommended_escalation": (
                "IMMEDIATE_RESPONSE"
            ),
            "timestamp": (
                "2026-09-24T10:00:01+00:00"
            )
        }

        analysis_id = (
            self.database.save_analysis(
                analysis
            )
        )

        stored_analysis = (
            self.database.get_record(
                "analyses",
                analysis_id
            )
        )

        self.assertEqual(
            stored_analysis["risk_score"],
            90
        )

        self.assertEqual(
            stored_analysis[
                "requires_human_review"
            ],
            0
        )

    def test_save_decision_response_and_audit(self):

        decision = {
            "incident_id": "incident-test",
            "recommended_action": "BLOCK_IP",
            "automatic": True,
            "requires_human_review": False
        }

        response = {
            "incident_id": "incident-test",
            "attack_type": "BRUTE_FORCE",
            "action": "BLOCK_IP",
            "status": "SIMULATED_SUCCESS",
            "automatic": True,
            "simulated": True,
            "audit_id": "audit-test",
            "timestamp_utc": (
                "2026-09-24T10:00:02+00:00"
            ),
            "policy_status": "ALLOWED",
            "policy_reason": (
                "The action passed response policy."
            )
        }

        decision_id = (
            self.database.save_decision(
                decision
            )
        )

        response_id = (
            self.database.save_response(
                response
            )
        )

        audit_id = (
            self.database.save_audit_record(
                response
            )
        )

        self.assertIsNotNone(
            self.database.get_record(
                "decisions",
                decision_id
            )
        )

        self.assertIsNotNone(
            self.database.get_record(
                "responses",
                response_id
            )
        )

        self.assertIsNotNone(
            self.database.get_record(
                "audit_records",
                audit_id
            )
        )

    def test_get_records_supports_limit(self):

        for index in range(3):

            self.database.save_event(
                {
                    "event_id": (
                        f"event-{index}"
                    ),
                    "event_type": "HTTP_REQUEST",
                    "timestamp": (
                        f"10:00:0{index}"
                    )
                }
            )

        records = self.database.get_records(
            "events",
            limit=2
        )

        self.assertEqual(
            len(records),
            2
        )

    def test_unknown_table_is_rejected(self):

        with self.assertRaises(ValueError):

            self.database.get_records(
                "not_a_real_table"
            )


if __name__ == "__main__":
    unittest.main()
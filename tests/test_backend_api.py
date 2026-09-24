import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api import create_app
from storage.database import SecurityDatabase


class TestBackendAPI(unittest.TestCase):

    def setUp(self):

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        database_path = (
            Path(self.temp_directory.name)
            / "api_test.db"
        )

        self.database = SecurityDatabase(
            database_path
        )

        self.event = {
            "event_id": "event-test",
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "status": "FAILED"
        }

        self.incident = {
            "incident_id": "incident-test",
            "incident_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "confidence": 1.0,
            "status": "OPEN",
            "created_at": (
                "2026-09-24T10:00:00+00:00"
            ),
            "updated_at": (
                "2026-09-24T10:00:01+00:00"
            ),
            "alerts": []
        }

        self.database.save_event(
            self.event
        )

        self.database.save_incident(
            self.incident
        )

        self.app = create_app(
            database=self.database
        )

        self.client = TestClient(
            self.app
        )

    def tearDown(self):

        self.client.close()
        self.temp_directory.cleanup()

    def test_root_returns_api_information(self):

        response = self.client.get("/")

        self.assertEqual(
            response.status_code,
            200
        )

        data = response.json()

        self.assertEqual(
            data["name"],
            "AI-Powered Cyber Defense API"
        )

        self.assertEqual(
            data["documentation"],
            "/docs"
        )

    def test_health_endpoint(self):

        response = self.client.get(
            "/api/health"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        data = response.json()

        self.assertEqual(
            data["status"],
            "HEALTHY"
        )

        self.assertEqual(
            data["database"],
            "CONNECTED"
        )

        self.assertEqual(
            data["stored_events"],
            1
        )

    def test_statistics_endpoint(self):

        response = self.client.get(
            "/api/statistics"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        counts = response.json()[
            "counts"
        ]

        self.assertEqual(
            counts["events"],
            1
        )

        self.assertEqual(
            counts["incidents"],
            1
        )

        self.assertEqual(
            counts["responses"],
            0
        )

    def test_collection_endpoints_are_available(
        self
    ):

        endpoints = [
            "/api/events",
            "/api/alerts",
            "/api/incidents",
            "/api/analyses",
            "/api/decisions",
            "/api/responses",
            "/api/audit-records"
        ]

        for endpoint in endpoints:

            with self.subTest(
                endpoint=endpoint
            ):

                response = self.client.get(
                    endpoint
                )

                self.assertEqual(
                    response.status_code,
                    200
                )

                data = response.json()

                self.assertIn(
                    "count",
                    data
                )

                self.assertIn(
                    "items",
                    data
                )

    def test_event_list_returns_stored_event(
        self
    ):

        response = self.client.get(
            "/api/events"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        data = response.json()

        self.assertEqual(
            data["count"],
            1
        )

        self.assertEqual(
            data["items"][0]["event_id"],
            "event-test"
        )

        self.assertEqual(
            data["items"][0]["payload"],
            self.event
        )

    def test_get_incident_by_id(self):

        response = self.client.get(
            "/api/incidents/incident-test"
        )

        self.assertEqual(
            response.status_code,
            200
        )

        data = response.json()

        self.assertEqual(
            data["incident_id"],
            "incident-test"
        )

        self.assertEqual(
            data["incident_type"],
            "BRUTE_FORCE"
        )

    def test_missing_record_returns_404(self):

        response = self.client.get(
            "/api/incidents/missing-incident"
        )

        self.assertEqual(
            response.status_code,
            404
        )

        self.assertEqual(
            response.json()["detail"],
            "Incident was not found"
        )

    def test_invalid_limit_returns_422(self):

        response = self.client.get(
            "/api/events?limit=0"
        )

        self.assertEqual(
            response.status_code,
            422
        )

    def test_dashboard_origin_is_allowed(self):

        response = self.client.get(
            "/api/health",
            headers={
                "Origin":
                    "http://localhost:5173"
            }
        )

        self.assertEqual(
            response.headers[
                "access-control-allow-origin"
            ],
            "http://localhost:5173"
        )


if __name__ == "__main__":
    unittest.main()
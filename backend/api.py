from pathlib import Path

from fastapi import (
    FastAPI,
    HTTPException,
    Query
)

from fastapi.middleware.cors import (
    CORSMiddleware
)

from storage.database import (
    SecurityDatabase
)


PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent

DEFAULT_DATABASE_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_defense.db"
)


def create_app(database=None):

    app = FastAPI(
        title=(
            "AI-Powered Cyber Defense API"
        ),
        description=(
            "REST API for accessing security "
            "events, incidents, analyses, "
            "decisions and simulated responses."
        ),
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173"
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    app.state.database = (
        database
        if database is not None
        else SecurityDatabase(
            DEFAULT_DATABASE_FILE
        )
    )

    def get_records(
        table_name,
        limit
    ):

        records = (
            app.state.database.get_records(
                table_name,
                limit=limit
            )
        )

        return {
            "count": len(records),
            "items": records
        }

    def get_record(
        table_name,
        record_id,
        record_name
    ):

        record = (
            app.state.database.get_record(
                table_name,
                record_id
            )
        )

        if record is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"{record_name} was not found"
                )
            )

        return record

    @app.get("/")
    def api_information():

        return {
            "name": (
                "AI-Powered Cyber Defense API"
            ),
            "version": "1.0.0",
            "documentation": "/docs",
            "health": "/api/health"
        }

    @app.get("/api/health")
    def health_check():

        event_count = (
            app.state.database.count_records(
                "events"
            )
        )

        return {
            "status": "HEALTHY",
            "database": "CONNECTED",
            "stored_events": event_count
        }

    @app.get("/api/statistics")
    def get_statistics():

        table_names = [
            "events",
            "alerts",
            "incidents",
            "analyses",
            "decisions",
            "responses",
            "audit_records"
        ]

        counts = {
            table_name: (
                app.state.database.count_records(
                    table_name
                )
            )
            for table_name in table_names
        }

        return {
            "status": "SUCCESS",
            "counts": counts
        }

    @app.get("/api/events")
    def get_events(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "events",
            limit
        )

    @app.get(
        "/api/events/{event_id}"
    )
    def get_event(event_id: str):

        return get_record(
            "events",
            event_id,
            "Event"
        )

    @app.get("/api/alerts")
    def get_alerts(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "alerts",
            limit
        )

    @app.get(
        "/api/alerts/{alert_id}"
    )
    def get_alert(alert_id: str):

        return get_record(
            "alerts",
            alert_id,
            "Alert"
        )

    @app.get("/api/incidents")
    def get_incidents(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "incidents",
            limit
        )

    @app.get(
        "/api/incidents/{incident_id}"
    )
    def get_incident(
        incident_id: str
    ):

        return get_record(
            "incidents",
            incident_id,
            "Incident"
        )

    @app.get("/api/analyses")
    def get_analyses(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "analyses",
            limit
        )

    @app.get(
        "/api/analyses/{analysis_id}"
    )
    def get_analysis(
        analysis_id: str
    ):

        return get_record(
            "analyses",
            analysis_id,
            "Analysis"
        )

    @app.get("/api/decisions")
    def get_decisions(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "decisions",
            limit
        )

    @app.get(
        "/api/decisions/{decision_id}"
    )
    def get_decision(
        decision_id: str
    ):

        return get_record(
            "decisions",
            decision_id,
            "Decision"
        )

    @app.get("/api/responses")
    def get_responses(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "responses",
            limit
        )

    @app.get(
        "/api/responses/{response_id}"
    )
    def get_response(
        response_id: str
    ):

        return get_record(
            "responses",
            response_id,
            "Response"
        )

    @app.get("/api/audit-records")
    def get_audit_records(
        limit: int = Query(
            default=100,
            ge=1,
            le=500
        )
    ):

        return get_records(
            "audit_records",
            limit
        )

    @app.get(
        "/api/audit-records/{audit_id}"
    )
    def get_audit_record(
        audit_id: str
    ):

        return get_record(
            "audit_records",
            audit_id,
            "Audit record"
        )

    return app


app = create_app()
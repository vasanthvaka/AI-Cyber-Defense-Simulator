from pathlib import Path

from pydantic import BaseModel, Field

from backend.simulation_controller import (
    SimulationController,
    SimulationBusyError
)

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

from agents.llm_explainer import (
    LLMExplainer
)

class NormalTrafficRequest(BaseModel):

    count: int = Field(
        default=10,
        ge=1,
        le=100
    )


class DemoSimulationRequest(BaseModel):

    seed: int | None = Field(default=42)


class LiveSimulationRequest(BaseModel):

    seed: int | None = Field(default=None)
    use_random_seed: bool = Field(default=False)

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

    app.state.simulation_controller = (
        SimulationController(
            database=app.state.database
        )
    )

    app.state.llm_explainer = (
        LLMExplainer()
    )

    # =====================================
    # SIMULATION CONTROL ENDPOINTS
    # =====================================

    @app.get("/api/simulation/status")
    def simulation_status():

        return (
            app.state.simulation_controller
            .get_status()
        )

    @app.post("/api/simulation/normal")
    def generate_normal_traffic(
        request: NormalTrafficRequest
    ):

        try:

            return (
                app.state.simulation_controller
                .generate_normal_batch(
                    count=request.count
                )
            )

        except SimulationBusyError as error:

            raise HTTPException(
                status_code=409,
                detail=str(error)
            )

    @app.post(
        "/api/simulation/attacks/random"
    )
    def inject_random_attack():

        try:

            return (
                app.state.simulation_controller
                .inject_random_attack()
            )

        except SimulationBusyError as error:

            raise HTTPException(
                status_code=409,
                detail=str(error)
            )

    @app.post(
        "/api/simulation/attacks/{attack_type}"
    )
    def inject_attack(
        attack_type: str
    ):

        try:

            return (
                app.state.simulation_controller
                .inject_attack(
                    attack_type
                )
            )

        except ValueError as error:

            raise HTTPException(
                status_code=400,
                detail=str(error)
            )

        except SimulationBusyError as error:

            raise HTTPException(
                status_code=409,
                detail=str(error)
            )

    @app.post("/api/simulation/demo")
    def run_demo_simulation(
        request: DemoSimulationRequest = None
    ):

        seed = request.seed if request is not None else 42

        try:

            return (
                app.state.simulation_controller
                .run_demo(seed=seed)
            )

        except SimulationBusyError as error:

            raise HTTPException(
                status_code=409,
                detail=str(error)
            )

    @app.post("/api/simulation/live/start")
    def start_live_simulation(
        request: LiveSimulationRequest = None
    ):

        seed = None
        if request is not None and not request.use_random_seed:
            seed = request.seed

        try:

            return (
                app.state.simulation_controller
                .start_live_mode(seed=seed)
            )

        except SimulationBusyError as error:

            raise HTTPException(
                status_code=409,
                detail=str(error)
            )

    @app.post("/api/simulation/live/stop")
    def stop_live_simulation():

        return (
            app.state.simulation_controller
            .stop_live_mode()
        )

    @app.get("/api/simulation/live/log")
    def get_live_log():
        ctrl = app.state.simulation_controller
        return {
            "entries": list(ctrl.live_log),
            "is_running": ctrl.live_status.get("is_running", False),
            "events_generated": ctrl.live_status.get("events_generated", 0),
            "attacks_injected": ctrl.live_status.get("attacks_injected", 0)
        }
    
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

    @app.post(
        "/api/incidents/{incident_id}/explain"
    )
    def explain_incident(
        incident_id: str
    ):

        incident = app.state.database.get_record(
            "incidents",
            incident_id
        )

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id} was not found"
            )

        analysis = (
            app.state.database.get_analysis_for_incident(
                incident_id
            )
        )

        decision = (
            app.state.database.get_decision_for_incident(
                incident_id
            )
        )

        incident_data = dict(
            incident.get("payload", incident)
        )
        incident_data["incident_id"] = incident["incident_id"]
        incident_data["incident_type"] = incident["incident_type"]
        incident_data["severity"] = incident["severity"]
        incident_data["confidence"] = incident["confidence"]

        analysis_payload = (
            analysis.get("payload", analysis)
            if analysis is not None
            else None
        )

        decision_payload = (
            decision.get("payload", decision)
            if decision is not None
            else None
        )

        explanation = (
            app.state.llm_explainer.explain_incident(
                incident=incident_data,
                analysis=analysis_payload,
                decision=decision_payload
            )
        )

        if analysis is not None:
            analysis_dict = dict(
                analysis.get("payload", analysis)
            )
            analysis_dict["analysis_method"] = (
                "LLM_ASSISTED"
            )
            analysis_dict["llm_enrichment"] = (
                explanation
            )
            app.state.database.save_analysis(
                analysis_dict
            )

        incident_dict = dict(
            incident.get("payload", incident)
        )
        incident_dict["incident_id"] = incident["incident_id"]
        incident_dict["incident_type"] = incident["incident_type"]
        incident_dict["severity"] = incident["severity"]
        incident_dict["confidence"] = incident["confidence"]
        incident_dict["status"] = incident["status"]
        incident_dict["created_at"] = incident["created_at"]
        incident_dict["updated_at"] = incident["updated_at"]
        incident_dict["llm_enrichment"] = explanation
        app.state.database.save_incident(
            incident_dict
        )

        return {
            "status": "SUCCESS",
            "incident_id": incident_id,
            "explanation": explanation
        }

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
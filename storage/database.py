import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from contextlib import contextmanager

TABLE_ID_COLUMNS = {
    "events": "event_id",
    "alerts": "alert_id",
    "incidents": "incident_id",
    "analyses": "analysis_id",
    "decisions": "decision_id",
    "responses": "response_id",
    "audit_records": "audit_id"
}


class SecurityDatabase:

    def __init__(self, database_path):

        if not isinstance(
            database_path,
            (str, Path)
        ):
            raise TypeError(
                "Database path must be a string or Path"
            )

        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.initialize_database()
        
    @contextmanager
    def connect(self):

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        try:
            yield connection
            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def initialize_database(self):

        with self.connect() as connection:

            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    event_timestamp TEXT,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    attack_type TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL,
                    alert_timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    requires_human_review INTEGER NOT NULL,
                    recommended_escalation TEXT NOT NULL,
                    analysis_timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    automatic INTEGER NOT NULL,
                    requires_human_review INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS responses (
                    response_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    automatic INTEGER NOT NULL,
                    simulated INTEGER NOT NULL,
                    audit_id TEXT,
                    response_timestamp TEXT,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_records (
                    audit_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    action TEXT NOT NULL,
                    policy_status TEXT NOT NULL,
                    policy_reason TEXT NOT NULL,
                    audit_timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS
                    index_events_type
                    ON events(event_type);

                CREATE INDEX IF NOT EXISTS
                    index_alerts_attack_type
                    ON alerts(attack_type);

                CREATE INDEX IF NOT EXISTS
                    index_incidents_status
                    ON incidents(status);

                CREATE INDEX IF NOT EXISTS
                    index_analyses_incident
                    ON analyses(incident_id);

                CREATE INDEX IF NOT EXISTS
                    index_decisions_incident
                    ON decisions(incident_id);

                CREATE INDEX IF NOT EXISTS
                    index_responses_incident
                    ON responses(incident_id);

                CREATE INDEX IF NOT EXISTS
                    index_audit_incident
                    ON audit_records(incident_id);
                """
            )

    def save_event(self, event):

        event = self._to_dictionary(
            event,
            "Event"
        )

        event_id = event.get(
            "event_id",
            f"event-{uuid4()}"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT INTO events (
                    event_id,
                    event_type,
                    event_timestamp,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.get(
                        "event_type",
                        "UNKNOWN"
                    ),
                    event.get("timestamp"),
                    self._to_json(event),
                    self._current_timestamp()
                )
            )

        return event_id

    def save_alert(self, alert):

        alert = self._to_dictionary(
            alert,
            "Alert"
        )

        alert_id = self._required(
            alert,
            "alert_id",
            "Alert"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id,
                    attack_type,
                    detection_method,
                    severity,
                    confidence,
                    status,
                    alert_timestamp,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    self._required(
                        alert,
                        "attack_type",
                        "Alert"
                    ),
                    self._required(
                        alert,
                        "detection_method",
                        "Alert"
                    ),
                    self._required(
                        alert,
                        "severity",
                        "Alert"
                    ),
                    float(
                        alert.get(
                            "confidence",
                            0
                        )
                    ),
                    alert.get(
                        "status",
                        "NEW"
                    ),
                    self._required(
                        alert,
                        "timestamp",
                        "Alert"
                    ),
                    self._to_json(alert),
                    self._current_timestamp()
                )
            )

        return alert_id

    def save_incident(self, incident):

        incident = self._to_dictionary(
            incident,
            "Incident"
        )

        incident_id = self._required(
            incident,
            "incident_id",
            "Incident"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id,
                    incident_type,
                    severity,
                    confidence,
                    status,
                    created_at,
                    updated_at,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(incident_id)
                DO UPDATE SET
                    incident_type =
                        excluded.incident_type,
                    severity =
                        excluded.severity,
                    confidence =
                        excluded.confidence,
                    status =
                        excluded.status,
                    updated_at =
                        excluded.updated_at,
                    payload_json =
                        excluded.payload_json,
                    stored_at =
                        excluded.stored_at
                """,
                (
                    incident_id,
                    self._required(
                        incident,
                        "incident_type",
                        "Incident"
                    ),
                    self._required(
                        incident,
                        "severity",
                        "Incident"
                    ),
                    float(
                        incident.get(
                            "confidence",
                            0
                        )
                    ),
                    incident.get(
                        "status",
                        "OPEN"
                    ),
                    self._required(
                        incident,
                        "created_at",
                        "Incident"
                    ),
                    self._required(
                        incident,
                        "updated_at",
                        "Incident"
                    ),
                    self._to_json(incident),
                    self._current_timestamp()
                )
            )

        return incident_id

    def save_analysis(self, analysis):

        analysis = self._to_dictionary(
            analysis,
            "Analysis"
        )

        analysis_id = self._required(
            analysis,
            "analysis_id",
            "Analysis"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO analyses (
                    analysis_id,
                    incident_id,
                    risk_score,
                    confidence,
                    severity,
                    requires_human_review,
                    recommended_escalation,
                    analysis_timestamp,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    self._required(
                        analysis,
                        "incident_id",
                        "Analysis"
                    ),
                    float(
                        analysis.get(
                            "risk_score",
                            0
                        )
                    ),
                    float(
                        analysis.get(
                            "confidence",
                            0
                        )
                    ),
                    self._required(
                        analysis,
                        "severity",
                        "Analysis"
                    ),
                    int(
                        bool(
                            analysis.get(
                                "requires_human_review",
                                False
                            )
                        )
                    ),
                    self._required(
                        analysis,
                        "recommended_escalation",
                        "Analysis"
                    ),
                    self._required(
                        analysis,
                        "timestamp",
                        "Analysis"
                    ),
                    self._to_json(analysis),
                    self._current_timestamp()
                )
            )

        return analysis_id

    def save_decision(self, decision):

        decision = self._to_dictionary(
            decision,
            "Decision"
        )

        decision_id = decision.get(
            "decision_id",
            f"decision-{uuid4()}"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT INTO decisions (
                    decision_id,
                    incident_id,
                    recommended_action,
                    automatic,
                    requires_human_review,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    self._required(
                        decision,
                        "incident_id",
                        "Decision"
                    ),
                    self._required(
                        decision,
                        "recommended_action",
                        "Decision"
                    ),
                    int(
                        bool(
                            decision.get(
                                "automatic",
                                False
                            )
                        )
                    ),
                    int(
                        bool(
                            decision.get(
                                "requires_human_review",
                                False
                            )
                        )
                    ),
                    self._to_json(decision),
                    self._current_timestamp()
                )
            )

        return decision_id

    def save_response(self, response):

        response = self._to_dictionary(
            response,
            "Response"
        )

        response_id = response.get(
            "response_id",
            f"response-{uuid4()}"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT INTO responses (
                    response_id,
                    incident_id,
                    action,
                    status,
                    automatic,
                    simulated,
                    audit_id,
                    response_timestamp,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response_id,
                    response.get("incident_id"),
                    self._required(
                        response,
                        "action",
                        "Response"
                    ),
                    self._required(
                        response,
                        "status",
                        "Response"
                    ),
                    int(
                        bool(
                            response.get(
                                "automatic",
                                False
                            )
                        )
                    ),
                    int(
                        bool(
                            response.get(
                                "simulated",
                                False
                            )
                        )
                    ),
                    response.get("audit_id"),
                    response.get(
                        "timestamp_utc"
                    ),
                    self._to_json(response),
                    self._current_timestamp()
                )
            )

        return response_id

    def save_audit_record(self, response):

        response = self._to_dictionary(
            response,
            "Audit record"
        )

        audit_id = self._required(
            response,
            "audit_id",
            "Audit record"
        )

        with self.connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO audit_records (
                    audit_id,
                    incident_id,
                    action,
                    policy_status,
                    policy_reason,
                    audit_timestamp,
                    payload_json,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    response.get("incident_id"),
                    self._required(
                        response,
                        "action",
                        "Audit record"
                    ),
                    self._required(
                        response,
                        "policy_status",
                        "Audit record"
                    ),
                    self._required(
                        response,
                        "policy_reason",
                        "Audit record"
                    ),
                    self._required(
                        response,
                        "timestamp_utc",
                        "Audit record"
                    ),
                    self._to_json(response),
                    self._current_timestamp()
                )
            )

        return audit_id

    def get_records(
        self,
        table_name,
        limit=100
    ):

        self._validate_table_name(
            table_name
        )

        if not isinstance(limit, int):
            raise TypeError(
                "Limit must be an integer"
            )

        if limit <= 0:
            raise ValueError(
                "Limit must be greater than zero"
            )

        with self.connect() as connection:

            rows = connection.execute(
                f"""
                SELECT *
                FROM {table_name}
                ORDER BY rowid DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        return [
            self._decode_row(row)
            for row in rows
        ]

    def get_record(
        self,
        table_name,
        record_id
    ):

        self._validate_table_name(
            table_name
        )

        id_column = TABLE_ID_COLUMNS[
            table_name
        ]

        with self.connect() as connection:

            row = connection.execute(
                f"""
                SELECT *
                FROM {table_name}
                WHERE {id_column} = ?
                """,
                (record_id,)
            ).fetchone()

        if row is None:
            return None

        return self._decode_row(row)

    def count_records(self, table_name):

        self._validate_table_name(
            table_name
        )

        with self.connect() as connection:

            row = connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM {table_name}
                """
            ).fetchone()

        return row["total"]

    @staticmethod
    def _to_dictionary(
        record,
        record_name
    ):

        if isinstance(record, dict):
            return dict(record)

        if is_dataclass(record):
            return asdict(record)

        to_dict = getattr(
            record,
            "to_dict",
            None
        )

        if callable(to_dict):

            converted_record = to_dict()

            if isinstance(
                converted_record,
                dict
            ):
                return converted_record

        raise TypeError(
            f"{record_name} must be a dictionary "
            f"or serializable model"
        )

    @staticmethod
    def _required(
        record,
        field_name,
        record_name
    ):

        value = record.get(field_name)

        if value is None:
            raise ValueError(
                f"{record_name} must contain "
                f"{field_name}"
            )

        if (
            isinstance(value, str)
            and not value.strip()
        ):
            raise ValueError(
                f"{record_name} must contain "
                f"{field_name}"
            )

        return value

    @staticmethod
    def _to_json(record):

        return json.dumps(
            record,
            sort_keys=True,
            default=(
                lambda value:
                sorted(value)
                if isinstance(value, set)
                else str(value)
            )
        )

    @staticmethod
    def _decode_row(row):

        result = dict(row)

        result["payload"] = json.loads(
            result.pop("payload_json")
        )

        return result

    @staticmethod
    def _current_timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _validate_table_name(
        table_name
    ):

        if table_name not in TABLE_ID_COLUMNS:
            raise ValueError(
                f"Unsupported table: {table_name}"
            )
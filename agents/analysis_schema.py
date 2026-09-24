from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
from alerting.alert_schema import VALID_SEVERITIES


VALID_ANALYSIS_METHODS = {
    "DETERMINISTIC",
    "LLM_ASSISTED",
    "HYBRID"
}


VALID_ESCALATIONS = {
    "MONITOR",
    "INVESTIGATE",
    "RESPOND",
    "IMMEDIATE_RESPONSE"
}


def generate_analysis_id():

    return f"analysis-{uuid4()}"


def current_utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


@dataclass
class IncidentAnalysis:

    incident_id: str
    incident_type: str
    risk_score: float
    confidence: float
    severity: str
    evidence_count: int
    detection_methods: list[str]
    key_findings: list[str]
    requires_human_review: bool
    recommended_escalation: str

    analysis_method: str = "DETERMINISTIC"
    llm_enrichment: dict | None = None

    analysis_id: str = field(
        default_factory=generate_analysis_id
    )

    timestamp: str = field(
        default_factory=current_utc_timestamp
    )

    def __post_init__(self):

        self._validate_required_string(
            self.incident_id,
            "Incident ID"
        )

        self._validate_required_string(
            self.incident_type,
            "Incident type"
        )

        if not isinstance(
            self.risk_score,
            (int, float)
        ):
            raise TypeError(
                "Risk score must be numeric"
            )

        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                "Risk score must be between "
                "0 and 100"
            )

        if not isinstance(
            self.confidence,
            (int, float)
        ):
            raise TypeError(
                "Confidence must be numeric"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Confidence must be between "
                "0 and 1"
            )

        self._validate_required_string(
            self.severity,
            "Severity"
        )
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid analysis severity: "
                f"{self.severity}"
            )

        if not isinstance(
            self.evidence_count,
            int
        ):
            raise TypeError(
                "Evidence count must be an integer"
            )

        if self.evidence_count < 0:
            raise ValueError(
                "Evidence count cannot be negative"
            )

        self._validate_string_list(
            self.detection_methods,
            "Detection methods"
        )

        self._validate_string_list(
            self.key_findings,
            "Key findings"
        )

        if not isinstance(
            self.requires_human_review,
            bool
        ):
            raise TypeError(
                "Human-review flag must be "
                "a boolean"
            )

        if (
            self.recommended_escalation
            not in VALID_ESCALATIONS
        ):
            raise ValueError(
                f"Invalid recommended escalation: "
                f"{self.recommended_escalation}"
            )

        if (
            self.analysis_method
            not in VALID_ANALYSIS_METHODS
        ):
            raise ValueError(
                f"Invalid analysis method: "
                f"{self.analysis_method}"
            )

        if (
            self.llm_enrichment is not None
            and not isinstance(
                self.llm_enrichment,
                dict
            )
        ):
            raise TypeError(
                "LLM enrichment must be a "
                "dictionary or None"
            )

        self._validate_required_string(
            self.analysis_id,
            "Analysis ID"
        )

        self._validate_required_string(
            self.timestamp,
            "Timestamp"
        )

    def to_dict(self):

        return asdict(self)

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
    def _validate_string_list(
        values,
        field_name
    ):

        if not isinstance(values, list):
            raise TypeError(
                f"{field_name} must be a list"
            )

        if not all(
            isinstance(value, str)
            for value in values
        ):
            raise TypeError(
                f"Every item in {field_name} "
                f"must be a string"
            )
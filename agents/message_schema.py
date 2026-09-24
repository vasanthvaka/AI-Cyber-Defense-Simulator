from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


VALID_AGENT_NAMES = {
    "MONITORING_AGENT",
    "ANALYSIS_AGENT",
    "DECISION_AGENT",
    "RESPONSE_AGENT",
    "COORDINATOR"
}


VALID_MESSAGE_TYPES = {
    "EVENT_OBSERVED",
    "ALERT_CREATED",
    "INCIDENT_CREATED",
    "INCIDENT_UPDATED",
    "ANALYSIS_COMPLETED",
    "DECISION_CREATED",
    "RESPONSE_EXECUTED",
    "ERROR"
}


VALID_PRIORITIES = {
    "LOW",
    "NORMAL",
    "HIGH",
    "CRITICAL"
}


VALID_MESSAGE_STATUSES = {
    "CREATED",
    "DELIVERED",
    "PROCESSED",
    "FAILED"
}


def generate_message_id():

    return f"message-{uuid4()}"


def current_utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


@dataclass
class AgentMessage:

    message_type: str
    sender: str
    recipient: str
    payload: dict[str, Any]

    correlation_id: str | None = None
    priority: str = "NORMAL"
    status: str = "CREATED"
    parent_message_id: str | None = None
    schema_version: str = "1.0"

    message_id: str = field(
        default_factory=generate_message_id
    )

    timestamp: str = field(
        default_factory=current_utc_timestamp
    )

    def __post_init__(self):

        if self.message_type not in VALID_MESSAGE_TYPES:
            raise ValueError(
                f"Invalid message type: "
                f"{self.message_type}"
            )

        if self.sender not in VALID_AGENT_NAMES:
            raise ValueError(
                f"Invalid sender: {self.sender}"
            )

        if self.recipient not in VALID_AGENT_NAMES:
            raise ValueError(
                f"Invalid recipient: "
                f"{self.recipient}"
            )

        if not isinstance(self.payload, dict):
            raise TypeError(
                "Message payload must be a dictionary"
            )

        if (
            self.correlation_id is not None
            and not isinstance(
                self.correlation_id,
                str
            )
        ):
            raise TypeError(
                "Correlation ID must be a string "
                "or None"
            )

        if self.priority not in VALID_PRIORITIES:
            raise ValueError(
                f"Invalid message priority: "
                f"{self.priority}"
            )

        if self.status not in VALID_MESSAGE_STATUSES:
            raise ValueError(
                f"Invalid message status: "
                f"{self.status}"
            )

        if (
            self.parent_message_id is not None
            and not isinstance(
                self.parent_message_id,
                str
            )
        ):
            raise TypeError(
                "Parent message ID must be a "
                "string or None"
            )

        self._validate_required_string(
            self.schema_version,
            "Schema version"
        )

        self._validate_required_string(
            self.message_id,
            "Message ID"
        )

        self._validate_required_string(
            self.timestamp,
            "Timestamp"
        )

    def mark_delivered(self):

        self.status = "DELIVERED"

    def mark_processed(self):

        self.status = "PROCESSED"

    def mark_failed(self):

        self.status = "FAILED"

    def create_reply(
        self,
        message_type,
        sender,
        recipient,
        payload,
        priority=None
    ):

        return AgentMessage(
            message_type=message_type,
            sender=sender,
            recipient=recipient,
            payload=payload,
            correlation_id=self.correlation_id,
            priority=(
                priority
                if priority is not None
                else self.priority
            ),
            parent_message_id=self.message_id
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
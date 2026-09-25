from datetime import datetime
from ipaddress import ip_address


class EventValidationError(ValueError):
    """Raised when a security event is malformed."""


EVENT_SCHEMAS = {
    "LOGIN_ATTEMPT": {
        "username": str,
        "source_ip": str,
        "status": str
    },
    "HTTP_REQUEST": {
        "source_ip": str,
        "target_service": str,
        "endpoint": str,
        "method": str
    },
    "NETWORK_CONNECTION": {
        "source_ip": str,
        "target_ip": str,
        "destination_port": int,
        "protocol": str,
        "connection_status": str
    },
    "PROCESS_ACTIVITY": {
        "process_name": str,
        "process_id": int,
        "parent_process": str,
        "user": str,
        "executable_path": str,
        "command_line": str,
        "action": str
    }
}


def validate_event(event):

    if not isinstance(event, dict):
        raise EventValidationError(
            "Event must be a dictionary"
        )

    if not event:
        raise EventValidationError(
            "Event must not be empty"
        )

    event_type = event.get("event_type")
    timestamp = event.get("timestamp")

    _validate_non_empty_string(
        event_type,
        "event_type"
    )

    _validate_non_empty_string(
        timestamp,
        "timestamp"
    )

    _validate_timestamp(timestamp)

    schema = EVENT_SCHEMAS.get(event_type)

    # Unknown event types are allowed so the system
    # can log future event types without detecting them.
    if schema is None:
        return event

    for field_name, expected_type in schema.items():

        if field_name not in event:
            raise EventValidationError(
                f"Missing required field: {field_name}"
            )

        value = event[field_name]

        if expected_type is int:

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
            ):
                raise EventValidationError(
                    f"{field_name} must be an integer"
                )

        elif not isinstance(value, expected_type):
            raise EventValidationError(
                f"{field_name} must be a "
                f"{expected_type.__name__}"
            )

        if expected_type is str:
            _validate_non_empty_string(
                value,
                field_name
            )

    _validate_event_specific_fields(
        event_type,
        event
    )

    return event


def _validate_non_empty_string(value, field_name):

    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        raise EventValidationError(
            f"{field_name} must be a non-empty string"
        )


def _validate_timestamp(timestamp):

    try:
        datetime.strptime(
            timestamp,
            "%H:%M:%S"
        )

    except ValueError as error:
        raise EventValidationError(
            "timestamp must use HH:MM:SS format"
        ) from error


def _validate_ip(value, field_name):

    try:
        ip_address(value)

    except ValueError as error:
        raise EventValidationError(
            f"{field_name} must contain a valid IP address"
        ) from error


def _validate_event_specific_fields(
    event_type,
    event
):

    if event_type == "LOGIN_ATTEMPT":

        _validate_ip(
            event["source_ip"],
            "source_ip"
        )

        if event["status"] not in {
            "SUCCESS",
            "FAILED"
        }:
            raise EventValidationError(
                "status must be SUCCESS or FAILED"
            )

    elif event_type == "HTTP_REQUEST":

        _validate_ip(
            event["source_ip"],
            "source_ip"
        )

    elif event_type == "NETWORK_CONNECTION":

        _validate_ip(
            event["source_ip"],
            "source_ip"
        )

        _validate_ip(
            event["target_ip"],
            "target_ip"
        )

        destination_port = event[
            "destination_port"
        ]

        if not 1 <= destination_port <= 65535:
            raise EventValidationError(
                "destination_port must be between "
                "1 and 65535"
            )

        if event["connection_status"] not in {
            "OPEN",
            "CLOSED"
        }:
            raise EventValidationError(
                "connection_status must be "
                "OPEN or CLOSED"
            )

    elif event_type == "PROCESS_ACTIVITY":

        if event["process_id"] <= 0:
            raise EventValidationError(
                "process_id must be greater than zero"
            )
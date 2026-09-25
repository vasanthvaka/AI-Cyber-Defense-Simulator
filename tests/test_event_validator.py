import unittest

from monitor.event_validator import (
    EventValidationError,
    validate_event
)


class TestEventValidator(unittest.TestCase):

    def test_valid_login_event(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "status": "FAILED"
        }

        self.assertIs(
            validate_event(event),
            event
        )

    def test_valid_http_event(self):

        event = {
            "event_type": "HTTP_REQUEST",
            "timestamp": "10:30:45",
            "source_ip": "192.168.1.20",
            "target_service": "web-server",
            "endpoint": "/login",
            "method": "GET"
        }

        self.assertIs(
            validate_event(event),
            event
        )

    def test_valid_network_event(self):

        event = {
            "event_type": "NETWORK_CONNECTION",
            "timestamp": "10:30:45",
            "source_ip": "10.0.0.10",
            "target_ip": "192.168.1.100",
            "destination_port": 443,
            "protocol": "TCP",
            "connection_status": "OPEN"
        }

        self.assertIs(
            validate_event(event),
            event
        )

    def test_valid_process_event(self):

        event = {
            "event_type": "PROCESS_ACTIVITY",
            "timestamp": "10:30:45",
            "process_name": "powershell.exe",
            "process_id": 1234,
            "parent_process": "WINWORD.EXE",
            "user": "vasanth",
            "executable_path": (
                r"C:\Windows\Temp\powershell.exe"
            ),
            "command_line": "powershell.exe test",
            "action": "STARTED"
        }

        self.assertIs(
            validate_event(event),
            event
        )

    def test_unknown_event_type_is_allowed(self):

        event = {
            "event_type": "FUTURE_EVENT",
            "timestamp": "10:30:45"
        }

        self.assertIs(
            validate_event(event),
            event
        )

    def test_non_dictionary_event_is_rejected(self):

        with self.assertRaises(
            EventValidationError
        ):
            validate_event("invalid event")

    def test_missing_event_type_is_rejected(self):

        event = {
            "timestamp": "10:30:45"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_invalid_timestamp_is_rejected(self):

        event = {
            "event_type": "FUTURE_EVENT",
            "timestamp": "25:70:90"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_missing_required_field_is_rejected(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "192.168.1.10"
        }

        with self.assertRaisesRegex(
            EventValidationError,
            "status"
        ):
            validate_event(event)

    def test_invalid_ip_address_is_rejected(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "not-an-ip",
            "status": "FAILED"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_invalid_login_status_is_rejected(self):

        event = {
            "event_type": "LOGIN_ATTEMPT",
            "timestamp": "10:30:45",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "status": "UNKNOWN"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_invalid_destination_port_is_rejected(self):

        event = {
            "event_type": "NETWORK_CONNECTION",
            "timestamp": "10:30:45",
            "source_ip": "10.0.0.10",
            "target_ip": "192.168.1.100",
            "destination_port": 70000,
            "protocol": "TCP",
            "connection_status": "CLOSED"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_boolean_destination_port_is_rejected(self):

        event = {
            "event_type": "NETWORK_CONNECTION",
            "timestamp": "10:30:45",
            "source_ip": "10.0.0.10",
            "target_ip": "192.168.1.100",
            "destination_port": True,
            "protocol": "TCP",
            "connection_status": "CLOSED"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)

    def test_invalid_process_id_is_rejected(self):

        event = {
            "event_type": "PROCESS_ACTIVITY",
            "timestamp": "10:30:45",
            "process_name": "powershell.exe",
            "process_id": 0,
            "parent_process": "WINWORD.EXE",
            "user": "vasanth",
            "executable_path": (
                r"C:\Windows\Temp\powershell.exe"
            ),
            "command_line": "powershell.exe test",
            "action": "STARTED"
        }

        with self.assertRaises(
            EventValidationError
        ):
            validate_event(event)


if __name__ == "__main__":
    unittest.main()
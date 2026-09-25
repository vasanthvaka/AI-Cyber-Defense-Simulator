from collections import deque

from agents.base_agent import BaseAgent
from alerting.alert_correlator import AlertCorrelator
from alerting.alert_normalizer import normalize_alert

from detector.brute_force_detector import (
    detect_brute_force
)

from detector.ddos_detector import detect_ddos
from detector.port_scan_detector import detect_port_scan

from detector.process_detector import (
    detect_suspicious_process
)

from monitor.ai_window_collector import (
    AIWindowCollector
)


SEVERITY_TO_PRIORITY = {
    "UNKNOWN": "NORMAL",
    "LOW": "LOW",
    "MEDIUM": "NORMAL",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL"
}


class MonitoringAgent(BaseAgent):

    def __init__(
        self,
        correlation_window=30,
        ai_window_collector=None,
        event_logger=None
    ):

        super().__init__(
            agent_name="MONITORING_AGENT"
        )

        self.alert_correlator = AlertCorrelator()

        if ai_window_collector is None:
            ai_window_collector = (
                AIWindowCollector(
                    window_size=5
                )
            )

        self.ai_window_collector = (
            ai_window_collector
        )

        self.event_logger = event_logger

        self.observed_event_count = 0
        self.raw_alerts = deque(maxlen=1000)
        self.normalized_alerts = deque(
            maxlen=1000
        )

    @property
    def incidents(self):

        return self.alert_correlator.incidents

    def handle_message(self, message):

        if message.message_type != "EVENT_OBSERVED":
            raise ValueError(
                "Monitoring Agent only accepts "
                "EVENT_OBSERVED messages"
            )

        event = message.payload.get("event")

        if not isinstance(event, dict):
            raise TypeError(
                "EVENT_OBSERVED payload must "
                "contain an event dictionary"
            )

        self.observed_event_count += 1

        if self.event_logger is not None:
            self.event_logger(event)

        raw_alerts = []

        rule_alert = self._detect_rule_alert(
            event
        )

        if rule_alert is not None:
            raw_alerts.append(rule_alert)

        ai_alert = (
            self.ai_window_collector.add_event(
                event
            )
        )

        if ai_alert is not None:
            raw_alerts.append(ai_alert)

        incident_messages = [
            self._create_incident_message(
                raw_alert=raw_alert,
                parent_message_id=(
                    message.message_id
                )
            )
            for raw_alert in raw_alerts
        ]

        if not incident_messages:
            return None

        return incident_messages

    def flush_ai_window(self):

        ai_alert = (
            self.ai_window_collector.flush()
        )

        if ai_alert is None:
            return []

        incident_message = (
            self._create_incident_message(
                raw_alert=ai_alert,
                parent_message_id=None
            )
        )

        self.outbox.append(
            incident_message
        )

        return [
            incident_message
        ]

    def _detect_rule_alert(self, event):

        event_type = event.get("event_type")

        if event_type == "LOGIN_ATTEMPT":
            return detect_brute_force(event)

        if event_type == "HTTP_REQUEST":
            return detect_ddos(event)

        if event_type == "NETWORK_CONNECTION":
            return detect_port_scan(event)

        if event_type == "PROCESS_ACTIVITY":
            return detect_suspicious_process(
                event
            )

        return None

    def _create_incident_message(
        self,
        raw_alert,
        parent_message_id
    ):

        self.raw_alerts.append(raw_alert)

        normalized_alert = normalize_alert(
            raw_alert
        )

        self.normalized_alerts.append(
            normalized_alert
        )

        incident_count_before = len(
            self.alert_correlator.incidents
        )

        incident = (
            self.alert_correlator.correlate(
                normalized_alert
            )
        )

        is_new_incident = (
            len(self.alert_correlator.incidents)
            > incident_count_before
        )

        if is_new_incident:
            message_type = "INCIDENT_CREATED"
        else:
            message_type = "INCIDENT_UPDATED"

        priority = SEVERITY_TO_PRIORITY[
            incident.severity
        ]

        return self.create_message(
            message_type=message_type,
            recipient="ANALYSIS_AGENT",
            payload={
                "incident": incident.to_dict()
            },
            correlation_id=(
                incident.incident_id
            ),
            priority=priority,
            parent_message_id=parent_message_id
        )
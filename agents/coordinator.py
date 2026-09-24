from collections import deque

from agents.analysis_agent import AnalysisAgent
from agents.decision_agent import DecisionAgent
from agents.message_schema import AgentMessage
from agents.monitoring_agent import MonitoringAgent
from agents.response_agent import ResponseAgent


class AgentCoordinator:

    def __init__(
        self,
        monitoring_agent=None,
        analysis_agent=None,
        decision_agent=None,
        response_agent=None,
        max_messages_per_run=10000,
        database=None
    ):

        if not isinstance(
            max_messages_per_run,
            int
        ):
            raise TypeError(
                "Maximum messages per run "
                "must be an integer"
            )

        if max_messages_per_run <= 0:
            raise ValueError(
                "Maximum messages per run "
                "must be greater than zero"
            )

        self.monitoring_agent = (
            monitoring_agent
            if monitoring_agent is not None
            else MonitoringAgent()
        )

        self.analysis_agent = (
            analysis_agent
            if analysis_agent is not None
            else AnalysisAgent()
        )

        self.decision_agent = (
            decision_agent
            if decision_agent is not None
            else DecisionAgent()
        )

        self.response_agent = (
            response_agent
            if response_agent is not None
            else ResponseAgent()
        )

        self.database = database

        self.agents = {
            "MONITORING_AGENT":
                self.monitoring_agent,
            "ANALYSIS_AGENT":
                self.analysis_agent,
            "DECISION_AGENT":
                self.decision_agent,
            "RESPONSE_AGENT":
                self.response_agent
        }

        self.max_messages_per_run = (
            max_messages_per_run
        )

        self.message_queue = deque()

        self.message_history = deque(
            maxlen=5000
        )

        self.completed_responses = deque(
            maxlen=1000
        )

        self.failed_messages = deque(
            maxlen=1000
        )

        self.submitted_event_count = 0
        self.routed_message_count = 0

    def submit_event(self, event):

        if not isinstance(event, dict):
            raise TypeError(
                "Submitted event must be a "
                "dictionary"
            )

        if self.database is not None:
            self.database.save_event(event)

        response_count_before = len(
            self.completed_responses
        )

        event_message = AgentMessage(
            message_type="EVENT_OBSERVED",
            sender="COORDINATOR",
            recipient="MONITORING_AGENT",
            payload={
                "event": event
            }
        )

        self.submitted_event_count += 1

        self._enqueue_message(
            event_message
        )

        self.run_until_idle()

        completed_responses = list(
            self.completed_responses
        )

        return completed_responses[
            response_count_before:
        ]

    def flush_ai_window(self):

        response_count_before = len(
            self.completed_responses
        )

        self.monitoring_agent.flush_ai_window()

        self._drain_agent_outbox(
            self.monitoring_agent
        )

        self.run_until_idle()

        completed_responses = list(
            self.completed_responses
        )

        return completed_responses[
            response_count_before:
        ]

    def run_until_idle(self):

        processed_during_run = 0

        while self.message_queue:

            processed_during_run += 1

            if (
                processed_during_run
                > self.max_messages_per_run
            ):
                raise RuntimeError(
                    "Maximum message limit "
                    "exceeded"
                )

            message = (
                self.message_queue.popleft()
            )

            try:
                self._route_message(message)

            except Exception as error:

                self.failed_messages.append(
                    {
                        "message_id":
                            message.message_id,
                        "message_type":
                            message.message_type,
                        "recipient":
                            message.recipient,
                        "error":
                            str(error)
                    }
                )

                raise

    def get_message_trace(
        self,
        correlation_id
    ):

        return [
            message
            for message in self.message_history
            if (
                message.correlation_id
                == correlation_id
            )
        ]

    def _route_message(self, message):

        if not isinstance(
            message,
            AgentMessage
        ):
            raise TypeError(
                "Coordinator can only route "
                "AgentMessage objects"
            )

        self.routed_message_count += 1

        if message.recipient == "COORDINATOR":

            self._handle_coordinator_message(
                message
            )

            return

        agent = self.agents.get(
            message.recipient
        )

        if agent is None:
            raise ValueError(
                f"No registered agent for "
                f"recipient: "
                f"{message.recipient}"
            )

        agent.receive(message)
        agent.process_next()

        self._drain_agent_outbox(agent)

    def _handle_coordinator_message(
        self,
        message
    ):

        message.mark_delivered()

        if (
            message.message_type
            == "RESPONSE_EXECUTED"
        ):

            if self.database is not None:

                self._persist_pipeline_result(
                    message.payload
                )

            self.completed_responses.append(
                message
            )

            message.mark_processed()

            return

        if message.message_type == "ERROR":

            self.failed_messages.append(
                {
                    "message_id":
                        message.message_id,
                    "message_type":
                        message.message_type,
                    "recipient":
                        message.recipient,
                    "error":
                        message.payload.get(
                            "error",
                            "Unknown agent error"
                        )
                }
            )

            message.mark_processed()

            return

        message.mark_failed()

        raise ValueError(
            "Coordinator received an "
            f"unsupported message type: "
            f"{message.message_type}"
        )

    def _persist_pipeline_result(
        self,
        payload
    ):

        incident = payload.get(
            "incident"
        )

        analysis = payload.get(
            "analysis"
        )

        decision = payload.get(
            "decision"
        )

        response = payload.get(
            "response"
        )

        if not isinstance(
            incident,
            dict
        ):
            raise TypeError(
                "Completed pipeline result must "
                "contain an incident dictionary"
            )

        if not isinstance(
            analysis,
            dict
        ):
            raise TypeError(
                "Completed pipeline result must "
                "contain an analysis dictionary"
            )

        if not isinstance(
            decision,
            dict
        ):
            raise TypeError(
                "Completed pipeline result must "
                "contain a decision dictionary"
            )

        if not isinstance(
            response,
            dict
        ):
            raise TypeError(
                "Completed pipeline result must "
                "contain a response dictionary"
            )

        for alert in incident.get(
            "alerts",
            []
        ):

            self.database.save_alert(
                alert
            )

        self.database.save_incident(
            incident
        )

        self.database.save_analysis(
            analysis
        )

        self.database.save_decision(
            decision
        )

        self.database.save_response(
            response
        )

        if response.get("audit_id"):

            self.database.save_audit_record(
                response
            )

    def _drain_agent_outbox(
        self,
        agent
    ):

        while True:

            outgoing_message = (
                agent
                .take_next_outgoing_message()
            )

            if outgoing_message is None:
                break

            self._enqueue_message(
                outgoing_message
            )

    def _enqueue_message(
        self,
        message
    ):

        if not isinstance(
            message,
            AgentMessage
        ):
            raise TypeError(
                "Only AgentMessage objects "
                "can enter the message queue"
            )

        self.message_queue.append(
            message
        )

        self.message_history.append(
            message
        )
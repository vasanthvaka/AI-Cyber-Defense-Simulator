import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent
from agents.response_agent import ResponseAgent
from agents.response_policy import ResponsePolicy


class ControlledAICollector:

    def add_event(self, event):
        return None

    def flush(self):
        return None


class TestResponseSafetyPipeline(unittest.TestCase):

    def make_coordinator(self, response_agent):
        monitoring_agent = MonitoringAgent(
            ai_window_collector=ControlledAICollector()
        )

        return AgentCoordinator(
            monitoring_agent=monitoring_agent,
            response_agent=response_agent,
        )

    def test_protected_ip_is_not_blocked(self):
        response_agent = ResponseAgent(
            policy=ResponsePolicy(
                protected_ips={"10.0.0.50"}
            )
        )
        coordinator = self.make_coordinator(response_agent)

        with patch(
            "agents.monitoring_agent.detect_brute_force",
            return_value={
                "attack_type": "BRUTE_FORCE",
                "source_ip": "10.0.0.50",
                "target_user": "admin",
                "failed_attempts": 5,
                "severity": "HIGH",
            },
        ):
            responses = coordinator.submit_event(
                {"event_type": "LOGIN_ATTEMPT"}
            )

        self.assertEqual(len(responses), 1)
        result = responses[0].payload["response"]

        self.assertEqual(result["action"], "BLOCK_IP")
        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(response_agent.blocked_ips, set())
        self.assertEqual(
            result["policy_evaluation"]["protected_targets"],
            ["10.0.0.50"],
        )

    def test_process_waits_for_approval(self):
        response_agent = ResponseAgent()
        coordinator = self.make_coordinator(response_agent)

        with patch(
            "agents.monitoring_agent.detect_suspicious_process",
            return_value={
                "attack_type": "SUSPICIOUS_PROCESS",
                "process_name": "powershell.exe",
                "process_id": 4321,
                "parent_process": "WINWORD.EXE",
                "user": "vasanth",
                "executable_path": (
                    r"C:\Users\vasanth\AppData"
                    r"\Local\Temp\powershell.exe"
                ),
                "command_line": (
                    "powershell.exe -EncodedCommand "
                    "[SIMULATED_DATA]"
                ),
                "risk_score": 4,
                "indicators": [
                    "Suspicious parent process",
                    "Encoded command",
                ],
                "severity": "HIGH",
            },
        ):
            responses = coordinator.submit_event(
                {"event_type": "PROCESS_ACTIVITY"}
            )

        self.assertEqual(len(responses), 1)
        pending = responses[0].payload["response"]

        self.assertEqual(
            pending["action"],
            "QUARANTINE_PROCESS",
        )
        self.assertEqual(
            pending["status"],
            "APPROVAL_REQUIRED",
        )
        self.assertEqual(
            response_agent.quarantined_processes,
            set(),
        )

        approved = response_agent.approve_response(
            pending["approval_id"],
            approved_by="Test analyst",
        )

        self.assertEqual(
            approved["status"],
            "SIMULATED_SUCCESS",
        )
        self.assertEqual(
            response_agent.quarantined_processes,
            {4321},
        )


if __name__ == "__main__":
    unittest.main()
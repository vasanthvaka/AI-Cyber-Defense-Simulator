import unittest
from unittest.mock import patch

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent


class ControlledAICollector:

    def __init__(self, alert=None):

        self.alert = alert

    def add_event(self, event):

        return self.alert

    def flush(self):

        return None


class TestMultiAgentAttackScenarios(
    unittest.TestCase
):

    def run_rule_scenario(
        self,
        event_type,
        detector_path,
        raw_alert
    ):

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                ControlledAICollector()
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        with patch(
            detector_path,
            return_value=raw_alert
        ):

            responses = coordinator.submit_event(
                {
                    "event_type": event_type
                }
            )

        self.assertEqual(
            len(responses),
            1
        )

        response_message = responses[0]

        trace = coordinator.get_message_trace(
            response_message.correlation_id
        )

        self.assertEqual(
            [
                message.message_type
                for message in trace
            ],
            [
                "INCIDENT_CREATED",
                "ANALYSIS_COMPLETED",
                "DECISION_CREATED",
                "RESPONSE_EXECUTED"
            ]
        )

        return response_message.payload

    def test_brute_force_pipeline(self):

        payload = self.run_rule_scenario(
            event_type="LOGIN_ATTEMPT",
            detector_path=(
                "agents.monitoring_agent."
                "detect_brute_force"
            ),
            raw_alert={
                "attack_type": "BRUTE_FORCE",
                "source_ip": "10.0.0.50",
                "target_user": "admin",
                "failed_attempts": 5,
                "severity": "HIGH"
            }
        )

        self.assertEqual(
            payload["response"]["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            payload["response"]["targets"],
            [
                "10.0.0.50"
            ]
        )

    def test_distributed_brute_force_pipeline(
        self
    ):

        source_ips = [
            "10.0.0.51",
            "10.0.0.52",
            "10.0.0.53"
        ]

        payload = self.run_rule_scenario(
            event_type="LOGIN_ATTEMPT",
            detector_path=(
                "agents.monitoring_agent."
                "detect_brute_force"
            ),
            raw_alert={
                "attack_type":
                    "DISTRIBUTED_BRUTE_FORCE",
                "source_ip": "10.0.0.51",
                "source_ips": source_ips,
                "target_user": "admin",
                "failed_attempts": 5,
                "unique_ip_count": 3,
                "severity": "HIGH"
            }
        )

        self.assertEqual(
            payload["response"]["action"],
            "BLOCK_IPS"
        )

        self.assertEqual(
            payload["response"]["targets"],
            source_ips
        )

    def test_ddos_pipeline(self):

        source_ips = [
            "10.0.1.1",
            "10.0.1.2",
            "10.0.1.3",
            "10.0.1.4",
            "10.0.1.5"
        ]

        payload = self.run_rule_scenario(
            event_type="HTTP_REQUEST",
            detector_path=(
                "agents.monitoring_agent."
                "detect_ddos"
            ),
            raw_alert={
                "attack_type": "DDOS",
                "source_ips": source_ips,
                "target_service": "web-server",
                "endpoint": "/payment",
                "request_count": 20,
                "unique_ip_count": 5,
                "time_window": 2,
                "severity": "HIGH"
            }
        )

        self.assertEqual(
            payload["response"]["action"],
            "RATE_LIMIT_IPS"
        )

        self.assertEqual(
            payload["response"]["targets"],
            source_ips
        )

    def test_port_scan_pipeline(self):

        payload = self.run_rule_scenario(
            event_type=(
                "NETWORK_CONNECTION"
            ),
            detector_path=(
                "agents.monitoring_agent."
                "detect_port_scan"
            ),
            raw_alert={
                "attack_type": "PORT_SCAN",
                "source_ip": "10.0.2.50",
                "target_ip": "192.168.1.100",
                "ports_scanned": [
                    21,
                    22,
                    80,
                    443
                ],
                "unique_port_count": 4,
                "time_window": 10,
                "severity": "MEDIUM"
            }
        )

        self.assertEqual(
            payload["response"]["action"],
            "BLOCK_IP"
        )

        self.assertEqual(
            payload["response"]["targets"],
            [
                "10.0.2.50"
            ]
        )

    def test_suspicious_process_pipeline(self):

        payload = self.run_rule_scenario(
            event_type="PROCESS_ACTIVITY",
            detector_path=(
                "agents.monitoring_agent."
                "detect_suspicious_process"
            ),
            raw_alert={
                "attack_type":
                    "SUSPICIOUS_PROCESS",
                "process_name":
                    "powershell.exe",
                "process_id": 4321,
                "parent_process":
                    "WINWORD.EXE",
                "user": "vasanth",
                "executable_path": (
                    r"C:\Users\vasanth\AppData"
                    r"\Local\Temp\powershell.exe"
                ),
                "command_line": (
                    "powershell.exe "
                    "-EncodedCommand "
                    "[SIMULATED_DATA]"
                ),
                "risk_score": 4,
                "indicators": [
                    "Suspicious parent process",
                    "Encoded command"
                ],
                "severity": "HIGH"
            }
        )

        self.assertEqual(
            payload["response"]["action"],
            "QUARANTINE_PROCESS"
        )

        self.assertEqual(
            payload["response"]["targets"],
            [
                4321
            ]
        )

    def test_ai_only_pipeline_requires_review(
        self
    ):

        ai_alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "detection_method": "ISOLATION_FOREST",
            "severity": "MEDIUM",
            "anomaly_score": -0.08,
            "event_count": 10,
            "source_ips": [
                "10.0.9.50"
            ],
            "features": {
                "total_events": 10
            }
        }

        monitoring_agent = MonitoringAgent(
            ai_window_collector=(
                ControlledAICollector(
                    alert=ai_alert
                )
            )
        )

        coordinator = AgentCoordinator(
            monitoring_agent=monitoring_agent
        )

        responses = coordinator.submit_event(
            {
                "event_type": "UNKNOWN_EVENT"
            }
        )

        payload = responses[0].payload

        self.assertTrue(
            payload["analysis"][
                "requires_human_review"
            ]
        )

        self.assertEqual(
            payload["analysis"][
                "recommended_escalation"
            ],
            "INVESTIGATE"
        )

        self.assertEqual(
            payload["decision"][
                "recommended_action"
            ],
            "FLAG_FOR_INVESTIGATION"
        )

        self.assertFalse(
            payload["response"]["automatic"]
        )


if __name__ == "__main__":
    unittest.main()
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from detector import brute_force_detector
from detector import ddos_detector
from detector import port_scan_detector
from detector import process_detector

from evaluation.response_evaluator import (
    EXPECTED_ACTIONS,
    evaluate_response_pipeline,
    extract_responses
)

from evaluation.system_evaluator import (
    SCENARIOS,
    detect_rule_alerts,
    evaluate_system,
    reset_rule_detector_state
)


class TestEvaluationPipeline(unittest.TestCase):

    def test_rule_detector_state_is_reset(self):

        brute_force_detector\
            .failed_attempts_by_ip["test"] = [1]

        brute_force_detector\
            .failed_attempts_by_username[
                "admin"
            ] = [(1, "test")]

        brute_force_detector\
            .flagged_ips["test"] = 1

        brute_force_detector\
            .flagged_usernames["admin"] = 1

        ddos_detector\
            .requests_by_target["test"] = [1]

        ddos_detector\
            .flagged_targets["test"] = 1

        port_scan_detector\
            .connection_attempts["test"] = [1]

        port_scan_detector\
            .flagged_scanners["test"] = 1

        process_detector\
            .flagged_processes.add(100)

        reset_rule_detector_state()

        self.assertEqual(
            brute_force_detector
            .failed_attempts_by_ip,
            {}
        )

        self.assertEqual(
            brute_force_detector
            .failed_attempts_by_username,
            {}
        )

        self.assertEqual(
            brute_force_detector.flagged_ips,
            {}
        )

        self.assertEqual(
            brute_force_detector
            .flagged_usernames,
            {}
        )

        self.assertEqual(
            ddos_detector.requests_by_target,
            {}
        )

        self.assertEqual(
            ddos_detector.flagged_targets,
            {}
        )

        self.assertEqual(
            port_scan_detector
            .connection_attempts,
            {}
        )

        self.assertEqual(
            port_scan_detector.flagged_scanners,
            {}
        )

        self.assertEqual(
            process_detector.flagged_processes,
            set()
        )

    def test_events_are_routed_to_rule_detectors(
        self
    ):

        events = [
            {"event_type": "LOGIN_ATTEMPT"},
            {"event_type": "HTTP_REQUEST"},
            {
                "event_type":
                    "NETWORK_CONNECTION"
            },
            {"event_type": "PROCESS_ACTIVITY"},
            {"event_type": "UNKNOWN"}
        ]

        with (
            patch(
                "evaluation.system_evaluator."
                "detect_brute_force",
                return_value={
                    "attack_type": "BRUTE_FORCE"
                }
            ),
            patch(
                "evaluation.system_evaluator."
                "detect_ddos",
                return_value={
                    "attack_type": "DDOS"
                }
            ),
            patch(
                "evaluation.system_evaluator."
                "detect_port_scan",
                return_value={
                    "attack_type": "PORT_SCAN"
                }
            ),
            patch(
                "evaluation.system_evaluator."
                "detect_suspicious_process",
                return_value={
                    "attack_type":
                        "SUSPICIOUS_PROCESS"
                }
            )
        ):

            alerts = detect_rule_alerts(events)

        self.assertEqual(len(alerts), 4)

        self.assertEqual(
            [
                alert["attack_type"]
                for alert in alerts
            ],
            [
                "BRUTE_FORCE",
                "DDOS",
                "PORT_SCAN",
                "SUSPICIOUS_PROCESS"
            ]
        )

    def test_system_evaluation_rejects_invalid_runs(
        self
    ):

        with self.assertRaises(TypeError):
            evaluate_system(
                runs_per_scenario=1.5
            )

        with self.assertRaises(ValueError):
            evaluate_system(
                runs_per_scenario=0
            )

        with self.assertRaises(TypeError):
            evaluate_system(
                runs_per_scenario=1,
                random_seed="42"
            )

    def test_response_extraction(self):

        valid_message = SimpleNamespace(
            payload={
                "response": {
                    "action": "BLOCK_IP",
                    "status":
                        "SIMULATED_SUCCESS"
                }
            }
        )

        invalid_message = SimpleNamespace(
            payload={
                "unrelated": True
            }
        )

        responses = extract_responses(
            [
                valid_message,
                invalid_message
            ]
        )

        self.assertEqual(
            responses,
            [
                {
                    "action": "BLOCK_IP",
                    "status":
                        "SIMULATED_SUCCESS"
                }
            ]
        )

    def test_response_evaluation_rejects_invalid_runs(
        self
    ):

        with self.assertRaises(TypeError):
            evaluate_response_pipeline(
                runs_per_scenario="100"
            )

        with self.assertRaises(ValueError):
            evaluate_response_pipeline(
                runs_per_scenario=0
            )

    def test_every_scenario_has_response_expectations(
        self
    ):

        scenario_names = {
            scenario["name"]
            for scenario in SCENARIOS
        }

        self.assertEqual(
            scenario_names,
            set(EXPECTED_ACTIONS)
        )


if __name__ == "__main__":
    unittest.main()
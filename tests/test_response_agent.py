import unittest

from agents.response_agent import ResponseAgent


class TestResponseAgent(unittest.TestCase):

    def setUp(self):

        self.agent = ResponseAgent()

    def create_decision(
        self,
        action,
        targets,
        attack_type="TEST_ATTACK",
        automatic=True
    ):

        return {
            "attack_type": attack_type,
            "severity": "HIGH",
            "recommended_action": action,
            "target_type": "TEST_TARGET",
            "targets": targets,
            "automatic": automatic,
            "reason": "Test response decision"
        }

    def test_block_ip_updates_blocked_ips(self):

        decision = self.create_decision(
            "BLOCK_IP",
            ["10.0.0.10"]
        )

        result = self.agent.execute(decision)

        self.assertIn(
            "10.0.0.10",
            self.agent.blocked_ips
        )
        self.assertEqual(
            result["new_targets"],
            ["10.0.0.10"]
        )
        self.assertTrue(result["simulated"])

    def test_block_multiple_ips(self):

        decision = self.create_decision(
            "BLOCK_IPS",
            [
                "10.0.0.1",
                "10.0.0.2"
            ]
        )

        self.agent.execute(decision)

        self.assertEqual(
            self.agent.blocked_ips,
            {
                "10.0.0.1",
                "10.0.0.2"
            }
        )

    def test_duplicate_target_is_not_added_again(self):

        decision = self.create_decision(
            "BLOCK_IP",
            ["10.0.0.10"]
        )

        first_result = self.agent.execute(decision)
        second_result = self.agent.execute(decision)

        self.assertEqual(
            first_result["new_targets"],
            ["10.0.0.10"]
        )
        self.assertEqual(
            second_result["new_targets"],
            []
        )
        self.assertEqual(
            len(self.agent.blocked_ips),
            1
        )
        self.assertEqual(
            len(self.agent.action_history),
            2
        )

    def test_rate_limit_updates_rate_limited_ips(self):

        decision = self.create_decision(
            "RATE_LIMIT_IPS",
            [
                "10.0.1.1",
                "10.0.1.2"
            ]
        )

        self.agent.execute(decision)

        self.assertEqual(
            self.agent.rate_limited_ips,
            {
                "10.0.1.1",
                "10.0.1.2"
            }
        )

    def test_quarantine_updates_process_state(self):

        decision = self.create_decision(
            "QUARANTINE_PROCESS",
            [7736]
        )

        self.agent.execute(decision)

        self.assertIn(
            7736,
            self.agent.quarantined_processes
        )

    def test_investigation_is_queued(self):

        decision = self.create_decision(
            "FLAG_FOR_INVESTIGATION",
            ["10.0.1.1"],
            attack_type="ANOMALOUS_BEHAVIOR",
            automatic=False
        )

        result = self.agent.execute(decision)

        self.assertEqual(
            len(self.agent.investigation_queue),
            1
        )
        self.assertEqual(
            self.agent.investigation_queue[0][
                "attack_type"
            ],
            "ANOMALOUS_BEHAVIOR"
        )
        self.assertFalse(result["automatic"])

    def test_continue_monitoring_changes_no_state(self):

        decision = self.create_decision(
            "CONTINUE_MONITORING",
            [],
            automatic=False
        )

        result = self.agent.execute(decision)

        self.assertEqual(
            result["new_targets"],
            []
        )
        self.assertEqual(
            self.agent.blocked_ips,
            set()
        )
        self.assertEqual(
            len(self.agent.action_history),
            1
        )

    def test_non_dictionary_decision_raises_type_error(self):

        with self.assertRaises(TypeError):
            self.agent.execute("BLOCK_IP")

    def test_unsupported_action_raises_value_error(self):

        decision = self.create_decision(
            "DELETE_SYSTEM",
            []
        )

        with self.assertRaises(ValueError):
            self.agent.execute(decision)


if __name__ == "__main__":
    unittest.main()
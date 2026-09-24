import unittest
from types import SimpleNamespace

from agents.response_agent import ResponseAgent
from agents.response_policy import ResponsePolicy


def decision(action, targets, risk=90, confidence=0.95):
    return {
        "incident_id": "incident-test",
        "attack_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "risk_score": risk,
        "confidence": confidence,
        "recommended_action": action,
        "target_type": "IP_ADDRESS",
        "targets": targets,
        "automatic": True,
        "requires_human_review": False,
        "reason": "Test decision",
    }


def send_decision(agent, proposed_decision):
    message = SimpleNamespace(
        message_type="DECISION_CREATED",
        payload={"decision": proposed_decision},
        correlation_id="incident-test",
        priority="HIGH",
        message_id="message-test",
    )
    return agent.handle_message(message).payload["response"]


class ResponsePolicyIntegrationTests(unittest.TestCase):

    def test_protected_ip_is_excluded_from_multi_target_action(self):
        agent = ResponseAgent(
            policy=ResponsePolicy(
                protected_ips={"10.0.0.1"},
                approval_required_actions=set(),
            )
        )

        result = send_decision(
            agent,
            decision("BLOCK_IPS", ["10.0.0.1", "10.0.0.2"]),
        )

        self.assertEqual(result["status"], "SIMULATED_SUCCESS")
        self.assertEqual(agent.blocked_ips, {"10.0.0.2"})
        self.assertEqual(
            result["policy_evaluation"]["protected_targets"],
            ["10.0.0.1"],
        )

    def test_dangerous_action_waits_for_approval(self):
        agent = ResponseAgent()

        proposed = decision("QUARANTINE_PROCESS", [123])
        proposed["attack_type"] = "SUSPICIOUS_PROCESS"
        proposed["target_type"] = "PROCESS_ID"

        result = send_decision(agent, proposed)

        self.assertEqual(result["status"], "APPROVAL_REQUIRED")
        self.assertEqual(agent.quarantined_processes, set())

    def test_low_risk_action_does_not_execute(self):
        agent = ResponseAgent()

        result = send_decision(
            agent,
            decision("BLOCK_IP", ["10.0.0.3"], risk=40),
        )

        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual(agent.blocked_ips, set())

    def test_approval_executes_once(self):
        agent = ResponseAgent()

        proposed = decision("QUARANTINE_PROCESS", [123])
        proposed["attack_type"] = "SUSPICIOUS_PROCESS"
        proposed["target_type"] = "PROCESS_ID"

        pending = send_decision(agent, proposed)

        self.assertEqual(pending["status"], "APPROVAL_REQUIRED")
        self.assertEqual(agent.quarantined_processes, set())

        result = agent.approve_response(
            pending["approval_id"],
            approved_by="Test analyst",
        )

        self.assertEqual(result["new_targets"], [123])
        self.assertEqual(result["approved_by"], "Test analyst")
        self.assertEqual(agent.quarantined_processes, {123})

        with self.assertRaises(ValueError):
            agent.approve_response(
                pending["approval_id"],
                approved_by="Test analyst",
            )

    def test_repeated_block_is_suppressed(self):
        agent = ResponseAgent()
        proposed = decision("BLOCK_IP", ["10.0.0.8"])

        first = send_decision(agent, proposed)
        second = send_decision(agent, proposed)

        self.assertEqual(first["status"], "SIMULATED_SUCCESS")
        self.assertEqual(first["new_targets"], ["10.0.0.8"])
        self.assertEqual(second["status"], "SUPPRESSED_DUPLICATE")
        self.assertEqual(second["new_targets"], [])
        self.assertEqual(
            second["suppressed_targets"],
            ["10.0.0.8"],
        )
        self.assertEqual(agent.blocked_ips, {"10.0.0.8"})

    def test_block_expires_and_can_be_applied_again(self):
        agent = ResponseAgent(
            policy=ResponsePolicy(
                cooldown_seconds=5,
                action_expiration_seconds=10,
            )
        )

        current_time = [100.0]
        agent.clock = lambda: current_time[0]

        proposed = decision("BLOCK_IP", ["10.0.0.8"])

        first = send_decision(agent, proposed)
        self.assertEqual(first["new_targets"], ["10.0.0.8"])
        self.assertIn("10.0.0.8", agent.blocked_ips)

        duplicate = send_decision(agent, proposed)
        self.assertEqual(
            duplicate["status"],
            "SUPPRESSED_DUPLICATE",
        )

        current_time[0] = 111.0
        reversals = agent.expire_actions()

        self.assertEqual(len(reversals), 1)
        self.assertEqual(reversals[0]["action"], "UNBLOCK_IP")
        self.assertNotIn("10.0.0.8", agent.blocked_ips)

        applied_again = send_decision(agent, proposed)
        self.assertEqual(
            applied_again["new_targets"],
            ["10.0.0.8"],
        )

    def test_denied_action_has_policy_audit(self):
        agent = ResponseAgent(
            policy=ResponsePolicy(
                protected_ips={"10.0.0.9"}
            )
        )

        result = send_decision(
            agent,
            decision("BLOCK_IP", ["10.0.0.9"]),
        )

        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(result["policy_status"], "DENIED")
        self.assertTrue(result["audit_id"])
        self.assertTrue(result["timestamp_utc"])
        self.assertTrue(result["policy_reason"])
        self.assertEqual(agent.blocked_ips, set())
        self.assertIs(agent.action_history[-1], result)

    def test_expiry_audit_links_to_original_action(self):
        agent = ResponseAgent(
            policy=ResponsePolicy(
                cooldown_seconds=5,
                action_expiration_seconds=10,
            )
        )
        current_time = [100.0]
        agent.clock = lambda: current_time[0]

        applied = send_decision(
            agent,
            decision("BLOCK_IP", ["10.0.0.8"]),
        )

        current_time[0] = 111.0
        reversals = agent.expire_actions()

        self.assertEqual(len(reversals), 1)
        self.assertEqual(
            reversals[0]["reverses_audit_id"],
            applied["audit_id"],
        )
        self.assertEqual(
            reversals[0]["incident_id"],
            "incident-test",
        )
        self.assertEqual(
            reversals[0]["policy_status"],
            "EXPIRED",
        )
        self.assertNotIn("10.0.0.8", agent.blocked_ips)

if __name__ == "__main__":
    unittest.main()
import unittest

from agents.decision_agent import decide_response


class TestDecisionAgent(unittest.TestCase):

    def test_brute_force_blocks_source_ip(self):

        alert = {
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "10.0.0.10"
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "BLOCK_IP"
        )
        self.assertEqual(
            decision["targets"],
            ["10.0.0.10"]
        )
        self.assertTrue(decision["automatic"])

    def test_distributed_brute_force_blocks_multiple_ips(self):

        alert = {
            "attack_type": "DISTRIBUTED_BRUTE_FORCE",
            "severity": "HIGH",
            "source_ips": [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3"
            ]
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "BLOCK_IPS"
        )
        self.assertEqual(
            decision["targets"],
            alert["source_ips"]
        )
        self.assertTrue(decision["automatic"])

    def test_ddos_rate_limits_source_ips(self):

        alert = {
            "attack_type": "DDOS",
            "severity": "HIGH",
            "source_ips": [
                "10.0.1.1",
                "10.0.1.2"
            ]
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "RATE_LIMIT_IPS"
        )
        self.assertEqual(
            decision["target_type"],
            "IP_ADDRESS"
        )
        self.assertTrue(decision["automatic"])

    def test_port_scan_blocks_scanner_ip(self):

        alert = {
            "attack_type": "PORT_SCAN",
            "severity": "MEDIUM",
            "source_ip": "10.0.2.50"
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "BLOCK_IP"
        )
        self.assertEqual(
            decision["targets"],
            ["10.0.2.50"]
        )

    def test_suspicious_process_is_quarantined(self):

        alert = {
            "attack_type": "SUSPICIOUS_PROCESS",
            "severity": "HIGH",
            "process_id": 7736
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "QUARANTINE_PROCESS"
        )
        self.assertEqual(
            decision["target_type"],
            "PROCESS_ID"
        )
        self.assertEqual(
            decision["targets"],
            [7736]
        )

    def test_ai_anomaly_requires_investigation(self):

        alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "severity": "MEDIUM",
            "source_ips": [
                "10.0.1.1",
                "10.0.1.2"
            ]
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "FLAG_FOR_INVESTIGATION"
        )
        self.assertFalse(decision["automatic"])

    def test_unknown_alert_continues_monitoring(self):

        alert = {
            "attack_type": "UNKNOWN_ATTACK",
            "severity": "LOW"
        }

        decision = decide_response(alert)

        self.assertEqual(
            decision["recommended_action"],
            "CONTINUE_MONITORING"
        )
        self.assertEqual(decision["targets"], [])
        self.assertFalse(decision["automatic"])

    def test_non_dictionary_alert_raises_type_error(self):

        with self.assertRaises(TypeError):
            decide_response("BRUTE_FORCE")

    def test_missing_attack_type_raises_value_error(self):

        with self.assertRaises(ValueError):
            decide_response({
                "severity": "HIGH"
            })


if __name__ == "__main__":
    unittest.main()
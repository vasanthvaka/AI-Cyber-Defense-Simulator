import unittest

from alerting.alert_normalizer import normalize_alert
from alerting.alert_schema import SecurityAlert


class TestAlertNormalizer(unittest.TestCase):

    def test_normalize_brute_force_alert(self):

        raw_alert = {
            "attack_type": "BRUTE_FORCE",
            "source_ip": "10.0.0.50",
            "target_user": "admin",
            "failed_attempts": 5,
            "severity": "HIGH"
        }

        alert = normalize_alert(raw_alert)

        self.assertIsInstance(
            alert,
            SecurityAlert
        )

        self.assertEqual(
            alert.detection_method,
            "RULE_BASED"
        )

        self.assertEqual(
            alert.detector_name,
            "brute_force_detector"
        )

        self.assertEqual(
            alert.sources[0].entity_type,
            "IP_ADDRESS"
        )

        self.assertEqual(
            alert.sources[0].value,
            "10.0.0.50"
        )

        self.assertEqual(
            alert.targets[0].entity_type,
            "USER_ACCOUNT"
        )

        self.assertEqual(
            alert.targets[0].value,
            "admin"
        )

        self.assertEqual(
            alert.evidence["failed_attempts"],
            5
        )

    def test_normalize_distributed_brute_force_alert(self):

        raw_alert = {
            "attack_type": "DISTRIBUTED_BRUTE_FORCE",
            "source_ip": "10.0.0.51",
            "source_ips": [
                "10.0.0.51",
                "10.0.0.52",
                "10.0.0.53"
            ],
            "target_user": "admin",
            "failed_attempts": 5,
            "unique_ip_count": 3,
            "severity": "HIGH"
        }

        alert = normalize_alert(raw_alert)

        source_values = [
            source.value
            for source in alert.sources
        ]

        self.assertEqual(
            source_values,
            [
                "10.0.0.51",
                "10.0.0.52",
                "10.0.0.53"
            ]
        )

        self.assertEqual(
            alert.targets[0].value,
            "admin"
        )

        self.assertEqual(
            alert.evidence["unique_ip_count"],
            3
        )

    def test_normalize_ddos_alert(self):

        raw_alert = {
            "attack_type": "DDOS",
            "source_ips": [
                "10.0.1.1",
                "10.0.1.2"
            ],
            "target_service": "web-server",
            "endpoint": "/login",
            "request_count": 20,
            "unique_ip_count": 2,
            "time_window": 5,
            "severity": "HIGH"
        }

        alert = normalize_alert(raw_alert)

        self.assertEqual(
            len(alert.sources),
            2
        )

        self.assertEqual(
            alert.targets[0].entity_type,
            "SERVICE"
        )

        self.assertEqual(
            alert.targets[0].value,
            "web-server"
        )

        self.assertEqual(
            alert.targets[1].entity_type,
            "HTTP_ENDPOINT"
        )

        self.assertEqual(
            alert.targets[1].value,
            "/login"
        )

        self.assertEqual(
            alert.evidence["request_count"],
            20
        )

    def test_normalize_port_scan_alert(self):

        raw_alert = {
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

        alert = normalize_alert(raw_alert)

        self.assertEqual(
            alert.sources[0].value,
            "10.0.2.50"
        )

        self.assertEqual(
            alert.targets[0].value,
            "192.168.1.100"
        )

        self.assertEqual(
            alert.evidence["ports_scanned"],
            [
                21,
                22,
                80,
                443
            ]
        )

    def test_normalize_suspicious_process_alert(self):

        raw_alert = {
            "attack_type": "SUSPICIOUS_PROCESS",
            "process_name": "powershell.exe",
            "process_id": 4321,
            "parent_process": "WINWORD.EXE",
            "user": "vasanth",
            "executable_path": (
                r"C:\Users\vasanth\AppData\Local"
                r"\Temp\powershell.exe"
            ),
            "command_line": (
                "powershell.exe -EncodedCommand "
                "[SIMULATED_DATA]"
            ),
            "risk_score": 4,
            "indicators": [
                "Suspicious parent process",
                "Encoded PowerShell command"
            ],
            "severity": "HIGH"
        }

        alert = normalize_alert(raw_alert)

        self.assertEqual(
            alert.sources[0].entity_type,
            "PROCESS_ID"
        )

        self.assertEqual(
            alert.sources[0].value,
            4321
        )

        self.assertEqual(
            alert.sources[1].entity_type,
            "PROCESS_NAME"
        )

        self.assertEqual(
            alert.sources[1].value,
            "powershell.exe"
        )

        self.assertEqual(
            alert.targets[0].value,
            "vasanth"
        )

        self.assertEqual(
            alert.evidence["risk_score"],
            4
        )

    def test_normalize_ai_anomaly_alert(self):

        raw_alert = {
            "attack_type": "ANOMALOUS_BEHAVIOR",
            "detection_method": "ISOLATION_FOREST",
            "severity": "MEDIUM",
            "anomaly_score": -0.067,
            "event_count": 10,
            "source_ips": [
                "10.0.0.51",
                "10.0.0.52"
            ],
            "features": {
                "total_events": 10,
                "failed_logins": 8
            }
        }

        alert = normalize_alert(raw_alert)

        self.assertEqual(
            alert.detection_method,
            "ISOLATION_FOREST"
        )

        self.assertEqual(
            alert.detector_name,
            "anomaly_detector"
        )

        self.assertEqual(
            alert.confidence,
            0.5
        )

        self.assertEqual(
            alert.anomaly_score,
            -0.067
        )

        self.assertEqual(
            len(alert.sources),
            2
        )

        self.assertEqual(
            alert.evidence["event_count"],
            10
        )

    def test_normalize_unknown_alert(self):

        raw_alert = {
            "attack_type": "UNKNOWN_ACTIVITY",
            "severity": "LOW",
            "description": "Unknown simulated activity"
        }

        alert = normalize_alert(raw_alert)

        self.assertEqual(
            alert.attack_type,
            "UNKNOWN_ACTIVITY"
        )

        self.assertEqual(
            alert.detector_name,
            "unknown_detector"
        )

        self.assertEqual(
            alert.detection_method,
            "UNKNOWN"
        )

        self.assertEqual(
            alert.confidence,
            0.0
        )

        self.assertEqual(
            alert.evidence["description"],
            "Unknown simulated activity"
        )

    def test_non_dictionary_alert_is_rejected(self):

        with self.assertRaises(TypeError):
            normalize_alert(
                "BRUTE_FORCE"
            )

    def test_missing_attack_type_is_rejected(self):

        with self.assertRaises(ValueError):
            normalize_alert(
                {
                    "severity": "HIGH"
                }
            )

    def test_invalid_source_ips_is_rejected(self):

        raw_alert = {
            "attack_type": "DDOS",
            "source_ips": "10.0.1.1",
            "target_service": "web-server",
            "endpoint": "/login",
            "severity": "HIGH"
        }

        with self.assertRaises(TypeError):
            normalize_alert(raw_alert)


if __name__ == "__main__":
    unittest.main()
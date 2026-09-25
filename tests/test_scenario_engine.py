import random
import unittest
from unittest.mock import patch

from simulator.scenario_engine import SecurityScenarioEngine


class TestSecurityScenarioEngine(unittest.TestCase):

    def setUp(self):

        self.engine = SecurityScenarioEngine(
            random_generator=random.Random(42)
        )

    def test_generate_normal_events_uses_requested_count(self):

        sample_event = {
            "event_type": "LOGIN_ATTEMPT",
            "status": "SUCCESS"
        }

        with patch.object(
            self.engine,
            "generate_normal_event",
            return_value=sample_event
        ):
            events = self.engine.generate_normal_events(
                minimum=7,
                maximum=7
            )

        self.assertEqual(len(events), 7)

        self.assertTrue(
            all(
                event == sample_event
                for event in events
            )
        )

    def test_distributed_brute_force_is_within_configured_ranges(
        self
    ):

        events = (
            self.engine.generate_distributed_brute_force()
        )

        attack_config = self.engine.simulation_config[
            "distributed_brute_force"
        ]

        source_ips = {
            event["source_ip"]
            for event in events
        }

        usernames = {
            event["username"]
            for event in events
        }

        self.assertGreaterEqual(
            len(events),
            attack_config["minimum_attempts"]
        )

        self.assertLessEqual(
            len(events),
            attack_config["maximum_attempts"]
        )

        self.assertGreaterEqual(
            len(source_ips),
            attack_config["minimum_source_ips"]
        )

        self.assertLessEqual(
            len(source_ips),
            attack_config["maximum_source_ips"]
        )

        self.assertEqual(len(usernames), 1)

        self.assertTrue(
            usernames.issubset(
                set(self.engine.login_targets)
            )
        )

        self.assertTrue(
            source_ips.issubset(
                set(
                    self.engine.credential_attacker_ips
                )
            )
        )

        for event in events:

            self.assertEqual(
                event["event_type"],
                "LOGIN_ATTEMPT"
            )

            self.assertEqual(
                event["status"],
                "FAILED"
            )

    def test_ddos_is_within_configured_ranges(self):

        events = self.engine.generate_ddos()

        attack_config = (
            self.engine.simulation_config["ddos"]
        )

        source_ips = {
            event["source_ip"]
            for event in events
        }

        endpoints = {
            event["endpoint"]
            for event in events
        }

        self.assertGreaterEqual(
            len(events),
            attack_config["minimum_requests"]
        )

        self.assertLessEqual(
            len(events),
            attack_config["maximum_requests"]
        )

        self.assertGreaterEqual(
            len(source_ips),
            attack_config["minimum_source_ips"]
        )

        self.assertLessEqual(
            len(source_ips),
            attack_config["maximum_source_ips"]
        )

        # One DDoS scenario attacks one endpoint.
        self.assertEqual(len(endpoints), 1)

        self.assertTrue(
            endpoints.issubset(
                set(self.engine.attacked_endpoints)
            )
        )

        self.assertTrue(
            source_ips.issubset(
                set(self.engine.ddos_attacker_ips)
            )
        )

        for event in events:

            self.assertEqual(
                event["event_type"],
                "HTTP_REQUEST"
            )

            self.assertEqual(
                event["method"],
                "GET"
            )

    def test_port_scan_varies_ports_but_keeps_one_route(
        self
    ):

        events = self.engine.generate_port_scan()

        attack_config = self.engine.simulation_config[
            "port_scan"
        ]

        source_ips = {
            event["source_ip"]
            for event in events
        }

        target_ips = {
            event["target_ip"]
            for event in events
        }

        ports = {
            event["destination_port"]
            for event in events
        }

        self.assertGreaterEqual(
            len(events),
            attack_config["minimum_ports"]
        )

        self.assertLessEqual(
            len(events),
            attack_config["maximum_ports"]
        )

        # A scan should contact distinct ports.
        self.assertEqual(
            len(ports),
            len(events)
        )

        # One scanner attacks one target per scenario.
        self.assertEqual(len(source_ips), 1)
        self.assertEqual(len(target_ips), 1)

        self.assertTrue(
            source_ips.issubset(
                set(self.engine.scanner_ips)
            )
        )

        self.assertTrue(
            target_ips.issubset(
                set(self.engine.target_systems)
            )
        )

        for event in events:

            self.assertEqual(
                event["event_type"],
                "NETWORK_CONNECTION"
            )

    def test_suspicious_processes_use_known_templates(
        self
    ):

        events = (
            self.engine.generate_suspicious_processes()
        )

        attack_config = self.engine.simulation_config[
            "suspicious_process"
        ]

        valid_templates = {
            (
                template["process_name"],
                template["parent_process"],
                template["executable_path"],
                template["command_line"]
            )
            for template in self.engine.process_templates
        }

        self.assertGreaterEqual(
            len(events),
            attack_config["minimum_events"]
        )

        self.assertLessEqual(
            len(events),
            attack_config["maximum_events"]
        )

        for event in events:

            event_template = (
                event["process_name"],
                event["parent_process"],
                event["executable_path"],
                event["command_line"]
            )

            self.assertEqual(
                event["event_type"],
                "PROCESS_ACTIVITY"
            )

            self.assertIn(
                event_template,
                valid_templates
            )

    def test_random_attack_returns_supported_scenario(
        self
    ):

        scenario_name, events = (
            self.engine.generate_random_attack()
        )

        supported_scenarios = {
            "DISTRIBUTED_BRUTE_FORCE",
            "DDOS",
            "PORT_SCAN",
            "SUSPICIOUS_PROCESS"
        }

        self.assertIn(
            scenario_name,
            supported_scenarios
        )

        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

    def test_attack_delay_comes_from_configuration(
        self
    ):

        mappings = {
            "DISTRIBUTED_BRUTE_FORCE":
                "distributed_brute_force",
            "DDOS":
                "ddos",
            "PORT_SCAN":
                "port_scan",
            "SUSPICIOUS_PROCESS":
                "suspicious_process"
        }

        for scenario_name, config_name in mappings.items():

            with self.subTest(
                scenario_name=scenario_name
            ):

                expected_delay = (
                    self.engine.simulation_config[
                        config_name
                    ]["delay_seconds"]
                )

                actual_delay = (
                    self.engine.get_attack_delay(
                        scenario_name
                    )
                )

                self.assertEqual(
                    actual_delay,
                    expected_delay
                )

    def test_seed_reproduces_attack_structure(self):

        first_engine = SecurityScenarioEngine(
            random_generator=random.Random(99)
        )

        second_engine = SecurityScenarioEngine(
            random_generator=random.Random(99)
        )

        first_events = (
            first_engine.generate_distributed_brute_force()
        )

        second_events = (
            second_engine.generate_distributed_brute_force()
        )

        def stable_fields(events):

            return [
                {
                    "event_type":
                        event["event_type"],
                    "username":
                        event["username"],
                    "source_ip":
                        event["source_ip"],
                    "status":
                        event["status"]
                }
                for event in events
            ]

        self.assertEqual(
            stable_fields(first_events),
            stable_fields(second_events)
        )


if __name__ == "__main__":
    unittest.main()
import random
from copy import deepcopy

from config.settings import (
    get_config,
    validate_config
)

from simulator.brute_force import (
    create_login_event,
    generate_normal_login
)

from simulator.ddos import (
    create_http_event,
    generate_normal_request
)

from simulator.port_scan import (
    create_connection_event,
    generate_normal_connection,
    scan_ports
)

from simulator.process_activity import (
    create_process_event,
    generate_normal_process
)


class SecurityScenarioEngine:

    def __init__(
        self,
        config=None,
        random_generator=None
    ):

        if config is None:
            config = get_config()
        else:
            validate_config(config)
            config = deepcopy(config)

        self.config = config
        self.simulation_config = (
            config["simulation"]
        )

        self.random = (
            random_generator
            if random_generator is not None
            else random
        )

        self.login_targets = [
            "admin",
            "backup-admin",
            "service-account",
            "database-admin",
            "security-operator"
        ]

        self.credential_attacker_ips = [
            f"10.10.0.{index}"
            for index in range(1, 21)
        ]

        self.ddos_attacker_ips = [
            f"10.20.0.{index}"
            for index in range(1, 31)
        ]

        self.scanner_ips = [
            "10.30.0.10",
            "10.30.0.20",
            "10.30.0.30",
            "10.30.0.40"
        ]

        self.target_systems = [
            "192.168.1.100",
            "192.168.1.110",
            "192.168.1.120",
            "192.168.1.130"
        ]

        self.attacked_endpoints = [
            "/login",
            "/api/search",
            "/api/catalog",
            "/api/profile",
            "/api/payment",
            "/api/status"
        ]

        self.process_templates = [
            {
                "process_name":
                    "powershell.exe",
                "parent_process":
                    "WINWORD.EXE",
                "executable_path": (
                    r"C:\Users\vasanth\AppData"
                    r"\Local\Temp\powershell.exe"
                ),
                "command_line": (
                    "powershell.exe "
                    "-EncodedCommand "
                    "[SIMULATED_DATA]"
                )
            },
            {
                "process_name":
                    "cmd.exe",
                "parent_process":
                    "EXCEL.EXE",
                "executable_path": (
                    r"C:\Windows\Temp\cmd.exe"
                ),
                "command_line": (
                    "cmd.exe /c "
                    "simulated-command"
                )
            },
            {
                "process_name":
                    "powershell.exe",
                "parent_process":
                    "OUTLOOK.EXE",
                "executable_path": (
                    r"C:\Users\Public"
                    r"\powershell.exe"
                ),
                "command_line": (
                    "powershell.exe "
                    "Invoke-WebRequest "
                    "[SIMULATED_URL]"
                )
            }
        ]

    def generate_normal_event(self):

        generators = [
            generate_normal_login,
            generate_normal_request,
            generate_normal_connection,
            generate_normal_process
        ]

        generator = self.random.choice(
            generators
        )

        return generator()

    def generate_normal_events(
        self,
        minimum=None,
        maximum=None
    ):

        normal_config = (
            self.simulation_config[
                "normal_activity"
            ]
        )

        if minimum is None:
            minimum = normal_config[
                "minimum_events"
            ]

        if maximum is None:
            maximum = normal_config[
                "maximum_events"
            ]

        event_count = self.random.randint(
            minimum,
            maximum
        )

        return [
            self.generate_normal_event()
            for _ in range(event_count)
        ]

    def generate_distributed_brute_force(
        self
    ):

        attack_config = (
            self.simulation_config[
                "distributed_brute_force"
            ]
        )

        attempt_count = self.random.randint(
            attack_config[
                "minimum_attempts"
            ],
            attack_config[
                "maximum_attempts"
            ]
        )

        maximum_sources = min(
            attack_config[
                "maximum_source_ips"
            ],
            attempt_count,
            len(
                self.credential_attacker_ips
            )
        )

        minimum_sources = min(
            attack_config[
                "minimum_source_ips"
            ],
            maximum_sources
        )

        source_count = self.random.randint(
            minimum_sources,
            maximum_sources
        )

        selected_ips = self.random.sample(
            self.credential_attacker_ips,
            source_count
        )

        target_user = self.random.choice(
            self.login_targets
        )

        events = []

        for index in range(attempt_count):

            ip = selected_ips[
                index % len(selected_ips)
            ]

            events.append(
                create_login_event(
                    username=target_user,
                    ip=ip,
                    status="FAILED"
                )
            )

        self.random.shuffle(events)

        return events

    def generate_ddos(self):

        attack_config = (
            self.simulation_config["ddos"]
        )

        request_count = self.random.randint(
            attack_config[
                "minimum_requests"
            ],
            attack_config[
                "maximum_requests"
            ]
        )

        maximum_sources = min(
            attack_config[
                "maximum_source_ips"
            ],
            request_count,
            len(self.ddos_attacker_ips)
        )

        minimum_sources = min(
            attack_config[
                "minimum_source_ips"
            ],
            maximum_sources
        )

        source_count = self.random.randint(
            minimum_sources,
            maximum_sources
        )

        selected_ips = self.random.sample(
            self.ddos_attacker_ips,
            source_count
        )

        endpoint = self.random.choice(
            self.attacked_endpoints
        )

        events = []

        for index in range(request_count):

            ip = selected_ips[
                index % len(selected_ips)
            ]

            events.append(
                create_http_event(
                    ip=ip,
                    endpoint=endpoint
                )
            )

        self.random.shuffle(events)

        return events

    def generate_port_scan(self):

        attack_config = (
            self.simulation_config[
                "port_scan"
            ]
        )

        maximum_ports = min(
            attack_config[
                "maximum_ports"
            ],
            len(scan_ports)
        )

        minimum_ports = min(
            attack_config[
                "minimum_ports"
            ],
            maximum_ports
        )

        port_count = self.random.randint(
            minimum_ports,
            maximum_ports
        )

        selected_ports = self.random.sample(
            scan_ports,
            port_count
        )

        scanner_ip = self.random.choice(
            self.scanner_ips
        )

        target_address = self.random.choice(
            self.target_systems
        )

        return [
            create_connection_event(
                source_ip=scanner_ip,
                destination_port=port,
                target_address=target_address
            )
            for port in selected_ports
        ]

    def generate_suspicious_processes(self):

        attack_config = (
            self.simulation_config[
                "suspicious_process"
            ]
        )

        event_count = self.random.randint(
            attack_config[
                "minimum_events"
            ],
            attack_config[
                "maximum_events"
            ]
        )

        events = []

        for _ in range(event_count):

            template = self.random.choice(
                self.process_templates
            )

            events.append(
                create_process_event(
                    process_name=template[
                        "process_name"
                    ],
                    parent_process=template[
                        "parent_process"
                    ],
                    executable_path=template[
                        "executable_path"
                    ],
                    command_line=template[
                        "command_line"
                    ]
                )
            )

        return events

    def generate_random_attack(self):

        scenarios = [
            (
                "DISTRIBUTED_BRUTE_FORCE",
                self.generate_distributed_brute_force
            ),
            (
                "DDOS",
                self.generate_ddos
            ),
            (
                "PORT_SCAN",
                self.generate_port_scan
            ),
            (
                "SUSPICIOUS_PROCESS",
                self.generate_suspicious_processes
            )
        ]

        scenario_name, generator = (
            self.random.choice(scenarios)
        )

        return scenario_name, generator()

    def get_attack_delay(
        self,
        scenario_name
    ):

        config_names = {
            "DISTRIBUTED_BRUTE_FORCE":
                "distributed_brute_force",
            "DDOS": "ddos",
            "PORT_SCAN": "port_scan",
            "SUSPICIOUS_PROCESS":
                "suspicious_process"
        }

        config_name = config_names[
            scenario_name
        ]

        return self.simulation_config[
            config_name
        ]["delay_seconds"]
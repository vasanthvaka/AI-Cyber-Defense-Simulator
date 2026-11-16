
import json
import random
import threading
import time

from pathlib import Path

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent

from config.settings import get_config

from monitor.event_validator import (
    validate_event
)

from simulator.scenario_engine import (
    SecurityScenarioEngine
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events.jsonl"
)


class SimulationBusyError(Exception):
    pass


class SimulationController:

    ATTACK_GENERATORS = {
        "brute-force":
            "DISTRIBUTED_BRUTE_FORCE",

        "ddos":
            "DDOS",

        "port-scan":
            "PORT_SCAN",

        "suspicious-process":
            "SUSPICIOUS_PROCESS"
    }

    def __init__(self, database):

        self.config = get_config()

        self.engine = SecurityScenarioEngine(
            config=self.config
        )

        self.database = database

        self.monitoring_agent = MonitoringAgent(
            event_logger=self.log_event
        )

        self.coordinator = AgentCoordinator(
            monitoring_agent=self.monitoring_agent,
            database=self.database
        )

        self.lock = threading.Lock()

        self.current_operation = None
        self.last_operation = None

    def log_event(self, event):

        LOG_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(event) + "\n"
            )

    def get_status(self):

        is_running = self.lock.locked()

        return {
            "status": (
                "RUNNING"
                if is_running
                else "IDLE"
            ),
            "current_operation":
                self.current_operation,
            "last_operation":
                self.last_operation
        }

    def _run_events(
        self,
        operation,
        events,
        delay_function
    ):

        if not self.lock.acquire(
            blocking=False
        ):

            raise SimulationBusyError(
                "Another simulation is already running."
            )

        self.current_operation = operation

        try:

            response_count = 0

            for event in events:

                validate_event(event)

                responses = (
                    self.coordinator.submit_event(
                        event
                    )
                )

                response_count += len(responses)

                delay = delay_function()

                if delay > 0:
                    time.sleep(delay)

            # Process any remaining AI-window events.
            remaining_responses = (
                self.coordinator.flush_ai_window()
            )

            response_count += len(
                remaining_responses
            )

            self.last_operation = operation

            return {
                "status": "SUCCESS",
                "operation": operation,
                "events_generated": len(events),
                "pipeline_responses": response_count,
                "message": (
                    "Simulation completed successfully."
                )
            }

        finally:

            self.current_operation = None
            self.lock.release()

    def generate_normal_batch(
        self,
        count
    ):

        events = (
            self.engine.generate_normal_events(
                minimum=count,
                maximum=count
            )
        )

        normal_config = (
            self.config["simulation"][
                "normal_activity"
            ]
        )

        return self._run_events(
            operation="NORMAL_TRAFFIC",
            events=events,
            delay_function=lambda: random.uniform(
                normal_config[
                    "minimum_delay_seconds"
                ],
                normal_config[
                    "maximum_delay_seconds"
                ]
            )
        )

    def inject_attack(
        self,
        attack_type
    ):

        scenario_name = (
            self.ATTACK_GENERATORS.get(
                attack_type
            )
        )

        if scenario_name is None:

            raise ValueError(
                f"Unsupported attack type: {attack_type}"
            )

        generators = {
            "DISTRIBUTED_BRUTE_FORCE":
                self.engine.generate_distributed_brute_force,

            "DDOS":
                self.engine.generate_ddos,

            "PORT_SCAN":
                self.engine.generate_port_scan,

            "SUSPICIOUS_PROCESS":
                self.engine.generate_suspicious_processes
        }

        events = generators[
            scenario_name
        ]()

        delay = (
            self.engine.get_attack_delay(
                scenario_name
            )
        )

        result = self._run_events(
            operation=scenario_name,
            events=events,
            delay_function=lambda: delay
        )

        result["scenario"] = scenario_name

        return result

    def inject_random_attack(self):

        scenario_name, events = (
            self.engine.generate_random_attack()
        )

        delay = (
            self.engine.get_attack_delay(
                scenario_name
            )
        )

        result = self._run_events(
            operation=scenario_name,
            events=events,
            delay_function=lambda: delay
        )

        result["scenario"] = scenario_name

        return result


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

        self.live_thread = None
        self.live_stop_event = threading.Event()
        self.live_status = {
            "is_running": False,
            "seed": None,
            "started_at": None,
            "events_generated": 0,
            "attacks_injected": 0
        }

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

        is_running = self.lock.locked() or self.live_status["is_running"]

        return {
            "status": (
                "RUNNING"
                if is_running
                else "IDLE"
            ),
            "current_operation":
                self.current_operation or ("LIVE_MODE" if self.live_status["is_running"] else None),
            "last_operation":
                self.last_operation,
            "live_mode": dict(self.live_status)
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

    def run_demo(self, seed=42):

        if not self.lock.acquire(blocking=False):
            raise SimulationBusyError(
                "Another simulation is already running."
            )

        if seed is not None:
            random.seed(seed)

        self.current_operation = "DEMO_MODE"

        try:
            total_events = 0
            response_count = 0

            # Execute the 4 key scenarios punctuated by normal system events
            stages = [
                ("Normal Baseline", self.engine.generate_normal_events(minimum=6, maximum=8), 0.05),
                ("Distributed Brute Force", self.engine.generate_distributed_brute_force(), 0.06),
                ("Normal Traffic", self.engine.generate_normal_events(minimum=4, maximum=5), 0.05),
                ("DDoS Flood", self.engine.generate_ddos(), 0.04),
                ("Normal Traffic", self.engine.generate_normal_events(minimum=4, maximum=5), 0.05),
                ("Port Scan", self.engine.generate_port_scan(), 0.05),
                ("Normal Traffic", self.engine.generate_normal_events(minimum=4, maximum=5), 0.05),
                ("Suspicious Process", self.engine.generate_suspicious_processes(), 0.06),
                ("Normal Traffic", self.engine.generate_normal_events(minimum=4, maximum=5), 0.05)
            ]

            for _, events, delay in stages:
                for event in events:
                    validate_event(event)
                    responses = self.coordinator.submit_event(event)
                    response_count += len(responses)
                    total_events += 1
                    if delay > 0:
                        time.sleep(delay)

            remaining_responses = self.coordinator.flush_ai_window()
            response_count += len(remaining_responses)

            self.last_operation = "DEMO_MODE"

            return {
                "status": "SUCCESS",
                "operation": "DEMO_MODE",
                "seed": seed,
                "events_generated": total_events,
                "pipeline_responses": response_count,
                "message": "Demo mode completed: executed all 4 threat scenarios and baseline traffic."
            }

        finally:
            self.current_operation = None
            self.lock.release()

    def start_live_mode(self, seed=None):

        if self.live_status["is_running"]:
            raise SimulationBusyError(
                "Live mode is already running."
            )

        if self.lock.locked():
            raise SimulationBusyError(
                "Another simulation operation is in progress."
            )

        actual_seed = (
            seed
            if seed is not None
            else random.randint(1000, 999999)
        )
        random.seed(actual_seed)

        self.live_stop_event.clear()
        self.live_status = {
            "is_running": True,
            "seed": actual_seed,
            "started_at": time.time(),
            "events_generated": 0,
            "attacks_injected": 0
        }

        def _live_loop():
            live_config = self.config["simulation"]["live_mode"]
            while not self.live_stop_event.is_set():
                try:
                    # 1. Normal events batch
                    normal_events = self.engine.generate_normal_events(
                        minimum=live_config.get("minimum_normal_batches", 1) * 3,
                        maximum=live_config.get("maximum_normal_batches", 3) * 4
                    )
                    for event in normal_events:
                        if self.live_stop_event.is_set():
                            break
                        validate_event(event)
                        self.coordinator.submit_event(event)
                        self.live_status["events_generated"] += 1
                        time.sleep(0.08)

                    if self.live_stop_event.is_set():
                        break

                    # 2. Random attack check
                    if random.random() < live_config.get("attack_probability", 0.35):
                        scenario_name, attack_events = self.engine.generate_random_attack()
                        delay = max(self.engine.get_attack_delay(scenario_name) * 0.5, 0.04)
                        for event in attack_events:
                            if self.live_stop_event.is_set():
                                break
                            validate_event(event)
                            self.coordinator.submit_event(event)
                            self.live_status["events_generated"] += 1
                            time.sleep(delay)
                        self.live_status["attacks_injected"] += 1

                    # AI window flush
                    self.coordinator.flush_ai_window()
                    time.sleep(0.6)

                except Exception:
                    time.sleep(1)

            try:
                self.coordinator.flush_ai_window()
            except Exception:
                pass
            self.live_status["is_running"] = False

        self.live_thread = threading.Thread(
            target=_live_loop,
            daemon=True
        )
        self.live_thread.start()

        return {
            "status": "SUCCESS",
            "message": f"Live simulation started with seed {actual_seed}.",
            "live_mode": dict(self.live_status)
        }

    def stop_live_mode(self):

        if not self.live_status["is_running"]:
            return {
                "status": "IDLE",
                "message": "Live mode was not running."
            }

        self.live_stop_event.set()
        if self.live_thread and self.live_thread.is_alive():
            self.live_thread.join(timeout=3.0)

        self.live_status["is_running"] = False

        return {
            "status": "STOPPED",
            "message": "Live simulation stopped.",
            "events_generated": self.live_status["events_generated"],
            "attacks_injected": self.live_status["attacks_injected"]
        }

import argparse
import random
import time

from config.settings import get_config

from monitor.event_monitor import (
    flush_ai_window,
    process_event
)

from simulator.scenario_engine import (
    SecurityScenarioEngine
)


CONFIG = get_config()

SCENARIO_ENGINE = SecurityScenarioEngine(
    config=CONFIG
)


def process_events(events, delay_seconds):

    for event in events:

        process_event(event)

        if delay_seconds > 0:
            time.sleep(delay_seconds)


def generate_mixed_normal_event():

    return SCENARIO_ENGINE\
        .generate_normal_event()


def generate_normal_activity(
    minimum=None,
    maximum=None
):

    normal_config = (
        CONFIG["simulation"][
            "normal_activity"
        ]
    )

    events = (
        SCENARIO_ENGINE
        .generate_normal_events(
            minimum=minimum,
            maximum=maximum
        )
    )

    for event in events:

        process_event(event)

        time.sleep(
            random.uniform(
                normal_config[
                    "minimum_delay_seconds"
                ],
                normal_config[
                    "maximum_delay_seconds"
                ]
            )
        )


def simulate_distributed_brute_force():

    events = (
        SCENARIO_ENGINE
        .generate_distributed_brute_force()
    )

    delay = (
        SCENARIO_ENGINE.get_attack_delay(
            "DISTRIBUTED_BRUTE_FORCE"
        )
    )

    process_events(events, delay)


def simulate_ddos():

    events = (
        SCENARIO_ENGINE.generate_ddos()
    )

    delay = (
        SCENARIO_ENGINE.get_attack_delay(
            "DDOS"
        )
    )

    process_events(events, delay)


def simulate_port_scan():

    events = (
        SCENARIO_ENGINE.generate_port_scan()
    )

    delay = (
        SCENARIO_ENGINE.get_attack_delay(
            "PORT_SCAN"
        )
    )

    process_events(events, delay)


def simulate_suspicious_process():

    events = (
        SCENARIO_ENGINE
        .generate_suspicious_processes()
    )

    delay = (
        SCENARIO_ENGINE.get_attack_delay(
            "SUSPICIOUS_PROCESS"
        )
    )

    process_events(events, delay)


def run_demo():

    print(
        "\nStarting cyber-defense simulation "
        "in DEMO mode...\n"
    )

    generate_normal_activity(8, 8)

    print(
        "\nInjecting distributed "
        "brute-force activity...\n"
    )

    simulate_distributed_brute_force()

    generate_normal_activity(5, 5)

    print(
        "\nInjecting DDoS activity...\n"
    )

    simulate_ddos()

    generate_normal_activity(5, 5)

    print(
        "\nInjecting port-scan activity...\n"
    )

    simulate_port_scan()

    generate_normal_activity(5, 5)

    print(
        "\nInjecting suspicious-process "
        "activity...\n"
    )

    simulate_suspicious_process()

    generate_normal_activity(5, 5)

    flush_ai_window()

    print(
        "\nDemo simulation completed.\n"
    )


def run_live():

    live_config = (
        CONFIG["simulation"]["live_mode"]
    )

    print(
        "\nStarting cyber-defense simulation "
        "in LIVE mode..."
    )

    print(
        "Attacks will occur at unpredictable "
        "times."
    )

    print(
        "Press Ctrl+C to stop the "
        "simulation.\n"
    )

    try:

        while True:

            normal_batch_count = (
                random.randint(
                    live_config[
                        "minimum_normal_batches"
                    ],
                    live_config[
                        "maximum_normal_batches"
                    ]
                )
            )

            for _ in range(
                normal_batch_count
            ):
                generate_normal_activity()

            attack_occurs = (
                random.random()
                < live_config[
                    "attack_probability"
                ]
            )

            if not attack_occurs:
                continue

            scenario_name, events = (
                SCENARIO_ENGINE
                .generate_random_attack()
            )

            print(
                "\nSimulation introduced "
                f"{scenario_name} activity.\n"
            )

            delay = (
                SCENARIO_ENGINE
                .get_attack_delay(
                    scenario_name
                )
            )

            process_events(events, delay)

    except KeyboardInterrupt:

        flush_ai_window()

        print(
            "\nLive simulation stopped "
            "by the user.\n"
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "AI-Powered Cyber Defense "
            "Simulation"
        )
    )

    parser.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help=(
            "Select demonstration mode "
            "or continuous live mode"
        )
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help=(
            "Optional random seed for "
            "reproducible simulation"
        )
    )

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    elif args.mode == "demo":
        random.seed(42)

    if args.mode == "demo":
        run_demo()

    else:
        run_live()


if __name__ == "__main__":
    main()
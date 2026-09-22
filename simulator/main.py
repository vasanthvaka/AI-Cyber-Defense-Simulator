import argparse
import random
import time

from monitor.event_monitor import (
    flush_ai_window,
    process_event
)

from simulator.brute_force import (
    generate_normal_login,
    generate_distributed_brute_force
)

from simulator.ddos import (
    generate_normal_request,
    generate_ddos_request
)

from simulator.port_scan import (
    generate_normal_connection,
    generate_port_scan,
    scan_ports
)

from simulator.process_activity import (
    generate_normal_process,
    generate_suspicious_process
)


def generate_mixed_normal_event():

    normal_generators = [
        generate_normal_login,
        generate_normal_request,
        generate_normal_connection,
        generate_normal_process
    ]

    generator = random.choice(normal_generators)

    return generator()


def generate_normal_activity(minimum=5, maximum=10):

    event_count = random.randint(minimum, maximum)

    for _ in range(event_count):
        event = generate_mixed_normal_event()
        process_event(event)
        time.sleep(random.uniform(0.15, 0.35))


def simulate_distributed_brute_force():

    for _ in range(8):
        event = generate_distributed_brute_force()
        process_event(event)
        time.sleep(0.2)


def simulate_ddos():

    for _ in range(20):
        event = generate_ddos_request()
        process_event(event)
        time.sleep(0.08)


def simulate_port_scan():

    for port in scan_ports:
        event = generate_port_scan(port)
        process_event(event)
        time.sleep(0.15)


def simulate_suspicious_process():

    event = generate_suspicious_process()
    process_event(event)


def run_demo():

    print("\nStarting cyber-defense simulation in DEMO mode...\n")

    generate_normal_activity(8, 8)
    simulate_distributed_brute_force()

    generate_normal_activity(5, 5)
    simulate_ddos()

    generate_normal_activity(5, 5)
    simulate_port_scan()

    generate_normal_activity(5, 5)
    simulate_suspicious_process()

    generate_normal_activity(5, 5)

    # Analyse the final incomplete AI window.
    flush_ai_window()

    print("\nDemo simulation completed.\n")


def run_live():

    print("\nStarting cyber-defense simulation in LIVE mode...")
    print("Press Ctrl+C to stop the simulation.\n")

    attack_scenarios = [
        simulate_distributed_brute_force,
        simulate_ddos,
        simulate_port_scan,
        simulate_suspicious_process
    ]

    try:
        while True:

            # Randomize attack order during every cycle
            random.shuffle(attack_scenarios)

            for attack_scenario in attack_scenarios:

                # Generate a random amount of normal activity
                generate_normal_activity(6, 12)

                # Introduce one attack without telling the detector
                attack_scenario()

    except KeyboardInterrupt:

        # Analyse events remaining in the final AI window.
        flush_ai_window()

        print("\nLive simulation stopped by the user.\n")


def main():

    parser = argparse.ArgumentParser(
        description="AI-Powered Cyber Defense Simulation"
    )

    parser.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help="Select predictable demo mode or continuous live mode"
    )

    args = parser.parse_args()

    if args.mode == "demo":
        run_demo()

    elif args.mode == "live":
        run_live()


if __name__ == "__main__":
    main()
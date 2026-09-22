import random

from detector.anomaly_detector import analyze_window

from simulator.main import generate_mixed_normal_event

from simulator.brute_force import (
    generate_distributed_brute_force
)

from simulator.ddos import generate_ddos_request

from simulator.port_scan import (
    generate_port_scan,
    scan_ports
)

from simulator.process_activity import (
    generate_suspicious_process
)


EVALUATION_RUNS = 100


def generate_normal_window():

    event_count = random.randint(5, 15)

    return [
        generate_mixed_normal_event()
        for _ in range(event_count)
    ]


def generate_distributed_brute_force_window():

    events = generate_normal_window()

    events.extend(
        generate_distributed_brute_force()
        for _ in range(8)
    )

    return events


def generate_ddos_window():

    events = generate_normal_window()

    events.extend(
        generate_ddos_request()
        for _ in range(20)
    )

    return events


def generate_port_scan_window():

    events = generate_normal_window()

    events.extend(
        generate_port_scan(port)
        for port in scan_ports
    )

    return events


def generate_suspicious_process_window():

    events = generate_normal_window()
    events.append(generate_suspicious_process())

    return events


def evaluate_scenario(
    scenario_name,
    window_generator
):

    detected_count = 0
    scores = []

    for _ in range(EVALUATION_RUNS):

        events = window_generator()
        analysis = analyze_window(events)

        scores.append(
            analysis["anomaly_score"]
        )

        if analysis["is_anomaly"]:
            detected_count += 1

    average_score = sum(scores) / len(scores)

    print(f"\nScenario: {scenario_name}")

    print(
        f"Detected as anomalous: "
        f"{detected_count}/{EVALUATION_RUNS}"
    )

    print(
        f"Detection rate: "
        f"{detected_count / EVALUATION_RUNS:.0%}"
    )

    print(
        f"Average anomaly score: "
        f"{average_score:.4f}"
    )


def main():

    random.seed(42)
    
    print("\nEvaluating Isolation Forest...\n")

    scenarios = [
        (
            "NORMAL_ACTIVITY",
            generate_normal_window
        ),
        (
            "DISTRIBUTED_BRUTE_FORCE",
            generate_distributed_brute_force_window
        ),
        (
            "DDOS",
            generate_ddos_window
        ),
        (
            "PORT_SCAN",
            generate_port_scan_window
        ),
        (
            "SUSPICIOUS_PROCESS",
            generate_suspicious_process_window
        )
    ]

    for scenario_name, window_generator in scenarios:
        evaluate_scenario(
            scenario_name,
            window_generator
        )


if __name__ == "__main__":
    main()
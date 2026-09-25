import json
import random
from pathlib import Path
from time import perf_counter

from detector import brute_force_detector
from detector import ddos_detector
from detector import port_scan_detector
from detector import process_detector

from simulator.brute_force import (
    create_login_event
)

from simulator.ddos import (
    create_http_event
)

from detector.anomaly_detector import (
    analyze_window
)

from detector.brute_force_detector import (
    detect_brute_force
)

from detector.ddos_detector import detect_ddos

from detector.port_scan_detector import (
    detect_port_scan
)

from detector.process_detector import (
    detect_suspicious_process
)

from detector.evaluate_anomaly_model import (
    generate_normal_window,
    generate_distributed_brute_force_window,
    generate_ddos_window,
    generate_port_scan_window,
    generate_suspicious_process_window
)

from evaluation.metrics import (
    calculate_classification_metrics,
    calculate_latency_metrics
)


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

RESULTS_DIRECTORY = (
    PROJECT_ROOT
    / "evaluation"
    / "results"
)

RESULT_FILE = (
    RESULTS_DIRECTORY
    / "system_evaluation.json"
)

DEFAULT_RUNS_PER_SCENARIO = 100
DEFAULT_RANDOM_SEED = 42

def generate_low_and_slow_credential_window():

    events = generate_normal_window()

    events.extend(
        create_login_event(
            username="backup-admin",
            ip=f"10.10.0.{index}",
            status="FAILED"
        )
        for index in range(1, 5)
    )

    return events


def generate_distributed_endpoint_flood_window():

    events = generate_normal_window()

    attacker_ips = [
        f"10.20.0.{index}"
        for index in range(1, 9)
    ]

    attacked_endpoints = [
        "/api/search",
        "/api/catalog",
        "/api/status",
        "/api/profile"
    ]

    for endpoint_index, endpoint in enumerate(
        attacked_endpoints
    ):

        for offset in range(6):

            ip = attacker_ips[
                (
                    endpoint_index
                    + offset
                )
                % len(attacker_ips)
            ]

            events.append(
                create_http_event(
                    ip=ip,
                    endpoint=endpoint
                )
            )

    return events

SCENARIOS = [
    {
        "name": "NORMAL_ACTIVITY",
        "is_attack": False,
        "generator": generate_normal_window
    },
    {
        "name": "DISTRIBUTED_BRUTE_FORCE",
        "is_attack": True,
        "generator":
            generate_distributed_brute_force_window
    },
    {
        "name": "DDOS",
        "is_attack": True,
        "generator": generate_ddos_window
    },
    {
        "name": "PORT_SCAN",
        "is_attack": True,
        "generator": generate_port_scan_window
    },
    {
        "name": "SUSPICIOUS_PROCESS",
        "is_attack": True,
        "generator":
            generate_suspicious_process_window
    },
    {
        "name":
            "LOW_AND_SLOW_CREDENTIAL_ATTACK",
        "is_attack": True,
        "generator":
            generate_low_and_slow_credential_window
    },
    {
        "name":
            "DISTRIBUTED_ENDPOINT_FLOOD",
        "is_attack": True,
        "generator":
            generate_distributed_endpoint_flood_window
    }
]


METHOD_NAMES = [
    "rule_based",
    "isolation_forest",
    "hybrid"
]


def reset_rule_detector_state():

    brute_force_detector\
        .failed_attempts_by_ip.clear()

    brute_force_detector\
        .failed_attempts_by_username.clear()

    brute_force_detector\
        .flagged_ips.clear()

    brute_force_detector\
        .flagged_usernames.clear()

    ddos_detector.requests_by_target.clear()
    ddos_detector.flagged_targets.clear()

    port_scan_detector\
        .connection_attempts.clear()

    port_scan_detector\
        .flagged_scanners.clear()

    process_detector.flagged_processes.clear()


def detect_rule_alerts(events):

    alerts = []

    for event in events:

        event_type = event.get("event_type")
        alert = None

        if event_type == "LOGIN_ATTEMPT":
            alert = detect_brute_force(event)

        elif event_type == "HTTP_REQUEST":
            alert = detect_ddos(event)

        elif event_type == "NETWORK_CONNECTION":
            alert = detect_port_scan(event)

        elif event_type == "PROCESS_ACTIVITY":
            alert = detect_suspicious_process(
                event
            )

        if alert is not None:
            alerts.append(alert)

    return alerts


def create_empty_scenario_result(
    is_attack
):

    return {
        "is_attack": is_attack,
        "total_runs": 0,
        "detections": {
            method_name: 0
            for method_name in METHOD_NAMES
        }
    }


def evaluate_system(
    runs_per_scenario=(
        DEFAULT_RUNS_PER_SCENARIO
    ),
    random_seed=DEFAULT_RANDOM_SEED
):

    if not isinstance(runs_per_scenario, int):
        raise TypeError(
            "Runs per scenario must be an integer"
        )

    if runs_per_scenario <= 0:
        raise ValueError(
            "Runs per scenario must be greater than zero"
        )

    if not isinstance(random_seed, int):
        raise TypeError(
            "Random seed must be an integer"
        )

    random.seed(random_seed)

    expected_labels = []

    predictions = {
        method_name: []
        for method_name in METHOD_NAMES
    }

    latencies = {
        method_name: []
        for method_name in METHOD_NAMES
    }

    scenario_results = {
        scenario["name"]:
            create_empty_scenario_result(
                scenario["is_attack"]
            )
        for scenario in SCENARIOS
    }

    for scenario in SCENARIOS:

        scenario_name = scenario["name"]
        is_attack = scenario["is_attack"]
        window_generator = (
            scenario["generator"]
        )

        for _ in range(runs_per_scenario):

            events = window_generator()

            reset_rule_detector_state()

            rule_start = perf_counter()

            rule_alerts = detect_rule_alerts(
                events
            )

            rule_latency_ms = (
                perf_counter() - rule_start
            ) * 1000

            rule_detected = bool(rule_alerts)

            ai_start = perf_counter()

            ai_analysis = analyze_window(events)

            ai_latency_ms = (
                perf_counter() - ai_start
            ) * 1000

            ai_detected = bool(
                ai_analysis
                and ai_analysis["is_anomaly"]
            )

            hybrid_detected = (
                rule_detected
                or ai_detected
            )

            hybrid_latency_ms = (
                rule_latency_ms
                + ai_latency_ms
            )

            method_results = {
                "rule_based": rule_detected,
                "isolation_forest":
                    ai_detected,
                "hybrid": hybrid_detected
            }

            method_latencies = {
                "rule_based":
                    rule_latency_ms,
                "isolation_forest":
                    ai_latency_ms,
                "hybrid":
                    hybrid_latency_ms
            }

            expected_labels.append(
                is_attack
            )

            scenario_result = (
                scenario_results[
                    scenario_name
                ]
            )

            scenario_result[
                "total_runs"
            ] += 1

            for method_name in METHOD_NAMES:

                detected = method_results[
                    method_name
                ]

                predictions[
                    method_name
                ].append(detected)

                latencies[
                    method_name
                ].append(
                    method_latencies[
                        method_name
                    ]
                )

                if detected:
                    scenario_result[
                        "detections"
                    ][method_name] += 1

    for scenario_result in (
        scenario_results.values()
    ):

        total_runs = scenario_result[
            "total_runs"
        ]

        scenario_result[
            "positive_rates"
        ] = {
            method_name: (
                scenario_result[
                    "detections"
                ][method_name]
                / total_runs
            )
            for method_name in METHOD_NAMES
        }

    method_results = {}

    for method_name in METHOD_NAMES:

        method_results[method_name] = {
            "classification":
                calculate_classification_metrics(
                    expected_labels,
                    predictions[method_name]
                ),
            "latency":
                calculate_latency_metrics(
                    latencies[method_name]
                )
        }

    return {
        "configuration": {
            "random_seed": random_seed,
            "runs_per_scenario":
                runs_per_scenario,
            "scenario_count":
                len(SCENARIOS),
            "total_samples":
                len(expected_labels)
        },
        "methods": method_results,
        "scenarios": scenario_results
    }


def save_evaluation_report(report):

    RESULTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


def display_percentage(value):

    return f"{value * 100:.1f}%"


def display_report(report):

    print(
        "\nAI Cyber Defense "
        "System Evaluation\n"
    )

    configuration = report[
        "configuration"
    ]

    print(
        "Runs per scenario: "
        f"{configuration['runs_per_scenario']}"
    )

    print(
        "Total evaluated windows: "
        f"{configuration['total_samples']}"
    )

    print(
        "\nOverall Method Performance"
    )

    for method_name, result in (
        report["methods"].items()
    ):

        classification = result[
            "classification"
        ]

        latency = result["latency"]

        print(
            f"\nMethod: "
            f"{method_name.upper()}"
        )

        print(
            "  Accuracy: "
            + display_percentage(
                classification["accuracy"]
            )
        )

        print(
            "  Precision: "
            + display_percentage(
                classification["precision"]
            )
        )

        print(
            "  Detection Rate: "
            + display_percentage(
                classification[
                    "detection_rate"
                ]
            )
        )

        print(
            "  False Positive Rate: "
            + display_percentage(
                classification[
                    "false_positive_rate"
                ]
            )
        )

        print(
            "  F1 Score: "
            + display_percentage(
                classification["f1_score"]
            )
        )

        print(
            "  Average Latency: "
            f"{latency['average_ms']:.3f} ms"
        )

        print(
            "  P95 Latency: "
            f"{latency['p95_ms']:.3f} ms"
        )

    print("\nScenario Detection Results")

    for scenario_name, result in (
        report["scenarios"].items()
    ):

        print(f"\nScenario: {scenario_name}")

        for method_name, rate in (
            result["positive_rates"].items()
        ):

            label = (
                "false-positive rate"
                if not result["is_attack"]
                else "detection rate"
            )

            print(
                f"  {method_name}: "
                f"{display_percentage(rate)} "
                f"{label}"
            )

    print(
        "\nReport saved to: "
        f"{RESULT_FILE}"
    )


def main():

    report = evaluate_system()

    save_evaluation_report(report)
    display_report(report)


if __name__ == "__main__":
    main()
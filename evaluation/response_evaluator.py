import json
import random
from pathlib import Path
from time import perf_counter

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent

from evaluation.metrics import (
    calculate_latency_metrics
)

from evaluation.system_evaluator import (
    SCENARIOS,
    reset_rule_detector_state
)


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

RESULT_FILE = (
    PROJECT_ROOT
    / "evaluation"
    / "results"
    / "response_evaluation.json"
)

DEFAULT_RUNS_PER_SCENARIO = 100
DEFAULT_RANDOM_SEED = 42


EXPECTED_ACTIONS = {
    "NORMAL_ACTIVITY": set(),
    "DISTRIBUTED_BRUTE_FORCE": {
        "BLOCK_IPS"
    },
    "DDOS": {
        "RATE_LIMIT_IPS"
    },
    "PORT_SCAN": {
        "BLOCK_IP"
    },
    "SUSPICIOUS_PROCESS": {
        "QUARANTINE_PROCESS"
    },
    "LOW_AND_SLOW_CREDENTIAL_ATTACK": {
        "FLAG_FOR_INVESTIGATION"
    },
    "DISTRIBUTED_ENDPOINT_FLOOD": {
        "FLAG_FOR_INVESTIGATION"
    }
}


CONTAINMENT_ACTIONS = {
    "BLOCK_IP",
    "BLOCK_IPS",
    "RATE_LIMIT_IPS",
    "QUARANTINE_PROCESS"
}


def extract_responses(response_messages):

    return [
        message.payload["response"]
        for message in response_messages
        if (
            isinstance(message.payload, dict)
            and isinstance(
                message.payload.get("response"),
                dict
            )
        )
    ]


def run_scenario_pipeline(events):

    reset_rule_detector_state()

    monitoring_agent = MonitoringAgent()

    coordinator = AgentCoordinator(
        monitoring_agent=monitoring_agent
    )

    response_messages = []

    start_time = perf_counter()

    for event in events:

        response_messages.extend(
            coordinator.submit_event(event)
        )

    response_messages.extend(
        coordinator.flush_ai_window()
    )

    latency_ms = (
        perf_counter() - start_time
    ) * 1000

    return (
        extract_responses(
            response_messages
        ),
        latency_ms
    )


def create_scenario_result(
    scenario_name,
    is_attack
):

    return {
        "scenario": scenario_name,
        "is_attack": is_attack,
        "total_runs": 0,
        "runs_with_response": 0,
        "correct_workflow_runs": 0,
        "automatic_containment_runs": 0,
        "approval_required_runs": 0,
        "investigation_runs": 0,
        "unsafe_normal_containment_runs": 0,
        "statuses": {},
        "actions": {},
        "latencies_ms": []
    }


def increment_count(dictionary, key):

    dictionary[key] = (
        dictionary.get(key, 0) + 1
    )


def evaluate_response_pipeline(
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

    scenario_results = {}

    all_latencies = []

    total_attack_runs = 0
    attack_runs_with_response = 0
    total_normal_runs = 0
    unsafe_normal_runs = 0
    total_correct_workflow_runs = 0
    total_runs = 0

    for scenario in SCENARIOS:

        scenario_name = scenario["name"]
        is_attack = scenario["is_attack"]
        generator = scenario["generator"]

        result = create_scenario_result(
            scenario_name,
            is_attack
        )

        expected_actions = EXPECTED_ACTIONS[
            scenario_name
        ]

        for _ in range(runs_per_scenario):

            events = generator()

            responses, latency_ms = (
                run_scenario_pipeline(events)
            )

            result["total_runs"] += 1
            result["latencies_ms"].append(
                latency_ms
            )

            all_latencies.append(latency_ms)
            total_runs += 1

            if responses:
                result[
                    "runs_with_response"
                ] += 1

            actions = {
                response.get("action")
                for response in responses
                if response.get("action")
            }

            statuses = {
                response.get("status")
                for response in responses
                if response.get("status")
            }

            for action in actions:
                increment_count(
                    result["actions"],
                    action
                )

            for status in statuses:
                increment_count(
                    result["statuses"],
                    status
                )

            contains_automatic_response = any(
                response.get("automatic")
                and (
                    response.get("action")
                    in CONTAINMENT_ACTIONS
                )
                and (
                    response.get("status")
                    == "SIMULATED_SUCCESS"
                )
                for response in responses
            )

            requires_approval = any(
                response.get("status")
                == "APPROVAL_REQUIRED"
                for response in responses
            )

            requires_investigation = any(
                (
                    response.get("action")
                    == "FLAG_FOR_INVESTIGATION"
                )
                or (
                    response.get("status")
                    == "REVIEW_REQUIRED"
                )
                for response in responses
            )

            contains_containment = bool(
                actions & CONTAINMENT_ACTIONS
            )

            if contains_automatic_response:
                result[
                    "automatic_containment_runs"
                ] += 1

            if requires_approval:
                result[
                    "approval_required_runs"
                ] += 1

            if requires_investigation:
                result[
                    "investigation_runs"
                ] += 1

            if is_attack:

                total_attack_runs += 1

                if responses:
                    attack_runs_with_response += 1

                correct_workflow = bool(
                    actions & expected_actions
                )

            else:

                total_normal_runs += 1

                correct_workflow = (
                    not contains_containment
                )

                if contains_automatic_response:
                    result[
                        "unsafe_normal_containment_runs"
                    ] += 1

                    unsafe_normal_runs += 1

            if correct_workflow:

                result[
                    "correct_workflow_runs"
                ] += 1

                total_correct_workflow_runs += 1

        total_scenario_runs = result[
            "total_runs"
        ]

        result["rates"] = {
            "response_rate": (
                result["runs_with_response"]
                / total_scenario_runs
            ),
            "correct_workflow_rate": (
                result[
                    "correct_workflow_runs"
                ]
                / total_scenario_runs
            ),
            "automatic_containment_rate": (
                result[
                    "automatic_containment_runs"
                ]
                / total_scenario_runs
            ),
            "approval_required_rate": (
                result[
                    "approval_required_runs"
                ]
                / total_scenario_runs
            ),
            "investigation_rate": (
                result["investigation_runs"]
                / total_scenario_runs
            ),
            "unsafe_normal_containment_rate": (
                result[
                    "unsafe_normal_containment_runs"
                ]
                / total_scenario_runs
            )
        }

        result["latency"] = (
            calculate_latency_metrics(
                result.pop("latencies_ms")
            )
        )

        scenario_results[
            scenario_name
        ] = result

    return {
        "configuration": {
            "random_seed": random_seed,
            "runs_per_scenario":
                runs_per_scenario,
            "total_runs": total_runs
        },
        "overall": {
            "attack_response_coverage": (
                attack_runs_with_response
                / total_attack_runs
            ),
            "correct_workflow_rate": (
                total_correct_workflow_runs
                / total_runs
            ),
            "unsafe_normal_containment_rate": (
                unsafe_normal_runs
                / total_normal_runs
            ),
            "latency":
                calculate_latency_metrics(
                    all_latencies
                )
        },
        "scenarios": scenario_results
    }


def save_report(report):

    RESULT_FILE.parent.mkdir(
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


def percentage(value):

    return f"{value * 100:.1f}%"


def display_report(report):

    print(
        "\nResponse Pipeline Evaluation\n"
    )

    overall = report["overall"]

    print(
        "Attack response coverage: "
        + percentage(
            overall[
                "attack_response_coverage"
            ]
        )
    )

    print(
        "Correct workflow rate: "
        + percentage(
            overall[
                "correct_workflow_rate"
            ]
        )
    )

    print(
        "Unsafe normal containment rate: "
        + percentage(
            overall[
                "unsafe_normal_containment_rate"
            ]
        )
    )

    print(
        "Average pipeline latency: "
        f"{overall['latency']['average_ms']:.3f} ms"
    )

    print("\nScenario Results")

    for scenario_name, result in (
        report["scenarios"].items()
    ):

        rates = result["rates"]

        print(f"\nScenario: {scenario_name}")

        print(
            "  Response rate: "
            + percentage(
                rates["response_rate"]
            )
        )

        print(
            "  Correct workflow: "
            + percentage(
                rates[
                    "correct_workflow_rate"
                ]
            )
        )

        print(
            "  Automatic containment: "
            + percentage(
                rates[
                    "automatic_containment_rate"
                ]
            )
        )

        print(
            "  Approval required: "
            + percentage(
                rates[
                    "approval_required_rate"
                ]
            )
        )

        print(
            "  Investigation: "
            + percentage(
                rates[
                    "investigation_rate"
                ]
            )
        )

    print(
        "\nReport saved to: "
        f"{RESULT_FILE}"
    )


def main():

    report = evaluate_response_pipeline()

    save_report(report)
    display_report(report)


if __name__ == "__main__":
    main()
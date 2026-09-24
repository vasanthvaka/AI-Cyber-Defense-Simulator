import json
from pathlib import Path

from agents.coordinator import AgentCoordinator
from agents.monitoring_agent import MonitoringAgent
from storage.database import SecurityDatabase


PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent

LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events.jsonl"
)

DATABASE_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_defense.db"
)

def log_event(event):

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(event) + "\n"
        )


MONITORING_AGENT = MonitoringAgent(
    event_logger=log_event
)

SECURITY_DATABASE = SecurityDatabase(
    DATABASE_FILE
)

AGENT_COORDINATOR = AgentCoordinator(
    monitoring_agent=MONITORING_AGENT,
    database=SECURITY_DATABASE
)

def display_agent_result(
    response_message
):

    payload = response_message.payload

    incident = payload["incident"]
    analysis = payload["analysis"]
    decision = payload["decision"]
    response = payload["response"]

    sources = ", ".join(
        (
            f"{entity['entity_type']}="
            f"{entity['value']}"
        )
        for entity in incident["sources"]
    )

    targets = ", ".join(
        (
            f"{entity['entity_type']}="
            f"{entity['value']}"
        )
        for entity in incident["targets"]
    )

    methods = ", ".join(
        analysis["detection_methods"]
    )

    response_targets = ", ".join(
        str(target)
        for target in response["targets"]
    )

    new_targets = ", ".join(
        str(target)
        for target in response[
            "new_targets"
        ]
    )

    print("\n🤖 MULTI-AGENT SECURITY RESULT")

    print(
        f"Incident ID: "
        f"{incident['incident_id']}"
    )

    print(
        f"Incident Type: "
        f"{incident['incident_type']}"
    )

    print(
        f"Supporting Alerts: "
        f"{len(incident['alerts'])}"
    )

    print(
        f"Detection Methods: "
        f"{methods if methods else 'None'}"
    )

    print(
        f"Sources: "
        f"{sources if sources else 'None'}"
    )

    print(
        f"Targets: "
        f"{targets if targets else 'None'}"
    )

    print(
        f"Risk Score: "
        f"{analysis['risk_score']}"
    )

    print(
        f"Confidence: "
        f"{analysis['confidence']}"
    )

    print(
        f"Human Review Required: "
        f"{analysis['requires_human_review']}"
    )

    print(
        f"Escalation: "
        f"{analysis['recommended_escalation']}"
    )

    print(
        f"Decision: "
        f"{decision['recommended_action']}"
    )

    print(
        f"Decision Reason: "
        f"{decision['reason']}"
    )

    print(
        f"Response Status: "
        f"{response['status']}"
    )

    print(
        f"Response Targets: "
        f"{response_targets if response_targets else 'None'}"
    )

    print(
        f"New Targets: "
        f"{new_targets if new_targets else 'None'}"
    )

    print(
        f"Automatic: "
        f"{response['automatic']}"
    )

    print()


def process_event(event):

    print(event)

    response_messages = (
        AGENT_COORDINATOR.submit_event(
            event
        )
    )

    for response_message in response_messages:

        display_agent_result(
            response_message
        )

    return response_messages


def flush_ai_window():

    response_messages = (
        AGENT_COORDINATOR.flush_ai_window()
    )

    for response_message in response_messages:

        display_agent_result(
            response_message
        )

    return response_messages
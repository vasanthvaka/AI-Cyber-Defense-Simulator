from agents.base_agent import BaseAgent


class ResponseAgent(BaseAgent):

    def __init__(self):

        super().__init__(
            agent_name="RESPONSE_AGENT"
        )

        self.blocked_ips = set()
        self.rate_limited_ips = set()
        self.quarantined_processes = set()
        self.investigation_queue = []
        self.action_history = []

        self.response_message_count = 0

    def handle_message(self, message):

        if (
            message.message_type
            != "DECISION_CREATED"
        ):
            raise ValueError(
                "Response Agent only accepts "
                "DECISION_CREATED messages"
            )

        decision = message.payload.get(
            "decision"
        )

        if not isinstance(decision, dict):
            raise TypeError(
                "Decision payload must be "
                "a dictionary"
            )

        result = self.execute(decision)

        self.response_message_count += 1

        return self.create_message(
            message_type="RESPONSE_EXECUTED",
            recipient="COORDINATOR",
            payload={
                "response": result,
                "decision": decision,
                "analysis": message.payload.get(
                    "analysis"
                ),
                "incident": message.payload.get(
                    "incident"
                )
            },
            correlation_id=(
                message.correlation_id
            ),
            priority=message.priority,
            parent_message_id=(
                message.message_id
            )
        )

    def execute(self, decision):

        if not isinstance(decision, dict):
            raise TypeError(
                "Decision must be a dictionary"
            )

        action = decision.get(
            "recommended_action"
        )

        targets = decision.get(
            "targets",
            []
        )

        if not action:
            raise ValueError(
                "Decision must contain a "
                "recommended_action"
            )

        if not isinstance(targets, list):
            raise TypeError(
                "Decision targets must be a list"
            )

        if action in {
            "BLOCK_IP",
            "BLOCK_IPS"
        }:

            new_targets = self._add_new_targets(
                self.blocked_ips,
                targets
            )

        elif action == "RATE_LIMIT_IPS":

            new_targets = self._add_new_targets(
                self.rate_limited_ips,
                targets
            )

        elif action == "QUARANTINE_PROCESS":

            new_targets = self._add_new_targets(
                self.quarantined_processes,
                targets
            )

        elif action == "FLAG_FOR_INVESTIGATION":

            investigation = {
                "incident_id": decision.get(
                    "incident_id"
                ),
                "attack_type": decision[
                    "attack_type"
                ],
                "severity": decision[
                    "severity"
                ],
                "risk_score": decision.get(
                    "risk_score"
                ),
                "confidence": decision.get(
                    "confidence"
                ),
                "targets": list(targets),
                "reason": decision["reason"]
            }

            self.investigation_queue.append(
                investigation
            )

            new_targets = list(targets)

        elif action == "CONTINUE_MONITORING":

            new_targets = []

        else:
            raise ValueError(
                f"Unsupported response action: "
                f"{action}"
            )

        result = {
            "incident_id": decision.get(
                "incident_id"
            ),
            "attack_type": decision[
                "attack_type"
            ],
            "action": action,
            "status": "SIMULATED_SUCCESS",
            "targets": list(targets),
            "new_targets": new_targets,
            "automatic": decision[
                "automatic"
            ],
            "simulated": True
        }

        self.action_history.append(result)

        return result

    def _add_new_targets(
        self,
        state_set,
        targets
    ):

        new_targets = []

        for target in targets:

            if target not in state_set:
                state_set.add(target)
                new_targets.append(target)

        return new_targets
class ResponseAgent:

    def __init__(self):

        self.blocked_ips = set()
        self.rate_limited_ips = set()
        self.quarantined_processes = set()
        self.investigation_queue = []
        self.action_history = []

    def execute(self, decision):

        if not isinstance(decision, dict):
            raise TypeError(
                "Decision must be a dictionary"
            )

        action = decision.get("recommended_action")
        targets = decision.get("targets", [])

        if not action:
            raise ValueError(
                "Decision must contain a recommended_action"
            )

        if not isinstance(targets, list):
            raise TypeError(
                "Decision targets must be a list"
            )

        if action in {"BLOCK_IP", "BLOCK_IPS"}:
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
                "attack_type": decision["attack_type"],
                "severity": decision["severity"],
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
                f"Unsupported response action: {action}"
            )

        result = {
            "attack_type": decision["attack_type"],
            "action": action,
            "status": "SIMULATED_SUCCESS",
            "targets": list(targets),
            "new_targets": new_targets,
            "automatic": decision["automatic"],
            "simulated": True
        }

        self.action_history.append(result)

        return result

    def _add_new_targets(self, state_set, targets):

        new_targets = []

        for target in targets:

            if target not in state_set:
                state_set.add(target)
                new_targets.append(target)

        return new_targets
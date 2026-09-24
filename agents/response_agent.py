from copy import deepcopy
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4

from agents.base_agent import BaseAgent
from agents.response_policy import ResponsePolicy


class ResponseAgent(BaseAgent):

    def __init__(self, policy=None):
        super().__init__(agent_name="RESPONSE_AGENT")

        self.policy = policy if policy is not None else ResponsePolicy()

        self.blocked_ips = set()
        self.rate_limited_ips = set()
        self.quarantined_processes = set()
        self.investigation_queue = []
        self.action_history = []
        self.pending_approvals = {}

        self.last_action_times = {}
        self.action_expirations = {}
        self.action_origins = {}
        self.clock = monotonic

        self.response_message_count = 0

    def handle_message(self, message):
        if message.message_type != "DECISION_CREATED":
            raise ValueError(
                "Response Agent only accepts DECISION_CREATED messages"
            )

        decision = message.payload.get("decision")
        if not isinstance(decision, dict):
            raise TypeError("Decision payload must be a dictionary")

        evaluation = self.policy.evaluate(decision)
        status = evaluation["status"]

        if status in {"ALLOWED", "NO_CONTAINMENT"}:
            if status == "NO_CONTAINMENT":
                result = self.execute(decision)
                self._add_policy_audit(result, evaluation)
            else:
                safe_decision = {
                    **decision,
                    "targets": evaluation["allowed_targets"],
                }
                result = self._execute_with_suppression(
                    safe_decision,
                    evaluation,
                )
        else:
            result = {
                "incident_id": decision.get("incident_id"),
                "attack_type": decision["attack_type"],
                "action": decision["recommended_action"],
                "status": status,
                "targets": list(decision.get("targets", [])),
                "new_targets": [],
                "automatic": False,
                "simulated": True,
                "policy_evaluation": evaluation,
            }

            if status == "APPROVAL_REQUIRED":
                approval_id = message.message_id
                self.pending_approvals[approval_id] = deepcopy(decision)
                result["approval_id"] = approval_id

            self._record_action(
                result,
                policy_status=status,
                policy_reason=evaluation["reason"],
            )

        self.response_message_count += 1

        return self.create_message(
            message_type="RESPONSE_EXECUTED",
            recipient="COORDINATOR",
            payload={
                "response": result,
                "decision": decision,
                "analysis": message.payload.get("analysis"),
                "incident": message.payload.get("incident"),
            },
            correlation_id=message.correlation_id,
            priority=message.priority,
            parent_message_id=message.message_id,
        )

    def approve_response(self, approval_id, approved_by):
        """Approve and execute one pending simulated response."""
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError("An approver name is required")

        decision = self.pending_approvals.get(approval_id)
        if decision is None:
            raise ValueError("Approval request was not found")

        # Recheck the current policy before applying a pending action.
        evaluation = self.policy.evaluate(decision)
        if evaluation["status"] != "APPROVAL_REQUIRED":
            raise ValueError(
                "Decision is no longer eligible for approval: "
                + evaluation["reason"]
            )

        approved_decision = {
            **decision,
            "targets": evaluation["allowed_targets"],
            "automatic": False,
        }

        result = self._execute_with_suppression(
            approved_decision,
            evaluation,
        )
        result["approval_id"] = approval_id
        result["approved_by"] = approved_by.strip()
        result["policy_status"] = "APPROVED"
        result["policy_reason"] = (
            "Human approval granted after a fresh policy check."
        )

        del self.pending_approvals[approval_id]
        return result

    def execute(self, decision):
        """Apply an action to the simulated state."""
        if not isinstance(decision, dict):
            raise TypeError("Decision must be a dictionary")

        action = decision.get("recommended_action")
        targets = decision.get("targets", [])

        if not action:
            raise ValueError(
                "Decision must contain a recommended_action"
            )
        if not isinstance(targets, list):
            raise TypeError("Decision targets must be a list")

        if action in {"BLOCK_IP", "BLOCK_IPS"}:
            new_targets = self._add_new_targets(
                self.blocked_ips,
                targets,
            )

        elif action == "RATE_LIMIT_IPS":
            new_targets = self._add_new_targets(
                self.rate_limited_ips,
                targets,
            )

        elif action == "QUARANTINE_PROCESS":
            new_targets = self._add_new_targets(
                self.quarantined_processes,
                targets,
            )

        elif action == "FLAG_FOR_INVESTIGATION":
            investigation = {
                "incident_id": decision.get("incident_id"),
                "attack_type": decision["attack_type"],
                "severity": decision["severity"],
                "risk_score": decision.get("risk_score"),
                "confidence": decision.get("confidence"),
                "targets": list(targets),
                "reason": decision["reason"],
            }
            self.investigation_queue.append(investigation)
            new_targets = list(targets)

        elif action == "CONTINUE_MONITORING":
            new_targets = []

        else:
            raise ValueError(
                f"Unsupported response action: {action}"
            )

        result = {
            "incident_id": decision.get("incident_id"),
            "attack_type": decision["attack_type"],
            "action": action,
            "status": "SIMULATED_SUCCESS",
            "targets": list(targets),
            "new_targets": new_targets,
            "automatic": decision["automatic"],
            "simulated": True,
        }

        # A direct call remains available for older code. Its audit
        # record makes clear that no message-based policy was checked.
        return self._record_action(
            result,
            policy_status="DIRECT_CALL",
            policy_reason=decision.get(
                "reason",
                "Called through the direct execute interface.",
            ),
        )

    def expire_actions(self):
        """
        Reverse active actions whose configured lifetime has ended.

        Returns the reversal records created during this call.
        """
        now = self.clock()
        reversals = []

        for key, expires_at in list(self.action_expirations.items()):
            if now < expires_at:
                continue

            action, target = key
            active = self._active_targets(action)
            origin = self.action_origins.pop(key, {})

            if target in active:
                active.remove(target)

                reversal_action = {
                    "BLOCK_IP": "UNBLOCK_IP",
                    "RATE_LIMIT_IPS": "REMOVE_RATE_LIMIT",
                    "QUARANTINE_PROCESS": "RELEASE_PROCESS",
                }[action]

                record = {
                    "incident_id": origin.get("incident_id"),
                    "attack_type": origin.get("attack_type"),
                    "action": reversal_action,
                    "status": "SIMULATED_REVERSED",
                    "targets": [target],
                    "new_targets": [],
                    "automatic": True,
                    "simulated": True,
                    "reason": "Configured action lifetime expired.",
                    "reverses_audit_id": origin.get("audit_id"),
                }

                self._record_action(
                    record,
                    policy_status="EXPIRED",
                    policy_reason=record["reason"],
                )
                reversals.append(record)

            del self.action_expirations[key]

        return reversals

    def _add_new_targets(self, state_set, targets):
        new_targets = []

        for target in targets:
            if target not in state_set:
                state_set.add(target)
                new_targets.append(target)

        return new_targets

    @staticmethod
    def _action_key(action, target):
        # Both block actions change the same blocked_ips set.
        if action == "BLOCK_IPS":
            action = "BLOCK_IP"
        return action, target

    def _active_targets(self, action):
        if action in {"BLOCK_IP", "BLOCK_IPS"}:
            return self.blocked_ips
        if action == "RATE_LIMIT_IPS":
            return self.rate_limited_ips
        if action == "QUARANTINE_PROCESS":
            return self.quarantined_processes
        return set()

    def _split_repeated_targets(self, action, targets):
        self.expire_actions()

        now = self.clock()
        eligible = []
        suppressed = []

        for target in targets:
            key = self._action_key(action, target)
            last_time = self.last_action_times.get(key)

            already_active = target in self._active_targets(action)
            in_cooldown = (
                last_time is not None
                and now - last_time < self.policy.cooldown_seconds
            )

            if already_active or in_cooldown:
                suppressed.append(target)
            else:
                eligible.append(target)

        return eligible, suppressed

    def _execute_with_suppression(self, decision, evaluation):
        action = decision["recommended_action"]
        eligible, suppressed = self._split_repeated_targets(
            action,
            decision["targets"],
        )

        if not eligible:
            result = {
                "incident_id": decision.get("incident_id"),
                "attack_type": decision["attack_type"],
                "action": action,
                "status": "SUPPRESSED_DUPLICATE",
                "targets": list(decision["targets"]),
                "new_targets": [],
                "suppressed_targets": suppressed,
                "automatic": False,
                "simulated": True,
                "policy_evaluation": evaluation,
            }
            return self._record_action(
                result,
                policy_status="SUPPRESSED_DUPLICATE",
                policy_reason=(
                    "The target already has an active action "
                    "or remains in cooldown."
                ),
            )

        safe_decision = {
            **decision,
            "targets": eligible,
        }
        result = self.execute(safe_decision)

        self._add_policy_audit(result, evaluation)
        result["suppressed_targets"] = suppressed

        now = self.clock()
        for target in result["new_targets"]:
            key = self._action_key(action, target)
            self.last_action_times[key] = now

            if self.policy.action_expiration_seconds > 0:
                self.action_expirations[key] = (
                    now + self.policy.action_expiration_seconds
                )
                result["action_expiration_seconds"] = (
                    self.policy.action_expiration_seconds
                )
                self.action_origins[key] = {
                    "incident_id": result["incident_id"],
                    "attack_type": result["attack_type"],
                    "audit_id": result["audit_id"],
                }

        return result

    @staticmethod
    def _add_policy_audit(result, evaluation):
        # action_history contains the same result dictionary, so
        # these fields also appear in its audit record.
        result["policy_status"] = evaluation["status"]
        result["policy_reason"] = evaluation["reason"]
        result["policy_evaluation"] = evaluation

    def _record_action(self, result, policy_status, policy_reason):
        result["audit_id"] = str(uuid4())
        result["timestamp_utc"] = datetime.now(
            timezone.utc
        ).isoformat()
        result["policy_status"] = policy_status
        result["policy_reason"] = policy_reason

        self.action_history.append(result)
        return result
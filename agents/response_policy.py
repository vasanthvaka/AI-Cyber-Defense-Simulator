from dataclasses import dataclass, field


@dataclass
class ResponsePolicy:
    protected_ips: set[str] = field(default_factory=set)
    protected_processes: set[str] = field(default_factory=set)

    minimum_risk_score: int = 60
    minimum_confidence: float = 0.7

    approval_required_actions: set[str] = field(
        default_factory=lambda: {
            "BLOCK_IPS",
            "QUARANTINE_PROCESS",
        }
    )

    cooldown_seconds: int = 30
    action_expiration_seconds: int = 300

    def is_protected(self, action: str, target: object) -> bool:
        if action in {"BLOCK_IP", "BLOCK_IPS", "RATE_LIMIT_IPS"}:
            return str(target) in self.protected_ips

        if action == "QUARANTINE_PROCESS":
            return str(target) in self.protected_processes

        return False
    
    def split_targets(
        self,
        action: str,
        targets: list,
    ) -> tuple[list, list]:
        allowed = []
        protected = []

        for target in targets:
            if self.is_protected(action, target):
                protected.append(target)
            else:
                allowed.append(target)

        return allowed, protected

    def evaluate(self, decision: dict) -> dict:
        action = decision["recommended_action"]
        targets = decision.get("targets", [])

        if action in {"CONTINUE_MONITORING", "FLAG_FOR_INVESTIGATION"}:
            return {
                "status": "NO_CONTAINMENT",
                "allowed_targets": [],
                "protected_targets": [],
                "reason": "No containment action was requested.",
            }

        allowed, protected = self.split_targets(action, targets)

        if not allowed:
            return {
                "status": "DENIED",
                "allowed_targets": [],
                "protected_targets": protected,
                "reason": "No unprotected targets are available.",
            }

        if (
            decision.get("risk_score", 0) < self.minimum_risk_score
            or decision.get("confidence", 0) < self.minimum_confidence
            or decision.get("requires_human_review", False)
        ):
            status = "REVIEW_REQUIRED"
            reason = "Risk, confidence, or human-review policy requires review."
        elif action in self.approval_required_actions:
            status = "APPROVAL_REQUIRED"
            reason = "This action requires human approval."
        else:
            status = "ALLOWED"
            reason = "The action passed response policy."

        return {
            "status": status,
            "allowed_targets": allowed,
            "protected_targets": protected,
            "reason": reason,
        }
"""Response Gate policy engine. Loads from YAML, evaluates actions against thresholds."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from agent.state import PolicyDecision

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ROLE_ORDER = {"viewer": 0, "analyst": 1, "responder": 2, "approver": 3, "admin": 4}

class ResponseGatePolicy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.environment: str = config.get("environment", "dev")
        self.dry_run: bool = config.get("dry_run", False)
        self.actions: dict[str, dict] = config.get("actions", {})
        self.overrides: dict[str, dict] = config.get("overrides", {})
        approval_cfg = config.get("approval", {})
        self.approval_expiry_seconds: int = approval_cfg.get("expiry_seconds", 300)
        self.allow_reapproval: bool = approval_cfg.get("allow_reapproval", False)

    @classmethod
    def from_yaml(cls, path: Path) -> ResponseGatePolicy:
        with open(path) as f:
            config = yaml.safe_load(f)
        return cls(config)

    def evaluate(self, action_type: str, severity: str, confidence: float, user_role: str, target_tags: list[str]) -> PolicyDecision:
        # Check crown jewel override first
        crown_cfg = self.overrides.get("crown_jewel_assets", {})
        crown_tags = crown_cfg.get("asset_tags", [])
        if crown_tags and any(tag in crown_tags for tag in target_tags):
            return PolicyDecision(
                action_type=action_type, policy_mode="approval_required",
                matched_rule="overrides.crown_jewel_assets", override_applied="crown_jewel_assets",
                min_role_required=crown_cfg.get("min_role", "approver"),
                decision="requires_approval",
                reason=f"Target tagged as crown jewel asset ({', '.join(t for t in target_tags if t in crown_tags)})")

        action_cfg = self.actions.get(action_type)
        if action_cfg is None:
            return PolicyDecision(action_type=action_type, policy_mode="unknown",
                matched_rule="default_deny", min_role_required="admin",
                decision="denied_by_policy", reason=f"No policy defined for action type '{action_type}'")

        mode = action_cfg.get("mode", "approval_required")
        min_role = action_cfg.get("min_role", "analyst")
        matched_rule = f"actions.{action_type}"

        # Check role
        if ROLE_ORDER.get(user_role, 0) < ROLE_ORDER.get(min_role, 0):
            return PolicyDecision(action_type=action_type, policy_mode=mode,
                matched_rule=matched_rule, min_role_required=min_role,
                decision="denied_by_policy", reason=f"Role '{user_role}' insufficient; requires '{min_role}'")

        if mode == "auto":
            return PolicyDecision(action_type=action_type, policy_mode=mode,
                matched_rule=matched_rule, min_role_required=min_role,
                decision="auto_approved", reason="Auto-execute policy")

        if mode == "approval_required":
            return PolicyDecision(action_type=action_type, policy_mode=mode,
                matched_rule=matched_rule, min_role_required=min_role,
                decision="requires_approval", reason="Always requires manual approval")

        # mode == "conditional"
        min_severity = action_cfg.get("min_severity", "CRITICAL")
        min_confidence = action_cfg.get("min_confidence", 0.95)
        sev_met = SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 3)
        conf_met = confidence >= min_confidence

        if sev_met and conf_met:
            return PolicyDecision(action_type=action_type, policy_mode=mode,
                matched_rule=matched_rule, min_role_required=min_role,
                decision="auto_approved",
                reason=f"Severity {severity} >= {min_severity} and confidence {confidence:.2f} >= {min_confidence}")

        reasons = []
        if not sev_met: reasons.append(f"severity {severity} < {min_severity}")
        if not conf_met: reasons.append(f"confidence {confidence:.2f} < {min_confidence}")
        return PolicyDecision(action_type=action_type, policy_mode=mode,
            matched_rule=matched_rule, min_role_required=min_role,
            decision="requires_approval", reason=f"Conditional threshold not met: {'; '.join(reasons)}")

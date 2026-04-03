"""CRA — Containment & Response Agent node (with LangGraph interrupt for HITL approval)."""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.types import interrupt

from agent.audit import emit_audit
from agent.llm import get_llm
from agent.policy import ResponseGatePolicy
from agent.state import (
    ApprovedAction,
    ExecutedAction,
    GatraState,
    ProposedAction,
)
from agent.tools.response import execute_action

_SYSTEM_PROMPT = """You are CRA, the Containment and Response Agent in GATRA.
Based on the triage results and analyst query, propose ONE concrete containment action:
- action_type: one of block / isolate / kill / quarantine / suspend / notify / unblock / resume
- target_type: one of ip / host / endpoint / process / user / session
- target_value: the exact target identifier
- severity: CRITICAL / HIGH / MEDIUM / LOW
- confidence: float 0-1
- rationale: one sentence justification

Respond ONLY with a JSON object with those keys and no extra text."""

_DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "response_gate.yaml"


# ---------------------------------------------------------------------------
# Pure helper functions (testable without LangGraph runtime)
# ---------------------------------------------------------------------------


def build_proposed_action(
    *,
    incident_id: str,
    action_type: str,
    target_type: str,
    target_value: str,
    severity: str,
    confidence: float,
    rationale: str,
    requires_approval: bool,
    gate_reason: str | None = None,
    expiry_seconds: int = 300,
) -> ProposedAction:
    """Construct a ProposedAction with a deterministic fingerprint."""
    fingerprint = hashlib.sha256(
        f"{action_type}:{target_type}:{target_value}:{incident_id}".encode()
    ).hexdigest()[:16]

    return ProposedAction(
        action_id=str(uuid.uuid4()),
        incident_id=incident_id,
        action_type=action_type,  # type: ignore[arg-type]
        target_type=target_type,  # type: ignore[arg-type]
        target_value=target_value,
        target_fingerprint=fingerprint,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        rationale=rationale,
        requires_approval=requires_approval,
        gate_reason=gate_reason,
        requested_by_agent="CRA",
        status="proposed",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds),
    )


def check_action_expiry(expires_at: datetime) -> bool:
    """Return True if the action has expired."""
    now = datetime.now(timezone.utc)
    # Make naive datetimes comparable
    if expires_at.tzinfo is None:
        return expires_at < datetime.now()
    return expires_at < now


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def _load_policy() -> ResponseGatePolicy:
    try:
        return ResponseGatePolicy.from_yaml(_DEFAULT_POLICY_PATH)
    except Exception:
        # Fallback: empty policy that always requires approval
        return ResponseGatePolicy({"actions": {}, "environment": "dev", "dry_run": True})


def _parse_llm_proposal(text: str) -> dict[str, Any]:
    """Extract JSON proposal from LLM output."""
    import json
    import re

    # Try direct parse
    try:
        return json.loads(text.strip())
    except Exception:
        pass

    # Try extracting JSON block
    match = re.search(r"\{[^{}]+\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    # Fallback defaults
    return {
        "action_type": "notify",
        "target_type": "ip",
        "target_value": "unknown",
        "severity": "MEDIUM",
        "confidence": 0.5,
        "rationale": "Unable to parse LLM response; defaulting to notify action.",
    }


def cra_node(state: GatraState, config: dict) -> dict:
    """Propose, gate-evaluate, optionally interrupt for approval, then execute."""
    try:
        from copilotkit.langgraph import copilotkit_emit_state  # type: ignore
        copilotkit_emit_state(config, {"current_agent": "cra", "pipeline_stage": "responding"})
    except Exception:
        pass

    incident_id = state.incident_id or str(uuid.uuid4())
    policy = _load_policy()

    # --- 1. Ask LLM to propose an action ---
    triage_summary = "\n".join(
        f"- [{t.severity}] {t.mitre_id} {t.mitre_name} actor={t.actor_attribution}"
        for t in state.triage_results
    ) or "No structured triage. Use query context."

    llm = get_llm()
    proposal_text = llm.invoke([
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=(
            f"Query: {state.query}\n\n"
            f"Triage results:\n{triage_summary}\n\n"
            "Propose the most appropriate containment action as JSON."
        )),
    ]).content

    proposal = _parse_llm_proposal(str(proposal_text))

    # --- 2. Build ProposedAction ---
    action_type = proposal.get("action_type", "notify")
    target_type = proposal.get("target_type", "ip")
    target_value = proposal.get("target_value", "unknown")
    severity = proposal.get("severity", "MEDIUM")
    confidence = float(proposal.get("confidence", 0.5))
    rationale = proposal.get("rationale", "")

    # --- 3. Evaluate policy gate ---
    policy_decision = policy.evaluate(
        action_type=action_type,
        severity=severity,
        confidence=confidence,
        user_role=state.user_role,
        target_tags=[],
    )

    proposed_action = build_proposed_action(
        incident_id=incident_id,
        action_type=action_type,
        target_type=target_type,
        target_value=target_value,
        severity=severity,
        confidence=confidence,
        rationale=rationale,
        requires_approval=policy_decision.decision == "requires_approval",
        gate_reason=policy_decision.reason,
        expiry_seconds=policy.approval_expiry_seconds,
    )

    updated_state = emit_audit(
        state,
        event_type="policy_evaluated",
        agent="CRA",
        summary=f"Policy evaluated: {policy_decision.decision} for {action_type} on {target_value}",
        details={
            "action_type": action_type,
            "target_value": target_value,
            "severity": severity,
            "confidence": confidence,
            "policy_decision": policy_decision.model_dump(),
        },
        policy_decision=policy_decision,
    )

    new_proposed = [*updated_state.proposed_actions, proposed_action]

    # --- 4a. Denied by policy ---
    if policy_decision.decision == "denied_by_policy":
        denied = [*updated_state.denied_actions, proposed_action]
        return {
            "current_agent": "cra",
            "pipeline_stage": "responding",
            "last_updated_at": datetime.now(timezone.utc),
            "proposed_actions": new_proposed,
            "denied_actions": denied,
            "audit_log": updated_state.audit_log,
        }

    # --- 4b. Requires human approval — interrupt ---
    if policy_decision.decision == "requires_approval":
        approval_event: dict[str, Any] = {
            "event": "response_gate",
            "proposed_action": proposed_action.model_dump(mode="json"),
            "policy_decision": policy_decision.model_dump(mode="json"),
            "message": (
                f"CRA proposes: {action_type} on {target_value} "
                f"(severity={severity}, confidence={confidence:.2f}). "
                "Approve or deny?"
            ),
        }

        updated_state2 = emit_audit(
            updated_state,
            event_type="approval_requested",
            agent="CRA",
            summary=f"Human approval requested for {action_type} on {target_value}",
            details=approval_event,
        )

        human_response = interrupt(approval_event)
        approved = (
            isinstance(human_response, dict) and human_response.get("approved", False)
        ) or human_response is True

        if not approved:
            denied_action = proposed_action.model_copy(update={"status": "denied"})
            updated_state3 = emit_audit(
                updated_state2,
                event_type="approval_denied",
                agent="CRA",
                actor=state.user_id or "analyst",
                summary=f"Analyst denied {action_type} on {target_value}",
            )
            return {
                "current_agent": "cra",
                "pipeline_stage": "responding",
                "last_updated_at": datetime.now(timezone.utc),
                "proposed_actions": new_proposed,
                "denied_actions": [*updated_state3.denied_actions, denied_action],
                "approval_pending": False,
                "audit_log": updated_state3.audit_log,
            }

        approved_by = (
            human_response.get("approved_by", state.user_id or "analyst")
            if isinstance(human_response, dict) else (state.user_id or "analyst")
        )
        approved_action = ApprovedAction(
            action_id=proposed_action.action_id,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            original_action=proposed_action,
        )
        updated_state3 = emit_audit(
            updated_state2,
            event_type="approval_granted",
            agent="CRA",
            actor=approved_by,
            summary=f"Analyst approved {action_type} on {target_value}",
        )
    else:
        # --- 4c. Auto-approved ---
        approved_by = "system"
        approved_action = ApprovedAction(
            action_id=proposed_action.action_id,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            original_action=proposed_action,
        )
        updated_state3 = updated_state

    # --- 5. Execute action ---
    import asyncio
    idempotency_key = f"{proposed_action.target_fingerprint}-{proposed_action.action_id}"
    try:
        exec_result = asyncio.get_event_loop().run_until_complete(
            execute_action.ainvoke({
                "action_type": action_type,
                "target_type": target_type,
                "target_value": target_value,
                "idempotency_key": idempotency_key,
            })
        )
        success = exec_result.get("success", True)
        error: str | None = exec_result.get("error")
    except Exception as exc:
        success = False
        error = str(exc)

    executed = ExecutedAction(
        action_id=proposed_action.action_id,
        incident_id=incident_id,
        action_type=action_type,
        target_value=target_value,
        success=success,
        error=error,
        executed_at=datetime.now(timezone.utc),
        approved_by=approved_by,
        executed_by="CRA",
        execution_actor_type="human" if policy_decision.decision == "requires_approval" else "system",
        execution_mode="dry_run" if policy.dry_run else "enforced",
        rollback_available=action_type in {"block", "isolate", "suspend", "kill"},
        idempotency_key=idempotency_key,
    )

    event = "execution_succeeded" if success else "execution_failed"
    final_state = emit_audit(
        updated_state3,
        event_type=event,
        agent="CRA",
        summary=f"Action {action_type} on {target_value}: {'success' if success else 'failed'}",
        details={"executed_action": executed.model_dump(mode="json")},
    )

    return {
        "current_agent": "cra",
        "pipeline_stage": "responding",
        "last_updated_at": datetime.now(timezone.utc),
        "incident_id": incident_id,
        "proposed_actions": new_proposed,
        "approved_actions": [*final_state.approved_actions, approved_action],
        "executed_actions": [*final_state.executed_actions, executed],
        "approval_pending": False,
        "audit_log": final_state.audit_log,
    }

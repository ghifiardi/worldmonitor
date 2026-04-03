"""CLA audit utility — called by every node at significant events.
Nodes create structured AuditEntry payloads. This utility appends them to state.
No LLM involved — purely deterministic persistence."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any
from agent.state import AuditEntry, GatraState, PolicyDecision

def emit_audit(state: GatraState, *, event_type: str, agent: str, summary: str,
    actor: str | None = None, details: dict[str, Any] | None = None,
    compliance_frameworks: list[str] | None = None,
    policy_decision: PolicyDecision | None = None) -> GatraState:
    entry = AuditEntry(id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc),
        trace_id=state.trace_id, incident_id=state.incident_id or None,
        event_type=event_type, agent=agent, actor=actor or state.user_id or None,
        summary=summary, details=details, compliance_frameworks=compliance_frameworks or [],
        policy_decision=policy_decision)
    state.audit_log = [*state.audit_log, entry]
    return state

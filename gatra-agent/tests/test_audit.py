from agent.audit import emit_audit
from agent.state import GatraState, PolicyDecision

def test_emit_audit_appends_entry():
    state = GatraState(trace_id="t1", incident_id="inc1")
    updated = emit_audit(state, event_type="routing_start", agent="router", summary="Routing analyst query")
    assert len(updated.audit_log) == 1
    entry = updated.audit_log[0]
    assert entry.event_type == "routing_start"
    assert entry.trace_id == "t1"
    assert entry.incident_id == "inc1"

def test_emit_audit_with_policy_decision():
    state = GatraState(trace_id="t2")
    pd = PolicyDecision(action_type="block", policy_mode="conditional", matched_rule="actions.block",
        min_role_required="responder", decision="requires_approval", reason="Below threshold")
    updated = emit_audit(state, event_type="policy_evaluated", agent="CRA",
        summary="Policy gate evaluated", policy_decision=pd)
    assert updated.audit_log[0].policy_decision is not None

def test_emit_audit_preserves_existing():
    state = GatraState(trace_id="t3")
    state = emit_audit(state, event_type="routing_start", agent="router", summary="First")
    state = emit_audit(state, event_type="alert_fetched", agent="ADA", summary="Second")
    assert len(state.audit_log) == 2

from datetime import datetime, timedelta

from agent.state import (
    Alert, ApprovedAction, AuditEntry, AuditIdentity, ExecutedAction,
    GatraState, PolicyDecision, ProposedAction, StateError, TriageResult,
    VulnerabilityContext,
)


def test_alert_with_geo():
    alert = Alert(id="a1", severity="CRITICAL", mitre_id="T1566", mitre_name="Phishing",
        description="Spear phishing detected", confidence=0.92, lat=-6.2, lon=106.8,
        location_name="Jakarta DC-2", infrastructure="core-router-01",
        timestamp=datetime.now(), agent="ADA")
    assert alert.severity == "CRITICAL"
    assert alert.lat == -6.2


def test_alert_without_geo():
    alert = Alert(id="a2", severity="HIGH", mitre_id="T1078", mitre_name="Valid Accounts",
        description="Compromised credential detected", confidence=0.85,
        timestamp=datetime.now(), agent="ADA")
    assert alert.lat is None
    assert alert.infrastructure is None


def test_proposed_action_expires():
    action = ProposedAction(action_id="act1", incident_id="inc1", action_type="block",
        target_type="ip", target_value="45.33.32.156", target_fingerprint="abc123",
        severity="CRITICAL", confidence=0.95, rationale="Known C2 server",
        requires_approval=True, gate_reason="severity threshold met",
        expires_at=datetime.now() + timedelta(seconds=300))
    assert action.status == "proposed"
    assert action.requires_approval is True
    assert action.requested_by_agent == "CRA"


def test_executed_action_tracks_actors():
    action = ExecutedAction(action_id="act1", incident_id="inc1", action_type="block",
        target_value="45.33.32.156", success=True, executed_at=datetime.now(),
        approved_by="user-001", executed_by="system-svc", execution_actor_type="system",
        execution_mode="enforced", rollback_available=True, idempotency_key="idem-001")
    assert action.approved_by == "user-001"
    assert action.executed_by == "system-svc"
    assert action.execution_actor_type == "system"


def test_policy_decision():
    pd = PolicyDecision(action_type="block", policy_mode="conditional",
        matched_rule="actions.block", min_role_required="responder",
        decision="requires_approval", reason="Confidence 0.85 below threshold 0.90")
    assert pd.decision == "requires_approval"


def test_audit_entry_with_policy():
    entry = AuditEntry(id="ae1", timestamp=datetime.now(), trace_id="trace-001",
        event_type="policy_evaluated", agent="CRA",
        summary="Policy gate evaluated for block action",
        policy_decision=PolicyDecision(action_type="block", policy_mode="conditional",
            matched_rule="actions.block", min_role_required="responder",
            decision="requires_approval", reason="Below auto threshold"))
    assert entry.event_type == "policy_evaluated"
    assert entry.policy_decision is not None


def test_state_error_typed():
    err = StateError(code="TOOL_TIMEOUT", message="fetch_alerts timed out after 30s",
        retryable=True, source="ada", timestamp=datetime.now(),
        details={"endpoint": "/api/gatra-data"})
    assert err.retryable is True


def test_gatra_state_defaults():
    state = GatraState()
    assert state.alerts == []
    assert state.anomaly_scores == {}
    assert state.pipeline_stage == "idle"
    assert state.errors == []
    assert state.user_role == "analyst"


def test_gatra_state_no_shared_mutable_defaults():
    s1 = GatraState()
    s2 = GatraState()
    s1.alerts.append(Alert(id="x", severity="LOW", mitre_id="T1000", mitre_name="Test",
        description="Test", confidence=0.5, timestamp=datetime.now(), agent="ADA"))
    assert len(s2.alerts) == 0


def test_audit_identity():
    identity = AuditIdentity(user_id="user-001", role="approver", session_id="sess-abc",
        timestamp=datetime.now(), ticket_ref="INC-42")
    assert identity.role == "approver"


# AgentMode enum and mode field tests
def test_agent_mode_enum_values():
    from agent.state import AgentMode
    assert AgentMode.full == "full"
    assert AgentMode.lite == "lite"


def test_gatra_state_defaults_to_full_mode():
    from agent.state import AgentMode
    state = GatraState(messages=[])
    assert state.mode == AgentMode.full


def test_gatra_state_accepts_lite_mode():
    from agent.state import AgentMode
    state = GatraState(messages=[], mode=AgentMode.lite)
    assert state.mode == AgentMode.lite


def test_gatra_state_rejects_invalid_mode():
    import pytest
    with pytest.raises(Exception):
        GatraState(messages=[], mode="invalid")

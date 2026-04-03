from pathlib import Path
from agent.policy import ResponseGatePolicy

FIXTURE_PATH = Path(__file__).parent.parent / "config" / "response_gate.yaml"

def test_load_policy():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    assert policy.environment == "dev"
    assert policy.dry_run is False
    assert "notify" in policy.actions

def test_notify_auto_approved():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="notify", severity="LOW", confidence=0.5, user_role="analyst", target_tags=[])
    assert decision.decision == "auto_approved"

def test_block_requires_approval_below_threshold():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="block", severity="HIGH", confidence=0.85, user_role="responder", target_tags=[])
    assert decision.decision == "requires_approval"

def test_block_auto_on_critical_high_confidence():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="block", severity="CRITICAL", confidence=0.95, user_role="responder", target_tags=[])
    assert decision.decision == "auto_approved"

def test_isolate_always_requires_approval():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="isolate", severity="CRITICAL", confidence=1.0, user_role="approver", target_tags=[])
    assert decision.decision == "requires_approval"

def test_crown_jewel_override():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="notify", severity="LOW", confidence=1.0, user_role="admin", target_tags=["core-router"])
    assert decision.decision == "requires_approval"
    assert decision.override_applied == "crown_jewel_assets"

def test_insufficient_role_denied():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(action_type="kill", severity="CRITICAL", confidence=0.99, user_role="analyst", target_tags=[])
    assert decision.decision == "denied_by_policy"
    assert "role" in decision.reason.lower()

def test_approval_expiry():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    assert policy.approval_expiry_seconds == 300

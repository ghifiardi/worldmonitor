"""Tests for CRA pure helper functions — no LLM or LangGraph runtime needed."""
from datetime import datetime, timedelta

from agent.nodes.cra import build_proposed_action, check_action_expiry


def test_build_proposed_action():
    action = build_proposed_action(
        incident_id="inc1",
        action_type="block",
        target_type="ip",
        target_value="45.33.32.156",
        severity="CRITICAL",
        confidence=0.95,
        rationale="Known C2 server",
        requires_approval=True,
        gate_reason="threshold met",
        expiry_seconds=300,
    )
    assert action.action_type == "block"
    assert action.target_fingerprint != ""
    assert action.status == "proposed"


def test_check_expiry_valid():
    assert check_action_expiry(datetime.now() + timedelta(seconds=300)) is False


def test_check_expiry_expired():
    assert check_action_expiry(datetime.now() - timedelta(seconds=1)) is True


# ---------------------------------------------------------------------------
# Lite-mode tests
# ---------------------------------------------------------------------------

from agent.state import AgentMode, ProposedAction, GatraState
from agent.nodes.cra import enforce_lite_mode
from copy import deepcopy


def _sample_action() -> ProposedAction:
    return ProposedAction(
        action_id="act-001",
        incident_id="inc-001",
        action_type="block",
        target_type="ip",
        target_value="10.0.0.1",
        severity="HIGH",
        confidence=0.95,
        rationale="Suspicious outbound traffic",
        requires_approval=True,
        status="proposed",
        expires_at="2026-04-04T12:00:00Z",
    )


def test_enforce_lite_mode_marks_all_non_executable():
    actions = [_sample_action(), _sample_action()]
    result = enforce_lite_mode(actions)
    for a in result:
        assert a.executable is False
        assert a.reason == "read-only mode — view in Analyst Console for execution"


def test_enforce_lite_mode_does_not_mutate_originals():
    original = _sample_action()
    original_id = id(original)
    result = enforce_lite_mode([original])
    assert id(result[0]) != original_id


def test_enforce_lite_mode_empty_list():
    assert enforce_lite_mode([]) == []

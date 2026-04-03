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

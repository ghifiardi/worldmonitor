"""Integration tests — lite-mode end-to-end graph run.

These tests build the real LangGraph, invoke it with AgentMode.lite, and
assert the key invariants:
  - All proposed actions have executable=False
  - vulnerability_context is empty (RVA was skipped)
  - The graph completes without calling interrupt()
  - resolve_effective_mode enforces lite for soc-site regardless of requested_mode
  - resolve_effective_mode allows full for copilot source

Graph routing notes:
  - query "block 10.0.0.1 ..." -> router -> CRA directly (action intent, high confidence)
  - query "analyze ..." -> router -> ADA -> TAA -> CRA only if HIGH/CRITICAL alerts present
    otherwise TAA dispatches to RVA (which no-ops in lite mode)
  For the full ADA→TAA→CRA path we use a high-severity query that produces an action-intent
  route (direct to CRA).
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from agent.auth import resolve_effective_mode
from agent.graph import build_graph
from agent.state import AgentMode, GatraState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_mock(content: str = "ok") -> MagicMock:
    """Return a synchronous mock for get_llm() that yields an AIMessage."""
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(return_value=AIMessage(content=content))
    return mock_llm


def _cra_json_response() -> str:
    """Valid JSON proposal for CRA to parse."""
    return json.dumps({
        "action_type": "notify",
        "target_type": "ip",
        "target_value": "10.0.0.99",
        "severity": "MEDIUM",
        "confidence": 0.7,
        "rationale": "Suspicious outbound traffic detected.",
    })


def _initial_state_cra_direct(mode: AgentMode = AgentMode.lite) -> dict:
    """State that routes directly to CRA (action intent, specific IP target)."""
    return {
        "messages": [],
        "mode": mode,
        "session_id": "sess-test",
        "incident_id": str(uuid.uuid4()),
        "trace_id": "trace-test",
        "user_id": "analyst-test",
        "user_role": "analyst",
        # "block 10.0.0.1" → action intent, confidence=0.9 → routes to CRA
        "query": "block 10.0.0.1 it is a known malicious host",
    }


def _initial_state_detection(mode: AgentMode = AgentMode.lite) -> dict:
    """State that routes through ADA→TAA→RVA (detection intent, no high alerts)."""
    return {
        "messages": [],
        "mode": mode,
        "session_id": "sess-test",
        "incident_id": str(uuid.uuid4()),
        "trace_id": "trace-test",
        "user_id": "analyst-test",
        "user_role": "analyst",
        "query": "analyze suspicious activity",
    }


def _graph_config() -> dict:
    """LangGraph invoke config with a unique thread_id."""
    return {"configurable": {"thread_id": str(uuid.uuid4())}}


# ---------------------------------------------------------------------------
# Test: full graph lite-mode run
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lite_mode_graph_proposed_actions_not_executable():
    """Graph in lite mode must produce only non-executable proposed actions.

    Uses a query that routes directly to CRA (action intent with specific IP target),
    so proposed_actions is guaranteed to be populated.
    """
    graph = build_graph()

    with (
        patch("agent.nodes.cra.get_llm", return_value=_make_llm_mock(_cra_json_response())),
    ):
        result = await graph.ainvoke(_initial_state_cra_direct(AgentMode.lite), config=_graph_config())

    proposed = result.get("proposed_actions", [])
    # CRA produces at least one action in lite mode
    assert len(proposed) >= 1, "Expected at least one proposed action from CRA"
    for action in proposed:
        assert action.executable is False, (
            f"Action {action.action_id} must be non-executable in lite mode, got executable=True"
        )
        assert action.reason == "read-only mode — view in Analyst Console for execution"


@pytest.mark.asyncio
async def test_lite_mode_graph_rva_not_executed_via_cra_path():
    """RVA must not be reached when CRA is the terminal node in lite mode.

    Route: router -> CRA (direct action intent).
    After CRA, _cra_dispatch returns '__end__' in lite mode — RVA LLM is never called.
    """
    graph = build_graph()

    with (
        patch("agent.nodes.cra.get_llm", return_value=_make_llm_mock(_cra_json_response())),
        patch("agent.nodes.rva.get_llm") as mock_rva_llm,
    ):
        result = await graph.ainvoke(_initial_state_cra_direct(AgentMode.lite), config=_graph_config())
        mock_rva_llm.assert_not_called()

    vuln_ctx = result.get("vulnerability_context", [])
    assert vuln_ctx == [], (
        f"vulnerability_context must be empty when RVA is skipped; got {vuln_ctx}"
    )


@pytest.mark.asyncio
async def test_lite_mode_graph_rva_guard_via_detection_path():
    """RVA guard must no-op even when ADA→TAA dispatches to RVA in lite mode.

    Route: router -> ADA -> TAA -> RVA (no high severity alerts).
    RVA has a defense-in-depth guard that returns [] for vulnerability_context.
    """
    graph = build_graph()

    with (
        patch("agent.nodes.ada.get_llm", return_value=_make_llm_mock("ADA analysis done")),
        patch("agent.nodes.ada.fetch_alerts", new_callable=lambda: _make_fetch_alerts_mock),
        patch("agent.nodes.taa.get_llm", return_value=_make_llm_mock("TAA triage done")),
        patch("agent.nodes.rva.get_llm") as mock_rva_llm,
    ):
        result = await graph.ainvoke(_initial_state_detection(AgentMode.lite), config=_graph_config())
        # RVA guard should prevent LLM from being called even if node is reached
        mock_rva_llm.assert_not_called()

    vuln_ctx = result.get("vulnerability_context", [])
    assert vuln_ctx == [], (
        f"vulnerability_context must be empty in lite mode; got {vuln_ctx}"
    )


@pytest.mark.asyncio
async def test_lite_mode_graph_no_interrupt():
    """Graph must complete without raising LangGraph interrupt in lite mode.

    CRA's interrupt() call is guarded by the lite-mode early-return branch.
    """
    graph = build_graph()

    # If interrupt() is called, LangGraph raises NodeInterrupt — we assert it is NOT raised
    with (
        patch("agent.nodes.cra.get_llm", return_value=_make_llm_mock(_cra_json_response())),
    ):
        # This must complete without any exception
        result = await graph.ainvoke(_initial_state_cra_direct(AgentMode.lite), config=_graph_config())

    # Graph returned a valid state dict
    assert isinstance(result, dict)
    assert result.get("mode") == AgentMode.lite


@pytest.mark.asyncio
async def test_lite_mode_graph_pipeline_stage_is_responding():
    """After CRA-direct lite-mode run the pipeline_stage must end at 'responding'."""
    graph = build_graph()

    with (
        patch("agent.nodes.cra.get_llm", return_value=_make_llm_mock(_cra_json_response())),
    ):
        result = await graph.ainvoke(_initial_state_cra_direct(AgentMode.lite), config=_graph_config())

    assert result.get("pipeline_stage") == "responding", (
        f"Expected pipeline_stage='responding' after lite CRA, got {result.get('pipeline_stage')!r}"
    )


# ---------------------------------------------------------------------------
# Test: resolve_effective_mode — mode-override integration
# ---------------------------------------------------------------------------

def test_soc_site_always_returns_lite():
    """soc-site source must always resolve to lite, even when full is requested."""
    assert resolve_effective_mode(source="soc-site", requested_mode="full") == "lite"
    assert resolve_effective_mode(source="soc-site", requested_mode="lite") == "lite"
    assert resolve_effective_mode(source="soc-site", requested_mode=None) == "lite"


def test_copilot_source_returns_requested_mode():
    """copilot source must pass through the requested mode without override."""
    assert resolve_effective_mode(source="copilot", requested_mode="full") == "full"
    assert resolve_effective_mode(source="copilot", requested_mode="lite") == "lite"


def test_copilot_source_defaults_to_full_when_none():
    """copilot source with no explicit mode must default to full."""
    result = resolve_effective_mode(source="copilot", requested_mode=None)
    assert result == "full"


def test_unknown_source_passes_through():
    """Unknown sources must not be silently downgraded to lite."""
    assert resolve_effective_mode(source="internal-api", requested_mode="full") == "full"


# ---------------------------------------------------------------------------
# Internal mock helper (used via new_callable lambda above)
# ---------------------------------------------------------------------------

class _make_fetch_alerts_mock:  # noqa: N801
    """Callable mock for fetch_alerts tool (used with new_callable= in patch)."""

    def __call__(self, *args, **kwargs):
        # Returns a mock with ainvoke that resolves immediately
        m = MagicMock()
        m.ainvoke = AsyncMock(return_value={"alerts": [], "count": 0})
        return m

"""Tests for graph assembly — verifies compilation and node presence."""
from agent.graph import build_graph
from agent.state import AgentMode, GatraState


def test_graph_compiles():
    graph = build_graph()
    assert graph is not None


def test_graph_has_expected_nodes():
    graph = build_graph()
    node_names = set(graph.nodes.keys())
    expected = {"router", "ada", "taa", "cra", "rva", "cla_report", "llm_respond"}
    assert expected.issubset(node_names)


def test_cra_dispatch_returns_rva_for_full():
    from agent.graph import _cra_dispatch
    state = GatraState(messages=[], mode=AgentMode.full)
    assert _cra_dispatch(state) == "rva"


def test_cra_dispatch_returns_end_for_lite():
    from agent.graph import _cra_dispatch
    state = GatraState(messages=[], mode=AgentMode.lite)
    assert _cra_dispatch(state) == "__end__"

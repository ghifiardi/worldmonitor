"""Tests for graph assembly — verifies compilation and node presence."""
from agent.graph import build_graph


def test_graph_compiles():
    graph = build_graph()
    assert graph is not None


def test_graph_has_expected_nodes():
    graph = build_graph()
    node_names = set(graph.nodes.keys())
    expected = {"router", "ada", "taa", "cra", "rva", "cla_report", "llm_respond"}
    assert expected.issubset(node_names)

"""LangGraph StateGraph assembly for the GATRA SOC agent pipeline."""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agent.nodes.ada import ada_node
from agent.nodes.cla_report import cla_report_node
from agent.nodes.cra import cra_node
from agent.nodes.llm_respond import llm_respond_node
from agent.nodes.router import router_node
from agent.nodes.rva import rva_node
from agent.nodes.taa import taa_node
from agent.state import AgentMode, GatraState

# ---------------------------------------------------------------------------
# Conditional routing helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _router_dispatch(state: GatraState) -> str:
    """Read `_route` written by router_node and dispatch to the correct node."""
    # GatraState is a Pydantic model; _route is stored as extra field or we
    # read it from the last audit entry's details as a fallback.
    route = getattr(state, "_route", None)
    if route:
        return route
    # Fallback: parse from the last routing audit entry
    for entry in reversed(state.audit_log):
        if entry.event_type == "routing_start" and entry.details:
            return entry.details.get("route", "llm_respond")
    return "llm_respond"


def _taa_dispatch(state: GatraState) -> str:
    """After TAA: route to CRA if any alert is HIGH or CRITICAL, else RVA."""
    for alert in state.alerts:
        if _SEVERITY_ORDER.get(alert.severity, 0) >= _SEVERITY_ORDER["HIGH"]:
            return "cra"
    for triage in state.triage_results:
        if _SEVERITY_ORDER.get(triage.severity, 0) >= _SEVERITY_ORDER["HIGH"]:
            return "cra"
    return "rva"


def _cra_dispatch(state: GatraState) -> str:
    """Route CRA output: full mode → RVA, lite mode → END."""
    if state.mode == AgentMode.lite:
        return "__end__"
    return "rva"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def build_graph() -> StateGraph:
    """Construct and compile the GATRA LangGraph."""
    # Allow extra fields on state so router can write _route
    builder = StateGraph(GatraState)

    # Register nodes
    builder.add_node("router", router_node)
    builder.add_node("ada", ada_node)
    builder.add_node("taa", taa_node)
    builder.add_node("cra", cra_node)
    builder.add_node("rva", rva_node)
    builder.add_node("cla_report", cla_report_node)
    builder.add_node("llm_respond", llm_respond_node)

    # Entry point
    builder.add_edge(START, "router")

    # Router → conditional dispatch
    builder.add_conditional_edges(
        "router",
        _router_dispatch,
        {
            "ada": "ada",
            "taa": "taa",
            "cra": "cra",
            "rva": "rva",
            "cla_report": "cla_report",
            "llm_respond": "llm_respond",
        },
    )

    # ADA always flows to TAA
    builder.add_edge("ada", "taa")

    # TAA → CRA (high severity) or RVA
    builder.add_conditional_edges(
        "taa",
        _taa_dispatch,
        {"cra": "cra", "rva": "rva"},
    )

    # CRA → RVA (full mode) or END (lite mode)
    builder.add_conditional_edges(
        "cra",
        _cra_dispatch,
        {"rva": "rva", "__end__": "__end__"},
    )

    # Terminal edges
    builder.add_edge("rva", END)
    builder.add_edge("cla_report", END)
    builder.add_edge("llm_respond", END)

    return builder.compile(checkpointer=MemorySaver())

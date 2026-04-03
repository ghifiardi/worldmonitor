"""ADA — Anomaly Detection Agent node."""
from __future__ import annotations
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm
from agent.state import GatraState
from agent.tools.alerts import fetch_alerts

_SYSTEM_PROMPT = """You are ADA, the Anomaly Detection Agent in GATRA.
Your role is to analyze fetched SOC alerts and assign anomaly scores.
For each alert summarise: severity level, anomaly likelihood (0-1 float),
key indicators, and whether immediate triage is required.
Be concise — one paragraph per alert maximum."""


def ada_node(state: GatraState, config: RunnableConfig) -> dict:
    """Fetch alerts and score anomalies with the LLM."""
    try:
        from copilotkit.langgraph import copilotkit_emit_state  # type: ignore
        copilotkit_emit_state(config, {"current_agent": "ada", "pipeline_stage": "detecting"})
    except Exception:
        pass

    # Invoke fetch_alerts tool (sync wrapper for LangGraph context)
    try:
        import asyncio
        raw = asyncio.get_event_loop().run_until_complete(
            fetch_alerts.ainvoke({"severity": "all", "limit": 20})
        )
    except Exception as exc:
        raw = {"error": str(exc), "alerts": []}

    updated_state = emit_audit(
        state,
        event_type="alert_fetched",
        agent="ADA",
        summary=f"Fetched alerts from SOC pipeline. Raw count: {len(raw.get('alerts', []))}",
        details={"raw_response_keys": list(raw.keys())},
    )

    llm = get_llm()
    context = f"Current alerts in state: {len(state.alerts)}\nFetched raw data: {str(raw)[:2000]}"
    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=f"Analyze the following alert data and assign anomaly scores:\n\n{context}"),
    ]
    response = llm.invoke(messages)

    return {
        "current_agent": "ada",
        "pipeline_stage": "detecting",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": updated_state.audit_log,
        "messages": [response],
    }

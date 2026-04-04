"""RVA — Risk & Vulnerability Assessment node."""
from __future__ import annotations
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm
from agent.state import AgentMode, GatraState

_SYSTEM_PROMPT = """You are RVA, the Risk and Vulnerability Assessment Agent in GATRA.
Based on the incident context (alerts, triage results, executed actions), you:
1. Identify relevant CVEs and their CVSS v4 / EPSS scores.
2. Assess whether affected assets appear in the CISA KEV catalogue.
3. Recommend immediate patching priorities.
4. Quantify residual risk after any containment actions.
Always cite CVE IDs when referencing specific vulnerabilities."""


async def rva_node(state: GatraState, config: RunnableConfig) -> dict:
    """Assess vulnerabilities and residual risk."""
    # Defense-in-depth: RVA must no-op if accidentally reached in lite mode
    if state.mode == AgentMode.lite:
        return {"vulnerability_context": [], "current_agent": "rva", "pipeline_stage": "assessing"}

    try:
        from copilotkit.langgraph import copilotkit_emit_state  # type: ignore
        await copilotkit_emit_state(config, {"current_agent": "rva", "pipeline_stage": "assessing"})
    except Exception:
        pass

    triage_summary = "\n".join(
        f"- [{t.severity}] {t.mitre_id} actor={t.actor_attribution} phase={t.kill_chain_phase}"
        for t in state.triage_results
    ) or "No structured triage results; use context from conversation."

    executed_summary = "\n".join(
        f"- {a.action_type} on {a.target_value} success={a.success}"
        for a in state.executed_actions
    ) or "No actions executed."

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Triage results:\n{triage_summary}\n\n"
                f"Executed containment actions:\n{executed_summary}\n\n"
                f"Query context: {state.query}\n\n"
                "Provide a vulnerability assessment and residual risk summary."
            )
        ),
    ]
    llm = get_llm()
    response = await llm.ainvoke(messages)

    updated_state = emit_audit(
        state,
        event_type="vulnerability_assessed",
        agent="RVA",
        summary="Vulnerability and residual risk assessment completed.",
        details={"triage_count": len(state.triage_results), "executed_count": len(state.executed_actions)},
    )

    return {
        "current_agent": "rva",
        "pipeline_stage": "assessing",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": updated_state.audit_log,
        "messages": [response],
    }

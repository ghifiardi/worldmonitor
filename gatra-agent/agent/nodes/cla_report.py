"""CLA Report — Compliance Logging Agent node."""
from __future__ import annotations
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm
from agent.state import GatraState

_SYSTEM_PROMPT = """You are CLA, the Compliance Logging Agent in GATRA.
Given the incident audit log and any executed containment actions, produce:
1. A structured compliance summary (frameworks: SOX, HIPAA, PCI-DSS where relevant).
2. Evidence of human-in-the-loop approval for any automated actions.
3. Traceability chain: detection → triage → action → outcome.
4. Flags for any policy deviations that require post-incident review.
Format as a concise compliance report suitable for auditors."""


def cla_report_node(state: GatraState, config: RunnableConfig) -> dict:
    """Generate compliance report from audit log and executed actions."""
    try:
        from copilotkit.langgraph import copilotkit_emit_state  # type: ignore
        copilotkit_emit_state(config, {"current_agent": "cla_report", "pipeline_stage": "logging"})
    except Exception:
        pass

    audit_summary = "\n".join(
        f"[{e.timestamp.isoformat()}] {e.event_type} agent={e.agent} — {e.summary}"
        for e in state.audit_log
    ) or "No audit entries recorded."

    executed_summary = "\n".join(
        f"- {a.action_type} on {a.target_value} approved_by={a.approved_by} success={a.success}"
        for a in state.executed_actions
    ) or "No actions executed."

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Audit log:\n{audit_summary}\n\n"
                f"Executed actions:\n{executed_summary}\n\n"
                f"Compliance flags: {state.compliance_flags}\n\n"
                "Generate the compliance report."
            )
        ),
    ]
    llm = get_llm()
    response = llm.invoke(messages)

    updated_state = emit_audit(
        state,
        event_type="compliance_checked",
        agent="CLA",
        summary="Compliance report generated from audit log.",
        details={
            "audit_entry_count": len(state.audit_log),
            "executed_action_count": len(state.executed_actions),
            "compliance_flags": state.compliance_flags,
        },
        compliance_frameworks=["SOX", "HIPAA", "PCI-DSS"],
    )

    return {
        "current_agent": "cla_report",
        "pipeline_stage": "logging",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": updated_state.audit_log,
        "messages": [response],
    }

"""TAA — Threat Actor Attribution node."""
from __future__ import annotations
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from agent.audit import emit_audit
from agent.llm import get_llm
from agent.state import GatraState

_SYSTEM_PROMPT = """You are TAA, the Threat Actor Attribution Agent in GATRA.
Given alerts and anomaly scores, perform:
1. MITRE ATT&CK technique mapping (list technique IDs and names).
2. Actor attribution — identify likely threat group or campaign based on TTPs.
3. Kill chain phase classification.
4. Confidence-weighted triage priority (CRITICAL / HIGH / MEDIUM / LOW).
Be precise — cite MITRE IDs. If attribution is uncertain, say so explicitly."""


def taa_node(state: GatraState, config: dict) -> dict:
    """Map MITRE techniques, attribute actors, and prioritise for triage."""
    try:
        from copilotkit.langgraph import copilotkit_emit_state  # type: ignore
        copilotkit_emit_state(config, {"current_agent": "taa", "pipeline_stage": "triaging"})
    except Exception:
        pass

    alert_summary = "\n".join(
        f"- [{a.severity}] {a.mitre_id} {a.mitre_name}: {a.description}"
        for a in state.alerts
    ) or "No structured alerts available; use anomaly analysis from previous agent output."

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Alerts:\n{alert_summary}\n\n"
                f"Anomaly scores: {state.anomaly_scores}\n\n"
                "Perform triage: MITRE mapping, actor attribution, kill chain phase."
            )
        ),
    ]
    llm = get_llm()
    response = llm.invoke(messages)

    updated_state = emit_audit(
        state,
        event_type="triage_completed",
        agent="TAA",
        summary="Triage completed — MITRE mapping and actor attribution generated.",
        details={"alert_count": len(state.alerts)},
    )

    return {
        "current_agent": "taa",
        "pipeline_stage": "triaging",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": updated_state.audit_log,
        "messages": [response],
    }

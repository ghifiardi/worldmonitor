"""LLM Respond node — handles general SOC questions with an LLM."""
from __future__ import annotations
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from agent.llm import get_llm
from agent.state import GatraState

_SYSTEM_PROMPT = """You are GATRA — an expert AI SOC analyst assistant.
You help security analysts understand threats, interpret alerts, investigate incidents,
and navigate cybersecurity frameworks like MITRE ATT&CK.
Be concise, precise, and always ground your answers in current threat intelligence best practices.
When uncertain, say so — never fabricate CVE IDs, MITRE technique IDs, or threat actor attributions."""


def llm_respond_node(state: GatraState, config: dict) -> dict:
    """Answer general SOC questions using the LLM."""
    llm = get_llm()
    messages = [SystemMessage(content=_SYSTEM_PROMPT)]
    if state.messages:
        messages.extend(state.messages)
    else:
        messages.append(HumanMessage(content=state.query or "Hello, I need SOC assistance."))

    response = llm.invoke(messages)

    return {
        "current_agent": "llm_respond",
        "pipeline_stage": "responding",
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }

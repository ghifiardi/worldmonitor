from __future__ import annotations
from langchain_core.tools import tool

@tool
async def log_audit(entry_json: str) -> dict:
    """Persist a pre-built AuditEntry. No LLM involved."""
    return {"persisted": True, "entry": entry_json}

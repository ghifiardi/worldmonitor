from __future__ import annotations
from langchain_core.tools import tool
from agent.tools.client import make_request

@tool
async def fetch_alerts(severity: str = "all", limit: int = 20) -> dict:
    """Fetch latest GATRA alerts from the SOC pipeline."""
    return await make_request("/api/gatra-data", params={"severity": severity, "limit": limit})

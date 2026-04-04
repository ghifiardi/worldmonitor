from __future__ import annotations
from langchain_core.tools import tool
from agent.tools.client import make_request

@tool
async def lookup_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    """Look up an Indicator of Compromise against VirusTotal and AbuseIPDB."""
    return await make_request("/api/ioc-lookup", params={"ioc": ioc, "type": ioc_type})

@tool
async def query_threat_feeds(query: str) -> dict:
    """Query aggregated threat intelligence feeds."""
    return await make_request("/api/threat-feeds", params={"q": query})

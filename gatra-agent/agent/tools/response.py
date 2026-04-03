from __future__ import annotations
import os
from langchain_core.tools import tool
from agent.tools.client import make_request

@tool
async def execute_action(action_type: str, target_type: str, target_value: str, idempotency_key: str) -> dict:
    """Execute a containment action against a target. Only called after policy gate approval."""
    dry_run = os.getenv("ACTION_DRY_RUN", "false").lower() == "true"
    return await make_request("/api/response-actions", method="POST",
        json_body={"action": action_type, "target_type": target_type, "target": target_value,
            "idempotency_key": idempotency_key, "dry_run": dry_run})

@tool
async def scan_yara(file_hash: str, scan_type: str = "hash") -> dict:
    """Run YARA malware scan against a file hash or sample."""
    return await make_request("/api/response-actions", method="POST",
        json_body={"action": "yara_scan", "hash": file_hash, "type": scan_type})

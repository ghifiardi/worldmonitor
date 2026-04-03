"""Router node — parses analyst intent and routes to the appropriate agent node."""
from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Any

from agent.audit import emit_audit
from agent.state import GatraState

# ---------------------------------------------------------------------------
# Intent pattern library
# ---------------------------------------------------------------------------

_PATTERNS: dict[str, re.Pattern] = {
    "action": re.compile(
        r"\b(block|isolate|kill|quarantine|contain|suspend|unblock|resume)\b", re.IGNORECASE
    ),
    # triage checked before detection so "triage" keyword wins over "alert" in same query
    "triage": re.compile(
        r"\b(triage|prioriti|escalat|assess|investigate|mitre|att&ck)\b", re.IGNORECASE
    ),
    "detection": re.compile(
        r"\b(analyze|scan|detect|anomal|alert|monitor)\b", re.IGNORECASE
    ),
    "vulnerability": re.compile(
        r"\b(cves?|vulnerabil|patch|epss|cvss|exploit)\b", re.IGNORECASE
    ),
    "compliance": re.compile(
        r"\b(compliance|audit|report|regulation|hipaa|pci|sox|log trail)\b", re.IGNORECASE
    ),
}

# Simple IP / hostname / FQDN extraction
_ENTITY_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ENTITY_HOST = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b")
_ENTITY_IDENTIFIER = re.compile(r"\b([A-Za-z0-9_-]{3,64})\b")

# Time-scope keywords
_TIME_SCOPE_PATTERN = re.compile(
    r"\b(last\s+(?:hour|day|week|month)|past\s+\d+\s+(?:minute|hour|day)s?|today|yesterday)\b",
    re.IGNORECASE,
)


def _extract_entities(query: str) -> list[str]:
    """Pull IPs and hostnames from query text."""
    entities: list[str] = []
    for ip in _ENTITY_IP.findall(query):
        entities.append(ip)
    # Only add hostnames if they look meaningful (contain a dot)
    for host in _ENTITY_HOST.findall(query):
        if host not in entities:
            entities.append(host)
    return entities


def parse_intent(query: str) -> dict[str, Any]:
    """Regex-based intent classification.

    Returns a dict with keys:
        intent            str — one of action / detection / triage / vulnerability / compliance / general
        target_entities   list[str] — extracted IPs / hosts
        time_scope        str | None — detected time window
        action_requested  str | None — the matched action verb if intent == "action"
        confidence        float
    """
    matches: dict[str, list[str]] = {}
    for intent_name, pattern in _PATTERNS.items():
        found = pattern.findall(query)
        if found:
            matches[intent_name] = [m.lower() if isinstance(m, str) else m[0].lower() for m in found]

    # Determine primary intent (priority order: action > detection > triage > vulnerability > compliance)
    priority = ["action", "triage", "detection", "vulnerability", "compliance"]
    intent = "general"
    for candidate in priority:
        if candidate in matches:
            intent = candidate
            break

    target_entities = _extract_entities(query)
    time_match = _TIME_SCOPE_PATTERN.search(query)
    time_scope: str | None = time_match.group(0) if time_match else None

    action_requested: str | None = None
    confidence: float

    if intent == "action":
        action_requested = matches["action"][0] if matches.get("action") else None
        # High confidence only when there is a clear target entity
        confidence = 0.9 if target_entities else 0.5
    elif intent == "general":
        confidence = 1.0
    else:
        confidence = 0.85

    return {
        "intent": intent,
        "target_entities": target_entities,
        "time_scope": time_scope,
        "action_requested": action_requested,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Routing map
# ---------------------------------------------------------------------------

_INTENT_TO_NODE: dict[str, str] = {
    "detection": "ada",
    "triage": "taa",
    "action": "cra",
    "vulnerability": "rva",
    "compliance": "cla_report",
    "general": "llm_respond",
}

_SAFE_FALLBACK = "taa"  # safe summary when action confidence is too low


def route_from_intent(intent: dict[str, Any]) -> str:
    """Map parsed intent to a node name.

    Safety rule: if action intent is detected but confidence < 0.7, route to TAA (safe summary).
    """
    node = _INTENT_TO_NODE.get(intent["intent"], "llm_respond")
    if intent["intent"] == "action" and intent["confidence"] < 0.7:
        node = _SAFE_FALLBACK
    return node


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


def router_node(state: GatraState, config: dict) -> dict:
    """Entry node — parses query, audits routing decision, sets _route."""
    intent = parse_intent(state.query)
    route = route_from_intent(intent)

    updated_state = emit_audit(
        state,
        event_type="routing_start",
        agent="router",
        summary=f"Routed query to '{route}' (intent={intent['intent']}, confidence={intent['confidence']:.2f})",
        details={
            "intent": intent["intent"],
            "confidence": intent["confidence"],
            "target_entities": intent["target_entities"],
            "time_scope": intent["time_scope"],
            "action_requested": intent["action_requested"],
            "route": route,
        },
    )

    return {
        "_route": route,
        "current_agent": "router",
        "pipeline_stage": "routing",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": updated_state.audit_log,
    }

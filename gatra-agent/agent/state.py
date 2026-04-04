"""Typed state models for the GATRA LangGraph agent pipeline."""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

class Alert(BaseModel):
    id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mitre_id: str
    mitre_name: str
    description: str
    confidence: float
    lat: float | None = None
    lon: float | None = None
    location_name: str | None = None
    infrastructure: str | None = None
    timestamp: datetime
    agent: Literal["ADA", "TAA", "CRA", "CLA", "RVA"]

class TriageResult(BaseModel):
    id: str
    alert_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mitre_id: str
    mitre_name: str
    kill_chain_phase: Literal["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "c2", "actions"]
    actor_attribution: str
    campaign: str | None = None
    confidence: float
    iocs: list[str] = Field(default_factory=list)
    timestamp: datetime

class ProposedAction(BaseModel):
    action_id: str
    incident_id: str
    action_type: Literal["notify", "unblock", "resume", "suspend", "block", "kill", "isolate"]
    target_type: Literal["ip", "host", "endpoint", "process", "user", "session"]
    target_value: str
    target_fingerprint: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    rationale: str
    requires_approval: bool
    gate_reason: str | None = None
    requested_by_agent: str = "CRA"
    status: Literal["proposed", "approved", "denied", "executed", "failed"] = "proposed"
    expires_at: datetime

class ApprovedAction(BaseModel):
    action_id: str
    approved_by: str
    approved_at: datetime
    original_action: ProposedAction

class ExecutedAction(BaseModel):
    action_id: str
    incident_id: str
    action_type: str
    target_value: str
    success: bool
    error: str | None = None
    executed_at: datetime
    approved_by: str
    executed_by: str
    execution_actor_type: Literal["system", "human"] = "system"
    execution_mode: Literal["dry_run", "enforced"]
    rollback_available: bool
    idempotency_key: str

class VulnerabilityContext(BaseModel):
    cve_id: str
    cvss_v4_score: float
    epss_percentile: float
    affected_products: list[str] = Field(default_factory=list)
    patch_available: bool
    cisa_kev: bool
    recommendation: str

class PolicyDecision(BaseModel):
    action_type: str
    policy_mode: str
    matched_rule: str
    override_applied: str | None = None
    min_role_required: str
    decision: Literal["auto_approved", "requires_approval", "denied_by_policy"]
    reason: str

class StateError(BaseModel):
    code: str
    message: str
    retryable: bool = False
    source: str
    timestamp: datetime
    details: dict[str, Any] | None = None

class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    trace_id: str
    incident_id: str | None = None
    event_type: Literal[
        "routing_start", "alert_fetched", "triage_completed", "action_proposed",
        "approval_requested", "approval_granted", "approval_denied",
        "execution_succeeded", "execution_failed", "vulnerability_assessed",
        "compliance_checked", "policy_evaluated",
    ]
    agent: str
    actor: str | None = None
    summary: str
    details: dict[str, Any] | None = None
    compliance_frameworks: list[str] = Field(default_factory=list)
    policy_decision: PolicyDecision | None = None

class AuditIdentity(BaseModel):
    user_id: str
    role: Literal["viewer", "analyst", "responder", "approver", "admin"]
    session_id: str
    timestamp: datetime
    ticket_ref: str | None = None

class AgentMode(str, Enum):
    full = "full"
    lite = "lite"

class GatraState(BaseModel):
    # CopilotKit / LangGraph messages state (kept for graph compatibility)
    messages: Annotated[list[AnyMessage], add_messages] = Field(default_factory=list)
    copilotkit: dict[str, Any] = Field(default_factory=dict)
    mode: AgentMode = AgentMode.full
    session_id: str = ""
    incident_id: str = ""
    trace_id: str = ""
    user_id: str = ""
    user_role: str = "analyst"
    query: str = ""
    alerts: list[Alert] = Field(default_factory=list)
    anomaly_scores: dict[str, float] = Field(default_factory=dict)
    triage_results: list[TriageResult] = Field(default_factory=list)
    actor_attribution: str = ""
    kill_chain_phase: str = ""
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    approved_actions: list[ApprovedAction] = Field(default_factory=list)
    denied_actions: list[ProposedAction] = Field(default_factory=list)
    executed_actions: list[ExecutedAction] = Field(default_factory=list)
    approval_pending: bool = False
    vulnerability_context: list[VulnerabilityContext] = Field(default_factory=list)
    audit_log: list[AuditEntry] = Field(default_factory=list)
    compliance_flags: list[str] = Field(default_factory=list)
    current_agent: str = ""
    pipeline_stage: str = "idle"
    last_updated_at: datetime | None = None
    errors: list[StateError] = Field(default_factory=list)

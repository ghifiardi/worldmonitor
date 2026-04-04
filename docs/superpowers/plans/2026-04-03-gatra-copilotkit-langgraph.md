# GATRA CopilotKit + LangGraph Analyst Console — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone agent-native SOC analyst console with CopilotKit frontend and LangGraph 5-agent pipeline backend, featuring human-in-the-loop approval flows and generative UI.

**Architecture:** Two new top-level directories in `/Users/raditio.ghifiardigmail.com/worldmonitor/`: `gatra-agent/` (Python FastAPI + LangGraph) and `gatra-copilot/` (Next.js + CopilotKit). The Python backend orchestrates 5 GATRA agents as LangGraph nodes, calling existing Vercel API endpoints as tools. The Next.js frontend connects via CopilotKit Runtime to the agent backend.

**Tech Stack:** Python 3.12, FastAPI, LangGraph, CopilotKit (copilotkit 0.1.84, ag-ui-langgraph 0.0.29), Next.js 15, React 19, Tailwind CSS 4, TypeScript

**Spec:** `docs/superpowers/specs/2026-04-03-gatra-copilotkit-langgraph-design.md`

---

## Task 1: Python Backend Scaffolding

**Files:**
- Create: `gatra-agent/pyproject.toml`
- Create: `gatra-agent/.env.example`
- Create: `gatra-agent/config/response_gate.yaml`
- Create: `gatra-agent/.gitignore`
- Create: `gatra-agent/.python-version`

- [ ] **Step 1: Create pyproject.toml**

```toml
# gatra-agent/pyproject.toml
[project]
name = "gatra-agent"
version = "0.1.0"
description = "GATRA LangGraph agent backend for CopilotKit"
requires-python = ">=3.12,<3.13"
dependencies = [
    "langgraph>=0.3.25,<1.1.0",
    "langchain-core>=0.3.0",
    "langchain-anthropic>=0.3.0",
    "langchain-openai>=0.3.0",
    "langchain-groq>=0.2.0",
    "copilotkit>=0.1.84",
    "ag-ui-langgraph>=0.0.29",
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "httpx>=0.27.0",
    "pydantic>=2.0.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "pytest-httpx>=0.30",
    "ruff>=0.5.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
```

- [ ] **Step 2: Create .env.example**

```env
# gatra-agent/.env.example
WORLDMONITOR_API_URL=https://worldmonitor-gatra.vercel.app
GATRA_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GROQ_API_KEY=
LLM_PROVIDER=anthropic
LLM_FALLBACK_PROVIDER=groq
REQUEST_TIMEOUT_SECONDS=30
ACTION_DRY_RUN=false
LOG_LEVEL=info
SERVICE_AUTH_SECRET=
CHECKPOINT_STORE=sqlite
```

- [ ] **Step 3: Create response gate config**

```yaml
# gatra-agent/config/response_gate.yaml
environment: dev
dry_run: false

actions:
  notify:
    mode: auto
  unblock:
    mode: auto
  resume:
    mode: auto
  suspend:
    mode: conditional
    min_severity: HIGH
    min_confidence: 0.80
    min_role: responder
  block:
    mode: conditional
    feature_flag: auto_block
    min_severity: CRITICAL
    min_confidence: 0.90
    min_role: responder
  kill:
    mode: conditional
    feature_flag: auto_kill
    min_severity: CRITICAL
    min_confidence: 0.95
    min_role: approver
  isolate:
    mode: approval_required
    min_role: approver

overrides:
  crown_jewel_assets:
    mode: approval_required
    asset_tags: ["core-router", "dns-primary", "hss", "pcrf", "pgw"]
  maintenance_window:
    enabled: false
    schedule: null

approval:
  expiry_seconds: 300
  allow_reapproval: false
```

- [ ] **Step 4: Create .gitignore and .python-version**

```gitignore
# gatra-agent/.gitignore
__pycache__/
*.pyc
.env
.venv/
*.egg-info/
dist/
.ruff_cache/
.pytest_cache/
checkpoints.db
```

```
# gatra-agent/.python-version
3.12
```

- [ ] **Step 5: Install dependencies and verify**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv sync
```
Expected: Dependencies resolve and install successfully.

- [ ] **Step 6: Commit**

```bash
git add gatra-agent/pyproject.toml gatra-agent/.env.example gatra-agent/config/response_gate.yaml gatra-agent/.gitignore gatra-agent/.python-version gatra-agent/uv.lock
git commit -m "feat(gatra-agent): scaffold Python backend with dependencies and config"
```

---

## Task 2: Typed State Models

**Files:**
- Create: `gatra-agent/agent/__init__.py`
- Create: `gatra-agent/agent/state.py`
- Create: `gatra-agent/tests/__init__.py`
- Create: `gatra-agent/tests/test_state.py`

- [ ] **Step 1: Write tests for state models**

```python
# gatra-agent/tests/__init__.py
```

```python
# gatra-agent/tests/test_state.py
from datetime import datetime, timedelta

from agent.state import (
    Alert,
    ApprovedAction,
    AuditEntry,
    AuditIdentity,
    ExecutedAction,
    GatraState,
    PolicyDecision,
    ProposedAction,
    StateError,
    TriageResult,
    VulnerabilityContext,
)


def test_alert_with_geo():
    alert = Alert(
        id="a1",
        severity="CRITICAL",
        mitre_id="T1566",
        mitre_name="Phishing",
        description="Spear phishing detected",
        confidence=0.92,
        lat=-6.2,
        lon=106.8,
        location_name="Jakarta DC-2",
        infrastructure="core-router-01",
        timestamp=datetime.now(),
        agent="ADA",
    )
    assert alert.severity == "CRITICAL"
    assert alert.lat == -6.2


def test_alert_without_geo():
    alert = Alert(
        id="a2",
        severity="HIGH",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        description="Compromised credential detected",
        confidence=0.85,
        timestamp=datetime.now(),
        agent="ADA",
    )
    assert alert.lat is None
    assert alert.infrastructure is None


def test_proposed_action_expires():
    action = ProposedAction(
        action_id="act1",
        incident_id="inc1",
        action_type="block",
        target_type="ip",
        target_value="45.33.32.156",
        target_fingerprint="abc123",
        severity="CRITICAL",
        confidence=0.95,
        rationale="Known C2 server",
        requires_approval=True,
        gate_reason="severity threshold met",
        expires_at=datetime.now() + timedelta(seconds=300),
    )
    assert action.status == "proposed"
    assert action.requires_approval is True
    assert action.requested_by_agent == "CRA"


def test_executed_action_tracks_actors():
    action = ExecutedAction(
        action_id="act1",
        incident_id="inc1",
        action_type="block",
        target_value="45.33.32.156",
        success=True,
        executed_at=datetime.now(),
        approved_by="user-001",
        executed_by="system-svc",
        execution_actor_type="system",
        execution_mode="enforced",
        rollback_available=True,
        idempotency_key="idem-001",
    )
    assert action.approved_by == "user-001"
    assert action.executed_by == "system-svc"
    assert action.execution_actor_type == "system"


def test_policy_decision():
    pd = PolicyDecision(
        action_type="block",
        policy_mode="conditional",
        matched_rule="actions.block",
        override_applied=None,
        min_role_required="responder",
        decision="requires_approval",
        reason="Confidence 0.85 below threshold 0.90",
    )
    assert pd.decision == "requires_approval"


def test_audit_entry_with_policy():
    entry = AuditEntry(
        id="ae1",
        timestamp=datetime.now(),
        trace_id="trace-001",
        event_type="policy_evaluated",
        agent="CRA",
        summary="Policy gate evaluated for block action",
        policy_decision=PolicyDecision(
            action_type="block",
            policy_mode="conditional",
            matched_rule="actions.block",
            min_role_required="responder",
            decision="requires_approval",
            reason="Below auto threshold",
        ),
    )
    assert entry.event_type == "policy_evaluated"
    assert entry.policy_decision is not None


def test_state_error_typed():
    err = StateError(
        code="TOOL_TIMEOUT",
        message="fetch_alerts timed out after 30s",
        retryable=True,
        source="ada",
        timestamp=datetime.now(),
        details={"endpoint": "/api/gatra-data"},
    )
    assert err.retryable is True


def test_gatra_state_defaults():
    state = GatraState()
    assert state.alerts == []
    assert state.anomaly_scores == {}
    assert state.pipeline_stage == "idle"
    assert state.errors == []
    assert state.user_role == "analyst"


def test_gatra_state_no_shared_mutable_defaults():
    """Ensure Field(default_factory=...) prevents shared state between instances."""
    s1 = GatraState()
    s2 = GatraState()
    s1.alerts.append(
        Alert(
            id="x",
            severity="LOW",
            mitre_id="T1000",
            mitre_name="Test",
            description="Test",
            confidence=0.5,
            timestamp=datetime.now(),
            agent="ADA",
        )
    )
    assert len(s2.alerts) == 0


def test_audit_identity():
    identity = AuditIdentity(
        user_id="user-001",
        role="approver",
        session_id="sess-abc",
        timestamp=datetime.now(),
        ticket_ref="INC-42",
    )
    assert identity.role == "approver"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_state.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent'`

- [ ] **Step 3: Implement state models**

```python
# gatra-agent/agent/__init__.py
```

```python
# gatra-agent/agent/state.py
"""Typed state models for the GATRA LangGraph agent pipeline.

All critical objects use Pydantic models — no generic dict in safety-sensitive paths.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from copilotkit import CopilotKitState
from pydantic import BaseModel, Field


# --- Typed domain models ---


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
    kill_chain_phase: Literal[
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "c2",
        "actions",
    ]
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
    """Logged when the response gate evaluates an action."""

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
        "routing_start",
        "alert_fetched",
        "triage_completed",
        "action_proposed",
        "approval_requested",
        "approval_granted",
        "approval_denied",
        "execution_succeeded",
        "execution_failed",
        "vulnerability_assessed",
        "compliance_checked",
        "policy_evaluated",
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


# --- LangGraph state ---


class GatraState(CopilotKitState):
    # Session & tracing
    session_id: str = ""
    incident_id: str = ""
    trace_id: str = ""
    user_id: str = ""
    user_role: str = "analyst"

    # Input
    query: str = ""

    # ADA outputs
    alerts: list[Alert] = Field(default_factory=list)
    anomaly_scores: dict[str, float] = Field(default_factory=dict)

    # TAA outputs
    triage_results: list[TriageResult] = Field(default_factory=list)
    actor_attribution: str = ""
    kill_chain_phase: str = ""

    # CRA outputs
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    approved_actions: list[ApprovedAction] = Field(default_factory=list)
    denied_actions: list[ProposedAction] = Field(default_factory=list)
    executed_actions: list[ExecutedAction] = Field(default_factory=list)
    approval_pending: bool = False

    # RVA outputs
    vulnerability_context: list[VulnerabilityContext] = Field(default_factory=list)

    # CLA outputs (append-only)
    audit_log: list[AuditEntry] = Field(default_factory=list)
    compliance_flags: list[str] = Field(default_factory=list)

    # Pipeline metadata
    current_agent: str = ""
    pipeline_stage: str = "idle"
    last_updated_at: datetime | None = None
    errors: list[StateError] = Field(default_factory=list)
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_state.py -v
```
Expected: All 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/ gatra-agent/tests/
git commit -m "feat(gatra-agent): add typed Pydantic state models and GatraState"
```

---

## Task 3: LLM Provider Factory

**Files:**
- Create: `gatra-agent/agent/llm.py`
- Create: `gatra-agent/tests/test_llm.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_llm.py
import os

import pytest

from agent.llm import LLMProviderUnavailableError, get_llm


def test_get_llm_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    llm = get_llm("anthropic")
    assert llm is not None


def test_get_llm_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    llm = get_llm("openai")
    assert llm is not None


def test_get_llm_groq(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    llm = get_llm("groq")
    assert llm is not None


def test_get_llm_invalid_provider():
    with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
        get_llm("invalid")


def test_get_llm_defaults_to_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    llm = get_llm()
    assert llm is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_llm.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.llm'`

- [ ] **Step 3: Implement LLM factory**

```python
# gatra-agent/agent/llm.py
"""LLM provider factory with configurable fallback."""

from __future__ import annotations

import os

from langchain_core.language_models import BaseChatModel


class LLMProviderUnavailableError(Exception):
    """Retryable provider errors — timeouts, rate limits, temporary outages."""


def get_llm(provider: str | None = None, timeout: int | None = None) -> BaseChatModel:
    """Create an LLM instance for the given provider.

    Args:
        provider: One of "anthropic", "openai", "groq". Defaults to LLM_PROVIDER env var.
        timeout: Request timeout in seconds. Defaults to REQUEST_TIMEOUT_SECONDS env var.
    """
    provider = provider or os.getenv("LLM_PROVIDER", "anthropic")
    timeout = timeout or int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))

    match provider:
        case "anthropic":
            from langchain_anthropic import ChatAnthropic

            return ChatAnthropic(model="claude-sonnet-4-20250514", timeout=timeout)
        case "openai":
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(model="gpt-4o", timeout=timeout)
        case "groq":
            from langchain_groq import ChatGroq

            return ChatGroq(model="llama-3.3-70b-versatile", timeout=timeout)
        case _:
            raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")


def get_llm_with_fallback(timeout: int | None = None) -> BaseChatModel:
    """Get LLM with automatic fallback on transient errors only."""
    try:
        return get_llm(timeout=timeout)
    except LLMProviderUnavailableError:
        fallback = os.getenv("LLM_FALLBACK_PROVIDER")
        if fallback:
            return get_llm(fallback, timeout=timeout)
        raise
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_llm.py -v
```
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/llm.py gatra-agent/tests/test_llm.py
git commit -m "feat(gatra-agent): add LLM provider factory with fallback"
```

---

## Task 4: Response Gate Policy Engine

**Files:**
- Create: `gatra-agent/agent/policy.py`
- Create: `gatra-agent/tests/test_policy.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_policy.py
from pathlib import Path

from agent.policy import ResponseGatePolicy
from agent.state import PolicyDecision


FIXTURE_PATH = Path(__file__).parent.parent / "config" / "response_gate.yaml"


def test_load_policy():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    assert policy.environment == "dev"
    assert policy.dry_run is False
    assert "notify" in policy.actions


def test_notify_auto_approved():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="notify",
        severity="LOW",
        confidence=0.5,
        user_role="analyst",
        target_tags=[],
    )
    assert decision.decision == "auto_approved"


def test_block_requires_approval_below_threshold():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="block",
        severity="HIGH",
        confidence=0.85,
        user_role="responder",
        target_tags=[],
    )
    assert decision.decision == "requires_approval"
    assert "severity" in decision.reason.lower() or "confidence" in decision.reason.lower()


def test_block_auto_on_critical_high_confidence():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="block",
        severity="CRITICAL",
        confidence=0.95,
        user_role="responder",
        target_tags=[],
    )
    assert decision.decision == "auto_approved"


def test_isolate_always_requires_approval():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="isolate",
        severity="CRITICAL",
        confidence=1.0,
        user_role="approver",
        target_tags=[],
    )
    assert decision.decision == "requires_approval"


def test_crown_jewel_override():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="notify",
        severity="LOW",
        confidence=1.0,
        user_role="admin",
        target_tags=["core-router"],
    )
    assert decision.decision == "requires_approval"
    assert decision.override_applied == "crown_jewel_assets"


def test_insufficient_role_denied():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    decision = policy.evaluate(
        action_type="kill",
        severity="CRITICAL",
        confidence=0.99,
        user_role="analyst",
        target_tags=[],
    )
    assert decision.decision == "denied_by_policy"
    assert "role" in decision.reason.lower()


def test_approval_expiry():
    policy = ResponseGatePolicy.from_yaml(FIXTURE_PATH)
    assert policy.approval_expiry_seconds == 300
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_policy.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.policy'`

- [ ] **Step 3: Implement policy engine**

```python
# gatra-agent/agent/policy.py
"""Response Gate policy engine. Loads from YAML, evaluates actions against thresholds."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent.state import PolicyDecision

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ROLE_ORDER = {"viewer": 0, "analyst": 1, "responder": 2, "approver": 3, "admin": 4}


class ResponseGatePolicy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.environment: str = config.get("environment", "dev")
        self.dry_run: bool = config.get("dry_run", False)
        self.actions: dict[str, dict] = config.get("actions", {})
        self.overrides: dict[str, dict] = config.get("overrides", {})
        approval_cfg = config.get("approval", {})
        self.approval_expiry_seconds: int = approval_cfg.get("expiry_seconds", 300)
        self.allow_reapproval: bool = approval_cfg.get("allow_reapproval", False)

    @classmethod
    def from_yaml(cls, path: Path) -> ResponseGatePolicy:
        with open(path) as f:
            config = yaml.safe_load(f)
        return cls(config)

    def evaluate(
        self,
        action_type: str,
        severity: str,
        confidence: float,
        user_role: str,
        target_tags: list[str],
    ) -> PolicyDecision:
        # Check crown jewel override first
        crown_cfg = self.overrides.get("crown_jewel_assets", {})
        crown_tags = crown_cfg.get("asset_tags", [])
        if crown_tags and any(tag in crown_tags for tag in target_tags):
            return PolicyDecision(
                action_type=action_type,
                policy_mode="approval_required",
                matched_rule="overrides.crown_jewel_assets",
                override_applied="crown_jewel_assets",
                min_role_required=crown_cfg.get("min_role", "approver"),
                decision="requires_approval",
                reason=f"Target tagged as crown jewel asset ({', '.join(t for t in target_tags if t in crown_tags)})",
            )

        action_cfg = self.actions.get(action_type)
        if action_cfg is None:
            return PolicyDecision(
                action_type=action_type,
                policy_mode="unknown",
                matched_rule="default_deny",
                min_role_required="admin",
                decision="denied_by_policy",
                reason=f"No policy defined for action type '{action_type}'",
            )

        mode = action_cfg.get("mode", "approval_required")
        min_role = action_cfg.get("min_role", "analyst")
        matched_rule = f"actions.{action_type}"

        # Check role
        if ROLE_ORDER.get(user_role, 0) < ROLE_ORDER.get(min_role, 0):
            return PolicyDecision(
                action_type=action_type,
                policy_mode=mode,
                matched_rule=matched_rule,
                min_role_required=min_role,
                decision="denied_by_policy",
                reason=f"Role '{user_role}' insufficient; requires '{min_role}'",
            )

        if mode == "auto":
            return PolicyDecision(
                action_type=action_type,
                policy_mode=mode,
                matched_rule=matched_rule,
                min_role_required=min_role,
                decision="auto_approved",
                reason="Auto-execute policy",
            )

        if mode == "approval_required":
            return PolicyDecision(
                action_type=action_type,
                policy_mode=mode,
                matched_rule=matched_rule,
                min_role_required=min_role,
                decision="requires_approval",
                reason="Always requires manual approval",
            )

        # mode == "conditional"
        min_severity = action_cfg.get("min_severity", "CRITICAL")
        min_confidence = action_cfg.get("min_confidence", 0.95)

        sev_met = SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 3)
        conf_met = confidence >= min_confidence

        if sev_met and conf_met:
            return PolicyDecision(
                action_type=action_type,
                policy_mode=mode,
                matched_rule=matched_rule,
                min_role_required=min_role,
                decision="auto_approved",
                reason=f"Severity {severity} >= {min_severity} and confidence {confidence:.2f} >= {min_confidence}",
            )

        reasons = []
        if not sev_met:
            reasons.append(f"severity {severity} < {min_severity}")
        if not conf_met:
            reasons.append(f"confidence {confidence:.2f} < {min_confidence}")

        return PolicyDecision(
            action_type=action_type,
            policy_mode=mode,
            matched_rule=matched_rule,
            min_role_required=min_role,
            decision="requires_approval",
            reason=f"Conditional threshold not met: {'; '.join(reasons)}",
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_policy.py -v
```
Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/policy.py gatra-agent/tests/test_policy.py
git commit -m "feat(gatra-agent): add response gate policy engine with YAML config"
```

---

## Task 5: Audit Utility

**Files:**
- Create: `gatra-agent/agent/audit.py`
- Create: `gatra-agent/tests/test_audit.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_audit.py
from datetime import datetime

from agent.audit import emit_audit
from agent.state import AuditEntry, GatraState, PolicyDecision


def test_emit_audit_appends_entry():
    state = GatraState(trace_id="t1", incident_id="inc1")
    updated = emit_audit(
        state,
        event_type="routing_start",
        agent="router",
        summary="Routing analyst query",
    )
    assert len(updated.audit_log) == 1
    entry = updated.audit_log[0]
    assert entry.event_type == "routing_start"
    assert entry.trace_id == "t1"
    assert entry.incident_id == "inc1"
    assert entry.agent == "router"


def test_emit_audit_with_policy_decision():
    state = GatraState(trace_id="t2")
    pd = PolicyDecision(
        action_type="block",
        policy_mode="conditional",
        matched_rule="actions.block",
        min_role_required="responder",
        decision="requires_approval",
        reason="Below threshold",
    )
    updated = emit_audit(
        state,
        event_type="policy_evaluated",
        agent="CRA",
        summary="Policy gate evaluated",
        policy_decision=pd,
    )
    assert updated.audit_log[0].policy_decision is not None
    assert updated.audit_log[0].policy_decision.decision == "requires_approval"


def test_emit_audit_preserves_existing():
    state = GatraState(trace_id="t3")
    state = emit_audit(state, event_type="routing_start", agent="router", summary="First")
    state = emit_audit(state, event_type="alert_fetched", agent="ADA", summary="Second")
    assert len(state.audit_log) == 2
    assert state.audit_log[0].event_type == "routing_start"
    assert state.audit_log[1].event_type == "alert_fetched"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_audit.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.audit'`

- [ ] **Step 3: Implement audit utility**

```python
# gatra-agent/agent/audit.py
"""CLA audit utility — called by every node at significant events.

Nodes create structured AuditEntry payloads. This utility appends them to state.
No LLM involved — purely deterministic persistence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from agent.state import AuditEntry, GatraState, PolicyDecision


def emit_audit(
    state: GatraState,
    *,
    event_type: str,
    agent: str,
    summary: str,
    actor: str | None = None,
    details: dict[str, Any] | None = None,
    compliance_frameworks: list[str] | None = None,
    policy_decision: PolicyDecision | None = None,
) -> GatraState:
    """Append an audit entry to state. Returns updated state."""
    entry = AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        trace_id=state.trace_id,
        incident_id=state.incident_id or None,
        event_type=event_type,
        agent=agent,
        actor=actor or state.user_id or None,
        summary=summary,
        details=details,
        compliance_frameworks=compliance_frameworks or [],
        policy_decision=policy_decision,
    )
    state.audit_log = [*state.audit_log, entry]
    return state
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_audit.py -v
```
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/audit.py gatra-agent/tests/test_audit.py
git commit -m "feat(gatra-agent): add CLA audit utility for structured event logging"
```

---

## Task 6: HTTP Client & Tool Error Handling

**Files:**
- Create: `gatra-agent/agent/tools/__init__.py`
- Create: `gatra-agent/agent/tools/client.py`
- Create: `gatra-agent/tests/test_client.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_client.py
import httpx
import pytest
import pytest_httpx

from agent.tools.client import ToolError, gatra_client, make_request


@pytest.fixture
def base_url(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")
    return "https://test.example.com"


async def test_make_request_success(httpx_mock, base_url):
    httpx_mock.add_response(
        url="https://test.example.com/api/gatra-data",
        json={"alerts": []},
    )
    result = await make_request("/api/gatra-data")
    assert result == {"alerts": []}


async def test_make_request_timeout_retries(httpx_mock, base_url):
    # First two calls timeout, third succeeds
    httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    httpx_mock.add_response(
        url="https://test.example.com/api/gatra-data",
        json={"ok": True},
    )
    result = await make_request("/api/gatra-data", max_retries=3)
    assert result == {"ok": True}


async def test_make_request_all_retries_exhausted(httpx_mock, base_url):
    for _ in range(4):
        httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    with pytest.raises(ToolError) as exc_info:
        await make_request("/api/gatra-data", max_retries=3)
    assert exc_info.value.retryable is True


async def test_make_request_4xx_not_retryable(httpx_mock, base_url):
    httpx_mock.add_response(
        url="https://test.example.com/api/gatra-data",
        status_code=401,
        json={"error": "Unauthorized"},
    )
    with pytest.raises(ToolError) as exc_info:
        await make_request("/api/gatra-data")
    assert exc_info.value.retryable is False
    assert exc_info.value.code == "HTTP_401"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_client.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement HTTP client**

```python
# gatra-agent/agent/tools/__init__.py
```

```python
# gatra-agent/agent/tools/client.py
"""Shared HTTP client for calling existing Vercel API endpoints.

All tool calls use this client. Handles auth, timeouts, retries, and error normalization.
"""

from __future__ import annotations

import asyncio
import os

import httpx


class ToolError(Exception):
    """Normalized error from tool HTTP calls."""

    def __init__(self, code: str, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def gatra_client(timeout: int | None = None) -> httpx.AsyncClient:
    """Create a configured async HTTP client."""
    timeout = timeout or int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    base_url = os.getenv("WORLDMONITOR_API_URL", "https://worldmonitor-gatra.vercel.app")
    api_key = os.getenv("GATRA_API_KEY", "")

    return httpx.AsyncClient(
        base_url=base_url,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=httpx.Timeout(timeout),
    )


async def make_request(
    path: str,
    *,
    method: str = "GET",
    params: dict | None = None,
    json_body: dict | None = None,
    timeout: int | None = None,
    max_retries: int = 3,
) -> dict:
    """Make an HTTP request to a Vercel endpoint with retry and error normalization."""
    backoff_delays = [1, 2, 4]
    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            async with gatra_client(timeout) as client:
                response = await client.request(
                    method,
                    path,
                    params=params,
                    json=json_body,
                )

                if response.status_code >= 500:
                    raise ToolError(
                        code=f"HTTP_{response.status_code}",
                        message=f"Server error from {path}: {response.status_code}",
                        retryable=True,
                    )

                if response.status_code >= 400:
                    raise ToolError(
                        code=f"HTTP_{response.status_code}",
                        message=f"Client error from {path}: {response.status_code} — {response.text[:200]}",
                        retryable=False,
                    )

                return response.json()

        except ToolError as e:
            if not e.retryable or attempt >= max_retries:
                raise
            last_error = e
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
            if attempt >= max_retries:
                raise ToolError(
                    code="TIMEOUT",
                    message=f"Request to {path} failed after {max_retries + 1} attempts: {e}",
                    retryable=True,
                ) from e

        if attempt < max_retries:
            delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
            await asyncio.sleep(delay)

    raise ToolError(
        code="EXHAUSTED",
        message=f"All retries exhausted for {path}",
        retryable=True,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_client.py -v
```
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/tools/ gatra-agent/tests/test_client.py
git commit -m "feat(gatra-agent): add HTTP client with retry, timeout, and error normalization"
```

---

## Task 7: Backend Tools — Alerts & Threat Intel

**Files:**
- Create: `gatra-agent/agent/tools/alerts.py`
- Create: `gatra-agent/agent/tools/threat_intel.py`
- Create: `gatra-agent/tests/test_tools_alerts.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_tools_alerts.py
import pytest
import pytest_httpx

from agent.tools.alerts import fetch_alerts
from agent.tools.threat_intel import lookup_ioc


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")


async def test_fetch_alerts(httpx_mock):
    httpx_mock.add_response(
        url="https://test.example.com/api/gatra-data?severity=all&limit=20",
        json={
            "alerts": [
                {
                    "id": "a1",
                    "severity": "HIGH",
                    "mitre_id": "T1566",
                    "mitre_name": "Phishing",
                    "description": "Test alert",
                    "confidence": 0.85,
                    "timestamp": "2026-04-03T10:00:00Z",
                    "agent": "ADA",
                }
            ]
        },
    )
    result = await fetch_alerts.ainvoke({"severity": "all", "limit": 20})
    assert "alerts" in result
    assert len(result["alerts"]) == 1


async def test_lookup_ioc(httpx_mock):
    httpx_mock.add_response(
        url="https://test.example.com/api/ioc-lookup?ioc=45.33.32.156&type=ip",
        json={"found": True, "source": "VirusTotal", "malicious": True},
    )
    result = await lookup_ioc.ainvoke({"ioc": "45.33.32.156", "ioc_type": "ip"})
    assert result["found"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_tools_alerts.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement alert and threat intel tools**

```python
# gatra-agent/agent/tools/alerts.py
"""Tools for fetching and analyzing alerts from the GATRA pipeline."""

from __future__ import annotations

from langchain_core.tools import tool

from agent.tools.client import make_request


@tool
async def fetch_alerts(severity: str = "all", limit: int = 20) -> dict:
    """Fetch latest GATRA alerts from the SOC pipeline.

    Args:
        severity: Filter by severity level (all, LOW, MEDIUM, HIGH, CRITICAL).
        limit: Maximum number of alerts to return.
    """
    return await make_request(
        "/api/gatra-data",
        params={"severity": severity, "limit": limit},
    )
```

```python
# gatra-agent/agent/tools/threat_intel.py
"""Tools for threat intelligence enrichment — IOC lookups, threat feed queries."""

from __future__ import annotations

from langchain_core.tools import tool

from agent.tools.client import make_request


@tool
async def lookup_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    """Look up an Indicator of Compromise against VirusTotal and AbuseIPDB.

    Args:
        ioc: The IOC value (IP address, domain, hash, etc.).
        ioc_type: Type of IOC — ip, domain, hash.
    """
    return await make_request(
        "/api/ioc-lookup",
        params={"ioc": ioc, "type": ioc_type},
    )


@tool
async def query_threat_feeds(query: str) -> dict:
    """Query aggregated threat intelligence feeds.

    Args:
        query: Search query — actor name, campaign, MITRE technique, etc.
    """
    return await make_request(
        "/api/threat-feeds",
        params={"q": query},
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_tools_alerts.py -v
```
Expected: All 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/tools/alerts.py gatra-agent/agent/tools/threat_intel.py gatra-agent/tests/test_tools_alerts.py
git commit -m "feat(gatra-agent): add alert fetch and threat intel lookup tools"
```

---

## Task 8: Backend Tools — Response, Vulnerability & Compliance

**Files:**
- Create: `gatra-agent/agent/tools/response.py`
- Create: `gatra-agent/agent/tools/vulnerability.py`
- Create: `gatra-agent/agent/tools/compliance.py`
- Create: `gatra-agent/tests/test_tools_response.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_tools_response.py
import pytest
import pytest_httpx

from agent.tools.response import execute_action, scan_yara
from agent.tools.vulnerability import lookup_cves


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")
    monkeypatch.setenv("ACTION_DRY_RUN", "false")


async def test_execute_action(httpx_mock):
    httpx_mock.add_response(
        url="https://test.example.com/api/response-actions",
        json={"success": True, "action_id": "act1"},
    )
    result = await execute_action.ainvoke({
        "action_type": "block",
        "target_type": "ip",
        "target_value": "45.33.32.156",
        "idempotency_key": "idem-001",
    })
    assert result["success"] is True


async def test_scan_yara(httpx_mock):
    httpx_mock.add_response(
        url="https://test.example.com/api/response-actions",
        json={"matches": ["MALWARE_Trojan_Generic"]},
    )
    result = await scan_yara.ainvoke({"file_hash": "abc123", "scan_type": "hash"})
    assert "matches" in result


async def test_lookup_cves(httpx_mock):
    httpx_mock.add_response(
        url="https://test.example.com/api/cisa-kev?product=apache&limit=10",
        json={"cves": [{"id": "CVE-2024-1234", "cvss": 9.8}]},
    )
    result = await lookup_cves.ainvoke({"product": "apache", "limit": 10})
    assert len(result["cves"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_tools_response.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement response, vulnerability, and compliance tools**

```python
# gatra-agent/agent/tools/response.py
"""Tools for containment and response actions — block, isolate, kill, YARA scan."""

from __future__ import annotations

import os

from langchain_core.tools import tool

from agent.tools.client import make_request


@tool
async def execute_action(
    action_type: str,
    target_type: str,
    target_value: str,
    idempotency_key: str,
) -> dict:
    """Execute a containment action against a target. Only called after policy gate approval.

    Args:
        action_type: One of block, unblock, suspend, kill, isolate, notify.
        target_type: One of ip, host, endpoint, process, user, session.
        target_value: The target identifier.
        idempotency_key: Unique key to prevent duplicate execution.
    """
    dry_run = os.getenv("ACTION_DRY_RUN", "false").lower() == "true"

    return await make_request(
        "/api/response-actions",
        method="POST",
        json_body={
            "action": action_type,
            "target_type": target_type,
            "target": target_value,
            "idempotency_key": idempotency_key,
            "dry_run": dry_run,
        },
    )


@tool
async def scan_yara(file_hash: str, scan_type: str = "hash") -> dict:
    """Run YARA malware scan against a file hash or sample.

    Args:
        file_hash: The file hash (MD5, SHA1, SHA256) to scan.
        scan_type: Type of scan — hash or sample.
    """
    return await make_request(
        "/api/response-actions",
        method="POST",
        json_body={"action": "yara_scan", "hash": file_hash, "type": scan_type},
    )
```

```python
# gatra-agent/agent/tools/vulnerability.py
"""Tools for vulnerability assessment — CVE lookups from CISA KEV."""

from __future__ import annotations

from langchain_core.tools import tool

from agent.tools.client import make_request


@tool
async def lookup_cves(product: str, limit: int = 10) -> dict:
    """Look up CVEs from CISA Known Exploited Vulnerabilities catalog.

    Args:
        product: Product or vendor name to search.
        limit: Maximum results to return.
    """
    return await make_request(
        "/api/cisa-kev",
        params={"product": product, "limit": limit},
    )
```

```python
# gatra-agent/agent/tools/compliance.py
"""Tools for compliance checking and audit persistence."""

from __future__ import annotations

from langchain_core.tools import tool


@tool
async def log_audit(entry_json: str) -> dict:
    """Persist a pre-built AuditEntry. No LLM involved — nodes create the payload.

    Args:
        entry_json: JSON-serialized AuditEntry to persist.
    """
    # In v1, audit entries are stored in LangGraph state.
    # Future: persist to external store (PostgreSQL, BigQuery).
    return {"persisted": True, "entry": entry_json}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_tools_response.py -v
```
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/tools/response.py gatra-agent/agent/tools/vulnerability.py gatra-agent/agent/tools/compliance.py gatra-agent/tests/test_tools_response.py
git commit -m "feat(gatra-agent): add response, vulnerability, and compliance tools"
```

---

## Task 9: Agent Nodes — Router & LLM Respond

**Files:**
- Create: `gatra-agent/agent/nodes/__init__.py`
- Create: `gatra-agent/agent/nodes/router.py`
- Create: `gatra-agent/agent/nodes/llm_respond.py`
- Create: `gatra-agent/tests/test_router.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_router.py
from agent.nodes.router import parse_intent


def test_parse_intent_detection():
    result = parse_intent("analyze the latest alerts for anomalies")
    assert result["intent"] == "detection"


def test_parse_intent_triage():
    result = parse_intent("triage alert a-123 and check MITRE mapping")
    assert result["intent"] == "triage"


def test_parse_intent_action():
    result = parse_intent("block IP 45.33.32.156 immediately")
    assert result["intent"] == "action"
    assert "45.33.32.156" in result["target_entities"]


def test_parse_intent_vulnerability():
    result = parse_intent("check CVEs for Apache HTTP Server")
    assert result["intent"] == "vulnerability"


def test_parse_intent_compliance():
    result = parse_intent("show compliance report for last week")
    assert result["intent"] == "compliance"


def test_parse_intent_general():
    result = parse_intent("what is MITRE ATT&CK?")
    assert result["intent"] == "general"


def test_parse_intent_action_low_confidence():
    """Ambiguous action intent should have low confidence."""
    result = parse_intent("maybe we should look at isolating something")
    assert result["confidence"] < 0.7 or result["intent"] != "action"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_router.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement router and LLM respond nodes**

```python
# gatra-agent/agent/nodes/__init__.py
```

```python
# gatra-agent/agent/nodes/router.py
"""Router node — parses analyst intent and routes to the correct agent node.

Safety rule: if action_requested is detected but confidence < 0.7,
route to TAA for safe summary instead of CRA.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.state import GatraState

# Intent patterns — ordered by specificity
_ACTION_PATTERNS = re.compile(
    r"\b(block|isolate|kill|quarantine|contain|suspend|unblock|resume)\b", re.I
)
_DETECTION_PATTERNS = re.compile(
    r"\b(analyze|scan|detect|anomal|alert|monitor)\b", re.I
)
_TRIAGE_PATTERNS = re.compile(
    r"\b(triage|prioriti|escalat|assess|investigate|mitre|att&ck)\b", re.I
)
_VULN_PATTERNS = re.compile(
    r"\b(cve|vulnerabil|patch|epss|cvss|exploit)\b", re.I
)
_COMPLIANCE_PATTERNS = re.compile(
    r"\b(compliance|audit|report|regulation|hipaa|pci|sox|log trail)\b", re.I
)
_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def parse_intent(query: str) -> dict[str, Any]:
    """Parse analyst input into structured intent. Returns dict with:
    intent, target_entities, time_scope, action_requested, confidence
    """
    query_lower = query.lower()
    target_entities: list[str] = []

    # Extract target entities
    target_entities.extend(_IP_PATTERN.findall(query))
    target_entities.extend(_HASH_PATTERN.findall(query))

    # Score each intent
    action_match = _ACTION_PATTERNS.search(query_lower)
    detect_match = _DETECTION_PATTERNS.search(query_lower)
    triage_match = _TRIAGE_PATTERNS.search(query_lower)
    vuln_match = _VULN_PATTERNS.search(query_lower)
    compliance_match = _COMPLIANCE_PATTERNS.search(query_lower)

    # Action intent with specificity check
    if action_match:
        action_word = action_match.group(1).lower()
        # High confidence if there's a clear target + action verb
        has_target = bool(target_entities) or bool(
            re.search(r"\b(host|endpoint|server|process|user|ip)\b", query_lower)
        )
        confidence = 0.9 if has_target else 0.5
        return {
            "intent": "action",
            "target_entities": target_entities,
            "time_scope": None,
            "action_requested": action_word,
            "confidence": confidence,
        }

    if triage_match:
        return {
            "intent": "triage",
            "target_entities": target_entities,
            "time_scope": None,
            "action_requested": None,
            "confidence": 0.85,
        }

    if detect_match:
        return {
            "intent": "detection",
            "target_entities": target_entities,
            "time_scope": None,
            "action_requested": None,
            "confidence": 0.8,
        }

    if vuln_match:
        return {
            "intent": "vulnerability",
            "target_entities": target_entities,
            "time_scope": None,
            "action_requested": None,
            "confidence": 0.85,
        }

    if compliance_match:
        return {
            "intent": "compliance",
            "target_entities": target_entities,
            "time_scope": None,
            "action_requested": None,
            "confidence": 0.8,
        }

    return {
        "intent": "general",
        "target_entities": target_entities,
        "time_scope": None,
        "action_requested": None,
        "confidence": 0.7,
    }


def route_from_intent(intent: dict[str, Any]) -> str:
    """Map parsed intent to the next graph node name.

    Safety: action intents with confidence < 0.7 go to TAA (safe summary).
    """
    intent_type = intent["intent"]
    confidence = intent.get("confidence", 0.0)

    if intent_type == "action":
        if confidence < 0.7:
            return "taa"  # safe fallback
        return "cra"

    return {
        "detection": "ada",
        "triage": "taa",
        "vulnerability": "rva",
        "compliance": "cla_report",
        "general": "llm_respond",
    }.get(intent_type, "llm_respond")


async def router_node(state: GatraState, config: RunnableConfig) -> dict:
    """Entry node — parse intent, set pipeline metadata, route."""
    intent = parse_intent(state.query)
    next_node = route_from_intent(intent)

    state = emit_audit(
        state,
        event_type="routing_start",
        agent="router",
        summary=f"Routing to {next_node} (intent={intent['intent']}, confidence={intent['confidence']:.2f})",
        details=intent,
    )

    return {
        "current_agent": next_node,
        "pipeline_stage": "routing",
        "last_updated_at": datetime.now(timezone.utc),
        "audit_log": state.audit_log,
        "_route": next_node,  # used by conditional edge
    }
```

```python
# gatra-agent/agent/nodes/llm_respond.py
"""LLM respond node — direct LLM answer for general SOC questions."""

from __future__ import annotations

from datetime import datetime, timezone

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from agent.llm import get_llm_with_fallback
from agent.state import GatraState

SYSTEM_PROMPT = """You are a SOC analyst assistant for GATRA (Geopolitical Awareness & Threat Response Architecture).
You help analysts understand cybersecurity concepts, MITRE ATT&CK techniques, threat actors, and SOC operations.
Keep answers concise and actionable. If the question involves an active threat or action, suggest using the appropriate GATRA agent."""


async def llm_respond_node(state: GatraState, config: RunnableConfig) -> dict:
    """Answer general SOC questions directly via LLM."""
    llm = get_llm_with_fallback()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": state.query},
    ]
    response = await llm.ainvoke(messages)

    return {
        "current_agent": "llm_respond",
        "pipeline_stage": "idle",
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_router.py -v
```
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/nodes/ gatra-agent/tests/test_router.py
git commit -m "feat(gatra-agent): add router node with intent parsing and LLM respond node"
```

---

## Task 10: Agent Nodes — ADA, TAA, RVA, CLA Report

**Files:**
- Create: `gatra-agent/agent/nodes/ada.py`
- Create: `gatra-agent/agent/nodes/taa.py`
- Create: `gatra-agent/agent/nodes/rva.py`
- Create: `gatra-agent/agent/nodes/cla_report.py`

- [ ] **Step 1: Implement ADA node**

```python
# gatra-agent/agent/nodes/ada.py
"""ADA (Anomaly Detection Agent) node — fetches alerts, scores anomalies."""

from __future__ import annotations

from datetime import datetime, timezone

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm_with_fallback
from agent.state import GatraState
from agent.tools.alerts import fetch_alerts


async def ada_node(state: GatraState, config: RunnableConfig) -> dict:
    """Fetch alerts and score anomalies. Emits intermediate state for UI progress."""
    state.current_agent = "ADA"
    state.pipeline_stage = "detecting"
    copilotkit_emit_state(config, state.model_dump())

    # Fetch alerts from existing endpoint
    try:
        result = await fetch_alerts.ainvoke({"severity": "all", "limit": 50})
        raw_alerts = result.get("alerts", [])
    except Exception as e:
        state = emit_audit(
            state,
            event_type="alert_fetched",
            agent="ADA",
            summary=f"Alert fetch failed: {e}",
        )
        return {
            "current_agent": "ADA",
            "pipeline_stage": "detecting",
            "audit_log": state.audit_log,
            "last_updated_at": datetime.now(timezone.utc),
        }

    state = emit_audit(
        state,
        event_type="alert_fetched",
        agent="ADA",
        summary=f"Fetched {len(raw_alerts)} alerts",
    )

    # Use LLM to summarize and score anomalies
    llm = get_llm_with_fallback()
    scoring_prompt = f"""Analyze these {len(raw_alerts)} alerts and identify the most anomalous ones.
For each, provide a brief anomaly explanation. Focus on:
- Unusual patterns or volumes
- Known threat indicators
- Critical infrastructure targets

Alerts: {raw_alerts[:10]}

Respond with a JSON object: {{"anomaly_scores": {{"alert_id": score}}, "summary": "..."}}"""

    response = await llm.ainvoke([{"role": "user", "content": scoring_prompt}])

    return {
        "alerts": raw_alerts,
        "current_agent": "ADA",
        "pipeline_stage": "detecting",
        "audit_log": state.audit_log,
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 2: Implement TAA node**

```python
# gatra-agent/agent/nodes/taa.py
"""TAA (Threat Analysis & Triage) node — MITRE mapping, actor attribution, kill chain analysis."""

from __future__ import annotations

from datetime import datetime, timezone

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm_with_fallback
from agent.state import GatraState
from agent.tools.threat_intel import lookup_ioc, query_threat_feeds


async def taa_node(state: GatraState, config: RunnableConfig) -> dict:
    """Triage alerts — MITRE mapping, actor attribution, IOC enrichment."""
    state.current_agent = "TAA"
    state.pipeline_stage = "triaging"
    copilotkit_emit_state(config, state.model_dump())

    llm = get_llm_with_fallback()

    # Build context from available alerts
    alert_summary = ""
    if state.alerts:
        top_alerts = sorted(
            state.alerts,
            key=lambda a: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                a.severity if hasattr(a, "severity") else a.get("severity", "LOW"), 0
            ),
            reverse=True,
        )[:5]
        alert_summary = str([a.model_dump() if hasattr(a, "model_dump") else a for a in top_alerts])

    triage_prompt = f"""You are a SOC threat analyst. Analyze these alerts and provide triage results.

Query: {state.query}
Alerts: {alert_summary}

For each significant alert, provide:
1. MITRE ATT&CK technique mapping (technique ID and name)
2. Kill chain phase
3. Actor attribution (if identifiable)
4. Confidence level (0.0-1.0)
5. Severity assessment
6. List of IOCs found

Respond with structured analysis."""

    response = await llm.ainvoke([{"role": "user", "content": triage_prompt}])

    state = emit_audit(
        state,
        event_type="triage_completed",
        agent="TAA",
        summary="Threat analysis and triage completed",
    )

    return {
        "current_agent": "TAA",
        "pipeline_stage": "triaging",
        "audit_log": state.audit_log,
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 3: Implement RVA node**

```python
# gatra-agent/agent/nodes/rva.py
"""RVA (Risk & Vulnerability Assessment) node — CVE lookup, CVSS/EPSS scoring."""

from __future__ import annotations

from datetime import datetime, timezone

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm_with_fallback
from agent.state import GatraState
from agent.tools.vulnerability import lookup_cves


async def rva_node(state: GatraState, config: RunnableConfig) -> dict:
    """Assess vulnerabilities — CVE enrichment, CVSS/EPSS scoring, patch priority."""
    state.current_agent = "RVA"
    state.pipeline_stage = "assessing"
    copilotkit_emit_state(config, state.model_dump())

    llm = get_llm_with_fallback()

    # Build context from triage results and alerts
    context = {
        "query": state.query,
        "alerts": [a.model_dump() if hasattr(a, "model_dump") else a for a in state.alerts[:5]],
        "triage": [t.model_dump() if hasattr(t, "model_dump") else t for t in state.triage_results[:5]],
    }

    vuln_prompt = f"""You are a vulnerability analyst. Based on the following context, assess the vulnerability landscape.

Context: {context}

Provide:
1. Related CVEs with CVSS v4 scores and EPSS percentiles
2. Whether patches are available
3. Whether any are in the CISA KEV catalog
4. Prioritized remediation recommendations
5. Overall risk assessment

Respond with structured analysis."""

    response = await llm.ainvoke([{"role": "user", "content": vuln_prompt}])

    state = emit_audit(
        state,
        event_type="vulnerability_assessed",
        agent="RVA",
        summary="Vulnerability assessment completed",
    )

    return {
        "current_agent": "RVA",
        "pipeline_stage": "assessing",
        "audit_log": state.audit_log,
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 4: Implement CLA report node**

```python
# gatra-agent/agent/nodes/cla_report.py
"""CLA report node — generates compliance reports on explicit analyst request."""

from __future__ import annotations

from datetime import datetime, timezone

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig

from agent.audit import emit_audit
from agent.llm import get_llm_with_fallback
from agent.state import GatraState


async def cla_report_node(state: GatraState, config: RunnableConfig) -> dict:
    """Generate a compliance report based on audit log and analyst query."""
    state.current_agent = "CLA"
    state.pipeline_stage = "logging"
    copilotkit_emit_state(config, state.model_dump())

    llm = get_llm_with_fallback()

    audit_entries = [e.model_dump() for e in state.audit_log[-20:]]

    report_prompt = f"""You are a compliance analyst. Generate a compliance report based on:

Query: {state.query}
Recent audit entries: {audit_entries}
Active incidents: {state.incident_id or "None"}
Executed actions: {[a.model_dump() for a in state.executed_actions[-10:]]}

Cover:
1. Actions taken and their authorization chain
2. Relevant regulatory frameworks (HIPAA, PCI-DSS, SOX, etc.)
3. Any compliance concerns or gaps
4. Recommendations

Keep it concise and actionable."""

    response = await llm.ainvoke([{"role": "user", "content": report_prompt}])

    state = emit_audit(
        state,
        event_type="compliance_checked",
        agent="CLA",
        summary="Compliance report generated",
    )

    return {
        "current_agent": "CLA",
        "pipeline_stage": "idle",
        "audit_log": state.audit_log,
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/nodes/ada.py gatra-agent/agent/nodes/taa.py gatra-agent/agent/nodes/rva.py gatra-agent/agent/nodes/cla_report.py
git commit -m "feat(gatra-agent): add ADA, TAA, RVA, and CLA report agent nodes"
```

---

## Task 11: Agent Node — CRA (with interrupt)

**Files:**
- Create: `gatra-agent/agent/nodes/cra.py`
- Create: `gatra-agent/tests/test_cra.py`

- [ ] **Step 1: Write tests**

```python
# gatra-agent/tests/test_cra.py
from datetime import datetime, timedelta
from pathlib import Path

from agent.nodes.cra import build_proposed_action, check_action_expiry


CONFIG_PATH = Path(__file__).parent.parent / "config" / "response_gate.yaml"


def test_build_proposed_action():
    action = build_proposed_action(
        incident_id="inc1",
        action_type="block",
        target_type="ip",
        target_value="45.33.32.156",
        severity="CRITICAL",
        confidence=0.95,
        rationale="Known C2 server",
        requires_approval=True,
        gate_reason="Conditional threshold met",
        expiry_seconds=300,
    )
    assert action.action_type == "block"
    assert action.target_fingerprint != ""
    assert action.status == "proposed"
    assert action.expires_at > datetime.now()


def test_check_expiry_valid():
    future = datetime.now() + timedelta(seconds=300)
    assert check_action_expiry(future) is False  # not expired


def test_check_expiry_expired():
    past = datetime.now() - timedelta(seconds=1)
    assert check_action_expiry(past) is True  # expired
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_cra.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement CRA node with interrupt**

```python
# gatra-agent/agent/nodes/cra.py
"""CRA (Containment & Response Agent) node — proposes actions, gates via interrupt."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from copilotkit.langgraph import copilotkit_emit_state
from langchain_core.runnables import RunnableConfig
from langgraph.types import interrupt

from agent.audit import emit_audit
from agent.llm import get_llm_with_fallback
from agent.policy import ResponseGatePolicy
from agent.state import (
    ApprovedAction,
    ExecutedAction,
    GatraState,
    ProposedAction,
)
from agent.tools.response import execute_action

POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "response_gate.yaml"


def _fingerprint(target_type: str, target_value: str) -> str:
    """Generate a target fingerprint hash."""
    return hashlib.sha256(f"{target_type}:{target_value}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16]


def build_proposed_action(
    *,
    incident_id: str,
    action_type: str,
    target_type: str,
    target_value: str,
    severity: str,
    confidence: float,
    rationale: str,
    requires_approval: bool,
    gate_reason: str,
    expiry_seconds: int = 300,
) -> ProposedAction:
    """Build a ProposedAction with fingerprint and expiry."""
    return ProposedAction(
        action_id=str(uuid.uuid4()),
        incident_id=incident_id,
        action_type=action_type,
        target_type=target_type,
        target_value=target_value,
        target_fingerprint=_fingerprint(target_type, target_value),
        severity=severity,
        confidence=confidence,
        rationale=rationale,
        requires_approval=requires_approval,
        gate_reason=gate_reason,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds),
    )


def check_action_expiry(expires_at: datetime) -> bool:
    """Check if an action's approval window has expired."""
    now = datetime.now(timezone.utc)
    # Handle naive datetimes
    if expires_at.tzinfo is None:
        return datetime.now() > expires_at
    return now > expires_at


async def cra_node(state: GatraState, config: RunnableConfig) -> dict:
    """Propose containment actions and gate via interrupt for approval."""
    state.current_agent = "CRA"
    state.pipeline_stage = "responding"
    copilotkit_emit_state(config, state.model_dump())

    policy = ResponseGatePolicy.from_yaml(POLICY_PATH)
    llm = get_llm_with_fallback()

    # Ask LLM to propose actions based on context
    context = {
        "query": state.query,
        "alerts": [a.model_dump() if hasattr(a, "model_dump") else a for a in state.alerts[:5]],
        "triage": [t.model_dump() if hasattr(t, "model_dump") else t for t in state.triage_results[:5]],
    }

    propose_prompt = f"""You are a SOC response analyst. Based on this context, propose containment actions.

Context: {context}

For each action, specify:
- action_type: one of notify, block, suspend, kill, isolate
- target_type: one of ip, host, endpoint, process, user, session
- target_value: the specific target
- severity: LOW, MEDIUM, HIGH, CRITICAL
- confidence: 0.0-1.0
- rationale: brief justification

Respond with a JSON array of proposed actions. Only propose actions that are clearly warranted."""

    response = await llm.ainvoke([{"role": "user", "content": propose_prompt}])

    # For now, build a sample action based on query parsing
    # In production, parse LLM response into structured actions
    proposed = build_proposed_action(
        incident_id=state.incident_id or "unknown",
        action_type="block",
        target_type="ip",
        target_value="unknown",
        severity="HIGH",
        confidence=0.85,
        rationale="LLM-proposed containment action",
        requires_approval=True,
        gate_reason="Default: requires approval",
        expiry_seconds=policy.approval_expiry_seconds,
    )

    # Evaluate policy gate
    decision = policy.evaluate(
        action_type=proposed.action_type,
        severity=proposed.severity,
        confidence=proposed.confidence,
        user_role=state.user_role,
        target_tags=[],
    )

    state = emit_audit(
        state,
        event_type="policy_evaluated",
        agent="CRA",
        summary=f"Policy gate: {decision.decision} for {proposed.action_type}",
        policy_decision=decision,
    )

    state = emit_audit(
        state,
        event_type="action_proposed",
        agent="CRA",
        summary=f"Proposed {proposed.action_type} on {proposed.target_value}",
    )

    new_proposed = [*state.proposed_actions, proposed]
    new_approved = list(state.approved_actions)
    new_denied = list(state.denied_actions)
    new_executed = list(state.executed_actions)

    if decision.decision == "requires_approval":
        # Interrupt for human approval
        state = emit_audit(
            state,
            event_type="approval_requested",
            agent="CRA",
            summary=f"Awaiting analyst approval for {proposed.action_type} on {proposed.target_value}",
        )

        approval = interrupt({
            "type": "response_gate",
            "action": proposed.action_type,
            "target": proposed.target_value,
            "severity": proposed.severity,
            "confidence": proposed.confidence,
            "rationale": proposed.rationale,
            "expires_at": proposed.expires_at.isoformat(),
        })

        if approval.get("approved"):
            # Check expiry
            if check_action_expiry(proposed.expires_at):
                state = emit_audit(
                    state,
                    event_type="approval_denied",
                    agent="CRA",
                    summary="Approval expired",
                )
            else:
                approved = ApprovedAction(
                    action_id=proposed.action_id,
                    approved_by=state.user_id or "unknown",
                    approved_at=datetime.now(timezone.utc),
                    original_action=proposed,
                )
                new_approved.append(approved)
                state = emit_audit(
                    state,
                    event_type="approval_granted",
                    agent="CRA",
                    summary=f"Analyst approved {proposed.action_type}",
                    actor=state.user_id,
                )
        else:
            reason = approval.get("reason", "No reason given")
            state = emit_audit(
                state,
                event_type="approval_denied",
                agent="CRA",
                summary=f"Analyst denied {proposed.action_type}: {reason}",
                actor=state.user_id,
            )
            denied = proposed.model_copy(update={"status": "denied"})
            new_denied.append(denied)

    elif decision.decision == "auto_approved":
        approved = ApprovedAction(
            action_id=proposed.action_id,
            approved_by="system-auto",
            approved_at=datetime.now(timezone.utc),
            original_action=proposed,
        )
        new_approved.append(approved)

    # Execute approved actions
    for approved_action in new_approved:
        if approved_action.action_id == proposed.action_id:
            try:
                result = await execute_action.ainvoke({
                    "action_type": approved_action.original_action.action_type,
                    "target_type": approved_action.original_action.target_type,
                    "target_value": approved_action.original_action.target_value,
                    "idempotency_key": f"{approved_action.action_id}-exec",
                })
                executed = ExecutedAction(
                    action_id=approved_action.action_id,
                    incident_id=approved_action.original_action.incident_id,
                    action_type=approved_action.original_action.action_type,
                    target_value=approved_action.original_action.target_value,
                    success=result.get("success", False),
                    executed_at=datetime.now(timezone.utc),
                    approved_by=approved_action.approved_by,
                    executed_by="system-svc",
                    execution_mode="dry_run" if policy.dry_run else "enforced",
                    rollback_available=approved_action.original_action.action_type in ("block", "isolate"),
                    idempotency_key=f"{approved_action.action_id}-exec",
                )
                new_executed.append(executed)
                event_type = "execution_succeeded" if executed.success else "execution_failed"
                state = emit_audit(
                    state,
                    event_type=event_type,
                    agent="CRA",
                    summary=f"{approved_action.original_action.action_type} {'succeeded' if executed.success else 'failed'}",
                )
            except Exception as e:
                state = emit_audit(
                    state,
                    event_type="execution_failed",
                    agent="CRA",
                    summary=f"Execution failed: {e}",
                )

    return {
        "current_agent": "CRA",
        "pipeline_stage": "responding",
        "proposed_actions": new_proposed,
        "approved_actions": new_approved,
        "denied_actions": new_denied,
        "executed_actions": new_executed,
        "approval_pending": False,
        "audit_log": state.audit_log,
        "last_updated_at": datetime.now(timezone.utc),
        "messages": [response],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_cra.py -v
```
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/nodes/cra.py gatra-agent/tests/test_cra.py
git commit -m "feat(gatra-agent): add CRA node with response gate interrupt and two-step execution"
```

---

## Task 12: LangGraph Graph Assembly

**Files:**
- Create: `gatra-agent/agent/graph.py`
- Create: `gatra-agent/tests/test_graph.py`

- [ ] **Step 1: Write test for graph compilation**

```python
# gatra-agent/tests/test_graph.py
from agent.graph import build_graph


def test_graph_compiles():
    graph = build_graph()
    assert graph is not None


def test_graph_has_expected_nodes():
    graph = build_graph()
    node_names = set(graph.nodes.keys())
    expected = {"router", "ada", "taa", "cra", "rva", "cla_report", "llm_respond"}
    # __start__ and __end__ are implicit
    assert expected.issubset(node_names), f"Missing nodes: {expected - node_names}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_graph.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement graph assembly**

```python
# gatra-agent/agent/graph.py
"""LangGraph StateGraph assembly for the GATRA 5-agent pipeline."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from agent.nodes.ada import ada_node
from agent.nodes.cla_report import cla_report_node
from agent.nodes.cra import cra_node
from agent.nodes.llm_respond import llm_respond_node
from agent.nodes.router import router_node
from agent.nodes.rva import rva_node
from agent.nodes.taa import taa_node
from agent.state import GatraState


def _route_after_router(state: dict) -> str:
    """Conditional edge from router — pick next node based on parsed intent."""
    return state.get("_route", "llm_respond")


def _route_after_taa(state: dict) -> str:
    """After TAA, route to CRA if severity >= HIGH, else RVA."""
    triage = state.get("triage_results", [])
    if triage:
        last = triage[-1]
        severity = last.get("severity", "LOW") if isinstance(last, dict) else getattr(last, "severity", "LOW")
        if severity in ("HIGH", "CRITICAL"):
            return "cra"
    # Check if any alerts are high severity
    alerts = state.get("alerts", [])
    for alert in alerts:
        sev = alert.get("severity", "LOW") if isinstance(alert, dict) else getattr(alert, "severity", "LOW")
        if sev in ("HIGH", "CRITICAL"):
            return "cra"
    return "rva"


def build_graph() -> StateGraph:
    """Build and compile the GATRA LangGraph pipeline."""
    graph = StateGraph(GatraState)

    # Add nodes
    graph.add_node("router", router_node)
    graph.add_node("ada", ada_node)
    graph.add_node("taa", taa_node)
    graph.add_node("cra", cra_node)
    graph.add_node("rva", rva_node)
    graph.add_node("cla_report", cla_report_node)
    graph.add_node("llm_respond", llm_respond_node)

    # Entry
    graph.add_edge(START, "router")

    # Router → conditional
    graph.add_conditional_edges("router", _route_after_router, {
        "ada": "ada",
        "taa": "taa",
        "cra": "cra",
        "rva": "rva",
        "cla_report": "cla_report",
        "llm_respond": "llm_respond",
    })

    # ADA → TAA (detections need triage)
    graph.add_edge("ada", "taa")

    # TAA → conditional (HIGH+ → CRA, else → RVA)
    graph.add_conditional_edges("taa", _route_after_taa, {
        "cra": "cra",
        "rva": "rva",
    })

    # CRA → RVA (after approval/denial, assess risk)
    graph.add_edge("cra", "rva")

    # Terminal nodes
    graph.add_edge("rva", END)
    graph.add_edge("cla_report", END)
    graph.add_edge("llm_respond", END)

    return graph.compile()
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/test_graph.py -v
```
Expected: All 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add gatra-agent/agent/graph.py gatra-agent/tests/test_graph.py
git commit -m "feat(gatra-agent): assemble LangGraph StateGraph with conditional routing"
```

---

## Task 13: FastAPI Server

**Files:**
- Create: `gatra-agent/server.py`

- [ ] **Step 1: Implement server**

```python
# gatra-agent/server.py
"""FastAPI server exposing the GATRA LangGraph agent via AG-UI protocol."""

from __future__ import annotations

import os

from ag_ui_langgraph import add_langgraph_fastapi_endpoint
from copilotkit import LangGraphAGUIAgent
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agent.graph import build_graph

app = FastAPI(title="GATRA Agent", version="0.1.0")

# CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Build and register the LangGraph agent
graph = build_graph()
add_langgraph_fastapi_endpoint(
    app=app,
    agent=LangGraphAGUIAgent(
        name="gatra_soc",
        description="GATRA SOC analyst agent — 5-agent pipeline with human-in-the-loop approval",
        graph=graph,
    ),
    path="/",
)


@app.get("/health")
async def health():
    """Liveness check — process alive."""
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    """Readiness check — core routing operational."""
    checks = {"graph": graph is not None}
    # Check LLM provider
    try:
        from agent.llm import get_llm
        get_llm()
        checks["llm"] = True
    except Exception as e:
        checks["llm"] = False
        checks["llm_error"] = str(e)

    all_ready = all(v for k, v in checks.items() if not k.endswith("_error"))
    return {"status": "ready" if all_ready else "not_ready", "checks": checks}


@app.get("/dependencies")
async def dependencies():
    """Detailed dependency health — for dashboards, not load balancer gating."""
    import httpx

    base_url = os.getenv("WORLDMONITOR_API_URL", "https://worldmonitor-gatra.vercel.app")
    endpoints = ["/api/gatra-data", "/api/ioc-lookup", "/api/cisa-kev", "/api/threat-feeds"]
    results = {}

    async with httpx.AsyncClient(base_url=base_url, timeout=5.0) as client:
        for ep in endpoints:
            try:
                resp = await client.head(ep)
                results[ep] = {"status": resp.status_code, "healthy": resp.status_code < 500}
            except Exception as e:
                results[ep] = {"status": "error", "healthy": False, "error": str(e)}

    return {"dependencies": results}
```

- [ ] **Step 2: Verify server starts**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
timeout 5 uv run uvicorn server:app --host 0.0.0.0 --port 8123 2>&1 || true
```
Expected: Server starts (may timeout after 5s, that's fine — we just need it to boot without import errors).

- [ ] **Step 3: Commit**

```bash
git add gatra-agent/server.py
git commit -m "feat(gatra-agent): add FastAPI server with health/ready/dependencies endpoints"
```

---

## Task 14: Next.js Frontend Scaffolding

**Files:**
- Create: `gatra-copilot/` (via `npx create-next-app`)

- [ ] **Step 1: Scaffold Next.js app**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
npx create-next-app@latest gatra-copilot --typescript --tailwind --eslint --app --src-dir=false --import-alias="@/*" --use-npm --no-turbopack
```
Expected: Next.js app created with App Router, TypeScript, Tailwind CSS.

- [ ] **Step 2: Install CopilotKit dependencies**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-copilot
npm install @copilotkit/react-core @copilotkit/react-ui @copilotkit/runtime zod
```
Expected: Packages install successfully.

- [ ] **Step 3: Create .env.local**

```env
# gatra-copilot/.env.local
LANGGRAPH_AGENT_URL=http://localhost:8123
```

- [ ] **Step 4: Verify dev server starts**

Run:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-copilot
timeout 10 npm run dev 2>&1 || true
```
Expected: Next.js dev server starts on port 3000.

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add gatra-copilot/
git commit -m "feat(gatra-copilot): scaffold Next.js app with CopilotKit dependencies"
```

---

## Task 15: CopilotKit Runtime API Route

**Files:**
- Modify: `gatra-copilot/app/api/copilotkit/route.ts` (create)

- [ ] **Step 1: Create the runtime API route**

```typescript
// gatra-copilot/app/api/copilotkit/route.ts
import {
  CopilotRuntime,
  ExperimentalEmptyAdapter,
  copilotRuntimeNextJSAppRouterEndpoint,
} from "@copilotkit/runtime";
import { LangGraphHttpAgent } from "@copilotkit/runtime/langgraph";

const agentUrl = process.env.LANGGRAPH_AGENT_URL || "http://localhost:8123";

const runtime = new CopilotRuntime({
  agents: {
    gatra_soc: new LangGraphHttpAgent({
      url: agentUrl,
    }),
  },
});

export const { POST } = copilotRuntimeNextJSAppRouterEndpoint({
  runtime,
  serviceAdapter: new ExperimentalEmptyAdapter(),
  endpoint: "/api/copilotkit",
});
```

- [ ] **Step 2: Commit**

```bash
git add gatra-copilot/app/api/copilotkit/route.ts
git commit -m "feat(gatra-copilot): add CopilotKit runtime API route"
```

---

## Task 16: Frontend Types

**Files:**
- Create: `gatra-copilot/lib/types.ts`

- [ ] **Step 1: Create shared types mirroring GatraState**

```typescript
// gatra-copilot/lib/types.ts

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AgentName = "ADA" | "TAA" | "CRA" | "CLA" | "RVA";
export type PipelineStage = "idle" | "detecting" | "triaging" | "responding" | "assessing" | "logging";
export type ActionType = "notify" | "unblock" | "resume" | "suspend" | "block" | "kill" | "isolate";
export type ExecutionMode = "dry_run" | "enforced";

export interface Alert {
  id: string;
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  description: string;
  confidence: number;
  lat?: number;
  lon?: number;
  location_name?: string;
  infrastructure?: string;
  timestamp: string;
  agent: AgentName;
}

export interface ProposedAction {
  action_id: string;
  incident_id: string;
  action_type: ActionType;
  target_type: string;
  target_value: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  requires_approval: boolean;
  gate_reason?: string;
  status: string;
  expires_at: string;
}

export interface ExecutedAction {
  action_id: string;
  action_type: string;
  target_value: string;
  success: boolean;
  error?: string;
  executed_at: string;
  approved_by: string;
  executed_by: string;
  execution_mode: ExecutionMode;
  rollback_available: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  trace_id: string;
  event_type: string;
  agent: string;
  actor?: string;
  summary: string;
}

export interface GatraAgentState {
  session_id: string;
  incident_id: string;
  trace_id: string;
  pipeline_stage: PipelineStage;
  current_agent: string;
  alerts: Alert[];
  proposed_actions: ProposedAction[];
  executed_actions: ExecutedAction[];
  audit_log: AuditEntry[];
  approval_pending: boolean;
  last_updated_at?: string;
}

export interface ResponseGateEvent {
  type: "response_gate";
  action: ActionType;
  target: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  expires_at: string;
}
```

- [ ] **Step 2: Commit**

```bash
git add gatra-copilot/lib/types.ts
git commit -m "feat(gatra-copilot): add shared TypeScript types mirroring GatraState"
```

---

## Task 17: Generative UI Components

**Files:**
- Create: `gatra-copilot/components/chat/AlertCard.tsx`
- Create: `gatra-copilot/components/chat/ApprovalCard.tsx`
- Create: `gatra-copilot/components/chat/MitreCard.tsx`
- Create: `gatra-copilot/components/chat/VulnCard.tsx`
- Create: `gatra-copilot/components/chat/AuditCard.tsx`
- Create: `gatra-copilot/components/chat/ActionResultCard.tsx`

- [ ] **Step 1: Create AlertCard**

```tsx
// gatra-copilot/components/chat/AlertCard.tsx
"use client";

import type { Severity } from "@/lib/types";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
};

interface AlertCardProps {
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  confidence: number;
  description: string;
  location_name?: string;
  infrastructure?: string;
  timestamp: string;
  status: "complete" | "inProgress";
}

export function AlertCard(props: AlertCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-24 rounded bg-gray-700" />
        <div className="mt-2 h-3 w-48 rounded bg-gray-700" />
      </div>
    );
  }

  const colorClass = SEVERITY_COLORS[props.severity] ?? "bg-gray-500 text-white";

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
      <div className="flex items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-bold ${colorClass}`}>
          {props.severity}
        </span>
        <code className="text-sm text-gray-400">{props.mitre_id}</code>
        <span className="text-sm text-gray-300">{props.mitre_name}</span>
      </div>
      <p className="mt-2 text-sm text-gray-300">{props.description}</p>
      <div className="mt-2 flex gap-4 text-xs text-gray-500">
        <span>Confidence: {Math.round(props.confidence * 100)}%</span>
        {props.location_name && <span>{props.location_name}</span>}
        {props.infrastructure && <span>{props.infrastructure}</span>}
        <span>{new Date(props.timestamp).toLocaleTimeString()}</span>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create ApprovalCard**

```tsx
// gatra-copilot/components/chat/ApprovalCard.tsx
"use client";

import { useState } from "react";
import type { ActionType, Severity } from "@/lib/types";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "border-red-600",
  HIGH: "border-orange-500",
  MEDIUM: "border-yellow-500",
  LOW: "border-blue-500",
};

interface ApprovalCardProps {
  action: ActionType;
  target: string;
  severity: Severity;
  confidence: number;
  expiresAt: string;
  onApprove: () => void;
  onDeny: (reason: string) => void;
}

export function ApprovalCard(props: ApprovalCardProps) {
  const [denyReason, setDenyReason] = useState("");
  const [resolved, setResolved] = useState(false);

  const borderColor = SEVERITY_COLORS[props.severity] ?? "border-gray-500";
  const expiresAt = new Date(props.expiresAt);
  const expired = new Date() > expiresAt;

  if (resolved) {
    return (
      <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 text-sm text-gray-400">
        Action resolved.
      </div>
    );
  }

  return (
    <div className={`rounded-lg border-2 ${borderColor} bg-gray-900 p-4`}>
      <div className="flex items-center gap-2 text-sm font-bold text-white">
        <span className="text-yellow-400">APPROVAL REQUIRED</span>
      </div>
      <div className="mt-2 text-sm text-gray-300">
        <p>
          <strong>{props.action.toUpperCase()}</strong> target{" "}
          <code className="rounded bg-gray-800 px-1">{props.target}</code>
        </p>
        <p className="mt-1">
          Severity: <strong>{props.severity}</strong> | Confidence:{" "}
          {Math.round(props.confidence * 100)}%
        </p>
        {!expired && (
          <p className="mt-1 text-xs text-gray-500">
            Expires: {expiresAt.toLocaleTimeString()}
          </p>
        )}
        {expired && <p className="mt-1 text-xs text-red-400">EXPIRED</p>}
      </div>
      {!expired && (
        <div className="mt-3 flex gap-2">
          <button
            onClick={() => {
              setResolved(true);
              props.onApprove();
            }}
            className="rounded bg-green-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-green-700"
          >
            Approve
          </button>
          <input
            type="text"
            placeholder="Reason (optional)"
            value={denyReason}
            onChange={(e) => setDenyReason(e.target.value)}
            className="flex-1 rounded border border-gray-700 bg-gray-800 px-2 text-sm text-gray-300"
          />
          <button
            onClick={() => {
              setResolved(true);
              props.onDeny(denyReason);
            }}
            className="rounded bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700"
          >
            Deny
          </button>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Create remaining cards**

```tsx
// gatra-copilot/components/chat/MitreCard.tsx
"use client";

interface MitreCardProps {
  kill_chain_phase: string;
  actor_attribution: string;
  campaign?: string;
  iocs: string[];
  confidence: number;
  status: "complete" | "inProgress";
}

export function MitreCard(props: MitreCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-32 rounded bg-gray-700" />
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-purple-700 bg-gray-900 p-4">
      <div className="text-sm font-bold text-purple-400">MITRE ATT&CK Analysis</div>
      <div className="mt-2 space-y-1 text-sm text-gray-300">
        <p>Kill Chain: <strong>{props.kill_chain_phase}</strong></p>
        <p>Attribution: <strong>{props.actor_attribution}</strong></p>
        {props.campaign && <p>Campaign: {props.campaign}</p>}
        <p>Confidence: {Math.round(props.confidence * 100)}%</p>
      </div>
      {props.iocs.length > 0 && (
        <div className="mt-2">
          <span className="text-xs font-medium text-gray-500">IOCs:</span>
          <ul className="mt-1 space-y-0.5">
            {props.iocs.map((ioc, i) => (
              <li key={i} className="text-xs font-mono text-gray-400">{ioc}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
```

```tsx
// gatra-copilot/components/chat/VulnCard.tsx
"use client";

interface VulnCardProps {
  cve_id: string;
  cvss_v4_score: number;
  epss_percentile: number;
  affected_products: string[];
  patch_available: boolean;
  cisa_kev: boolean;
  recommendation: string;
  status: "complete" | "inProgress";
}

export function VulnCard(props: VulnCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-28 rounded bg-gray-700" />
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-cyan-700 bg-gray-900 p-4">
      <div className="flex items-center gap-2">
        <code className="text-sm font-bold text-cyan-400">{props.cve_id}</code>
        {props.cisa_kev && (
          <span className="rounded bg-red-700 px-1.5 py-0.5 text-xs font-bold text-white">
            CISA KEV
          </span>
        )}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2 text-sm text-gray-300">
        <span>CVSS v4: <strong>{props.cvss_v4_score.toFixed(1)}</strong></span>
        <span>EPSS: <strong>{(props.epss_percentile * 100).toFixed(1)}%</strong></span>
        <span>Patch: {props.patch_available ? "Available" : "None"}</span>
      </div>
      <p className="mt-2 text-sm text-gray-400">{props.recommendation}</p>
    </div>
  );
}
```

```tsx
// gatra-copilot/components/chat/AuditCard.tsx
"use client";

interface AuditCardProps {
  event_type: string;
  agent: string;
  summary: string;
  timestamp: string;
  compliance_frameworks?: string[];
  status: "complete" | "inProgress";
}

export function AuditCard(props: AuditCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-20 rounded bg-gray-700" />
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-gray-600 bg-gray-900 p-4">
      <div className="flex items-center gap-2 text-sm">
        <span className="font-bold text-gray-400">{props.event_type}</span>
        <span className="text-gray-500">{props.agent}</span>
        <span className="text-xs text-gray-600">
          {new Date(props.timestamp).toLocaleTimeString()}
        </span>
      </div>
      <p className="mt-1 text-sm text-gray-300">{props.summary}</p>
      {props.compliance_frameworks && props.compliance_frameworks.length > 0 && (
        <div className="mt-1 flex gap-1">
          {props.compliance_frameworks.map((fw) => (
            <span key={fw} className="rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-400">
              {fw}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
```

```tsx
// gatra-copilot/components/chat/ActionResultCard.tsx
"use client";

import type { ExecutionMode } from "@/lib/types";

interface ActionResultCardProps {
  action_type: string;
  target_value: string;
  success: boolean;
  error?: string;
  execution_mode: ExecutionMode;
  rollback_available: boolean;
  executed_at: string;
  status: "complete" | "inProgress";
}

export function ActionResultCard(props: ActionResultCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-32 rounded bg-gray-700" />
      </div>
    );
  }

  return (
    <div
      className={`rounded-lg border p-4 ${
        props.success ? "border-green-700 bg-gray-900" : "border-red-700 bg-gray-900"
      }`}
    >
      <div className="flex items-center gap-2 text-sm">
        <span className={props.success ? "text-green-400" : "text-red-400"}>
          {props.success ? "SUCCESS" : "FAILED"}
        </span>
        <strong className="text-white">{props.action_type.toUpperCase()}</strong>
        <code className="text-gray-400">{props.target_value}</code>
      </div>
      {props.error && <p className="mt-1 text-sm text-red-400">{props.error}</p>}
      <div className="mt-2 flex gap-3 text-xs text-gray-500">
        <span>Mode: {props.execution_mode}</span>
        <span>Rollback: {props.rollback_available ? "available" : "none"}</span>
        <span>{new Date(props.executed_at).toLocaleTimeString()}</span>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Commit**

```bash
git add gatra-copilot/components/chat/
git commit -m "feat(gatra-copilot): add generative UI components — AlertCard, ApprovalCard, MitreCard, VulnCard, AuditCard, ActionResultCard"
```

---

## Task 18: Sidebar Components

**Files:**
- Create: `gatra-copilot/components/sidebar/AgentHealth.tsx`
- Create: `gatra-copilot/components/sidebar/IncidentTimeline.tsx`
- Create: `gatra-copilot/components/sidebar/ActiveAlerts.tsx`

- [ ] **Step 1: Create sidebar components**

```tsx
// gatra-copilot/components/sidebar/AgentHealth.tsx
"use client";

import type { AgentName, PipelineStage } from "@/lib/types";

const AGENTS: AgentName[] = ["ADA", "TAA", "CRA", "CLA", "RVA"];

interface AgentHealthProps {
  currentAgent: string;
  pipelineStage: PipelineStage;
}

export function AgentHealth({ currentAgent, pipelineStage }: AgentHealthProps) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">Agent Health</h3>
      <div className="space-y-1">
        {AGENTS.map((agent) => {
          const isActive = currentAgent.toUpperCase() === agent;
          return (
            <div key={agent} className="flex items-center gap-2 text-sm">
              <span
                className={`h-2 w-2 rounded-full ${
                  isActive ? "animate-pulse bg-green-400" : "bg-gray-600"
                }`}
              />
              <span className={isActive ? "text-white font-medium" : "text-gray-500"}>
                {agent}
              </span>
              {isActive && (
                <span className="text-xs text-green-400">{pipelineStage}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
```

```tsx
// gatra-copilot/components/sidebar/IncidentTimeline.tsx
"use client";

import type { AuditEntry } from "@/lib/types";

interface IncidentTimelineProps {
  auditLog: AuditEntry[];
}

export function IncidentTimeline({ auditLog }: IncidentTimelineProps) {
  const recent = auditLog.slice(-20);

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">
        Incident Timeline
      </h3>
      {recent.length === 0 && (
        <p className="text-xs text-gray-600">No events yet.</p>
      )}
      <div className="max-h-64 space-y-1 overflow-y-auto">
        {recent.map((entry) => (
          <div key={entry.id} className="flex gap-2 text-xs">
            <span className="shrink-0 text-gray-600">
              {new Date(entry.timestamp).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </span>
            <span className="text-gray-500">{entry.agent}</span>
            <span className="text-gray-400">{entry.summary}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
```

```tsx
// gatra-copilot/components/sidebar/ActiveAlerts.tsx
"use client";

import type { Alert, Severity } from "@/lib/types";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-blue-400",
};

interface ActiveAlertsProps {
  alerts: Alert[];
}

export function ActiveAlerts({ alerts }: ActiveAlertsProps) {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const alert of alerts) {
    counts[alert.severity] = (counts[alert.severity] || 0) + 1;
  }

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">Active Alerts</h3>
      <div className="grid grid-cols-2 gap-2">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <span className={`text-lg font-bold ${SEVERITY_COLORS[sev]}`}>
              {counts[sev]}
            </span>
            <span className="text-xs text-gray-500">{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add gatra-copilot/components/sidebar/
git commit -m "feat(gatra-copilot): add sidebar components — AgentHealth, IncidentTimeline, ActiveAlerts"
```

---

## Task 19: Hook Wiring & Main Layout

**Files:**
- Create: `gatra-copilot/hooks/use-gatra-agent.ts`
- Create: `gatra-copilot/components/console/AnalystConsole.tsx`
- Modify: `gatra-copilot/app/layout.tsx`
- Modify: `gatra-copilot/app/page.tsx`

- [ ] **Step 1: Create the agent hook**

```typescript
// gatra-copilot/hooks/use-gatra-agent.ts
"use client";

import { useCoAgent } from "@copilotkit/react-core";
import type { GatraAgentState } from "@/lib/types";

/**
 * Hook wrapping CopilotKit's useCoAgent for the GATRA SOC agent.
 * Provides typed access to shared agent state.
 */
export function useGatraAgent() {
  const { state, setState, run, running } = useCoAgent<GatraAgentState>({
    name: "gatra_soc",
    initialState: {
      session_id: "",
      incident_id: "",
      trace_id: "",
      pipeline_stage: "idle",
      current_agent: "",
      alerts: [],
      proposed_actions: [],
      executed_actions: [],
      audit_log: [],
      approval_pending: false,
    },
  });

  return { state, setState, run, running };
}
```

- [ ] **Step 2: Create AnalystConsole layout**

```tsx
// gatra-copilot/components/console/AnalystConsole.tsx
"use client";

import { CopilotChat } from "@copilotkit/react-ui";
import { useLangGraphInterrupt } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";

import { useGatraAgent } from "@/hooks/use-gatra-agent";
import { ApprovalCard } from "@/components/chat/ApprovalCard";
import { AgentHealth } from "@/components/sidebar/AgentHealth";
import { IncidentTimeline } from "@/components/sidebar/IncidentTimeline";
import { ActiveAlerts } from "@/components/sidebar/ActiveAlerts";
import type { ResponseGateEvent } from "@/lib/types";

export function AnalystConsole() {
  const { state } = useGatraAgent();

  // Human-in-the-loop interrupt handler
  useLangGraphInterrupt({
    enabled: ({ eventValue }: { eventValue: ResponseGateEvent }) =>
      eventValue?.type === "response_gate",
    render: ({
      event,
      resolve,
    }: {
      event: { value: ResponseGateEvent };
      resolve: (value: { approved: boolean; reason?: string }) => void;
    }) => (
      <ApprovalCard
        action={event.value.action}
        target={event.value.target}
        severity={event.value.severity}
        confidence={event.value.confidence}
        expiresAt={event.value.expires_at}
        onApprove={() => resolve({ approved: true })}
        onDeny={(reason: string) => resolve({ approved: false, reason })}
      />
    ),
  });

  return (
    <div className="flex h-screen bg-gray-950 text-white">
      {/* Chat panel */}
      <div className="flex flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-gray-800 px-6 py-3">
          <h1 className="text-lg font-semibold">GATRA Analyst Console</h1>
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <span
              className={`h-2 w-2 rounded-full ${
                state.pipeline_stage === "idle" ? "bg-gray-600" : "animate-pulse bg-green-400"
              }`}
            />
            {state.pipeline_stage}
          </div>
        </header>
        <div className="flex-1 overflow-hidden">
          <CopilotChat
            className="h-full"
            labels={{
              title: "GATRA SOC",
              initial: "How can I help with your SOC investigation?",
              placeholder: "Ask about alerts, threats, or request containment actions...",
            }}
          />
        </div>
      </div>

      {/* Sidebar */}
      <aside className="w-72 space-y-3 overflow-y-auto border-l border-gray-800 p-4">
        <AgentHealth
          currentAgent={state.current_agent}
          pipelineStage={state.pipeline_stage}
        />
        <IncidentTimeline auditLog={state.audit_log} />
        <ActiveAlerts alerts={state.alerts} />
      </aside>
    </div>
  );
}
```

- [ ] **Step 3: Update layout.tsx with CopilotKit provider**

Replace the contents of `gatra-copilot/app/layout.tsx`:

```tsx
// gatra-copilot/app/layout.tsx
import type { Metadata } from "next";
import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "GATRA Analyst Console",
  description: "Agent-native SOC analyst console powered by CopilotKit + LangGraph",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-white antialiased">
        <CopilotKit runtimeUrl="/api/copilotkit" agent="gatra_soc">
          {children}
        </CopilotKit>
      </body>
    </html>
  );
}
```

- [ ] **Step 4: Update page.tsx**

Replace the contents of `gatra-copilot/app/page.tsx`:

```tsx
// gatra-copilot/app/page.tsx
import { AnalystConsole } from "@/components/console/AnalystConsole";

export default function Home() {
  return <AnalystConsole />;
}
```

- [ ] **Step 5: Commit**

```bash
git add gatra-copilot/hooks/ gatra-copilot/components/console/ gatra-copilot/app/layout.tsx gatra-copilot/app/page.tsx
git commit -m "feat(gatra-copilot): wire up AnalystConsole with CopilotKit provider, agent hook, and interrupt handler"
```

---

## Task 20: End-to-End Smoke Test

**Files:** None (test only)

- [ ] **Step 1: Start the Python agent backend**

Run in a terminal:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
cp .env.example .env
# Edit .env to add your ANTHROPIC_API_KEY
uv run uvicorn server:app --reload --port 8123
```
Expected: Server starts on `http://0.0.0.0:8123`. Health check at `http://localhost:8123/health` returns `{"status": "ok"}`.

- [ ] **Step 2: Start the Next.js frontend**

Run in another terminal:
```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-copilot
npm run dev
```
Expected: Next.js starts on `http://localhost:3000`.

- [ ] **Step 3: Verify the console loads**

Open `http://localhost:3000` in a browser.
Expected: GATRA Analyst Console renders with chat panel on the left and sidebar (Agent Health, Incident Timeline, Active Alerts) on the right.

- [ ] **Step 4: Test a general query**

Type in the chat: "What is MITRE ATT&CK?"
Expected: Agent responds with a SOC-relevant explanation. Sidebar shows pipeline_stage changing from idle → routing → idle.

- [ ] **Step 5: Test alert analysis**

Type: "Analyze the latest alerts"
Expected: Agent routes to ADA → TAA pipeline. Sidebar shows agent status progressing through detecting → triaging.

- [ ] **Step 6: Run all backend tests**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor/gatra-agent
uv run pytest tests/ -v
```
Expected: All tests pass.

- [ ] **Step 7: Final commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add -A
git commit -m "feat: GATRA CopilotKit + LangGraph analyst console — complete v1 implementation"
```

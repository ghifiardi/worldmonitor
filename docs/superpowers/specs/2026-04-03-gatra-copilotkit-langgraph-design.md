# GATRA CopilotKit + LangGraph Analyst Console

**Date:** 2026-04-03
**Status:** Approved (rev 3 — final polish per review)
**Author:** Ghifi + Claude

## Overview

A standalone GATRA Analyst Console built with CopilotKit and LangGraph, providing an agent-native analyst console for SOC workflows with shared state, gated response actions, and generative UI where agents render custom alert cards and dashboards directly in the chat.

Two new top-level directories in the `worldmonitor` repo:
- `gatra-copilot/` — Next.js + CopilotKit React frontend
- `gatra-agent/` — Python FastAPI + LangGraph backend

The existing worldmonitor codebase remains untouched. The Python backend calls existing Vercel API endpoints as tools, using `GATRA_API_KEY` bearer auth, 30s default timeout, and exponential backoff (3 retries, 1s/2s/4s). Tool errors are normalized to a standard `ToolError(code, message, retryable)` shape before surfacing to the graph.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 ANALYST WORKSTATION / BROWSER            │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │         gatra-copilot (Next.js App)              │    │
│  │                                                   │    │
│  │  <CopilotKit runtimeUrl="/api/copilotkit">       │    │
│  │    ┌──────────┐  ┌───────────────────────┐       │    │
│  │    │ Chat     │  │ Sidebar               │       │    │
│  │    │ Panel    │  │ - Agent Health         │       │    │
│  │    │          │  │ - Incident Timeline    │       │    │
│  │    │ useAgent │  │ - Active Alerts Feed   │       │    │
│  │    │ useInter │  │                        │       │    │
│  │    │ useRende │  │ useAgent (shared state)│       │    │
│  │    └──────────┘  └───────────────────────┘       │    │
│  └───────────────────────┬───────────────────────────┘    │
│                          │ SSE (AG-UI Protocol)          │
│                          │ browser ↔ Next.js route only;  │
│                          │ Next.js proxies to agent via   │
│                          │ HTTP (not SSE end-to-end)      │
└──────────────────────────┼───────────────────────────────┘
                           │
              ┌────────────▼────────────────┐
              │  Next.js API Route           │
              │  /api/copilotkit             │
              │  CopilotRuntime              │
              │  └─ LangGraphHttpAgent       │
              │      url: AGENT_BACKEND_URL  │
              │  Auth: SSO session validated  │
              │  Signed service token to agent│
              └────────────┬────────────────┘
                           │ HTTP (signed)
              ┌────────────▼────────────────┐
              │  gatra-agent (FastAPI)       │
              │                              │
              │  LangGraph StateGraph:       │
              │  START → router → agents     │
              │  ADA → TAA → CRA → RVA      │
              │  CLA: parallel audit sink    │
              │  CRA uses interrupt() for    │
              │  Response Gate approvals      │
              │                              │
              │  Tools call ──────────────┐  │
              └───────────────────────────┼──┘
                                          │ HTTP
              ┌───────────────────────────▼──┐
              │  Existing Vercel Endpoints    │
              │  /api/gatra-data              │
              │  /api/gatra-cra               │
              │  /api/ioc-lookup              │
              │  /api/threat-feeds            │
              │  /api/soc-intent              │
              │  /api/response-actions        │
              │  /api/cisa-kev                │
              └──────────────────────────────┘
```

## Authentication & RBAC

Full SSO/RBAC enforcement is not required for local development, but identity propagation, signed service auth, and audit attribution are **mandatory for pilot deployment**. Full enforcement becomes mandatory for hardened production rollout. The design supports these controls from day one even if enforcement is initially permissive.

### Role Model

| Role | Permissions |
|------|------------|
| `viewer` | Read alerts, view dashboards, read audit log |
| `analyst` | All viewer + triage alerts, run investigations, `notify` actions |
| `responder` | All analyst + `block`, `suspend` actions |
| `approver` | All responder + approve `kill`, `isolate` actions |
| `admin` | All approver + manage policy, manage users |

### Action Authorization

| Action | Minimum Role |
|--------|-------------|
| `notify` | analyst |
| `block`, `suspend` | responder or approver |
| `kill`, `isolate` | approver only |

### Implementation Path

- **Local dev:** No auth required. All requests treated as `admin` role.
- **Phase 0 (pilot):** SSO or trusted reverse-proxy auth in front of `gatra-copilot`. Signed HMAC service-to-service token between Next.js runtime and `gatra-agent`. Role passed as claim in service token. Identity propagation and audit attribution are mandatory. Destructive action authorization uses simplified enforcement logic (role checked but not centrally managed).
- **Phase 1 (hardened production):** Full centralized RBAC enforcement at `gatra-agent` level. Role-based action gating with policy service. Session management with expiry. SSO provider integration.

### Audit Identity Fields

Every action in the pipeline carries:

```python
class AuditIdentity(BaseModel):
    user_id: str
    role: Literal["viewer", "analyst", "responder", "approver", "admin"]
    session_id: str
    timestamp: datetime
    ticket_ref: str | None = None       # case/incident reference
```

## LangGraph Agent Graph

### Typed State Models

All critical objects use typed Pydantic models — no generic `dict` in safety-sensitive paths.

```python
from pydantic import BaseModel, Field
from typing import Any, Literal
from datetime import datetime

class Alert(BaseModel):
    id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mitre_id: str
    mitre_name: str
    description: str
    confidence: float                    # 0.0–1.0
    lat: float | None = None             # optional — not all alerts are geolocated
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
        "reconnaissance", "weaponization", "delivery",
        "exploitation", "installation", "c2", "actions"
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
    target_fingerprint: str              # hash of target state at proposal time
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    rationale: str
    requires_approval: bool
    gate_reason: str | None = None
    requested_by_agent: str = "CRA"
    status: Literal["proposed", "approved", "denied", "executed", "failed"] = "proposed"
    expires_at: datetime                 # approval expiry

class ApprovedAction(BaseModel):
    action_id: str
    approved_by: str                     # user_id
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
    approved_by: str                     # user_id who approved
    executed_by: str                     # user_id or service principal who ran it
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
    cisa_kev: bool                       # in CISA Known Exploited Vulnerabilities
    recommendation: str

class PolicyDecision(BaseModel):
    """Logged when the response gate evaluates an action."""
    action_type: str
    policy_mode: str                     # auto|conditional|approval_required
    matched_rule: str                    # which config rule matched
    override_applied: str | None = None  # e.g. "crown_jewel_assets"
    min_role_required: str
    decision: Literal["auto_approved", "requires_approval", "denied_by_policy"]
    reason: str                          # human-readable explanation

class StateError(BaseModel):
    code: str
    message: str
    retryable: bool = False
    source: str                          # node or tool name
    timestamp: datetime
    details: dict[str, Any] | None = None

class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    trace_id: str
    incident_id: str | None = None
    event_type: Literal[
        "routing_start", "alert_fetched", "triage_completed",
        "action_proposed", "approval_requested", "approval_granted",
        "approval_denied", "execution_succeeded", "execution_failed",
        "vulnerability_assessed", "compliance_checked",
        "policy_evaluated"
    ]
    agent: str
    actor: str | None = None             # user_id if human-initiated
    summary: str
    details: dict[str, Any] | None = None
    compliance_frameworks: list[str] = Field(default_factory=list)
    # policy_evaluated fields (populated when event_type == "policy_evaluated")
    policy_decision: PolicyDecision | None = None
```

### State Schema

```python
from copilotkit import CopilotKitState

class GatraState(CopilotKitState):
    # Session & tracing
    session_id: str = ""
    incident_id: str = ""
    trace_id: str = ""
    user_id: str = ""
    user_role: str = "analyst"

    # Input
    query: str = ""

    # ADA outputs (owner: ADA node)
    alerts: list[Alert] = Field(default_factory=list)
    anomaly_scores: dict[str, float] = Field(default_factory=dict)

    # TAA outputs (owner: TAA node)
    triage_results: list[TriageResult] = Field(default_factory=list)
    actor_attribution: str = ""
    kill_chain_phase: str = ""

    # CRA outputs (owner: CRA node)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    approved_actions: list[ApprovedAction] = Field(default_factory=list)
    denied_actions: list[ProposedAction] = Field(default_factory=list)
    executed_actions: list[ExecutedAction] = Field(default_factory=list)
    approval_pending: bool = False

    # RVA outputs (owner: RVA node)
    vulnerability_context: list[VulnerabilityContext] = Field(default_factory=list)

    # CLA outputs (owner: CLA utility — append-only)
    audit_log: list[AuditEntry] = Field(default_factory=list)
    compliance_flags: list[str] = Field(default_factory=list)

    # Pipeline metadata (owner: router node)
    current_agent: str = ""
    pipeline_stage: str = "idle"         # idle|detecting|triaging|responding|assessing|logging
    last_updated_at: datetime | None = None
    errors: list[StateError] = Field(default_factory=list)
```

### State Ownership & Merge Rules

| Field | Owner | Merge Semantics |
|-------|-------|----------------|
| `query`, `current_agent`, `pipeline_stage` | Router | Replace |
| `alerts`, `anomaly_scores` | ADA | Replace (fresh scan) |
| `triage_results` | TAA | Append, dedupe by `id` |
| `proposed_actions` | CRA | Append |
| `approved_actions`, `denied_actions` | CRA (after interrupt) | Append |
| `executed_actions` | CRA | Append |
| `vulnerability_context` | RVA | Replace per assessment |
| `audit_log` | CLA utility | Append-only, timestamp ordered |
| `compliance_flags` | CLA utility | Append, dedupe |
| `errors` | Any node | Append |

Nodes must only write to fields they own. Violations are logged as errors.

### Graph Edges (Conditional Routing)

```
START → router_node
  router_node parses analyst input into structured intent:
    {intent, target_entities, time_scope, action_requested, confidence}

  Routing decisions:
    - detection/scan intent → ADA
    - triage/analysis intent → TAA
    - action/containment intent → CRA
    - vulnerability/CVE intent → RVA
    - compliance/audit intent → CLA report node
    - compound intent → first relevant node (graph continues via edges)
    - general question → llm_respond (direct LLM answer)

  Safety rule: if action_requested is detected but routing confidence < 0.7,
  do NOT route directly to CRA/execution path. Instead route to TAA for
  safe summary/clarification. A misrouted containment request is far worse
  than a misrouted summary request.

ADA → TAA (by default for prioritized detections requiring analyst interpretation;
           low-confidence noise below threshold skips to END with summary)

TAA → cra_decision
  cra_decision:
    - severity >= HIGH → CRA
    - severity < HIGH → RVA (skip containment, assess risk)

CRA → interrupt (for gated actions per Response Gate policy)
    → after approval/denial → RVA

RVA → END

CLA: parallel audit utility, NOT a terminal node. Called by every node
     at significant events (see AuditEntry.event_type for the full list).
     CLA also has a dedicated report node reachable from router for
     explicit compliance queries.
```

### Compound Workflow Support

The router supports multi-agent intents. Examples:

| Analyst Input | Decomposition |
|--------------|---------------|
| "show critical VPN alerts and check for Volt Typhoon" | ADA (fetch) → TAA (attribution analysis) |
| "triage and tell me if patching is urgent" | TAA → RVA |
| "check whether host X should be isolated" | TAA (assess) → CRA (propose, gated) |
| "find related CVEs and summarize compliance impact" | RVA → CLA report |

### Response Gate Policy

Externalized as a config file loaded at startup, editable without redeploy:

```yaml
# gatra-agent/config/response_gate.yaml
environment: pilot                       # dev | pilot | prod
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
    # never auto-execute on critical infrastructure
    mode: approval_required
    asset_tags: ["core-router", "dns-primary", "hss", "pcrf", "pgw"]

  maintenance_window:
    # during maintenance, suppress auto-actions
    enabled: false
    schedule: null                       # cron expression when active

approval:
  expiry_seconds: 300                    # 5-minute approval window
  allow_reapproval: false                # expired approvals cannot be re-approved
```

### Action Execution Guardrails

Before executing any action, the CRA node enforces:

1. **Idempotency:** Each action has a unique `idempotency_key`. Duplicate execution attempts are no-ops.
2. **Target fingerprint verification:** Before execution, re-fetch target state and compare `target_fingerprint`. If the target has changed since approval, abort and re-propose.
3. **Approval expiry:** Check `expires_at`. Expired approvals are logged and rejected.
4. **Allowed targets:** Only targets matching configured `allowed_target_patterns` are executable. Command injection is prevented by allowlisting action types and validating target values against patterns (IP regex, hostname regex, process name allowlist).
5. **Execution mode:** Respects `dry_run` flag from response gate config. Dry-run logs the action as if executed but takes no effect.
6. **Rollback tracking:** Each `ExecutedAction` records `rollback_available`. For `block` actions, the compensating action is `unblock`. For `isolate`, it is `rejoin`. Rollback actions go through the same approval flow.

Two-step execution flow:
1. `propose_action` → creates `ProposedAction` with `target_fingerprint`
2. After approval: `confirm_and_execute` → re-validates fingerprint, checks expiry, executes only if target still matches

## Trust Model

Clarifies what the LLM can and cannot do autonomously:

| Category | Examples | Authority |
|----------|---------|-----------|
| **Deterministic enrichment** | `fetch_alerts`, `lookup_ioc`, `lookup_cves`, `scan_yara` | Authoritative — data from external sources |
| **Model-assisted interpretation** | `detect_anomalies`, `analyze_threat`, `assess_vulnerability` | Advisory — confidence-bearing, not binding |
| **Decision recommendation** | `propose_action` | Non-binding — always requires policy gate check |
| **Deterministic execution** | `execute_action` | Authoritative after policy gate + approval |
| **Audit persistence** | `log_audit` | Deterministic — nodes create structured `AuditEntry` payloads, `log_audit` persists them as-is without LLM transformation |
| **Compliance advisory** | `check_compliance` | Advisory — not authoritative for regulatory purposes |

Key principle: **The LLM recommends, the policy gate decides, the analyst approves, the system executes.** No LLM output directly triggers a destructive action.

## Frontend Components & Generative UI

### App Layout

```
┌──────────────────────────────────────────────────┐
│  GATRA Analyst Console            [agent status] │
├────────────────────────┬─────────────────────────┤
│     CopilotChat        │      Sidebar            │
│                        │                         │
│  Agent messages with   │  Agent Health            │
│  inline generative UI: │  ADA/TAA/CRA/CLA/RVA    │
│                        │  status indicators       │
│  - AlertCard           │                         │
│  - ApprovalCard        │  Incident Timeline       │
│  - MitreCard           │  chronological entries   │
│  - VulnCard            │  (append-only from state)│
│  - AuditCard           │                         │
│  - ActionResultCard    │  Active Alerts           │
│                        │  severity counts         │
│  [input]        [send] │  (from alerts array)     │
└────────────────────────┴─────────────────────────┘
```

### Generative UI Components (via `useRenderTool`)

| Component | Triggered by | Shows | Fallback |
|-----------|-------------|-------|----------|
| `AlertCard` | ADA `detect_anomalies` tool | Severity badge, MITRE ID + name, confidence %, location, infrastructure, timestamp | Markdown: severity, MITRE technique, confidence, location |
| `ApprovalCard` | CRA `interrupt()` | Action type, target, risk context, expiry countdown, Approve/Deny buttons | Markdown: action summary + text prompt for approve/deny |
| `MitreCard` | TAA `analyze_threat` tool | Kill chain phase, actor attribution, campaign, IOC list | Markdown: technique, attribution, IOCs as bullet list |
| `VulnCard` | RVA `assess_vulnerability` tool | CVE ID, CVSS v4 score, EPSS percentile, affected products, patch status | Markdown: CVE ID, scores, patch status |
| `AuditCard` | CLA `log_audit` tool | Audit entry, regulatory framework tags, timestamp | Markdown: event type, timestamp, summary |
| `ActionResultCard` | CRA `execute_action` tool | Action taken, target, success/failure, execution time, rollback available, dry-run/enforced | Markdown: action, result, target, execution mode, rollback status |

Every component defines:
- **Structured payload schema** (Zod on frontend, Pydantic on backend)
- **Loading/skeleton state** while tool is executing
- **Empty state** when no data
- **Fallback markdown renderer** if the React component fails to render or payload is malformed
- **PII redaction:** Hostnames and IPs may be shown in full for authorized internal analysts; user identifiers are masked by default (role + last 4 chars). Redaction policy is configurable per environment.

### Human-in-the-Loop

Uses `useInterrupt` hook filtered to `response_gate` type events:

```tsx
useInterrupt({
  enabled: ({ eventValue }) => eventValue?.type === "response_gate",
  render: ({ event, resolve }) => (
    <ApprovalCard
      action={event.value.action}
      target={event.value.target}
      severity={event.value.severity}
      confidence={event.value.confidence}
      expiresAt={event.value.expires_at}
      onApprove={() => resolve({ approved: true })}
      onDeny={(reason) => resolve({ approved: false, reason })}
    />
  ),
});
```

### Sidebar (driven by shared state)

Reads `agent.state` via `useAgent` hook and renders three persistent widgets:
- **Agent Health** — maps `pipeline_stage` and `current_agent` to status indicators. Updates on every `copilotkit_emit_state` call.
- **Incident Timeline** — append-only from `audit_log`. New entries appear at the bottom. Source of truth is `audit_log` array from state.
- **Active Alerts** — counts from `alerts` array grouped by `severity` field. Severity source of truth is the `Alert.severity` field set by ADA/TAA.

## Backend Tools & Vercel Endpoint Integration

| Tool Name | Called By | Source | Category | Purpose |
|-----------|----------|--------|----------|---------|
| `fetch_alerts` | ADA | `/api/gatra-data` | Deterministic enrichment | Pull latest alert feed |
| `detect_anomalies` | ADA | Statistical scoring + LLM summarization | Model-assisted | Score anomalies via rules/stats, LLM explains findings |
| `lookup_ioc` | TAA | `/api/ioc-lookup` | Deterministic enrichment | VirusTotal + AbuseIPDB enrichment |
| `analyze_threat` | TAA | LLM + `/api/threat-feeds` | Model-assisted | MITRE mapping, actor attribution, kill chain |
| `classify_intent` | Router | `/api/soc-intent` | Model-assisted | Intent classification for routing |
| `propose_action` | CRA | LLM reasoning + policy gate | Decision recommendation | Decide containment action, non-binding |
| `execute_action` | CRA | `/api/response-actions` | Deterministic execution | Block IP, isolate endpoint, kill process (after approval) |
| `scan_yara` | CRA | `/api/response-actions` | Deterministic enrichment | YARA malware scan |
| `lookup_cves` | RVA | `/api/cisa-kev` | Deterministic enrichment | CISA KEV + CVE enrichment |
| `assess_vulnerability` | RVA | LLM reasoning over CVE data | Model-assisted advisory | CVSS/EPSS interpretation, patch priority |
| `log_audit` | CLA | Structured persistence | Deterministic | Persist pre-built `AuditEntry` — no LLM involved, nodes create the payload |
| `check_compliance` | CLA | LLM reasoning | Advisory, not authoritative | Flag potential regulatory concerns |

All tools calling Vercel endpoints use `httpx.AsyncClient` with:
- Base URL: `WORLDMONITOR_API_URL`
- Auth: `GATRA_API_KEY` bearer token
- Timeout: 30s default, configurable per tool
- Retries: 3x exponential backoff (1s, 2s, 4s)
- Errors normalized to `ToolError(code, message, retryable)`

## State & Persistence

### Session Model

- Sessions are **per analyst, per browser tab**
- Each session gets a unique `session_id` and `trace_id`
- An `incident_id` is attached once an alert or case is selected
- **Reconnection:** If the browser tab is refreshed or SSE reconnects, the frontend attempts to resume the existing session via `session_id` stored in sessionStorage. If the checkpoint exists, state and pending approvals are restored. If not (e.g., backend restarted without checkpoint), a fresh session begins.

### Persistence Layers

| What | Where | Durability |
|------|-------|-----------|
| LangGraph state (in-flight) | In-memory on `gatra-agent` | Lost on restart |
| LangGraph checkpoints | LangGraph checkpoint store (SQLite for pilot, PostgreSQL for prod) | Survives restart |
| Pending approvals | Checkpoint store + `approval_pending` flag | Resumable after reconnect |
| Audit log | Persisted via `log_audit` tool to external store | Durable |
| Action history | Persisted alongside audit log | Durable |

### Recovery Behavior

- **Agent backend restart:** In-flight sessions are lost. Pending approvals in checkpoint store can be resumed when the analyst reconnects. The frontend detects disconnect and shows a reconnection banner.
- **SSE stream disconnect:** The CopilotKit runtime handles reconnection. If the analyst reconnects to a session with `approval_pending: true`, the `ApprovalCard` re-renders from checkpoint state.
- **Stale approval:** If `expires_at` has passed, the approval is rejected and the analyst is prompted to re-evaluate.

### Concurrency

Even without multi-user collaboration:
- **Duplicate tab:** Same analyst, same incident — second tab gets a new session. Actions use `idempotency_key` to prevent duplicate execution.
- **Multiple analysts, same target:** `target_fingerprint` verification before execution catches conflicts. If another analyst already acted on the target, the fingerprint won't match and the action is aborted with an explanation.
- **One-time approval:** Approval tokens are consumed on use. Re-submitting a consumed approval is a no-op. Each token is bound to: `action_id` + `session_id` + `user_id` + `expires_at` + `target_fingerprint` hash. This prevents replay across sessions or after target state changes.

## Observability

### Tracing

- `trace_id` generated at request start, propagated through all tool calls and audit entries
- `incident_id` attached once an alert/case is selected
- Correlation: `trace_id` links frontend request → CopilotKit runtime → agent backend → Vercel endpoint calls

### Structured Logging

All logs are JSON-structured with fields:
- `trace_id`, `session_id`, `incident_id`, `agent`, `event_type`, `timestamp`
- Tool call logs include parameters (with sensitive fields redacted)

### Metrics

| Metric | Source |
|--------|--------|
| Per-node latency | Each agent node measures wall-clock time |
| Approval duration | Time between `approval_requested` and `approval_granted`/`denied` |
| Action success/failure rate | `ExecutedAction.success` aggregation |
| LLM token usage + cost | LangChain callback handler per provider |
| Tool call latency + error rate | `httpx` response timing |
| SSE stream disconnects | CopilotKit runtime logs |

### Health & Readiness

`gatra-agent` exposes:
- `GET /health` — liveness check (process alive)
- `GET /ready` — readiness check (core routing operational + checkpoint store connected + at least one configured LLM provider reachable). Does NOT require all Vercel enrichment endpoints to be healthy — those degrade gracefully.
- `GET /dependencies` — detailed sub-checks for each Vercel endpoint, threat feed, LLM provider. For dashboards/debugging, not load balancer gating.

## Failure Modes & Error Handling

| Failure | System Behavior |
|---------|----------------|
| Vercel endpoint unavailable | Tool returns `ToolError(retryable=true)`. Node retries 3x, then surfaces error to analyst in chat. |
| LLM provider timeout | 30s timeout per call. Falls back to next configured provider if `LLM_FALLBACK_PROVIDER` is set. Otherwise surfaces error. |
| Approval event lost (SSE disconnect) | Approval persisted in checkpoint store. On reconnect, pending approval re-renders. |
| Duplicate approval click | Idempotent — second click is a no-op, card shows "already approved". |
| Stale state after reconnect | Frontend re-fetches full state from agent. `last_updated_at` shown to analyst. |
| Malformed generative UI payload | Component catches error, falls back to markdown renderer with available fields. |
| Execution tool partial failure | Action marked `failed` with error detail. Analyst notified. No automatic retry for destructive actions. |
| Target changed since approval | `target_fingerprint` mismatch aborts execution. Analyst sees explanation + option to re-propose. |

## Project Structure

### `gatra-copilot/` (Next.js frontend)

```
gatra-copilot/
├── app/
│   ├── layout.tsx              # CopilotKit provider wrapper
│   ├── page.tsx                # Main console layout (chat + sidebar)
│   └── api/
│       └── copilotkit/
│           └── route.ts        # CopilotRuntime → LangGraphHttpAgent
├── components/
│   ├── chat/
│   │   ├── AlertCard.tsx
│   │   ├── ApprovalCard.tsx
│   │   ├── MitreCard.tsx
│   │   ├── VulnCard.tsx
│   │   ├── AuditCard.tsx
│   │   └── ActionResultCard.tsx
│   ├── sidebar/
│   │   ├── AgentHealth.tsx
│   │   ├── IncidentTimeline.tsx
│   │   └── ActiveAlerts.tsx
│   └── console/
│       └── AnalystConsole.tsx   # Main layout orchestrator
├── hooks/
│   └── use-gatra-agent.ts      # useAgent + useInterrupt + useRenderTool wiring
├── lib/
│   └── types.ts                # Shared types mirroring GatraState
├── package.json
├── next.config.ts
├── tailwind.config.ts
└── tsconfig.json
```

### `gatra-agent/` (Python backend)

```
gatra-agent/
├── agent/
│   ├── graph.py                # LangGraph StateGraph definition
│   ├── state.py                # GatraState + typed models
│   ├── audit.py                # CLA audit utility (called by all nodes)
│   ├── llm.py                  # LLM provider factory with fallback
│   ├── nodes/
│   │   ├── router.py           # Intent routing → correct agent
│   │   ├── ada.py              # Anomaly Detection node
│   │   ├── taa.py              # Threat Analysis node
│   │   ├── cra.py              # Containment & Response node (interrupt)
│   │   ├── rva.py              # Risk & Vulnerability node
│   │   ├── cla_report.py       # Compliance report node (explicit queries)
│   │   └── llm_respond.py      # Direct LLM response for general queries
│   └── tools/
│       ├── alerts.py           # fetch_alerts, detect_anomalies
│       ├── threat_intel.py     # lookup_ioc, analyze_threat
│       ├── response.py         # propose_action, confirm_and_execute, scan_yara
│       ├── vulnerability.py    # lookup_cves, assess_vulnerability
│       └── compliance.py       # log_audit, check_compliance
├── config/
│   └── response_gate.yaml      # Externalized response gate policy
├── server.py                   # FastAPI + ag-ui-langgraph endpoint + /health + /ready
├── pyproject.toml
└── .env.example
```

## Dependencies

### Frontend (`gatra-copilot/package.json`)

- `next` 15.x, `react` 19.x
- `@copilotkit/react-core`, `@copilotkit/react-ui`, `@copilotkit/runtime`
- `@copilotkit/runtime/langgraph`
- `tailwindcss` 4.x
- `zod` (tool parameter schemas)

Note: exact versions to be pinned after POC smoke test validates compatibility.

### Backend (`gatra-agent/pyproject.toml`)

- `langgraph`, `langchain-core`
- `langchain-anthropic` (default), `langchain-openai`, `langchain-groq` (swappable)
- `copilotkit`, `ag-ui-langgraph`
- `fastapi`, `uvicorn`
- `httpx` (async HTTP to Vercel endpoints)
- `pydantic` (state/tool schemas)

## Environment Variables

### `gatra-copilot/.env.local`

```env
LANGGRAPH_AGENT_URL=http://localhost:8123
SESSION_SECRET=                          # session signing key
```

### `gatra-agent/.env`

```env
WORLDMONITOR_API_URL=https://worldmonitor-gatra.vercel.app
GATRA_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=                          # optional
GROQ_API_KEY=                            # optional
LLM_PROVIDER=anthropic                   # anthropic|openai|groq
LLM_FALLBACK_PROVIDER=groq              # optional fallback
REQUEST_TIMEOUT_SECONDS=30
ACTION_DRY_RUN=false                     # true for safe testing
LOG_LEVEL=info
SERVICE_AUTH_SECRET=                      # HMAC signing key for service-to-service auth
CHECKPOINT_STORE=sqlite                  # sqlite|postgresql
```

## Development & Deployment

### Local Development

```bash
# Terminal 1: Python agent backend
cd gatra-agent
uv run uvicorn server:app --reload --port 8123

# Terminal 2: Next.js frontend
cd gatra-copilot
npm run dev  # port 3000
```

### Deployment

| Component | Platform | Reason |
|-----------|----------|--------|
| `gatra-copilot` | Vercel | Next.js native, same org as worldmonitor |
| `gatra-agent` | Fly.io or Railway | Long-running Python process needed for LangGraph execution, checkpoint-backed session resumability, and low-latency streaming-compatible request handling. Must support health/readiness endpoints. Sessions may require sticky routing or checkpoint-based resumability. |

### LLM Provider Configuration

The backend abstracts the LLM behind `langchain-core`. Switching providers is a single env var change:

```python
def get_llm(provider: str | None = None):
    provider = provider or os.getenv("LLM_PROVIDER", "anthropic")
    match provider:
        case "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model="claude-sonnet-4-20250514", timeout=30)
        case "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model="gpt-4o", timeout=30)
        case "groq":
            from langchain_groq import ChatGroq
            return ChatGroq(model="llama-3.3-70b-versatile", timeout=30)
        case _:
            raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")

class LLMProviderUnavailableError(Exception):
    """Retryable provider errors — timeouts, rate limits, temporary outages."""
    pass

def get_llm_with_fallback():
    try:
        return get_llm()
    except LLMProviderUnavailableError:
        # Only fallback on transient errors (timeout, rate limit, 5xx)
        # Config errors (invalid API key, bad model name) must fail loudly
        fallback = os.getenv("LLM_FALLBACK_PROVIDER")
        if fallback:
            return get_llm(fallback)
        raise
```

## Out of Scope

- Map visualization (stays in worldmonitor)
- Multi-user real-time collaboration / WebSocket transport
- Real GATRA BigQuery backend (currently disabled)
- ML model training (LSTM autoencoders for ADA)
- Mobile / Tauri desktop builds
- Full SSO provider integration (Phase 1 — pilot uses reverse-proxy auth)

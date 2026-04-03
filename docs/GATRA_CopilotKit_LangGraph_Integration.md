# GATRA CopilotKit + LangGraph Integration

**Version:** 1.0.0
**Date:** 2026-04-03
**Authors:** Ghifi Ardiansyah + Claude
**Repository:** `worldmonitor/gatra-agent` + `worldmonitor/gatra-copilot`
**Production URL:** https://worldmonitor-gatra.vercel.app

---

## 1. Executive Summary

The GATRA (Geopolitical Awareness & Threat Response Architecture) CopilotKit + LangGraph integration delivers an **agent-native SOC analyst console** — a standalone web application where security analysts interact with five autonomous AI agents through a conversational interface with real-time status visualization.

The system combines:
- **CopilotKit** (v1.50) — React-based agent UI framework with generative UI components
- **LangGraph** — stateful multi-agent orchestration with conditional routing
- **AG-UI Protocol** — Server-Sent Events (SSE) streaming between frontend and agent backend

Key capabilities:
- Natural language SOC operations (alert analysis, threat triage, containment actions)
- Human-in-the-loop approval flows for destructive actions (block, isolate, kill)
- Generative UI — agents render custom alert cards, approval dialogs, and vulnerability reports inline in the chat
- Five-agent pipeline: ADA (detection) → TAA (triage) → CRA (response) → RVA (vulnerability) → CLA (compliance)
- Response Gate policy engine with YAML-driven rules, RBAC, and crown jewel asset overrides

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                 ANALYST WORKSTATION / BROWSER            │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │         gatra-copilot (Next.js 16 App)           │    │
│  │                                                   │    │
│  │  <CopilotKit runtimeUrl="/api/copilotkit">       │    │
│  │    ┌──────────┐  ┌───────────────────────┐       │    │
│  │    │ Chat     │  │ Sidebar               │       │    │
│  │    │ Panel    │  │ - Agent Health         │       │    │
│  │    │          │  │ - Incident Timeline    │       │    │
│  │    │ Generati │  │ - Active Alerts Feed   │       │    │
│  │    │ ve UI    │  │                        │       │    │
│  │    └──────────┘  └───────────────────────┘       │    │
│  └───────────────────────┬───────────────────────────┘    │
│                          │ SSE (AG-UI Protocol)          │
└──────────────────────────┼───────────────────────────────┘
                           │
              ┌────────────▼────────────────┐
              │  Next.js API Route           │
              │  /api/copilotkit             │
              │  CopilotRuntime              │
              │  └─ LangGraphHttpAgent       │
              │      url → localhost:8123    │
              └────────────┬────────────────┘
                           │ HTTP
              ┌────────────▼────────────────┐
              │  gatra-agent (FastAPI)       │
              │                              │
              │  LangGraph StateGraph:       │
              │  START → Router → Agents     │
              │  ADA → TAA → CRA → RVA      │
              │  CLA: parallel audit sink    │
              │                              │
              │  Checkpointer: MemorySaver   │
              │  AG-UI: SSE streaming        │
              │                              │
              │  Tools ───────────────────┐  │
              └───────────────────────────┼──┘
                                          │ HTTP
              ┌───────────────────────────▼──┐
              │  Existing Vercel Endpoints    │
              │  /api/gatra-data              │
              │  /api/ioc-lookup              │
              │  /api/response-actions        │
              │  /api/threat-feeds            │
              │  /api/cisa-kev                │
              └──────────────────────────────┘
```

### Data Flow

1. Analyst types a message in the CopilotChat UI
2. CopilotKit sends the message via SSE to the Next.js API route (`/api/copilotkit`)
3. The CopilotRuntime proxies the request to the FastAPI backend via `LangGraphHttpAgent`
4. The LangGraph StateGraph processes the request through the agent pipeline
5. Each agent node emits intermediate state updates via `copilotkit_emit_state`
6. The LLM response streams back through the SSE connection to the chat UI
7. Generative UI components render inline for tool calls (alert cards, approval dialogs, etc.)

---

## 3. Project Structure

### 3.1 Backend — `gatra-agent/`

```
gatra-agent/
├── agent/
│   ├── __init__.py
│   ├── state.py                # Pydantic state models (Alert, ProposedAction, etc.)
│   ├── graph.py                # LangGraph StateGraph assembly + conditional routing
│   ├── llm.py                  # LLM provider factory (Anthropic/OpenAI/Groq)
│   ├── policy.py               # Response Gate policy engine (YAML-driven)
│   ├── audit.py                # CLA audit utility — structured event logging
│   ├── nodes/
│   │   ├── router.py           # Intent parsing + routing (regex-based)
│   │   ├── ada.py              # Anomaly Detection Agent
│   │   ├── taa.py              # Threat Analysis & Triage Agent
│   │   ├── cra.py              # Containment & Response Agent (with interrupt)
│   │   ├── rva.py              # Risk & Vulnerability Assessment Agent
│   │   ├── cla_report.py       # Compliance & Logging report node
│   │   └── llm_respond.py      # Direct LLM response for general questions
│   └── tools/
│       ├── client.py           # HTTP client with retry + error normalization
│       ├── alerts.py           # fetch_alerts → /api/gatra-data
│       ├── threat_intel.py     # lookup_ioc → /api/ioc-lookup
│       ├── response.py         # execute_action → /api/response-actions
│       ├── vulnerability.py    # lookup_cves → /api/cisa-kev
│       └── compliance.py       # log_audit (structured persistence)
├── config/
│   └── response_gate.yaml      # Externalized response gate policy
├── tests/                       # 51 tests across 11 test files
├── server.py                    # FastAPI entry point
├── pyproject.toml               # Dependencies + config
└── .env.example                 # Environment variables template
```

### 3.2 Frontend — `gatra-copilot/`

```
gatra-copilot/
├── app/
│   ├── layout.tsx              # CopilotKit provider wrapper
│   ├── page.tsx                # Main entry — renders AnalystConsole
│   └── api/copilotkit/
│       └── route.ts            # CopilotRuntime → LangGraphHttpAgent proxy
├── components/
│   ├── chat/                   # Generative UI components
│   │   ├── AlertCard.tsx       # SOC alert with severity badge + MITRE mapping
│   │   ├── ApprovalCard.tsx    # Human-in-the-loop approve/deny dialog
│   │   ├── MitreCard.tsx       # MITRE ATT&CK analysis card
│   │   ├── VulnCard.tsx        # CVE vulnerability assessment card
│   │   ├── AuditCard.tsx       # Compliance audit entry card
│   │   └── ActionResultCard.tsx # Execution result (success/fail + rollback)
│   ├── sidebar/
│   │   ├── AgentHealth.tsx     # Live agent status indicators
│   │   ├── IncidentTimeline.tsx # Chronological event log
│   │   └── ActiveAlerts.tsx    # Severity count dashboard
│   └── console/
│       └── AnalystConsole.tsx  # Main layout orchestrator
├── hooks/
│   └── use-gatra-agent.ts     # useCoAgent hook for shared state
├── lib/
│   └── types.ts               # TypeScript types mirroring GatraState
└── package.json               # Next.js 16 + CopilotKit 1.50 + Tailwind 4
```

---

## 4. Agent Pipeline

### 4.1 LangGraph State Machine

The agent pipeline is modeled as a LangGraph `StateGraph` with conditional routing:

```
START → Router
         ├── "detection" → ADA → TAA → [severity check]
         │                                ├── HIGH/CRITICAL → CRA → RVA → END
         │                                └── LOW/MEDIUM → RVA → END
         ├── "triage" → TAA → ...
         ├── "action" → CRA → RVA → END
         ├── "vulnerability" → RVA → END
         ├── "compliance" → CLA Report → END
         └── "general" → LLM Respond → END
```

**CLA (Compliance & Logging)** operates as a parallel audit utility — called by every node at significant events, not as a terminal node.

### 4.2 Agent Descriptions

| Agent | Role | Key Capabilities |
|-------|------|------------------|
| **ADA** | Anomaly Detection | Fetches alerts from `/api/gatra-data`, uses LLM to score anomalies |
| **TAA** | Threat Analysis & Triage | MITRE ATT&CK mapping, actor attribution, kill chain analysis |
| **CRA** | Containment & Response | Proposes actions, evaluates Response Gate policy, uses `interrupt()` for approval |
| **RVA** | Risk & Vulnerability | CVE lookup via CISA KEV, CVSS/EPSS scoring, patch prioritization |
| **CLA** | Compliance & Logging | Structured audit entries, compliance report generation |

### 4.3 Router — Intent Classification

The router uses regex-based pattern matching to classify analyst input:

| Intent | Trigger Patterns | Routes To |
|--------|-----------------|-----------|
| Action | block, isolate, kill, quarantine, contain, suspend | CRA |
| Triage | triage, prioritize, escalate, assess, investigate, mitre | TAA |
| Detection | analyze, scan, detect, anomaly, alert, monitor | ADA |
| Vulnerability | CVE, vulnerability, patch, EPSS, CVSS, exploit | RVA |
| Compliance | compliance, audit, report, regulation, HIPAA, PCI | CLA Report |
| General | (no pattern match) | LLM Respond |

**Safety rule:** If an action intent is detected but routing confidence < 0.7 (no clear target entity), the router falls back to TAA for safe summary instead of routing to CRA.

---

## 5. Response Gate Policy

Destructive actions are gated by an externalized YAML policy (`config/response_gate.yaml`):

### 5.1 Action Modes

| Action | Mode | Auto-Execute Condition | Otherwise |
|--------|------|----------------------|-----------|
| `notify` | auto | Always | — |
| `unblock`, `resume` | auto | Always | — |
| `suspend` | conditional | severity >= HIGH + confidence >= 80% | Requires approval |
| `block` | conditional | severity >= CRITICAL + confidence >= 90% | Requires approval |
| `kill` | conditional | severity >= CRITICAL + confidence >= 95% | Requires approval |
| `isolate` | approval_required | Never auto | Always requires approval |

### 5.2 Overrides

- **Crown jewel assets** (`core-router`, `dns-primary`, `hss`, `pcrf`, `pgw`): Always require approval regardless of action mode
- **Maintenance window**: Suppress auto-actions during scheduled maintenance
- **Approval expiry**: 5-minute window; expired approvals are rejected

### 5.3 RBAC

| Role | Permitted Actions |
|------|------------------|
| `viewer` | Read-only |
| `analyst` | `notify` |
| `responder` | `block`, `suspend` |
| `approver` | `kill`, `isolate` |
| `admin` | All + manage policy |

---

## 6. Typed State Models

All state objects use Pydantic models — no generic `dict` in safety-sensitive paths.

### 6.1 Core Models

```python
class Alert(BaseModel):
    id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    mitre_id: str
    mitre_name: str
    description: str
    confidence: float                    # 0.0–1.0
    lat: float | None = None             # optional geolocation
    lon: float | None = None
    location_name: str | None = None
    infrastructure: str | None = None
    timestamp: datetime
    agent: Literal["ADA", "TAA", "CRA", "CLA", "RVA"]

class ProposedAction(BaseModel):
    action_id: str
    incident_id: str
    action_type: Literal["notify", "unblock", "resume", "suspend", "block", "kill", "isolate"]
    target_type: Literal["ip", "host", "endpoint", "process", "user", "session"]
    target_value: str
    target_fingerprint: str              # SHA-256 hash for verification
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    rationale: str
    requires_approval: bool
    expires_at: datetime                 # 5-minute approval window

class PolicyDecision(BaseModel):
    action_type: str
    policy_mode: str                     # auto | conditional | approval_required
    matched_rule: str
    override_applied: str | None
    min_role_required: str
    decision: Literal["auto_approved", "requires_approval", "denied_by_policy"]
    reason: str

class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    trace_id: str
    event_type: Literal[
        "routing_start", "alert_fetched", "triage_completed",
        "action_proposed", "approval_requested", "approval_granted",
        "approval_denied", "execution_succeeded", "execution_failed",
        "vulnerability_assessed", "compliance_checked", "policy_evaluated"
    ]
    agent: str
    summary: str
    policy_decision: PolicyDecision | None = None
```

### 6.2 GatraState — LangGraph State Schema

```python
class GatraState(BaseModel):
    # Session & tracing
    session_id: str
    incident_id: str
    trace_id: str
    user_id: str
    user_role: str                       # analyst | responder | approver | admin

    # LangGraph messages
    messages: Annotated[list[AnyMessage], add_messages]

    # Agent outputs
    alerts: list[Alert]
    triage_results: list[TriageResult]
    proposed_actions: list[ProposedAction]
    approved_actions: list[ApprovedAction]
    executed_actions: list[ExecutedAction]
    vulnerability_context: list[VulnerabilityContext]
    audit_log: list[AuditEntry]

    # Pipeline metadata
    current_agent: str
    pipeline_stage: str                  # idle | detecting | triaging | responding | assessing
```

---

## 7. Frontend Components

### 7.1 Generative UI Cards

CopilotKit renders custom React components inline in the chat when agents call tools:

| Component | Triggered By | Content |
|-----------|-------------|---------|
| `AlertCard` | ADA detection | Severity badge, MITRE ID, confidence %, location |
| `ApprovalCard` | CRA interrupt | Action details, approve/deny buttons, expiry countdown |
| `MitreCard` | TAA analysis | Kill chain phase, actor attribution, IOC list |
| `VulnCard` | RVA assessment | CVE ID, CVSS v4, EPSS percentile, patch status |
| `AuditCard` | CLA logging | Event type, timestamp, compliance frameworks |
| `ActionResultCard` | CRA execution | Success/failure, execution mode, rollback availability |

All cards include:
- Loading/skeleton state while the tool executes
- Fallback markdown renderer if the component fails
- Dark theme (gray-900/950 backgrounds, Tailwind CSS)

### 7.2 Sidebar Widgets

| Widget | Data Source | Updates |
|--------|-----------|---------|
| **Agent Health** | `pipeline_stage` + `current_agent` | Live pulse animation on active agent |
| **Incident Timeline** | `audit_log` array | Append-only, chronological entries |
| **Active Alerts** | `alerts` array | Severity count grouped by level |

### 7.3 CopilotKit Runtime Integration

```typescript
// app/api/copilotkit/route.ts
const runtime = new CopilotRuntime({
  agents: {
    gatra_soc: new LangGraphHttpAgent({
      url: process.env.LANGGRAPH_AGENT_URL || "http://localhost:8123",
    }),
  },
});

const { handleRequest } = copilotRuntimeNextJSAppRouterEndpoint({
  runtime,
  serviceAdapter: new ExperimentalEmptyAdapter(),
  endpoint: "/api/copilotkit",
});

export const POST = handleRequest;
```

---

## 8. Backend Tools

Tools wrap HTTP calls to existing worldmonitor Vercel API endpoints:

| Tool | Endpoint | Category | Purpose |
|------|----------|----------|---------|
| `fetch_alerts` | `/api/gatra-data` | Deterministic | Pull SOC alert feed |
| `lookup_ioc` | `/api/ioc-lookup` | Deterministic | VirusTotal + AbuseIPDB |
| `query_threat_feeds` | `/api/threat-feeds` | Deterministic | Threat intelligence |
| `execute_action` | `/api/response-actions` | Execution | Block/isolate/kill (after approval) |
| `scan_yara` | `/api/response-actions` | Deterministic | YARA malware scan |
| `lookup_cves` | `/api/cisa-kev` | Deterministic | CISA KEV catalog |
| `log_audit` | — | Persistence | Store audit entries |

All HTTP tools use:
- Bearer token auth (`GATRA_API_KEY`)
- 30s timeout (configurable)
- Exponential backoff retry (3x: 1s, 2s, 4s)
- Error normalization to `ToolError(code, message, retryable)`

---

## 9. LLM Provider Configuration

The backend abstracts LLM providers behind a factory:

```python
# Configured via environment variables:
LLM_PROVIDER=anthropic          # anthropic | openai | groq
LLM_FALLBACK_PROVIDER=groq     # optional fallback on transient errors

# Provider → Model mapping:
# anthropic → claude-sonnet-4-20250514
# openai    → gpt-4o
# groq      → llama-3.3-70b-versatile
```

Fallback only triggers on transient errors (timeout, rate limit, 5xx). Configuration errors (invalid API key, bad model name) fail loudly.

---

## 10. Health & Observability

### 10.1 Health Endpoints

| Endpoint | Purpose | Behavior |
|----------|---------|----------|
| `GET /health` | Liveness | Returns `{"status": "ok"}` if process alive |
| `GET /ready` | Readiness | Checks graph compiled + LLM provider reachable |
| `GET /dependencies` | Dependency health | HEAD-checks each Vercel endpoint |

### 10.2 Structured Audit Log

Every significant event is captured as a typed `AuditEntry` with:
- `trace_id` for end-to-end correlation
- `incident_id` for case-level grouping
- `event_type` for categorization (12 defined types)
- `policy_decision` for Response Gate evaluation logging

---

## 11. Development Setup

### 11.1 Prerequisites

- Python 3.12 + [uv](https://docs.astral.sh/uv/)
- Node.js 22+ + npm
- Anthropic API key (or OpenAI/Groq)

### 11.2 Backend

```bash
cd worldmonitor/gatra-agent
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY

uv sync                                    # Install dependencies
uv run pytest tests/ -v                    # Run tests (51 tests)
uv run uvicorn server:app --reload --port 8123  # Start dev server
```

### 11.3 Frontend

```bash
cd worldmonitor/gatra-copilot
npm install                                # Install dependencies
npm run dev                                # Start on localhost:3000
```

### 11.4 Environment Variables

**Backend (`gatra-agent/.env`):**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes* | — | Claude API key |
| `OPENAI_API_KEY` | No | — | GPT-4o API key (if using OpenAI) |
| `GROQ_API_KEY` | No | — | Groq API key (if using Groq) |
| `LLM_PROVIDER` | No | `anthropic` | Active provider |
| `LLM_FALLBACK_PROVIDER` | No | `groq` | Fallback on transient errors |
| `WORLDMONITOR_API_URL` | No | `https://worldmonitor-gatra.vercel.app` | Vercel endpoints base URL |
| `GATRA_API_KEY` | No | — | Bearer token for Vercel endpoints |
| `REQUEST_TIMEOUT_SECONDS` | No | `30` | HTTP timeout |
| `ACTION_DRY_RUN` | No | `false` | Dry-run mode for testing |
| `LOG_LEVEL` | No | `info` | Logging level |

*Required for the configured `LLM_PROVIDER`.

**Frontend (`gatra-copilot/.env.local`):**

| Variable | Default | Description |
|----------|---------|-------------|
| `LANGGRAPH_AGENT_URL` | `http://localhost:8123` | Backend URL |

---

## 12. Deployment

| Component | Platform | Reason |
|-----------|----------|--------|
| `gatra-copilot` | Vercel | Next.js native deployment |
| `gatra-agent` | Fly.io / Railway | Long-running Python process for LangGraph execution + SSE streaming |

---

## 13. Testing

### 13.1 Backend Test Suite

51 tests across 11 test files:

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_state.py` | 10 | All Pydantic models + GatraState defaults |
| `test_llm.py` | 5 | Provider factory + invalid provider handling |
| `test_policy.py` | 8 | Policy evaluation — all modes, RBAC, crown jewel override |
| `test_audit.py` | 3 | Audit entry creation + policy decision embedding |
| `test_client.py` | 4 | HTTP retry, timeout, error normalization |
| `test_tools_alerts.py` | 2 | Alert fetch + IOC lookup |
| `test_tools_response.py` | 3 | Action execution + YARA scan + CVE lookup |
| `test_router.py` | 11 | Intent classification + routing safety rule |
| `test_cra.py` | 3 | ProposedAction building + expiry checking |
| `test_graph.py` | 2 | Graph compilation + node registration |

Run all: `cd gatra-agent && uv run pytest tests/ -v`

---

## 14. Key Technical Decisions

| Decision | Rationale |
|----------|-----------|
| Pydantic BaseModel for GatraState (not CopilotKitState TypedDict) | LangGraph 0.3+ supports Pydantic natively; TypedDict caused attribute access issues |
| MemorySaver checkpointer | AG-UI protocol requires checkpointer; in-memory for dev, PostgreSQL for production |
| Regex-based router (not LLM) | Zero latency, deterministic, no LLM cost for routing; LLM fallback available via `/api/soc-intent` |
| `LangGraphHttpAgent` (not `LangGraphAgent`) | Self-hosted FastAPI backend, not LangSmith deployment |
| Named agents dict (not defaultAgent) | CopilotKit v1.50 requires agents dict + agent prop on provider |
| Async nodes throughout | Required for `await copilotkit_emit_state()` + `await llm.ainvoke()` |

---

## 15. Known Limitations & Future Work

| Limitation | Status | Plan |
|-----------|--------|------|
| Sidebar uses static state (useCoAgent removed) | Workaround | Re-wire shared state once CopilotKit agent resolution is debugged |
| Mock data for alerts (GATRA BigQuery disabled) | Expected | Re-enable when BigQuery quota is restored |
| In-memory checkpointer (lost on restart) | Dev-only | SQLite for pilot, PostgreSQL for production |
| No authentication/RBAC enforcement | By design | Phase 0 pilot; identity propagation mandatory for pilot deployment |
| Single uvicorn worker | Dev-only | Gunicorn + multiple workers for production |

---

## 16. Commit History

25 commits on `feat/gatra-copilotkit-langgraph`:

| Phase | Commits | Description |
|-------|---------|-------------|
| Foundation | 7 | State models, LLM factory, policy engine, audit utility, HTTP client |
| Tools | 3 | Alert, threat intel, response, vulnerability, compliance tools |
| Agent Nodes | 3 | Router, ADA, TAA, CRA (with interrupt), RVA, CLA report, LLM respond |
| Graph + Server | 2 | LangGraph assembly, FastAPI server |
| Frontend | 6 | Next.js scaffold, CopilotKit runtime, types, generative UI, sidebar, layout |
| Bug Fixes | 4 | Async nodes, checkpointer, CORS, agent registration |

---

## 17. References

- [CopilotKit Documentation](https://docs.copilotkit.ai/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [AG-UI Protocol](https://github.com/ag-ui-protocol/ag-ui)
- [GATRA Design Spec](docs/superpowers/specs/2026-04-03-gatra-copilotkit-langgraph-design.md)
- [Implementation Plan](docs/superpowers/plans/2026-04-03-gatra-copilotkit-langgraph.md)

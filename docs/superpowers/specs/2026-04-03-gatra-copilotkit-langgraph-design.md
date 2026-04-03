# GATRA CopilotKit + LangGraph Analyst Console

**Date:** 2026-04-03
**Status:** Approved
**Author:** Ghifi + Claude

## Overview

A standalone GATRA Analyst Console built with CopilotKit and LangGraph, providing an agent-native frontend for SOC analysts. The console features shared state between frontend and backend agents, human-in-the-loop approval flows for destructive containment actions, and generative UI where agents render custom alert cards and dashboards directly in the chat.

Two new top-level directories in the `worldmonitor` repo:
- `gatra-copilot/` — Next.js + CopilotKit React frontend
- `gatra-agent/` — Python FastAPI + LangGraph backend

The existing worldmonitor codebase remains untouched. The Python backend calls existing Vercel API endpoints as tools.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ANALYST BROWSER                       │
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
└──────────────────────────┼───────────────────────────────┘
                           │
              ┌────────────▼────────────────┐
              │  Next.js API Route           │
              │  /api/copilotkit             │
              │  CopilotRuntime              │
              │  └─ LangGraphHttpAgent       │
              │      url: AGENT_BACKEND_URL  │
              └────────────┬────────────────┘
                           │ HTTP
              ┌────────────▼────────────────┐
              │  gatra-agent (FastAPI)       │
              │                              │
              │  LangGraph StateGraph:       │
              │  START → router → agents     │
              │  ADA → TAA → CRA → RVA → CLA│
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
              │  /api/gatra-local.py          │
              │  /api/cisa-kev                │
              └──────────────────────────────┘
```

## LangGraph Agent Graph

### State Schema

```python
class GatraState(CopilotKitState):
    # Input
    query: str = ""

    # ADA outputs
    alerts: list[dict] = []
    anomaly_scores: dict = {}

    # TAA outputs
    triage_results: list[dict] = []      # severity, MITRE mapping, confidence
    actor_attribution: str = ""
    kill_chain_phase: str = ""

    # CRA outputs
    proposed_actions: list[dict] = []    # actions pending approval
    approved_actions: list[dict] = []    # analyst-approved
    denied_actions: list[dict] = []
    executed_actions: list[dict] = []

    # RVA outputs
    vulnerability_context: list[dict] = []  # CVE, EPSS, CVSS scores

    # CLA outputs
    audit_log: list[dict] = []
    compliance_flags: list[str] = []

    # Pipeline metadata
    current_agent: str = ""
    pipeline_stage: str = "idle"        # idle|detecting|triaging|responding|assessing|logging
```

### Graph Edges (Conditional Routing)

```
START → router_node
  router_node decides based on analyst input:
    - "analyze alerts" / new telemetry → ADA
    - "triage this" / alert reference → TAA
    - "block/isolate/kill" / direct action → CRA
    - "check CVEs for..." → RVA
    - "show compliance report" → CLA
    - general question → llm_respond (direct LLM answer)

ADA → TAA (always — detections need triage)
TAA → cra_decision
  cra_decision:
    - severity >= HIGH → CRA
    - severity < HIGH → RVA (skip containment, assess risk)

CRA → interrupt (for gated actions per Response Gate thresholds)
    → after approval/denial → RVA

RVA → CLA (always — log everything)
CLA → END
```

### Response Gate Thresholds (from existing worldmonitor)

| Action | Auto-Execute When | Otherwise |
|--------|---|---|
| `notify` | Always | — |
| `unblock`, `resume` | Always (safe reversals) | — |
| `suspend` | severity >= HIGH + confidence >= 80% | interrupt() for approval |
| `block` | auto_block + severity >= CRITICAL + confidence >= 90% | interrupt() for approval |
| `kill` | auto_kill + severity >= CRITICAL + confidence >= 95% | interrupt() for approval |
| `isolate` | Never | Always interrupt() |

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
│  - VulnCard            │                         │
│  - AuditCard           │  Active Alerts           │
│  - ActionResultCard    │  severity counts         │
│                        │                         │
│  [input]        [send] │                         │
└────────────────────────┴─────────────────────────┘
```

### Generative UI Components (via `useRenderTool`)

| Component | Triggered by | Shows |
|-----------|-------------|-------|
| `AlertCard` | ADA `detect_anomalies` tool | Severity badge, MITRE ID + name, confidence %, location, infrastructure, timestamp |
| `ApprovalCard` | CRA `interrupt()` | Action type, target, risk context, Approve/Deny buttons — resolves the interrupt |
| `MitreCard` | TAA `analyze_threat` tool | Kill chain phase, actor attribution, campaign, IOC list |
| `VulnCard` | RVA `assess_vulnerability` tool | CVE ID, CVSS v4 score, EPSS percentile, affected products, patch status |
| `AuditCard` | CLA `log_compliance` tool | Audit entry, regulatory framework tags, timestamp |
| `ActionResultCard` | CRA `execute_action` tool | Action taken, target, success/failure, execution time |

### Human-in-the-Loop

Uses `useInterrupt` hook filtered to `response_gate` type events:

```tsx
useInterrupt({
  enabled: ({ eventValue }) => eventValue.type === "response_gate",
  render: ({ event, resolve }) => (
    <ApprovalCard
      action={event.value.action}
      target={event.value.target}
      severity={event.value.severity}
      confidence={event.value.confidence}
      onApprove={() => resolve({ approved: true })}
      onDeny={(reason) => resolve({ approved: false, reason })}
    />
  ),
});
```

### Sidebar (driven by shared state)

Reads `agent.state` via `useAgent` hook and renders three persistent widgets:
- **Agent Health** — maps `pipeline_stage` and `current_agent` to status indicators
- **Incident Timeline** — appends entries from `audit_log` as they accumulate
- **Active Alerts** — counts from `alerts` grouped by severity

Updated in real-time via `copilotkit_emit_state` from each agent node.

## Backend Tools & Vercel Endpoint Integration

| Tool Name | Called By | Vercel Endpoint | Purpose |
|-----------|----------|----------------|---------|
| `fetch_alerts` | ADA | `/api/gatra-data` | Pull latest alert feed |
| `detect_anomalies` | ADA | LLM reasoning over alerts | Score anomalies, flag outliers |
| `lookup_ioc` | TAA | `/api/ioc-lookup` | VirusTotal + AbuseIPDB enrichment |
| `analyze_threat` | TAA | LLM + `/api/threat-feeds` | MITRE mapping, actor attribution, kill chain |
| `classify_intent` | Router | `/api/soc-intent` | Groq-based intent classification |
| `propose_action` | CRA | LLM reasoning | Decide containment action + gate level |
| `execute_action` | CRA | `/api/gatra-local.py` | Block IP, isolate endpoint, kill process |
| `scan_yara` | CRA | `/api/gatra-local.py` | YARA malware scan |
| `lookup_cves` | RVA | `/api/cisa-kev` | CISA KEV + CVE enrichment |
| `assess_vulnerability` | RVA | LLM reasoning over CVE data | CVSS/EPSS scoring, patch priority |
| `log_audit` | CLA | LLM structured output | Generate compliance audit entry |
| `check_compliance` | CLA | LLM reasoning | Flag regulatory concerns |

All tools calling Vercel endpoints use `httpx.AsyncClient` with `WORLDMONITOR_API_URL` base and `GATRA_API_KEY` for authentication.

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
│   ├── state.py                # GatraState(CopilotKitState)
│   ├── nodes/
│   │   ├── router.py           # Intent routing → correct agent
│   │   ├── ada.py              # Anomaly Detection node
│   │   ├── taa.py              # Threat Analysis node
│   │   ├── cra.py              # Containment & Response node (interrupt)
│   │   ├── rva.py              # Risk & Vulnerability node
│   │   ├── cla.py              # Compliance & Logging node
│   │   └── llm_respond.py      # Direct LLM response for general queries
│   └── tools/
│       ├── alerts.py           # fetch_alerts, detect_anomalies
│       ├── threat_intel.py     # lookup_ioc, analyze_threat
│       ├── response.py         # propose_action, execute_action, scan_yara
│       ├── vulnerability.py    # lookup_cves, assess_vulnerability
│       └── compliance.py       # log_audit, check_compliance
├── server.py                   # FastAPI + ag-ui-langgraph endpoint
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
LANGGRAPH_AGENT_URL=http://localhost:8123   # local dev
```

### `gatra-agent/.env`

```env
WORLDMONITOR_API_URL=https://worldmonitor-gatra.vercel.app
GATRA_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=                             # optional
GROQ_API_KEY=                               # optional
LLM_PROVIDER=anthropic                      # anthropic|openai|groq
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
| `gatra-agent` | Fly.io or Railway | Long-running Python process needs persistent connections for LangGraph state + SSE streaming |

### LLM Provider Configuration

The backend abstracts the LLM behind `langchain-core`. Switching providers is a single env var change:

```python
def get_llm():
    provider = os.getenv("LLM_PROVIDER", "anthropic")
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-20250514")
    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o")
    elif provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model="llama-3.3-70b-versatile")
```

## Out of Scope

- Map visualization (stays in worldmonitor)
- Multi-user collaboration / WebSocket transport
- Real GATRA BigQuery backend (currently disabled)
- ML model training (LSTM autoencoders for ADA)
- Mobile / Tauri desktop builds
- Authentication / RBAC for the analyst console

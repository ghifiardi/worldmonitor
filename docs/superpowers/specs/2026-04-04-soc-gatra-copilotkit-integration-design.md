# CopilotKit Integration into soc.gatra.ai

**Date:** 2026-04-04
**Status:** Draft
**Author:** Ghifi + Claude
**Related:** [GATRA CopilotKit + LangGraph Analyst Console](2026-04-03-gatra-copilotkit-langgraph-design.md)

## Overview

Integrate CopilotKit into the existing soc.gatra.ai (`gatra-production`) so that users get agent-powered threat analysis alongside the existing chatbot widget, without replacing it. Both soc.gatra.ai and the standalone `gatra-copilot` analyst console connect to the same `gatra-agent` LangGraph backend, but soc.gatra.ai operates in a restricted **lite mode** — full analytical intelligence, no execution capability.

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Two frontends | Keep both soc.gatra.ai and gatra-copilot | Different audiences: general users vs. SOC analysts |
| Shared backend | Single `gatra-agent` with mode flag | One reasoning pipeline, different execution ceilings |
| Lite mode scope | ADA + TAA + read-only CRA | Users see recommended actions but cannot execute them |
| UI placement | Separate `/soc-analyst` page, existing chatbot untouched | Low risk, preserves simple FAQ path |
| Router adoption | Incremental App Router (`app/` alongside `pages/`) | New experience on App Router, no migration risk |
| Auth model | SSO/RBAC from gatra-copilot spec, capped at `analyst` | Consistent identity model across both frontends |

---

## 1. Agent Mode System

The `gatra-agent` backend gains a `mode` enum enforced as a **backend execution invariant**, not only as graph topology.

### Mode Enum

```python
class AgentMode(str, Enum):
    full = "full"
    lite = "lite"
```

Added to the existing `GatraState` Pydantic model as a required field with default `full`.

### Behavior Per Mode

| Behavior | `full` (gatra-copilot) | `lite` (soc.gatra.ai) |
|----------|----------------------|----------------------|
| Agent nodes | ADA → TAA → CRA → RVA, CLA parallel | ADA → TAA → CRA (read-only), CLA parallel |
| CRA actions | Executable based on RBAC | All actions marked `executable: false`, `reason: "read-only mode"` |
| `interrupt()` | Called for destructive actions | Never called |
| RBAC ceiling | Up to `admin` | Capped at `analyst` |
| RVA node | Runs full vulnerability assessment | Skipped (router edge bypasses) |
| Generative UI | Full set | AlertCard, MitreCard, VulnCard only |

### Execution Graph

- `START` → `router` → `ADA` → `TAA` → `CRA` in all modes
- In `full` mode: `CRA` → `RVA` → `END`
- In `lite` mode: `CRA` → `END`
- `CLA` runs in parallel in both modes for audit, learning, and telemetry, with **no execution side effects in lite mode**

### Lite Mode as Execution Invariant

Lite mode is not just a routing hint. Every node in the graph must respect the mode constraint independently:

- Even if a future edge accidentally routes to RVA in lite mode, RVA must check `state.mode` and no-op
- Even if CRA somehow receives an executable action, it must override to `executable: false` before returning
- No response-action execution tool may be invoked in lite mode, regardless of graph path

This provides defense in depth against routing bugs or future graph changes.

### CRA Read-Only Behavior

In lite mode, CRA still produces recommended response actions but enforces a read-only execution boundary:

```python
if state.mode == AgentMode.lite:
    for action in proposed_actions:
        action.executable = False
        action.reason = "read-only mode — view in Analyst Console for execution"
    # No interrupt(), no approval flow
    return state
```

Actions are deep-copied or normalized before mutation to ensure no shared mutable references are reused elsewhere in the graph.

### CLA Side-Effect Boundary

CLA in lite mode:
- **Does**: log audit entries, record telemetry, capture trace data
- **Does not**: trigger downstream execution, emit operational commands, dispatch tasks

---

## 2. soc.gatra.ai Frontend Changes

### Directory Structure

Incremental App Router adoption — `app/` directory alongside existing `pages/`:

```
gatra-production/
├── pages/                    # existing — untouched
│   ├── index.js
│   ├── soc.tsx
│   └── api/
│       ├── chatbot-mcp.js
│       └── ...
├── app/                      # new — App Router
│   ├── layout.tsx            # minimal root layout (app/ routes only)
│   ├── soc-analyst/
│   │   └── page.tsx          # CopilotKit full-panel experience
│   └── api/
│       └── copilotkit/
│           └── route.ts      # CopilotKit runtime → LangGraphHttpAgent
├── components/
│   ├── ChatbotMCP.js         # existing widget — untouched
│   └── copilot/              # new
│       ├── AnalystPanel.tsx   # main CopilotKit chat layout
│       ├── LiteModeGuard.tsx  # shared guard wrapper
│       ├── AlertCard.tsx      # generative UI
│       ├── MitreCard.tsx
│       └── VulnCard.tsx
```

### Key Points

- **New route:** `/soc-analyst` provides the full-panel CopilotKit analyst experience, separate from the existing `/soc` page
- **Backward compatibility:** existing `/soc`, `pages/` routes, and `ChatbotMCP.js` remain unchanged
- **Server-side proxy boundary:** `app/api/copilotkit/route.ts` proxies requests to `gatra-agent`, enforces `mode=lite`, and signs a short-lived server-side service token with scoped claims for `soc-site`
- **Progressive discovery:** the existing `/soc` page includes a "Launch Analyst Console" CTA linking to `/soc-analyst`

### Page Shell

`/soc-analyst` layout:
- Lightweight header: GATRA logo, user identity badge, "Launch Full Console" link to gatra-copilot
- Chat panel fills remaining viewport — no split-pane, no sidebar widgets in v1
- All CopilotKit components are `'use client'` (hooks, state, CopilotKit UI bindings)

### Provider/CSS Isolation

- `app/layout.tsx` scopes the CopilotKit provider — it does not wrap `pages/` routes
- Global styles verified to apply correctly across both routers
- No conflicting context providers between `_app.js` (Pages Router) and `app/layout.tsx` (App Router)

---

## 3. Authentication & Token Flow

### End-to-End Flow (soc.gatra.ai)

```
Browser → /soc-analyst (App Router page)
  │  SSO login (same provider as gatra-copilot)
  │  Session cookie set
  │
  ▼
CopilotKit hooks → POST /api/copilotkit (App Router route)
  │  1. Validate SSO session cookie
  │  2. Extract user identity + role (capped at analyst)
  │  3. Mint short-lived service token:
  │       { sub, iss: "soc.gatra.ai", aud: "gatra-agent",
  │         source: "soc-site", role_ceiling: "analyst",
  │         route_scope: ["/agent/run"], exp: now+5m }
  │  4. Proxy to gatra-agent with mode=lite + token
  │
  ▼
gatra-agent FastAPI middleware:
  │  1. Verify token signature
  │  2. Reject if: missing/expired/malformed → 401
  │  3. Reject if: aud ≠ "gatra-agent" → 403
  │  4. Reject if: route_scope doesn't match endpoint → 403
  │  5. Reject if: missing required claims (aud, iss, exp, route_scope) → 401
  │  6. Set effective_mode from source claim (soc-site → lite)
  │  7. Set rbac_ceiling from role_ceiling claim
  │  8. Log: { requested_mode, effective_mode, sub, trace_id }
  │
  ▼
Graph executes with effective_mode + rbac_ceiling in state
```

### Security Properties

- **Server-only signing:** secret stored as `AGENT_SERVICE_SECRET` env var, never reaches client bundle
- **Short TTL:** tokens minted per-request with 5-minute expiration, not cached
- **Reject, not downgrade:** invalid or malformed tokens are rejected with 401/403, never silently downgraded to lite
- **Multi-claim trust:** `source` alone is not the only trust control; `aud`, `iss`, `exp`, and `route_scope` are all required and validated
- **Audit trail:** CLA logs `sub` (who), `effective_mode`, `requested_mode`, `trace_id` on every run

### Source-Based Mode Override

Service-token claims define the maximum permitted execution mode:

| Token `source` | `effective_mode` | RBAC ceiling |
|----------------|-----------------|--------------|
| `soc-site` | `lite` (forced) | `analyst` |
| `copilot` | As requested (up to `full`) | As token `role_ceiling` (up to `admin`) |

The backend forcibly sets `effective_mode=lite` for `soc-site` tokens regardless of any client-supplied mode parameter. The frontend cannot escalate.

### Contrast with gatra-copilot

Same SSO provider, same token structure. Differences:
- `iss: "gatra-copilot"`, `source: "copilot"`
- `role_ceiling` matches actual user role (up to `admin`)
- `mode=full` permitted

---

## 4. Generative UI & Component Sharing

### Components in soc.gatra.ai

| Component | Included | Behavior in lite mode |
|-----------|----------|----------------------|
| `AlertCard.tsx` | Yes | Displays alert details, severity, IOCs |
| `MitreCard.tsx` | Yes | Shows ATT&CK mapping, technique details |
| `VulnCard.tsx` | Yes | Vulnerability info, CVE, affected products |
| `ApprovalCard.tsx` | **No** | `interrupt()` never fires in lite mode |
| `ActionResultCard.tsx` | **No** | Actions are never executed |

All components are `'use client'` and receive `mode` as an **explicit required prop**, sourced from CopilotKit agent state in the parent `AnalystPanel.tsx`.

### LiteModeGuard Wrapper

A shared guard component used by all generative UI components that may receive action-like payloads:

```tsx
// components/copilot/LiteModeGuard.tsx
'use client';

export function LiteModeGuard({ mode, executable, children }) {
  if (mode === 'lite' && executable) {
    // Defensive — should never happen if backend enforces correctly
    return <InfoBanner>View-only recommendation — execution available in the full Analyst Console</InfoBanner>;
  }
  return children;
}
```

This is a **defensive safeguard only**; backend policy remains the primary enforcement layer.

Future components that handle action-like payloads must use this wrapper. This is the defined pattern, not per-component ad-hoc guards.

### Component Ownership

- `gatra-copilot` is the **source of truth** for shared generative UI components
- Changes and bugfixes land in `gatra-copilot` first, then are mirrored into soc.gatra.ai
- Each copied file includes a provenance header:

```tsx
// SOURCE: gatra-copilot/components/chat/AlertCard.tsx
// SYNCED FROM: commit abc1234
// LAST SYNCED: 2026-04-04
```

- Extraction into a shared package (`@gatra/copilot-ui`) is planned after both frontends stabilize and is not required for v1

### Excluded from v1

Sidebar widgets (AgentHealth, IncidentTimeline, ActiveAlerts) remain exclusive to `gatra-copilot`. This keeps the soc.gatra.ai integration lightweight and avoids pulling in additional real-time data subscriptions.

---

## 5. Deployment & Infrastructure

### soc.gatra.ai (Vercel)

Deployed on Vercel (existing). No platform changes required. The new `/soc-analyst` route is introduced through incremental App Router adoption within the existing deployment.

**New environment variables** (added via `vercel env`, separate values per dev/preview/production):

| Variable | Scope | Purpose |
|----------|-------|---------|
| `AGENT_BACKEND_URL` | Server | Backend endpoint for gatra-agent |
| `AGENT_SERVICE_SECRET` | Server | Server-only secret for signing service tokens. No secret reuse between preview and production. |
| `NEXT_PUBLIC_SOC_ANALYST_ENABLED` | Client | Controls UI visibility and rollout behavior for the analyst console |

### gatra-agent (Independent Service)

- Continues to run as an independent service (existing deployment)
- Token validation extended to trust `iss: "soc.gatra.ai"` alongside `iss: "gatra-copilot"`, with signature, issuer, audience, expiration, and route-scope checks enforced
- Browser access from soc.gatra.ai allowed via CORS configuration; **CORS is browser access control only — token validation remains the primary security boundary**

### Rollout Strategy

**Phase 1 — Internal pilot:**
- Code is deployed, but `/soc-analyst` remains access-restricted and undiscoverable from the public `/soc` page
- Access gating: server-side middleware checks SSO session + allowlisted user emails
- `NEXT_PUBLIC_SOC_ANALYST_ENABLED=false` — "Launch Analyst Console" CTA hidden on `/soc`
- Direct URL access requires valid SSO session + email on the pilot allowlist

**Phase 2 — Soft launch:**
- Enable `NEXT_PUBLIC_SOC_ANALYST_ENABLED=true` — CTA appears on `/soc`
- Remove pilot email allowlist — any authenticated user can access
- Monitor CLA audit logs, token enforcement telemetry, and error rates

**Phase 3 — GA:**
- Analyst console enabled by default
- Rollout flag **retained as an operational kill switch** for emergency rollback, incident mitigation, or staged experiments

### Failure Modes

| Scenario | Behavior |
|----------|----------|
| `gatra-agent` unavailable | Graceful degraded message: "Analyst service is temporarily unavailable" |
| Token signing failure / missing secret | Generic server error (500), no sensitive detail exposed |
| Backend rejects token (401/403) | "Unable to connect to analyst service — please try again or contact support" |
| Feature flag off | Controlled "Analyst Console is not currently available" page |
| Backend 5xx | Retry once, then show degraded message |

---

## 6. Testing Strategy

### Agent Backend (`gatra-agent`)

**Unit tests:**

| Test | Assertion |
|------|-----------|
| Mode routing logic | `lite` skips RVA, `full` includes RVA |
| CRA lite behavior | All actions return `executable: false`, no `interrupt()` called |
| No execution side effects in lite | No response-action execution tools invoked, no task dispatch, no outbound mutations downstream of CRA |
| CLA no-side-effect in lite | CLA logs and audits, triggers no operational actions |
| Token validation — valid | Accepted, claims extracted correctly |
| Token validation — expired/malformed | Rejected with 401 |
| Token validation — wrong aud/scope | Rejected with 403 |
| Token validation — missing claims | Missing `aud`, `iss`, `exp`, or `route_scope` each rejected with 401 |
| RBAC ceiling | Token says `responder` but source is `soc-site` → effective ceiling is `analyst`, responder-only actions blocked |

**Integration tests:**

| Test | Assertion |
|------|-----------|
| Full graph, lite mode | ADA → TAA → CRA (read-only) → END, verify state has non-executable actions, no RVA transition, no execution side effects |
| Full graph, full mode | Existing tests unchanged, confirm no regression |
| Mode override | Client sends `mode=full` with soc-site token → `effective_mode=lite` enforced |
| gatra-copilot regression | `copilot` token still gets `effective_mode=full`, approval and execution paths work after mode system introduction |

### soc.gatra.ai Frontend (`gatra-production`)

**Component tests:**

| Test | Assertion |
|------|-----------|
| `LiteModeGuard` | Renders info banner when `executable: true` + `mode: lite`; passes children through otherwise |
| AlertCard, MitreCard, VulnCard | Render correctly with sample payloads |
| Defensive render | Missing optional fields, unknown severity, empty IOC list, malformed action payload — all render without crash |

**Route tests:**

| Test | Assertion |
|------|-----------|
| `/api/copilotkit` — happy path | Token minted, `mode=lite` hardcoded, proxied to agent |
| `/api/copilotkit` — backend timeout | Controlled error response, no sensitive detail |
| `/api/copilotkit` — backend 401/403/5xx | Controlled error response per failure mode table |
| `/api/copilotkit` — missing signing secret | 500 with generic message |
| `/soc-analyst` — flag off | "Not available" page |
| `/soc-analyst` — flag on, no auth | Redirect to login |
| `/soc-analyst` — flag on, auth, not allowlisted (Phase 1) | Forbidden |

**E2E test:**

| Test | Assertion |
|------|-----------|
| Happy path | Authenticated user opens `/soc-analyst`, submits query, receives informational generative UI (AlertCard), confirms: no approval UI rendered, no action buttons, read-only banner present where applicable, no action execution request possible from the page |

**Contract test:**

| Test | Assertion |
|------|-----------|
| Generative UI payload shape | Agent output shape matches expectations of AlertCard, MitreCard, VulnCard across both frontends — catches component drift early |

### Not Tested in soc.gatra.ai

- Existing `pages/` routes, chatbot widget, and API routes — untouched, covered by existing tests
- Full-mode agent behavior — owned by `gatra-copilot`

---

## Appendix: What Is NOT Changing

- `pages/` directory, `_app.js`, existing API routes in `gatra-production`
- `ChatbotMCP.js` widget — still works as the simple FAQ chatbot
- `gatra-copilot` frontend — no changes needed
- `gatra-agent` tool implementations — same tools, same API calls
- Existing Vercel deployment configuration

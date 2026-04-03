# Sigma Rules Engine for GATRA SOC

**Date:** 2026-04-03
**Status:** Approved
**Scope:** v1 — Edge-native Sigma matching with asset context enrichment

---

## Overview

A pure TypeScript, Edge-native log/event detection engine that matches structured JSON events against Sigma-format YAML rules enriched with static asset context. Complements existing YARA file scanning with event/log-level detection. Integrated via MCP tools and SOC chat (ADA agent).

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Log format | Any structured JSON | Maximum flexibility — GATRA events, SIEM logs, network flows |
| Engine runtime | Browser/Edge (TypeScript) | No native deps (unlike YARA). Zero latency, works offline from gatra-local |
| Rule format | Standard Sigma YAML + GATRA extensions | Community rule compatibility + tight MITRE/agent integration |
| Integration points | MCP tools + SOC chat | Sufficient for v1. No dedicated panel needed yet |
| Rule count | 12 seed rules | Prove the engine, expand later. Structured for growth |
| Asset context | Static JSON file | Self-contained, easy to demo. Replaceable with CMDB API later |

## Architecture

```
Analyst (SOC Chat / MCP)
    │
    ▼
POST /api/sigma-scan ──── GET /api/sigma-scan?action=rules
    │
    ▼
┌─────────────────────────────────────┐
│  Edge Function (api/sigma-scan.js)  │
│  - Fetches & caches rules (10 min)  │
│  - Fetches & caches assets (10 min) │
│  - Delegates to sigma-engine        │
│  - Max 50 events per request        │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Sigma Engine (src/services/)       │
│  - sigma-engine.ts (core matching)  │
│  - Parses YAML → SigmaRule[]        │
│  - Evaluates detection + conditions │
│  - Resolves asset context           │
│  - Returns SigmaMatch[]             │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  Static Files (public/sigma-rules/) │
│  - index.json (manifest)            │
│  - assets.json (asset inventory)    │
│  - 12 YAML rule files               │
└─────────────────────────────────────┘
```

## 1. Rule Files

### Location

`public/sigma-rules/`

### Directory Structure

```
public/sigma-rules/
├── index.json              # Rule manifest
├── assets.json             # Asset inventory with CVEs, firmware, patch status
├── c2-beaconing.yml
├── brute-force.yml
├── dns-tunneling.yml
├── lateral-movement.yml
├── data-exfiltration.yml
├── suspicious-port.yml
├── credential-access.yml
├── privilege-escalation.yml
├── log-clearing.yml
├── phishing-delivery.yml
├── exploit-kev.yml
└── recon-scanning.yml
```

### Rule Format (Standard Sigma + GATRA Extensions)

```yaml
title: C2 Beaconing to Unpatched Critical Asset
id: gatra-sigma-001
status: stable
description: Detects regular-interval outbound connections to critical assets with unpatched KEV CVEs
logsource:
  category: network_connection
  product: any
detection:
  selection:
    direction: outbound
    duration|gte: 60
  asset_check:
    dst_ip|asset_criticality: critical
    dst_ip|asset_kev: true
  filter:
    dst_ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  condition: selection and asset_check and not filter
fields:
  - src_ip
  - dst_ip
  - port
  - duration
  - bytes_sent
falsepositives:
  - Legitimate keep-alive connections
  - Health check services
level: critical
tags:
  - attack.command_and_control
  - attack.t1071
# GATRA extensions
gatra_agent: taa
mitre_technique: T1071
kill_chain_phase: c2
```

### index.json

```json
{
  "version": "1.0.0",
  "rules": [
    { "file": "c2-beaconing.yml", "id": "gatra-sigma-001", "level": "critical" },
    { "file": "brute-force.yml", "id": "gatra-sigma-002", "level": "critical" },
    { "file": "dns-tunneling.yml", "id": "gatra-sigma-003", "level": "high" },
    { "file": "lateral-movement.yml", "id": "gatra-sigma-004", "level": "critical" },
    { "file": "data-exfiltration.yml", "id": "gatra-sigma-005", "level": "critical" },
    { "file": "suspicious-port.yml", "id": "gatra-sigma-006", "level": "high" },
    { "file": "credential-access.yml", "id": "gatra-sigma-007", "level": "critical" },
    { "file": "privilege-escalation.yml", "id": "gatra-sigma-008", "level": "high" },
    { "file": "log-clearing.yml", "id": "gatra-sigma-009", "level": "critical" },
    { "file": "phishing-delivery.yml", "id": "gatra-sigma-010", "level": "high" },
    { "file": "exploit-kev.yml", "id": "gatra-sigma-011", "level": "critical" },
    { "file": "recon-scanning.yml", "id": "gatra-sigma-012", "level": "high" }
  ]
}
```

### assets.json

~15 telco infrastructure assets matching connector.ts host_id patterns:
- Core routers (Jakarta, Surabaya)
- Edge gateways
- Firewalls
- DNS servers
- SIEM collectors
- Subscriber auth servers
- Billing systems

Each asset includes:
- `name`, `type`, `criticality` (critical/high/medium/low)
- `os`, `firmware`, `firmware_latest`, `firmware_upgrade_required`
- `hardware_model`, `hardware_eol`
- `location`, `owner`, `network_zone` (core/edge/management/dmz)
- `patch_status` (current/behind/critical), `last_patched`
- `cves[]` — each with `id`, `cvss`, `epss`, `patched`, `kev`
- `services[]` — running services (bgp, mpls, snmp, etc.)

## 2. Matching Engine

### File

`src/services/sigma-engine.ts`

### Design

Stateless, pure functions. Caller provides rules + events + assets, gets matches back.

### Types

```typescript
interface SigmaRule {
  id: string
  title: string
  status: string
  description: string
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical'
  logsource: { category?: string; product?: string }
  detection: {
    selections: Map<string, FieldMatcher[]>
    condition: string
  }
  fields: string[]
  tags: string[]
  falsepositives: string[]
  // GATRA extensions
  gatra_agent?: string
  mitre_technique?: string
  kill_chain_phase?: string
}

interface FieldMatcher {
  field: string
  modifier: string        // '', 'gte', 'lte', 'contains', 'startswith', 'endswith', 're', 'cidr', 'exists', 'asset_*'
  values: unknown[]
  negate: boolean
}

interface AssetRecord {
  name: string
  type: string
  criticality: string
  os: string
  firmware: string
  firmware_latest: string
  firmware_upgrade_required: boolean
  hardware_model: string
  hardware_eol: string
  location: string
  owner: string
  network_zone: string
  patch_status: string
  last_patched: string
  cves: Array<{ id: string; cvss: number; epss: number; patched: boolean; kev: boolean }>
  services: string[]
}

interface SigmaMatch {
  rule_id: string
  title: string
  level: string
  description: string
  matched_fields: Record<string, unknown>
  tags: string[]
  mitre_technique?: string
  gatra_agent?: string
  kill_chain_phase?: string
  asset_context?: {
    host_id: string
    criticality: string
    unpatched_cves: string[]
    firmware_outdated: boolean
    patch_status: string
    risk_factors: string[]
  }
  risk_impact: string
  recommended_actions: string[]
}
```

### Supported Modifiers

**Standard Sigma:**
| Modifier | Behavior |
|----------|----------|
| (none) | Exact match or string contains |
| `gte`, `lte`, `gt`, `lt` | Numeric comparison |
| `contains` | Substring match |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `re` | Regex match |
| `cidr` | CIDR range check |
| `exists` | Field presence |

**GATRA asset extensions:**
| Modifier | Behavior |
|----------|----------|
| `asset_criticality` | Resolve host → asset, check criticality tier |
| `asset_has_cve` | True if asset has any unpatched CVE |
| `asset_cvss_gte` | True if asset has unpatched CVE with CVSS >= value |
| `asset_kev` | True if asset has CISA KEV-listed unpatched CVE |
| `asset_patch_status` | Check patch status (current/behind/critical) |
| `asset_firmware_outdated` | True if firmware != firmware_latest |
| `asset_zone` | Check network zone (core/edge/management/dmz) |

Asset resolution: engine looks up the field value (e.g., `dst_ip` or `host_id`) in assets.json keys. If no match, asset modifiers evaluate to false (rule doesn't fire for unknown assets).

### Condition Evaluation

Supports:
- `selection and not filter`
- `selection or alternative`
- `selection and asset_check and not filter`
- `1 of selection*` (any selection matching the glob)
- `all of selection*`

Parsed into a simple boolean AST. No nested parentheses needed for v1.

### Public API

```typescript
function loadRules(yamls: string[]): SigmaRule[]
function loadAssets(json: string): Map<string, AssetRecord>
function matchEvent(
  event: Record<string, unknown>,
  rules: SigmaRule[],
  assets: Map<string, AssetRecord>
): SigmaMatch[]
```

## 3. API Endpoint

### File

`api/sigma-scan.js` (Vercel Edge Function)

### Endpoints

**POST /api/sigma-scan** — Scan events

Request:
```json
{
  "events": [
    { "src_ip": "203.0.113.5", "dst_ip": "10.45.2.1", "host_id": "TELCO-CORE-JKT-01", "port": 443, "duration": 120, "direction": "outbound" }
  ]
}
```

Response:
```json
{
  "results": [
    {
      "event_index": 0,
      "matches": [
        {
          "rule_id": "gatra-sigma-001",
          "title": "C2 Beaconing to Unpatched Critical Asset",
          "level": "critical",
          "matched_fields": { "direction": "outbound", "duration": 120 },
          "asset_context": {
            "host_id": "TELCO-CORE-JKT-01",
            "criticality": "critical",
            "unpatched_cves": ["CVE-2025-20188 (CVSS 9.8, KEV)"],
            "firmware_outdated": true,
            "patch_status": "behind",
            "risk_factors": ["KEV-listed CVE unpatched", "firmware 2 versions behind", "core network zone"]
          },
          "risk_impact": "Critical infrastructure with known exploitable vulnerability under active C2 targeting",
          "recommended_actions": ["Immediate isolation", "Emergency patch CVE-2025-20188", "Firmware upgrade to 7.11.2"],
          "tags": ["attack.command_and_control", "attack.t1071"],
          "mitre_technique": "T1071",
          "gatra_agent": "taa",
          "kill_chain_phase": "c2"
        }
      ]
    }
  ],
  "rules_count": 12,
  "scanned_at": "2026-04-03T12:00:00Z",
  "engine_version": "1.0.0"
}
```

**GET /api/sigma-scan?action=rules** — List rules

Response:
```json
{
  "rules": [
    { "id": "gatra-sigma-001", "title": "C2 Beaconing to Unpatched Critical Asset", "level": "critical", "mitre_technique": "T1071", "gatra_agent": "taa", "tags": ["attack.command_and_control", "attack.t1071"] }
  ],
  "count": 12,
  "version": "1.0.0"
}
```

### Caching

- Rules + assets fetched from `public/sigma-rules/` on first request
- In-memory cache, 10 minute TTL
- Max 50 events per POST request
- Standard CORS via `_cors.js`
- Cache-Control: `public, max-age=60, s-maxage=60, stale-while-revalidate=30`

## 4. MCP Tools

Added to `docs/MCP/gatra_mcp_config.md`:

### gatra_sigma_scan

- **Description:** Scan structured log events against Sigma detection rules with asset context enrichment
- **Input:** `events` (JSON array of log event objects)
- **Output:** Matches per event with rule details, MITRE mapping, asset context, risk impact, recommended actions
- **Calls:** POST /api/sigma-scan (Edge API, no gatra-local dependency)

### gatra_sigma_rules

- **Description:** List loaded Sigma detection rules with metadata
- **Input:** None
- **Output:** Rule count, list with id/title/level/mitre_technique/tags
- **Calls:** GET /api/sigma-scan?action=rules

## 5. SOC Chat Integration

### File

`src/panels/soc-chat-panel.ts`

### Changes

1. **ADA agent trigger patterns** — add: `/\bsigma\b|log.*scan|log.*analyz|detect.*event|match.*rule/i`

2. **JSON detection** — when analyst pastes a JSON object, ADA auto-runs Sigma matching via the `/api/sigma-scan` endpoint

3. **Result rendering** — display matches with:
   - Rule title and severity (color-coded)
   - Matched fields
   - Asset context (criticality, unpatched CVEs, firmware status)
   - Risk factors and recommended actions
   - Agent routing suggestion (@taa, @cra, etc.)

4. **ADA capability description** — update existing YARA line (~line 435) to include Sigma:
   ```
   — Signature matching: YARA rules (...) and Sigma log detection (12 rules, asset-aware)
   ```

### Example Chat Flow

```
Analyst: analyze this {"src_ip":"203.0.113.5","dst_ip":"10.45.2.1","host_id":"TELCO-CORE-JKT-01","port":443,"duration":120,"direction":"outbound"}

ADA: Sigma scan complete — 1 match

  CRITICAL: C2 Beaconing to Unpatched Critical Asset
  Rule: gatra-sigma-001 | MITRE: T1071 (Command and Control)
  Matched: direction=outbound, duration=120 (>=60)

  Asset: TELCO-CORE-JKT-01 (Core Router Jakarta Primary)
  Criticality: CRITICAL | Zone: core
  Unpatched: CVE-2025-20188 (CVSS 9.8, CISA KEV)
  Firmware: 7.9.1 → 7.11.2 needed
  Patch status: BEHIND (last patched 2025-11-15)

  Risk: Critical infrastructure with known exploitable vulnerability under active C2 targeting
  Actions: Immediate isolation, Emergency patch CVE-2025-20188, Firmware upgrade to 7.11.2
  Agent: @taa for deep behavioral analysis of 203.0.113.5
```

## Out of Scope (v1)

- Dedicated Sigma Rules UI panel
- Live alert auto-enrichment (Sigma matching on every GATRA alert)
- pySigma / Python backend integration
- Rule hot-reload / rule editor UI
- Dynamic asset inventory (CMDB API)
- Nested parentheses in condition expressions

## File Manifest

| File | Action | Description |
|------|--------|-------------|
| `public/sigma-rules/index.json` | Create | Rule manifest |
| `public/sigma-rules/assets.json` | Create | Asset inventory (~15 assets) |
| `public/sigma-rules/*.yml` | Create | 12 Sigma rule files |
| `src/services/sigma-engine.ts` | Create | Matching engine |
| `api/sigma-scan.js` | Create | Edge Function endpoint |
| `src/panels/soc-chat-panel.ts` | Modify | ADA agent Sigma integration |
| `docs/MCP/gatra_mcp_config.md` | Modify | Add 2 MCP tool definitions |

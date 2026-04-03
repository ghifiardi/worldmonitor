# Sigma Rules Engine for GATRA SOC

**Date:** 2026-04-03
**Status:** Approved (revised after review)
**Scope:** v1 — Edge-native Sigma matching with asset context enrichment

---

## Overview

A pure TypeScript, Edge-native event detection engine that evaluates normalized structured JSON events against a constrained Sigma-compatible rule set, enriched with static asset context for risk-aware prioritization. Complements existing YARA file scanning with event/log-level detection. Integrated via MCP tools and SOC chat (ADA agent).

## Goals

- Enable Sigma-based event detection in GATRA SOC
- Enrich detections with static asset context (CVEs, firmware, patch status, criticality)
- Expose scan capability via Edge API, MCP tools, and SOC chat
- Prove Edge-native matching on normalized JSON events with 12 seed rules
- Compute effective severity by combining rule level + asset risk posture

## Non-Goals

- Full Sigma specification compatibility (v1 supports a constrained subset)
- Streaming detection pipeline or real-time alert auto-enrichment
- Dynamic CMDB integration (static asset file only)
- Autonomous response execution (recommendations only, no automation authority)
- High-volume SIEM replacement
- Nested parentheses in condition expressions

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Log format | Normalized JSON (canonical schema) | Predictable field names for rule portability |
| Engine runtime | Browser/Edge (TypeScript) | No native deps (unlike YARA). Zero latency, works offline from gatra-local |
| Rule format | Standard Sigma YAML + GATRA extensions | Community rule compatibility + tight MITRE/agent integration |
| Integration points | MCP tools + SOC chat | Sufficient for v1. No dedicated panel needed yet |
| Rule count | 12 seed rules | Prove the engine, expand later. Structured for growth |
| Asset context | Static JSON file | Self-contained, easy to demo. Replaceable with CMDB API later |
| Default matcher | Strict equality | No implicit substring matching — use `contains` modifier explicitly |
| Caching | Best-effort in-memory per runtime instance | May vary across cold starts/regions; sufficient for v1 |

## Architecture

```
Analyst (SOC Chat / MCP)
    |
    v
POST /api/sigma-scan ---- GET /api/sigma-scan?action=rules
    |
    v
+-------------------------------------+
|  Edge Function (api/sigma-scan.js)  |
|  - Fetches & caches rules (10 min)  |
|  - Fetches & caches assets (10 min) |
|  - Validates request shape           |
|  - Delegates to sigma-engine        |
|  - Max 50 events per request        |
+---------------+---------------------+
                |
                v
+-------------------------------------+
|  Sigma Engine (src/services/)       |
|  - sigma-engine.ts (core matching)  |
|  - Parses YAML -> SigmaRule[]       |
|  - Normalizes event fields          |
|  - Evaluates detection + conditions |
|  - Resolves asset context           |
|  - Computes effective severity      |
|  - Returns SigmaMatch[]            |
+---------------+---------------------+
                |
                v
+-------------------------------------+
|  Static Files (public/sigma-rules/) |
|  - index.json (manifest)            |
|  - assets.json (asset inventory)    |
|  - 12 YAML rule files               |
+-------------------------------------+
```

## 1. Normalized Event Schema

All events — regardless of source format — are matched against a canonical field model. The API accepts arbitrary JSON, but the engine normalizes field names before rule evaluation.

### Canonical Fields

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | string | Source IP address (IPv4/IPv6) |
| `dst_ip` | string | Destination IP address |
| `src_port` | number | Source port |
| `dst_port` | number | Destination port |
| `host_id` | string | Asset identifier (e.g., TELCO-CORE-JKT-01) |
| `hostname` | string | Host FQDN or short name |
| `event_type` | string | Event category (network_connection, authentication, process, etc.) |
| `user` | string | Username or principal |
| `action` | string | Action performed (login, exec, connect, deny, etc.) |
| `protocol` | string | Network protocol (tcp, udp, icmp, http, dns, etc.) |
| `direction` | string | Traffic direction (inbound, outbound, internal, local) |
| `duration` | number | Connection/session duration in seconds |
| `bytes_sent` | number | Bytes sent |
| `bytes_received` | number | Bytes received |
| `port` | number | Alias for dst_port (for convenience) |
| `timestamp` | string | ISO 8601 timestamp |
| `details` | string | Free-text event description |
| `classification` | string | Threat classification label |
| `session_id` | string | Session identifier |

### Field Normalization Aliases

The engine maps common alternative field names to canonical fields before matching:

| Alias | Canonical |
|-------|-----------|
| `destination.ip`, `dest_ip`, `dst` | `dst_ip` |
| `source.ip`, `src` | `src_ip` |
| `destination.port`, `dport`, `sport` | `dst_port` / `src_port` |
| `device_id`, `asset_id` | `host_id` |
| `event.action` | `action` |
| `username`, `login` | `user` |

Sigma rules target canonical field names. Unmapped fields pass through as-is and can be matched directly.

## 2. Rule Files

### Location

`public/sigma-rules/`

### Directory Structure

```
public/sigma-rules/
+-- index.json              # Rule manifest with governance metadata
+-- assets.json             # Asset inventory with CVEs, firmware, patch status
+-- c2-beaconing.yml
+-- brute-force.yml
+-- dns-tunneling.yml
+-- lateral-movement.yml
+-- data-exfiltration.yml
+-- suspicious-port.yml
+-- credential-access.yml
+-- privilege-escalation.yml
+-- log-clearing.yml
+-- phishing-delivery.yml
+-- exploit-kev.yml
+-- recon-scanning.yml
```

### Rule Format (Standard Sigma + GATRA Extensions)

```yaml
title: C2 Beaconing to Unpatched Critical Asset
id: gatra-sigma-001
status: stable
description: >
  Detects regular-interval outbound connections where the source host is a
  critical asset with unpatched CISA KEV CVEs. Targets public-facing
  infrastructure that may have both internal host_id and external-facing IPs.
logsource:
  category: network_connection
  product: any
detection:
  selection:
    direction: outbound
    duration|gte: 60
  asset_check:
    host_id|asset_criticality: critical
    host_id|asset_kev: true
  condition: selection and asset_check
fields:
  - src_ip
  - dst_ip
  - host_id
  - port
  - duration
  - bytes_sent
falsepositives:
  - Legitimate keep-alive connections
  - Health check services
level: high
tags:
  - attack.command_and_control
  - attack.t1071
# GATRA extensions
gatra_agent: taa
mitre_technique: T1071
kill_chain_phase: c2
recommended_actions:
  - Investigate destination IP reputation
  - Check for C2 framework signatures
  - Consider isolation if confirmed
```

Note: `recommended_actions` is rule-authored. The engine may append additional asset-derived actions (e.g., "patch CVE-X", "upgrade firmware") but these are clearly separated in the output.

### index.json

```json
{
  "version": "1.0.0",
  "rules": [
    { "file": "c2-beaconing.yml", "id": "gatra-sigma-001", "level": "high", "status": "stable", "enabled": true },
    { "file": "brute-force.yml", "id": "gatra-sigma-002", "level": "high", "status": "stable", "enabled": true },
    { "file": "dns-tunneling.yml", "id": "gatra-sigma-003", "level": "high", "status": "stable", "enabled": true },
    { "file": "lateral-movement.yml", "id": "gatra-sigma-004", "level": "medium", "status": "stable", "enabled": true },
    { "file": "data-exfiltration.yml", "id": "gatra-sigma-005", "level": "high", "status": "stable", "enabled": true },
    { "file": "suspicious-port.yml", "id": "gatra-sigma-006", "level": "medium", "status": "stable", "enabled": true },
    { "file": "credential-access.yml", "id": "gatra-sigma-007", "level": "high", "status": "stable", "enabled": true },
    { "file": "privilege-escalation.yml", "id": "gatra-sigma-008", "level": "medium", "status": "stable", "enabled": true },
    { "file": "log-clearing.yml", "id": "gatra-sigma-009", "level": "high", "status": "stable", "enabled": true },
    { "file": "phishing-delivery.yml", "id": "gatra-sigma-010", "level": "medium", "status": "stable", "enabled": true },
    { "file": "exploit-kev.yml", "id": "gatra-sigma-011", "level": "high", "status": "stable", "enabled": true },
    { "file": "recon-scanning.yml", "id": "gatra-sigma-012", "level": "medium", "status": "stable", "enabled": true }
  ]
}
```

Rules with `"enabled": false` are skipped during loading. `status` follows Sigma convention (stable, test, experimental, deprecated).

Note: Rule base levels are set conservatively (high/medium). The effective severity is computed at match time by combining rule level + asset context (see Section 6).

### assets.json

~15 telco infrastructure assets matching connector.ts host_id patterns. Assets may be internal-only, public-facing, or both (e.g., a core router with a management IP and a public BGP peering IP).

**Asset identifier fields** (used for resolution):

```json
{
  "TELCO-CORE-JKT-01": {
    "host_id": "TELCO-CORE-JKT-01",
    "ip_addresses": ["10.1.1.1", "203.0.113.10"],
    "hostnames": ["core-rtr-jkt-01.indosat.net"],
    "aliases": ["jkt-core-primary"],

    "name": "Core Router Jakarta Primary",
    "type": "network_device",
    "criticality": "critical",
    "os": "Cisco IOS XR 7.9.1",
    "firmware": "7.9.1",
    "firmware_latest": "7.11.2",
    "firmware_upgrade_required": true,
    "hardware_model": "Cisco ASR 9000",
    "hardware_eol": "2028-06-30",
    "location": "Jakarta",
    "owner": "NOC-Core",
    "network_zone": "core",
    "patch_status": "behind",
    "last_patched": "2025-11-15",
    "cves": [
      { "id": "CVE-2025-20188", "cvss": 9.8, "epss": 0.72, "patched": false, "kev": true },
      { "id": "CVE-2025-20156", "cvss": 7.5, "epss": 0.35, "patched": false, "kev": false }
    ],
    "services": ["bgp", "mpls", "snmp"]
  }
}
```

The engine builds a reverse lookup index at load time: IP -> asset, hostname -> asset, alias -> asset, host_id -> asset.

## 3. Asset Resolution

### Resolution Order

When a rule uses an `|asset_*` modifier on a field (e.g., `host_id|asset_criticality`), the engine resolves the field value to an asset record using this deterministic order:

1. **host_id** — exact match against asset keys
2. **hostname** — match against `hostnames[]` array
3. **IP address** — match against `ip_addresses[]` array
4. **alias** — match against `aliases[]` array

The first match wins. If no asset is found, all `|asset_*` modifiers on that field evaluate to `false` (the clause does not match).

### Conflict Behavior

- If `host_id` and `dst_ip` in the same event resolve to different assets, each field resolves independently. The rule author controls which field the asset modifier is applied to.
- If a single field value matches multiple assets (e.g., shared IP), the first asset in iteration order wins. This is a known limitation for v1; a future version could annotate ambiguity.

## 4. Matching Engine

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
    clauses: Record<string, FieldMatcher[]>  // named blocks from YAML (selection, filter, asset_check, etc.)
    condition: string
  }
  fields: string[]
  tags: string[]
  falsepositives: string[]
  recommended_actions: string[]  // rule-authored
  // GATRA extensions
  gatra_agent?: string
  mitre_technique?: string
  kill_chain_phase?: string
}

interface FieldMatcher {
  field: string       // canonical field name (before |modifier)
  modifier: string    // '', 'gte', 'lte', 'contains', etc.
  values: unknown[]   // values to match against (OR within a single matcher)
  negate: boolean
}

interface AssetRecord {
  host_id: string
  ip_addresses: string[]
  hostnames: string[]
  aliases: string[]
  name: string
  type: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  os: string
  firmware: string
  firmware_latest: string
  firmware_upgrade_required: boolean
  hardware_model: string
  hardware_eol: string
  location: string
  owner: string
  network_zone: 'core' | 'edge' | 'management' | 'dmz' | 'subscriber'
  patch_status: 'current' | 'behind' | 'critical'
  last_patched: string
  cves: Array<{ id: string; cvss: number; epss: number; patched: boolean; kev: boolean }>
  services: string[]
}

interface SigmaMatch {
  rule_id: string
  title: string
  rule_level: string              // as authored in the rule
  effective_severity: string      // computed: rule_level + asset context
  description: string

  // Rule-authored metadata
  rule_metadata: {
    tags: string[]
    mitre_technique?: string
    gatra_agent?: string
    kill_chain_phase?: string
    falsepositives: string[]
    recommended_actions: string[]  // from the rule YAML
  }

  // Engine-derived enrichment
  enrichment: {
    matched_fields: Record<string, unknown>
    risk_factors: string[]         // computed from asset context
    severity_reason: string        // why effective_severity differs from rule_level
  }

  // Asset context (present only if asset was resolved)
  asset_context?: {
    host_id: string
    name: string
    criticality: string
    unpatched_cves: string[]
    firmware_outdated: boolean
    patch_status: string
    network_zone: string
    hardware_eol: string
  }

  // Combined recommendations (rule-authored + asset-derived)
  recommendations: string[]
}
```

### Supported Modifiers

**Standard Sigma:**

| Modifier | Behavior |
|----------|----------|
| (none) | **Strict equality** for scalars. For arrays: exact membership. Case-sensitive. |
| `contains` | Substring match (case-insensitive) |
| `startswith` | Prefix match (case-insensitive) |
| `endswith` | Suffix match (case-insensitive) |
| `re` | ECMAScript regex match. Max pattern length: 200 chars. Compiled with try/catch; invalid patterns skip the matcher with a warning. |
| `gte`, `lte`, `gt`, `lt` | Numeric comparison. Non-numeric values → no match. |
| `cidr` | CIDR range check for IP fields |
| `exists` | Field presence check (true/false) |

**GATRA asset extensions:**

| Modifier | Behavior |
|----------|----------|
| `asset_criticality` | Resolve field value → asset, check `criticality` |
| `asset_has_cve` | True if resolved asset has any unpatched CVE |
| `asset_cvss_gte` | True if resolved asset has unpatched CVE with CVSS >= value |
| `asset_kev` | True if resolved asset has CISA KEV-listed unpatched CVE |
| `asset_patch_status` | Check `patch_status` (current/behind/critical) |
| `asset_firmware_outdated` | True if `firmware != firmware_latest` |
| `asset_zone` | Check `network_zone` |

### Condition Grammar (v1)

Explicitly supported grammar:

```
condition   := expr
expr        := term (('and' | 'or') term)*
term        := 'not'? atom
atom        := <clause_name>
             | ('1' | 'all') 'of' <prefix> '*'
```

**Precedence:** `not` > `and` > `or`

**No parentheses** in v1. All expressions are evaluated left-to-right within same-precedence operators.

**Examples:**
- `selection` — single clause
- `not filter` — negated clause
- `selection and not filter` — conjunction with negation
- `selection and asset_check and not filter` — chained conjunction
- `selection or alternative` — disjunction
- `1 of selection*` — any clause whose name starts with "selection"
- `all of check*` — all clauses whose name starts with "check"

**Semantics within a clause:** All field matchers in a clause are AND-ed. Multiple values within a single field matcher are OR-ed (standard Sigma semantics).

### Regex Safety

- Maximum regex pattern length: 200 characters
- Regex compilation wrapped in try/catch; invalid patterns log a warning and skip
- Field values truncated to 10,000 characters before regex evaluation
- Only ECMAScript-compatible regex supported (no lookbehind in older runtimes)
- Rules with invalid regex are loaded but the affected clause always evaluates to false

### Public API

```typescript
function loadRules(yamls: string[]): SigmaRule[]
function loadAssets(json: string): AssetIndex  // { byHostId, byIp, byHostname, byAlias }
function normalizeEvent(event: Record<string, unknown>): Record<string, unknown>
function matchEvent(
  event: Record<string, unknown>,
  rules: SigmaRule[],
  assets: AssetIndex
): SigmaMatch[]
```

## 5. API Endpoint

### File

`api/sigma-scan.js` (Vercel Edge Function)

### Endpoints

**POST /api/sigma-scan** — Scan events

Request:
```json
{
  "events": [
    {
      "src_ip": "203.0.113.5",
      "host_id": "TELCO-CORE-JKT-01",
      "port": 443,
      "duration": 120,
      "direction": "outbound"
    }
  ]
}
```

Response (200):
```json
{
  "results": [
    {
      "event_index": 0,
      "matches": [
        {
          "rule_id": "gatra-sigma-001",
          "title": "C2 Beaconing to Unpatched Critical Asset",
          "rule_level": "high",
          "effective_severity": "critical",
          "description": "...",
          "rule_metadata": {
            "tags": ["attack.command_and_control", "attack.t1071"],
            "mitre_technique": "T1071",
            "gatra_agent": "taa",
            "kill_chain_phase": "c2",
            "falsepositives": ["Legitimate keep-alive connections"],
            "recommended_actions": ["Investigate destination IP reputation"]
          },
          "enrichment": {
            "matched_fields": { "direction": "outbound", "duration": 120 },
            "risk_factors": ["KEV-listed CVE unpatched", "firmware 2 versions behind", "core network zone"],
            "severity_reason": "Elevated high->critical: asset criticality=critical with KEV exposure"
          },
          "asset_context": {
            "host_id": "TELCO-CORE-JKT-01",
            "name": "Core Router Jakarta Primary",
            "criticality": "critical",
            "unpatched_cves": ["CVE-2025-20188 (CVSS 9.8, KEV)"],
            "firmware_outdated": true,
            "patch_status": "behind",
            "network_zone": "core",
            "hardware_eol": "2028-06-30"
          },
          "recommendations": [
            "Investigate destination IP reputation",
            "Check for C2 framework signatures",
            "Emergency patch CVE-2025-20188",
            "Firmware upgrade 7.9.1 -> 7.11.2"
          ]
        }
      ]
    }
  ],
  "rules_loaded": 12,
  "rules_failed": 0,
  "scanned_at": "2026-04-03T12:00:00Z",
  "engine_version": "1.0.0"
}
```

**GET /api/sigma-scan?action=rules** — List rules

Response (200):
```json
{
  "rules": [
    {
      "id": "gatra-sigma-001",
      "title": "C2 Beaconing to Unpatched Critical Asset",
      "level": "high",
      "status": "stable",
      "enabled": true,
      "mitre_technique": "T1071",
      "gatra_agent": "taa",
      "tags": ["attack.command_and_control", "attack.t1071"]
    }
  ],
  "count": 12,
  "version": "1.0.0"
}
```

### Error Contract

| Condition | HTTP Status | Response |
|-----------|-------------|----------|
| Invalid JSON body | 400 | `{ "error": "Invalid JSON body" }` |
| Missing `events` array | 400 | `{ "error": "Request must include 'events' array" }` |
| Empty `events` array | 400 | `{ "error": "Events array must not be empty" }` |
| More than 50 events | 413 | `{ "error": "Maximum 50 events per request", "received": N }` |
| Individual malformed event (not an object) | 200 | Event included in results with `"error": "Invalid event: must be a JSON object"` and empty matches |
| Rules failed to load | 503 | `{ "error": "Failed to load Sigma rules", "details": "..." }` |
| Assets failed to load | 200 | Scan proceeds without asset enrichment; response includes `"warnings": ["Asset inventory unavailable"]` |
| Method not allowed | 405 | `{ "error": "Method not allowed" }` |
| OPTIONS preflight | 204 | Empty body with CORS headers |

Partial success: if some events are valid and some are not, the request succeeds (200) with per-event error annotations. The API never fails the entire batch due to one bad event.

### Caching

- Rules + assets fetched from `public/sigma-rules/` on first request
- Best-effort in-memory cache per runtime instance, 10 minute TTL
- Cache may not persist across cold starts or across edge regions
- Max 50 events per POST request
- Standard CORS via `_cors.js`
- Cache-Control: `public, max-age=60, s-maxage=60, stale-while-revalidate=30`

## 6. Severity and Prioritization

### Effective Severity Computation

Base severity comes from the rule's `level` field. The engine elevates severity based on asset context:

| Condition | Elevation |
|-----------|-----------|
| Asset `criticality` = critical | +1 tier |
| Asset has unpatched CISA KEV CVE | +1 tier |
| Asset `patch_status` = critical | +1 tier |
| Asset `firmware_upgrade_required` = true AND `hardware_eol` within 12 months | +1 tier |

**Cap:** Maximum effective severity is `critical`. Elevations do not stack beyond critical.

**Severity tiers (ordered):** informational < low < medium < high < critical

**No asset resolved:** effective_severity = rule_level (no elevation).

**`severity_reason`** field explains why effective_severity differs from rule_level. If they are the same, this field is an empty string.

### Agent Routing by Severity

| Effective Severity | Suggested Agent | Action Type |
|--------------------|----------------|-------------|
| critical | CRA | Containment candidate (after analyst approval) |
| high | TAA | Deep investigation and behavioral analysis |
| medium | TAA | Standard investigation |
| low / informational | ADA | Monitor and log |

The `gatra_agent` in the rule can override this default routing. Rule-specified agent takes precedence over severity-based default.

## 7. MCP Tools

Added to `docs/MCP/gatra_mcp_config.md`:

### gatra_sigma_scan

- **Description:** Scan structured log events against Sigma detection rules with asset context enrichment
- **Input:** `events` (JSON array of log event objects)
- **Output:** Matches per event with rule details, MITRE mapping, asset context, effective severity, recommendations
- **Calls:** POST /api/sigma-scan (Edge API, no gatra-local dependency)

### gatra_sigma_rules

- **Description:** List loaded Sigma detection rules with metadata and governance status
- **Input:** None
- **Output:** Rule count, list with id/title/level/status/enabled/mitre_technique/tags
- **Calls:** GET /api/sigma-scan?action=rules

## 8. SOC Chat Integration

### File

`src/panels/soc-chat-panel.ts`

### Changes

1. **ADA agent trigger** — Sigma matching triggers when:
   - Analyst explicitly mentions "sigma" (keyword match)
   - Analyst pastes a valid JSON object (auto-detected via `{...}` parsing)
   - Analyst uses explicit intent phrases: "scan this log", "match against rules", "detect threats in"
   - Does NOT trigger on vague phrases like "analyze this" or "detect event trend" — those go through normal ADA response flow

2. **JSON auto-detection** — when a message contains a parseable JSON object, extract it and offer: "Detected a log event. Running Sigma scan..." Then call `/api/sigma-scan`.

3. **Result rendering** — display matches with:
   - Rule title and effective severity (color-coded: critical=red, high=orange, medium=yellow)
   - Matched fields with values
   - Asset context block (if resolved): criticality, unpatched CVEs, firmware, patch status
   - Risk factors and severity elevation reason
   - Combined recommendations (rule-authored + asset-derived)
   - Agent routing suggestion: "Escalate to @taa" or "CRA containment candidate (requires approval)"

4. **ADA capability description** — update existing YARA line (~line 435) to include Sigma:
   ```
   -- Signature matching: YARA rules (...) and Sigma log detection (12 rules, asset-aware)
   ```

### Example Chat Flow

```
Analyst: sigma scan {"src_ip":"203.0.113.5","host_id":"TELCO-CORE-JKT-01","port":443,"duration":120,"direction":"outbound"}

ADA: Sigma scan complete -- 1 match

  CRITICAL (elevated from HIGH): C2 Beaconing to Unpatched Critical Asset
  Rule: gatra-sigma-001 | MITRE: T1071 (Command and Control)
  Matched: direction=outbound, duration=120 (>=60)
  Elevated because: asset criticality=critical, KEV CVE unpatched

  Asset: TELCO-CORE-JKT-01 (Core Router Jakarta Primary)
  Criticality: CRITICAL | Zone: core
  Unpatched: CVE-2025-20188 (CVSS 9.8, CISA KEV)
  Firmware: 7.9.1 -> 7.11.2 needed
  Patch status: BEHIND (last patched 2025-11-15)

  Recommendations:
  1. Investigate destination IP reputation
  2. Check for C2 framework signatures
  3. Emergency patch CVE-2025-20188
  4. Firmware upgrade 7.9.1 -> 7.11.2

  CRA containment candidate (requires analyst approval)
```

## 9. Error Handling

### Rule Loading Errors

| Error | Behavior |
|-------|----------|
| YAML parse failure | Skip rule, increment `rules_failed` counter, log warning |
| Missing required field (id, title, detection, level) | Skip rule, log warning |
| Invalid modifier in detection clause | Load rule, but affected matcher always evaluates to false |
| Invalid regex pattern in `re` modifier | Load rule, but affected matcher always evaluates to false |
| Duplicate rule ID | Last-loaded wins, log warning |

### Asset Loading Errors

| Error | Behavior |
|-------|----------|
| assets.json not found or unparseable | Scan proceeds without asset enrichment. All `asset_*` modifiers evaluate to false. Response includes `warnings` array. |
| Individual asset record malformed | Skip that asset, log warning |

### Event Matching Errors

| Error | Behavior |
|-------|----------|
| Event is not a JSON object | Return `{ event_index, error: "...", matches: [] }` |
| Field value type mismatch (e.g., string vs number for `gte`) | Matcher evaluates to false (no match), no error |
| Regex timeout/catastrophic backtracking | Field value truncated to 10K chars; regex has implicit timeout via pattern length cap |

## 10. Testing Strategy

### Unit Tests (sigma-engine)

| Category | Tests |
|----------|-------|
| YAML parsing | Valid rule, missing fields, malformed YAML, duplicate IDs |
| Modifier: (none) | Exact string match, exact number match, no substring |
| Modifier: contains/startswith/endswith | Case-insensitive substring, prefix, suffix |
| Modifier: gte/lte/gt/lt | Numeric comparisons, type mismatch handling |
| Modifier: re | Valid regex, invalid regex, long pattern rejection |
| Modifier: cidr | IPv4 CIDR matching, non-IP values |
| Modifier: exists | Field present, field absent |
| Modifier: asset_* | Asset resolved, asset not found, each asset modifier |
| Condition parser | `and`, `or`, `not`, `and not`, `1 of`, `all of`, precedence |
| Normalization | Alias mapping, passthrough of unknown fields |
| Severity computation | Elevation logic, cap at critical, no-asset case |

### Golden Tests

12 test fixtures (one per seed rule) with:
- An event that SHOULD match → verify match returned with correct fields
- An event that SHOULD NOT match → verify no match
- Edge case for each rule's specific detection logic

### API Tests

| Test | Expected |
|------|----------|
| Valid POST with 1 event | 200, results array |
| POST with 51 events | 413 |
| POST with empty events | 400 |
| POST with mixed valid/invalid events | 200, per-event errors |
| GET ?action=rules | 200, rules array |
| Invalid method (PUT) | 405 |

## 11. Performance Assumptions

- 12 rules, ~15 assets: scan time per event < 5ms
- 50 events max per request: total < 250ms well within Edge Function limits
- Rule + asset loading: ~50ms on cold start (small YAML files)
- In-memory cache eliminates re-parsing for warm instances
- No heavy computation (no ML, no network calls during matching)
- Edge Function memory: well under 128MB default

## Out of Scope (v1)

- Dedicated Sigma Rules UI panel
- Live alert auto-enrichment (Sigma matching on every GATRA alert)
- pySigma / Python backend integration
- Rule hot-reload / rule editor UI
- Dynamic asset inventory (CMDB API)
- Nested parentheses in condition expressions
- Duplicate suppression / correlation across events
- Telemetry counters (rules loaded, match rates, scan times)

## File Manifest

| File | Action | Description |
|------|--------|-------------|
| `public/sigma-rules/index.json` | Create | Rule manifest with governance metadata |
| `public/sigma-rules/assets.json` | Create | Asset inventory (~15 assets with identifiers) |
| `public/sigma-rules/*.yml` | Create | 12 Sigma rule files |
| `src/services/sigma-engine.ts` | Create | Matching engine with normalization + severity |
| `api/sigma-scan.js` | Create | Edge Function endpoint with error contract |
| `src/panels/soc-chat-panel.ts` | Modify | ADA agent Sigma integration |
| `docs/MCP/gatra_mcp_config.md` | Modify | Add 2 MCP tool definitions |

# GATRA MCP Configuration Documentation

**Version:** 1.0  
**Date:** 2026-04-02  
**Author:** Raditio Ghifiardi — VP Security Strategy & Architecture, IOH  
**Platform:** PT Numedia Atrya Dinamika — GATRA SOC Platform

---

## Overview

GATRA (Multi-Agent AI-Driven Security Operations Center) exposes its SOC capabilities via a Model Context Protocol (MCP) server. This document describes all available MCP tools, their parameters, and usage guidance for integration with AI agents (Claude, ChatGPT, Cursor, etc.).

The GATRA MCP server provides 13 tools organized across four functional categories:

- **SOC Monitoring** — Status and alert visibility
- **Response & Enforcement** — IP blocking, escalation, alert resolution
- **YARA Threat Scanning** — File-level malware detection
- **Sigma Log Detection** — Structured log event detection against Sigma rules
- **ResponseGate** — Human-in-the-loop approval workflow

---

## MCP Server Registration

To register GATRA as an MCP server in your AI client, add the following to your MCP configuration:

```json
{
  "mcpServers": {
    "gatra": {
      "type": "url",
      "url": "https://<your-gatra-host>/mcp",
      "name": "gatra"
    }
  }
}
```

> Replace `<your-gatra-host>` with your GATRA deployment endpoint.

---

## Tool Reference

### 1. `gatra_status`

**Category:** SOC Monitoring  
**Description:** Returns the current GATRA SOC status including total events, alert counts, blocked IPs, and registered agents.

**Parameters:** None

**Response Fields:**

| Field | Type | Description |
|---|---|---|
| `total_events` | integer | Total events processed since deployment |
| `total_alerts` | integer | Total alerts generated |
| `active_alerts` | integer | Currently open/active alerts |
| `blocked_ips` | integer | Number of currently blocked IPs |
| `agents_registered` | integer | Number of registered AI agents |
| `events_last_hour` | integer | Events in the last 60 minutes |
| `agents` | array | Per-agent breakdown (id, name, event/alert counts, first/last seen) |

**Example Usage:**
```
gatra_status()
```

---

### 2. `gatra_alerts`

**Category:** SOC Monitoring  
**Description:** Lists recent security alerts with optional filtering by severity and result count.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `limit` | integer | No | 50 | Maximum number of alerts to return |
| `severity` | string (enum) | No | — | Filter: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

**Response Fields per Alert:**

| Field | Description |
|---|---|
| `alert_id` | Unique alert identifier (e.g., `ALR-fe070304c587`) |
| `timestamp` | ISO 8601 alert timestamp |
| `rule_id` | Detection rule identifier (e.g., `AAIT-103`) |
| `rule_name` | Human-readable rule name |
| `severity` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `priority` | P1–P4 priority classification |
| `confidence` | Detection confidence score (0.0–1.0) |
| `agent_id` | Agent that triggered the alert |
| `detection_method` | Detection method used (e.g., `windowed_rule`) |
| `description` | Natural language alert description |
| `status` | `NEW` / `ESCALATED` / `CLOSED` |
| `mitre_techniques` | JSON array of MITRE ATT&CK mappings |
| `response_actions` | Recommended response actions |

**Example Usage:**
```
gatra_alerts(severity="HIGH", limit=20)
```

---

### 3. `gatra_block_ip`

**Category:** Response & Enforcement  
**Description:** Submits an IP block request through the GATRA ResponseGate. Requests are auto-approved or queued for human review depending on `auto_block_enabled` configuration and confidence/severity thresholds.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `ip` | string | **Yes** | — | IP address, hostname, or domain:port to block |
| `reason` | string | **Yes** | — | Human-readable justification for the block |
| `confidence` | float | No | 0.8 | Confidence score (0.0–1.0) |
| `severity` | string (enum) | No | `HIGH` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

**Response Fields:**

| Field | Description |
|---|---|
| `status` | `pending_approval` or `approved` |
| `request_id` | ResponseGate request ID (e.g., `REQ-9931135a4825`) |
| `gate_decision` | Approval decision rationale |
| `message` | Action confirmation message |

> **Note:** When `auto_block_enabled` is `false`, all requests enter a pending queue and require human approval via `gatra_approve` or `gatra_approve_all`.

**Example Usage:**
```
gatra_block_ip(
  ip="moneroocean.stream",
  reason="Known XMR mining pool — T1496 Resource Hijacking",
  severity="HIGH",
  confidence=0.95
)
```

---

### 4. `gatra_unblock_ip`

**Category:** Response & Enforcement  
**Description:** Removes an IP address from the GATRA blocklist.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ip` | string | **Yes** | IP address or domain to unblock |

**Example Usage:**
```
gatra_unblock_ip(ip="192.168.1.100")
```

---

### 5. `gatra_blocked`

**Category:** SOC Monitoring  
**Description:** Returns a list of all currently blocked IP addresses with block reasons and timestamps.

**Parameters:** None

**Response Fields per Entry:**

| Field | Description |
|---|---|
| `ip` | Blocked IP/domain |
| `reason` | Block justification |
| `alert_id` | Associated alert ID (if applicable) |
| `blocked_at` | Timestamp when block was applied |
| `expires_at` | Expiry timestamp (null = permanent) |

**Example Usage:**
```
gatra_blocked()
```

---

### 6. `gatra_escalate`

**Category:** Response & Enforcement  
**Description:** Escalates alerts matching a given target. Matching alerts are marked as `ESCALATED` in the SOC queue.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `target` | string | **Yes** | MITRE technique ID (e.g., `T1059`), severity level (`HIGH`, `CRITICAL`), or specific alert ID |

**Response Fields:**

| Field | Description |
|---|---|
| `status` | `escalated` |
| `target` | The escalation target used |
| `escalated_count` | Number of alerts escalated |
| `alert_ids` | Array of escalated alert IDs |

**Example Usage:**
```
gatra_escalate(target="T1496")
gatra_escalate(target="CRITICAL")
gatra_escalate(target="ALR-fe070304c587")
```

---

### 7. `gatra_resolve_alerts`

**Category:** Response & Enforcement  
**Description:** Bulk-resolves GATRA alerts matching provided filters. Used for alert storm cleanup, false positive management, or closing confirmed incidents.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `resolution` | string (enum) | **Yes** | — | `FALSE_POSITIVE`, `TRUE_POSITIVE`, `DUPLICATE`, `STORM`, `TUNING_REQUIRED` |
| `agent_id` | string | No | All agents | Filter by agent ID |
| `rule_id` | string | No | All rules | Filter by rule ID (e.g., `AAIT-103`) |
| `severity` | string (enum) | No | All severities | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status_filter` | string (enum) | No | `NEW` | `NEW`, `ESCALATED`, `ALL` |
| `note` | string | No | — | Audit trail note (max 500 characters) |

**Response Fields:**

| Field | Description |
|---|---|
| `success` | Boolean outcome |
| `affected` | Number of alerts resolved |
| `resolution` | Resolution classification applied |
| `timestamp` | Resolution timestamp |
| `message` | Summary message |

**Example Usage:**
```
gatra_resolve_alerts(
  resolution="TRUE_POSITIVE",
  status_filter="ALL",
  note="YARA confirmed GATRA_Cryptominer — T1496. Analyst: Raditio Ghifiardi, 2026-04-02."
)
```

---

### 8. `gatra_approve_all`

**Category:** ResponseGate  
**Description:** Approves all currently pending ResponseGate actions in a single operation. Used when the SOC analyst has reviewed the pending queue and authorizes bulk execution.

**Parameters:** None

**Response Fields:**

| Field | Description |
|---|---|
| `status` | `approved_all` |
| `count` | Number of actions approved |
| `results` | Array of per-request approval outcomes |

Each result contains: `request_id`, `action`, `target`, `status`, `executed`.

**Example Usage:**
```
gatra_approve_all()
```

> **Security Note:** Always review `gatra_blocked` and pending queue before calling `gatra_approve_all` to prevent unintended bulk enforcement actions.

---

### 9. `gatra_yara_scan`

**Category:** YARA Threat Scanning  
**Description:** Scans a file on the local filesystem against all loaded GATRA YARA rules. Returns match details including rule name, MITRE mapping, matched string offsets, and encoded data.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file_path` | string | **Yes** | Absolute path to the file on the GATRA host filesystem |

**Response Fields:**

| Field | Description |
|---|---|
| `target` | File path scanned |
| `scanned_at` | ISO 8601 scan timestamp |
| `matched` | Boolean — true if any rules matched |
| `match_count` | Number of rules matched |
| `matches` | Array of match objects (see below) |
| `error` | Error message if scan failed (null on success) |

**Match Object Fields:**

| Field | Description |
|---|---|
| `rule_name` | Name of the matching YARA rule |
| `namespace` | Rule namespace (e.g., `gatra_base`) |
| `tags` | Array of rule tags |
| `meta.description` | Rule description |
| `meta.author` | Rule author |
| `meta.severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `meta.mitre` | MITRE ATT&CK technique ID |
| `strings` | Array of matched string locations (offset, identifier, hex-encoded data) |

> **Note:** `file_path` must be accessible on the machine running the GATRA MCP server. Cloud-side paths (e.g., `/mnt/user-data/uploads/`) are not reachable.

**Example Usage:**
```
gatra_yara_scan(file_path="/home/analyst/samples/suspicious.bin")
```

---

### 10. `gatra_yara_rules`

**Category:** YARA Threat Scanning  
**Description:** Returns metadata about currently loaded YARA rules including count, rules directory path, and load status.

**Parameters:** None

**Example Usage:**
```
gatra_yara_rules()
```

---

### 12. `gatra_sigma_scan`

**Category:** Sigma Log Detection  
**Description:** Scans structured log events against Sigma detection rules with asset context enrichment. Returns matches with MITRE mapping, effective severity (computed from rule level + asset risk posture), and actionable recommendations.

**Parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `events` | array | **Yes** | Array of JSON log event objects to scan (max 50) |

**Response Fields:**

| Field | Description |
|---|---|
| `results` | Array of per-event results |
| `results[].event_index` | Index of the event in the input array |
| `results[].matches` | Array of Sigma match objects |
| `results[].matches[].rule_id` | Matching rule ID (e.g., `gatra-sigma-001`) |
| `results[].matches[].title` | Rule title |
| `results[].matches[].rule_level` | Rule-authored severity level |
| `results[].matches[].effective_severity` | Computed severity after asset elevation |
| `results[].matches[].rule_metadata` | Tags, MITRE technique, agent, false positives |
| `results[].matches[].enrichment` | Matched fields, risk factors, severity reason |
| `results[].matches[].asset_context` | Resolved asset details (if found) |
| `results[].matches[].recommendations` | Combined rule + asset-derived recommendations |
| `rules_loaded` | Number of rules successfully loaded |
| `rules_failed` | Number of rules that failed to parse |
| `rules_degraded` | Number of rules loaded with invalid modifiers |
| `warnings` | Array of warning messages |

**Example Usage:**
```
gatra_sigma_scan(events=[{"src_ip":"203.0.113.5","host_id":"TELCO-CORE-JKT-01","port":443,"duration":120,"direction":"outbound"}])
```

> **Note:** Unlike YARA scanning, Sigma rules run entirely on the Edge — no local GATRA backend required. Events are matched against normalized canonical fields; see the spec for supported field aliases.

---

### 13. `gatra_sigma_rules`

**Category:** Sigma Log Detection  
**Description:** Lists all loaded Sigma detection rules with metadata and governance status.

**Parameters:** None

**Response Fields:**

| Field | Description |
|---|---|
| `rules` | Array of rule metadata objects |
| `rules[].id` | Rule ID |
| `rules[].title` | Rule title |
| `rules[].level` | Severity level |
| `rules[].status` | Rule status (stable, test, experimental, deprecated) |
| `rules[].enabled` | Whether rule is active |
| `rules[].mitre_technique` | MITRE ATT&CK technique ID |
| `rules[].gatra_agent` | Recommended GATRA agent |
| `rules[].tags` | Rule tags |
| `count` | Total number of rules |
| `version` | Rule set version |

**Example Usage:**
```
gatra_sigma_rules()
```

---

### 11. `gatra_pending`

**Category:** ResponseGate  
**Description:** Lists all pending ResponseGate actions awaiting human approval.

**Parameters:** None

**Example Usage:**
```
gatra_pending()
```

---

## MITRE ATT&CK Coverage

The following MITRE techniques are covered by GATRA's base ruleset:

| Technique | Name | Tactic | Relevant Tool |
|---|---|---|---|
| T1005 | Data from Local System | Collection | `gatra_alerts` |
| T1074.001 | Local Data Staging | Collection | `gatra_alerts` |
| T1496 | Resource Hijacking (Cryptomining) | Impact | `gatra_yara_scan` |
| T1059 | Command and Scripting Interpreter | Execution | `gatra_escalate` |

---

## ResponseGate Workflow

GATRA enforces a human-in-the-loop control plane for all enforcement actions:

```
gatra_block_ip()
       │
       ▼
 auto_block_enabled?
    YES ──────────────► Block applied immediately
    NO  ──────────────► status: pending_approval
                              │
                              ▼
                    gatra_pending() → review queue
                              │
                              ▼
              gatra_approve(request_id) or gatra_approve_all()
                              │
                              ▼
                       Block applied
```

---

## Alert Severity Matrix

| Severity | Priority | Response SLA | Auto-block Eligible |
|---|---|---|---|
| CRITICAL | P1 | Immediate | Yes (if enabled) |
| HIGH | P2 | < 1 hour | Yes (if enabled) |
| MEDIUM | P3 | < 4 hours | No |
| LOW | P4 | < 24 hours | No |

---

## Resolution Classifications

| Classification | Use Case |
|---|---|
| `TRUE_POSITIVE` | Confirmed malicious activity |
| `FALSE_POSITIVE` | Benign activity incorrectly flagged |
| `DUPLICATE` | Alert already captured by another rule |
| `STORM` | Alert storm — bulk noise from a single event |
| `TUNING_REQUIRED` | Rule needs threshold or logic adjustment |

---

## Registered Agents

GATRA supports multi-agent registration. Each agent is tracked independently:

| Agent ID | Description |
|---|---|
| `claude` | Anthropic Claude — primary SOC AI agent |
| `chatgpt` | OpenAI ChatGPT integration |
| `cursor` | Cursor IDE AI agent |
| `unknown` | Unidentified agent sources |

---

## Security Considerations

- **File path scope:** `gatra_yara_scan` only accesses files on the GATRA host. Never pass cloud-side upload paths.
- **Bulk approval risk:** `gatra_approve_all` approves **all** pending requests. Always verify the pending queue first.
- **Audit trail:** Always include a descriptive `note` when calling `gatra_resolve_alerts` for compliance traceability.
- **Permanent blocks:** All blocks have `expires_at: null` by default — they are permanent until explicitly unblocked via `gatra_unblock_ip`.

---

*Documentation generated from GATRA MCP tool schema — 2026-04-02*  
*PT Numedia Atrya Dinamika | Indosat Ooredoo Hutchison SOC Platform*

# SOC COMMS — Technical Documentation

## GATRA AI-Powered SOC Chat Interface

**Product:** World Monitor — Cyber Variant (soc.gatra.ai)
**Version:** 2.5.6
**Date:** April 1, 2026
**Author:** Raditio Ghifiardi / GATRA Team

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Response Gate — Trust-Gated Execution](#3-response-gate)
4. [Natural Language Processing](#4-natural-language-processing)
5. [MITRE ATT&CK Integration](#5-mitre-attck-integration)
6. [GATRA Agent System](#6-gatra-agent-system)
7. [Command Reference](#7-command-reference)
8. [Natural Language Reference](#8-natural-language-reference)
9. [API Reference](#9-api-reference)
10. [Deployment & Configuration](#10-deployment--configuration)
11. [Security Considerations](#11-security-considerations)

---

## 1. Overview

SOC COMMS is a real-time Security Operations Center communication interface embedded in the World Monitor Cyber dashboard. It provides:

- **5 AI agents** (ADA, TAA, CRA, CLA, RVA) that respond to analyst queries
- **Trust-gated response execution** — destructive actions require analyst approval
- **Hybrid natural language** — regex for instant responses, Groq LLM for ambiguous requests
- **691 MITRE ATT&CK techniques** — full enterprise matrix with contextual lookups
- **IOC scanning** — live lookups against ThreatFox, URLhaus, MalwareBazaar
- **Playbook engine** — guided threat hunts and incident response workflows
- **Cross-tab communication** — BroadcastChannel for multi-tab SOC coordination

### Key URLs

| Resource | URL |
|----------|-----|
| Production | https://soc.gatra.ai |
| SOC Demo | https://soc.gatra.ai/soc-demo.html |
| MITRE Data | https://soc.gatra.ai/data/mitre-techniques.json |
| Intent API | POST https://soc.gatra.ai/api/soc-intent |

---

## 2. Architecture

### Message Processing Pipeline

```
Analyst types message
        │
        ▼
┌───────────────┐
│ Playbook      │──waiting──▶ PlaybookEngine.handleInput()
│ input check   │
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ Slash command? │──yes──▶ processCommand() + alias resolution
│ /block, etc.  │         40+ aliases: /contain → /escalate
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ Playbook cmd? │──yes──▶ handlePlaybookCommand()
│ /hunt, /abort │         /hunt, /respond, /assess, /playbooks
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ Regex intent? │──yes──▶ detectActionIntent() → processCommand()
│ "block 10.."  │         Instant, 0ms, free
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ Looks like    │──yes──▶ classifyWithLLM() → Groq API
│ an action?    │         ~250ms, $0.0003/call
│ (heuristic)   │         Context-aware: resolves "it", "those"
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ IOC detected? │──yes──▶ IOC Scanner (ThreatFox, URLhaus, etc.)
│ IP, hash, URL │
└──────┬────────┘
       │ no
       ▼
┌───────────────┐
│ Agent trigger? │──yes──▶ Route to ADA/TAA/CRA/CLA/RVA
│ pattern match  │         Max 2 agents per message
└──────┬─────────┘
       │ no
       ▼
┌───────────────┐
│ Cyber topic?  │──yes──▶ SOC Knowledge Base response
│ general match │
└──────┬────────┘
       │ no
       ▼
  (no response — message posted to BroadcastChannel only)
```

### Component Map

```
src/panels/soc-chat-panel.ts     Main chat panel (slide-out drawer)
├── ResponseGateClient           Trust-gated response execution
├── detectActionIntent()         Regex-based NL action detection
├── looksLikeAction()            Heuristic for LLM fallback trigger
├── processCommand()             Slash command handler + alias map
├── generateAgentResponse()      Agent-specific response generation
├── extractIoC()                 IOC extraction (IP, hash, URL, domain)
├── GATRA_AGENTS[]               5 agent definitions with trigger patterns
├── MITRE_TECHNIQUE_DB           691 techniques loaded from JSON
└── PlaybookEngine               Guided workflow execution

api/soc-intent.js                Groq LLM intent classification endpoint
public/data/mitre-techniques.json  Full MITRE ATT&CK Enterprise dataset
```

---

## 3. Response Gate

### Purpose

Destructive SOC actions (blocking IPs, killing processes, isolating endpoints) must not execute immediately from chat commands. The Response Gate enforces analyst confirmation before any irreversible action.

### Decision Matrix

| Action | Auto-Execute When | Otherwise |
|--------|------------------|-----------|
| `notify` | Always | — |
| `unblock`, `resume` | Always (reversals are safe) | — |
| `suspend` | severity >= HIGH + confidence >= 80% | Queue for approval |
| `block` | `auto_block_enabled` + severity >= CRITICAL + confidence >= 90% | Queue for approval |
| `kill` | `auto_kill_enabled` + severity >= CRITICAL + confidence >= 95% | Queue for approval |
| `isolate` | Never auto-approved | Always queue |
| Unknown | Never | Always queue |

### Default Configuration

```
auto_block_enabled: false   → ALL blocks require analyst approval
auto_kill_enabled: false    → ALL kills require analyst approval
```

### Gate Workflow

```
1. Analyst: "block 45.133.0.0:4443"

2. System: CRA: ⏳ Block 45.133.0.0:4443 held for approval.
           • Reason: auto-block disabled
           • /approve G001  or  /approve-all

3. Analyst: "approve G001"    (or: "go ahead", "confirmed", "do it")

4. System: CRA: ✅ Approved — block 45.133.0.0:4443 executing.
```

### Gate IDs

- Format: `G001`, `G002`, `G003`... (incrementing per session)
- Case-insensitive: `g001` = `G001`
- Session-scoped: reset on page reload

### Approval Commands

| Command | Effect |
|---------|--------|
| `/approve G001` | Approve specific action |
| `/approve-all` | Approve all pending |
| `/deny G001` | Reject specific action |
| `/deny-all` | Reject all pending |
| `/pending` | List all queued actions |

### Python Backend Mirror

The browser-side `ResponseGateClient` mirrors the Python `ResponseGate` at:
```
gatra-local/response/gate.py
```
Both use identical severity thresholds and action classification, ensuring consistent trust-gate semantics across the SOC dashboard and the local GATRA agent system.

---

## 4. Natural Language Processing

### Three-Layer Architecture

#### Layer 1: Regex Detection (0ms, free)

Handles direct action phrases with 40+ verb synonyms:

```
"block 10.0.0.1"           → /block 10.0.0.1
"contain T1190"             → /escalate T1190
"quarantine web-srv-03"     → /isolate web-srv-03
"please investigate T1059"  → /investigate T1059
"mark T1078 as fp"          → /fp T1078
"go ahead"                  → /approve-all (if pending)
```

**Polite prefix stripping:** "please", "can you", "could you", "go ahead and", "we need to", "let's", "I want to"

#### Layer 2: Heuristic Gate

Before calling the LLM, a heuristic checks if the message looks action-like:

- Must be > 8 characters
- Must NOT be a greeting or pure question
- Must contain action signals: imperative verbs, pronoun references ("it", "those", "the last one"), or action+target patterns

This prevents unnecessary LLM calls for questions like "what is phishing" or "hello".

#### Layer 3: Groq LLM Fallback (~250ms, $0.0003/call)

When regex fails and heuristic triggers, the message is sent to `/api/soc-intent`:

- **Model:** llama-3.3-70b-versatile (Groq)
- **Temperature:** 0.1 (deterministic)
- **Context:** Recent alerts + pending gate actions
- **Confidence threshold:** 0.7 (below = route to agents instead)

**Handles contextual language:**

| Input | LLM Output |
|-------|-----------|
| "that IP from the last alert, block it" | `block 45.133.0.0` (resolves "that IP" from context) |
| "shut down everything related to powershell" | `kill powershell` |
| "the critical ones look bad, escalate them" | `escalate critical` (resolves "them") |
| "deal with the lateral movement stuff" | `investigate T1570` (maps concept to technique) |
| "what is lateral movement" | `null` (correctly identifies as question) |

### Cost Estimate

At typical SOC analyst usage (~100 messages/day):
- ~80% handled by regex (free)
- ~10% handled by heuristic filtering (free)
- ~10% sent to Groq (~10 calls × $0.0003 = $0.003/day)
- **Monthly cost: ~$0.09**

---

## 5. MITRE ATT&CK Integration

### Dataset

- **Source:** Official MITRE STIX 2.1 Enterprise bundle
- **File:** `/public/data/mitre-techniques.json` (225 KB)
- **Coverage:** 691 techniques (216 parent + 475 sub-techniques)
- **14 tactics:** Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
- **Preloaded:** Fetched on module init, cached in memory

### Context-Aware Responses

TAA detects whether the analyst wants a **definition** or an **alert query**:

**Definition query** — "what is T1059", "explain T1190":
```
MITRE ATT&CK: T1059 — Command and Scripting Interpreter
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tactic: Execution

Adversaries may abuse command and script interpreters...

Sub-techniques (13):
  T1059.001 — PowerShell
  T1059.002 — AppleScript
  T1059.003 — Windows Command Shell
  ...

Ref: https://attack.mitre.org/techniques/T1059/
```

**Alert query** — "any alert T1190", "show T1059 alerts", "new threats for T1570":
```
21 active alert(s) for T1190 — Exploit Public-Facing Application:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity: 0 CRIT / 20 HIGH / 1 MED / 0 LOW

  CVE-2025-53521  [high]  95%  3m ago  • DC-EU-FRA
  CVE-2026-33634  [medium]  95%  8m ago  • TECH-HQ-AUS
  ...

Actions: /escalate T1190  ·  /investigate T1190  ·  /dismiss T1190
```

**Detection keywords for alert view:** any, alert, threat, new, active, recent, current, show, list, how many, related, status, update, detect, trigger, match, hit.

---

## 6. GATRA Agent System

### 5 Agents

| Agent | Full Name | Role | Color |
|-------|-----------|------|-------|
| **ADA** | Anomaly Detection Agent | Detects anomalies using Isolation Forest + LSTM | Green (#4caf50) |
| **TAA** | Threat Analysis Agent | Triages alerts using Actor-Critic RL | Orange (#ff9800) |
| **CRA** | Containment & Response Agent | Executes automated containment actions | Red (#f44336) |
| **CLA** | Compliance & Logging Agent | Maintains audit trail and compliance | Blue (#2196f3) |
| **RVA** | Risk & Vulnerability Agent | Assesses vulnerability exposure | Purple (#9c27b0) |

### Trigger Routing

Each agent has regex trigger patterns. When an analyst message matches:
- Up to **2 agents** respond per message
- Agents respond with simulated delay (1.2–3.5s) for realistic UX
- Direct mention (`@ADA`, `@TAA`, etc.) forces routing to that agent

### ADA Capabilities
- IOC scanning (hashes, IPs, URLs, domains)
- Anomaly analysis with Isolation Forest scores
- False positive handling with model feedback
- Alert severity breakdown and technique analysis
- Sandbox/detonation summaries

### TAA Capabilities
- MITRE ATT&CK technique lookup (691 techniques)
- Alert-focused queries (severity, count, infrastructure)
- Triage queue management (ESCALATE / INVESTIGATE / MONITOR)
- APT/threat actor intelligence (20+ named groups with TTPs)
- Kill chain mapping

### CRA Capabilities
- Containment action summaries
- Response action history
- Playbook execution status
- Gate-aware responses (references pending approvals)

### CLA Capabilities
- Incident reporting
- Audit trail generation
- Compliance framework references (NIST, ISO, GDPR, HIPAA, PCI-DSS)
- Forensic evidence guidance
- SIEM integration references

### RVA Capabilities
- CVE analysis and CVSS scoring
- Patch/remediation guidance
- Attack surface assessment
- Cloud security posture
- Supply chain risk evaluation

### IOC Scanner
Automatically triggered when messages contain:
- IPv4 addresses: `192.168.1.1`
- MD5 hashes: 32 hex chars
- SHA1 hashes: 40 hex chars
- SHA256 hashes: 64 hex chars
- URLs: `https://...`
- Domains (only with IOC-context keywords)

Queries ThreatFox, URLhaus, MalwareBazaar, and VirusTotal.

### SOC Knowledge Base
Fallback for general cybersecurity topics not handled by specific agents. Covers:
- Detection, threats, response, compliance, vulnerability
- Architecture, identity, infrastructure
- 40+ cybersecurity domains

---

## 7. Command Reference

### Response Actions (Gate-Protected)

| Command | Effect | Gate |
|---------|--------|------|
| `/block <ip[:port]>` | Queue IP block | Held for approval |
| `/unblock <ip>` | Remove IP block | Immediate |
| `/isolate <host>` | Network-isolate endpoint | Held for approval |
| `/kill <pid>` | Terminate process | Held for approval |
| `/hold <target>` | Pause auto-containment | Immediate |
| `/release <target>` | Resume auto-containment | Immediate |

### Gate Management

| Command | Effect |
|---------|--------|
| `/approve <id>` | Approve specific pending action |
| `/approve-all` | Approve all pending actions |
| `/deny <id>` | Reject specific pending action |
| `/deny-all` | Reject all pending actions |
| `/pending` | List all pending actions |

### Alert Actions (Accept technique ID, alert ID, severity, or name)

| Command | Effect |
|---------|--------|
| `/escalate <target>` | Escalate matching alerts to CRITICAL |
| `/investigate <target>` | Move to INVESTIGATE queue |
| `/dismiss <target>` | Close/suppress alerts |
| `/fp <target>` | Mark as false positive |

**Target resolution:** `T1059` (technique), `ALR-abc123` (alert ID), `critical` (severity), `powershell` (name search)

### Status & Reporting

| Command | Effect |
|---------|--------|
| `/status` | Agent status + pending count |
| `/report` | Generate incident report |
| `/help` | Full command reference |

### Playbook Commands

| Command | Effect |
|---------|--------|
| `/playbooks` | List available playbooks |
| `/hunt <name>` | Start threat hunt playbook |
| `/respond <name>` | Start incident response playbook |
| `/assess <name>` | Start security assessment playbook |
| `/playbook <name>` | Start any playbook by exact name |
| `/abort` | Stop running playbook |

### Command Aliases (40+)

| Alias | Maps To |
|-------|---------|
| `/contain` | `/escalate` |
| `/quarantine` | `/isolate` |
| `/mitigate` | `/escalate` |
| `/triage` | `/investigate` |
| `/analyze` | `/investigate` |
| `/review` | `/investigate` |
| `/examine` | `/investigate` |
| `/suppress` | `/dismiss` |
| `/close` | `/dismiss` |
| `/terminate` | `/kill` |
| `/segment` | `/isolate` |
| `/disconnect` | `/isolate` |
| `/authorize` | `/approve` |
| `/reject` | `/deny` |
| `/cancel` | `/deny` |
| `/pause` | `/hold` |
| `/freeze` | `/hold` |
| `/resume` | `/release` |
| `/prioritize` | `/escalate` |
| `/raise` | `/escalate` |

---

## 8. Natural Language Reference

### Supported Phrases (Regex Layer — Instant)

#### Containment & Blocking
```
block 10.0.0.1
block ip 192.168.1.50:443
please block this ip 45.133.0.0
can you block 10.0.0.1
unblock 10.0.0.1
contain T1190
quarantine web-srv-03
mitigate T1059
respond to T1078
isolate endpoint db-prod-01
kill process 1234
terminate 5678
```

#### Alert Management
```
escalate T1059
prioritize T1190
raise critical
investigate T1570
look into T1078
dig into T1566
triage T1059
analyze critical
review T1190
dismiss T1189
close alert T1059
suppress T1078
mark T1059 as false positive
T1078 is a false positive
flag T1190 as benign
```

#### Gate Approval
```
approve G001
approve all
authorize everything
go ahead
do it
confirmed
deny G002
reject all
cancel G001
```

#### Status & Reporting
```
show status
what's pending
generate report
create incident report
```

### Supported Phrases (LLM Layer — Contextual)

```
that IP from the last alert, block it
deal with the lateral movement stuff
shut down everything related to powershell
the critical ones look bad, escalate them
same thing for the other high alerts
do what ADA recommended
take care of the T1190 situation
can we contain whatever is causing the credential alerts
```

---

## 9. API Reference

### POST /api/soc-intent

LLM-based intent classification for natural language SOC commands.

**Request:**
```json
{
  "message": "deal with the lateral movement stuff",
  "context": {
    "alerts": [
      "CVE-2025-53521 T1190 Exploit Public-Facing Application [high]",
      "CVE-2025-43510 T1570 Lateral Tool Transfer [high]"
    ],
    "pending": [
      "G001 block 45.133.0.0"
    ]
  }
}
```

**Response:**
```json
{
  "command": "investigate",
  "target": "T1570",
  "confidence": 0.8,
  "reasoning": "The analyst mentions 'lateral movement stuff', related to T1570",
  "model": "llama-3.3-70b-versatile",
  "usage": {
    "prompt_tokens": 544,
    "completion_tokens": 62,
    "total_tokens": 606,
    "total_time": 0.251
  }
}
```

**Confidence threshold:** Actions with confidence < 0.7 are not executed; the message is routed to agents instead.

**Error responses:**
- `400` — Missing `message` field
- `502` — Groq API error
- `503` — `GROQ_API_KEY` not configured

**Provider:** Groq (llama-3.3-70b-versatile)
**Latency:** ~250ms
**Cost:** ~$0.0003 per call

---

## 10. Deployment & Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_VARIANT` | Yes | Set to `cyber` for SOC dashboard |
| `GROQ_API_KEY` | Yes | Groq API key for LLM intent classification |
| `OPENROUTER_API_KEY` | Optional | OpenRouter fallback (not used by SOC intent) |

### Vercel Deployment

```bash
# Set env vars
vercel env add GROQ_API_KEY production

# Deploy
VITE_VARIANT=cyber vercel --prod
```

### Build Output

| Chunk | Size (gzip) |
|-------|-------------|
| `soc-chat-panel` | 72 KB |
| `mitre-techniques.json` | ~50 KB |
| `soc-intent.js` (serverless) | ~3 KB |

### Configuration Defaults (ResponseGate)

```
auto_block_enabled: false
auto_block_min_severity: CRITICAL
auto_block_min_confidence: 0.90
auto_kill_enabled: false
auto_kill_min_severity: CRITICAL
auto_kill_min_confidence: 0.95
auto_suspend_min_severity: HIGH
auto_suspend_min_confidence: 0.80
```

---

## 11. Security Considerations

### Edge Middleware
- Bot/crawler UAs blocked on all `/api/*` routes
- User-Agent < 10 chars rejected
- Social preview bots allowed only on `/api/story` and `/api/og-story`
- A2A protocol endpoints exempt from bot blocking

### Response Gate
- All destructive actions held by default (auto-block/auto-kill disabled)
- Gate decisions logged to audit trail
- Session-scoped IDs prevent cross-session replay
- Approval requires explicit analyst action (no auto-timeout)

### LLM Intent API
- Groq API key stored in Vercel encrypted env vars
- Input sanitized (message length not enforced — consider adding)
- Low temperature (0.1) prevents hallucinated actions
- Confidence threshold (0.7) prevents low-confidence execution
- Context limited to 5 recent alerts + pending actions

### IOC Scanning
- External API calls to ThreatFox, URLhaus, MalwareBazaar
- No credentials stored client-side
- Results rendered with HTML escaping (XSS prevention)

### BroadcastChannel Transport
- Same-origin only (no cross-origin leakage)
- No persistence (messages lost on page reload)
- No authentication (any same-origin tab can read/write)
- **Production upgrade path:** Replace with Ably or WebSocket for multi-user auth

---

## Appendix: File Inventory

```
src/panels/soc-chat-panel.ts        Main panel (~3,200 lines)
api/soc-intent.js                    Groq LLM intent endpoint
public/data/mitre-techniques.json    691 MITRE ATT&CK techniques

gatra-local/response/gate.py         Python ResponseGate (backend mirror)
gatra-local/response/blocker.py      Network blocking (pfctl)
gatra-local/response/process_killer.py  Process management
gatra-local/response/notifier.py     macOS notifications
gatra-local/tests/test_gate.py       18 gate unit tests
gatra-local/config.yaml              Gate configuration
```

## Appendix: Commit History

| Commit | Description |
|--------|-------------|
| `bc22b85e` | Add SOC dashboard variant, threat feeds API, user guide |
| `4794f5cd` | Wire trust-gated response execution into SOC chat panel |
| `8e5dd7a6` | Reverse message order — newest on top |
| `89b73606` | Shorter gate IDs (G001) and case-insensitive approve/deny |
| `84043219` | Add MITRE ATT&CK technique knowledge base (20 initial) |
| `6f7f73fb` | Load full MITRE ATT&CK database (691 techniques) |
| `02978257` | Prioritize technique lookup over triage in TAA handler |
| `de9e0e71` | Commands accept technique IDs, severity, and partial names |
| `400b63f3` | Natural language action detection in SOC chat |
| `5334dd85` | Hybrid natural language — regex first, Groq LLM fallback |
| `ac8687cf` | Distinguish alert queries from definition queries |
| `6711bb85` | Expand natural language with 40+ verb aliases |

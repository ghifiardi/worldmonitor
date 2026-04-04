# Sigma Rules Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Edge-native Sigma detection engine with asset-aware enrichment for the GATRA SOC, integrated via API, MCP tools, and SOC chat.

**Architecture:** Pure TypeScript matching engine (`src/services/sigma-engine.ts`) consumes YAML rules and a static asset inventory from `public/sigma-rules/`. A Vercel Edge Function (`api/sigma-scan.js`) exposes POST (scan events) and GET (list rules) endpoints. SOC chat panel wires ADA agent to auto-run Sigma scans on pasted JSON.

**Tech Stack:** TypeScript, js-yaml (already installed), Vercel Edge Functions, Node.js built-in test runner (`node:test` + `node:assert`)

**Spec:** `docs/superpowers/specs/2026-04-03-sigma-rules-engine-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/services/sigma-engine.ts` | Core matching engine: YAML parsing, field normalization, modifier evaluation, condition parsing, asset resolution, severity computation |
| `tests/sigma-engine.test.mjs` | Unit tests for all engine functions |
| `public/sigma-rules/index.json` | Rule manifest with governance metadata |
| `public/sigma-rules/assets.json` | Static asset inventory (~15 telco assets) |
| `public/sigma-rules/c2-beaconing.yml` | Sigma rule: C2 beaconing detection |
| `public/sigma-rules/brute-force.yml` | Sigma rule: brute force login attempts |
| `public/sigma-rules/dns-tunneling.yml` | Sigma rule: DNS tunneling |
| `public/sigma-rules/lateral-movement.yml` | Sigma rule: lateral movement toward core zone |
| `public/sigma-rules/data-exfiltration.yml` | Sigma rule: large outbound data transfer |
| `public/sigma-rules/suspicious-port.yml` | Sigma rule: unusual port on outdated firmware |
| `public/sigma-rules/credential-access.yml` | Sigma rule: credential dumping indicators |
| `public/sigma-rules/privilege-escalation.yml` | Sigma rule: privilege escalation via service account |
| `public/sigma-rules/log-clearing.yml` | Sigma rule: defense evasion log clearing |
| `public/sigma-rules/phishing-delivery.yml` | Sigma rule: phishing URL click from high-privilege zone |
| `public/sigma-rules/exploit-kev.yml` | Sigma rule: exploit attempt against KEV-listed CVE |
| `public/sigma-rules/recon-scanning.yml` | Sigma rule: port scanning of patch-behind hosts |
| `api/sigma-scan.js` | Vercel Edge Function: POST scan + GET rules |
| `tests/sigma-scan.test.mjs` | API endpoint tests |
| `src/panels/soc-chat-panel.ts` | Modify: add Sigma trigger + rendering to ADA agent |
| `docs/MCP/gatra_mcp_config.md` | Modify: add gatra_sigma_scan + gatra_sigma_rules tool docs |

---

### Task 1: Sigma Engine — Types and Field Normalization

**Files:**
- Create: `src/services/sigma-engine.ts`
- Create: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write failing tests for normalizeEvent**

Create `tests/sigma-engine.test.mjs`:

```javascript
import { strict as assert } from 'node:assert';
import test from 'node:test';
import { normalizeEvent } from '../src/services/sigma-engine.ts';

test('normalizeEvent: passes through canonical fields unchanged', () => {
  const event = { src_ip: '10.0.0.1', dst_ip: '10.0.0.2', port: 443 };
  const result = normalizeEvent(event);
  assert.equal(result.src_ip, '10.0.0.1');
  assert.equal(result.dst_ip, '10.0.0.2');
  assert.equal(result.port, 443);
});

test('normalizeEvent: maps destination.ip to dst_ip', () => {
  const event = { 'destination.ip': '10.0.0.2', 'source.ip': '10.0.0.1' };
  const result = normalizeEvent(event);
  assert.equal(result.dst_ip, '10.0.0.2');
  assert.equal(result.src_ip, '10.0.0.1');
});

test('normalizeEvent: maps dest_ip and dst aliases', () => {
  assert.equal(normalizeEvent({ dest_ip: '1.2.3.4' }).dst_ip, '1.2.3.4');
  assert.equal(normalizeEvent({ dst: '1.2.3.4' }).dst_ip, '1.2.3.4');
});

test('normalizeEvent: maps port aliases', () => {
  assert.equal(normalizeEvent({ dport: 80 }).dst_port, 80);
  assert.equal(normalizeEvent({ sport: 12345 }).src_port, 12345);
  assert.equal(normalizeEvent({ 'destination.port': 443 }).dst_port, 443);
  assert.equal(normalizeEvent({ 'source.port': 8080 }).src_port, 8080);
});

test('normalizeEvent: maps device_id and asset_id to host_id', () => {
  assert.equal(normalizeEvent({ device_id: 'DEV-01' }).host_id, 'DEV-01');
  assert.equal(normalizeEvent({ asset_id: 'AST-02' }).host_id, 'AST-02');
});

test('normalizeEvent: maps username and login to user', () => {
  assert.equal(normalizeEvent({ username: 'admin' }).user, 'admin');
  assert.equal(normalizeEvent({ login: 'root' }).user, 'root');
});

test('normalizeEvent: maps event.action to action', () => {
  assert.equal(normalizeEvent({ 'event.action': 'login' }).action, 'login');
});

test('normalizeEvent: preserves unmapped fields as-is', () => {
  const event = { custom_field: 'value', src_ip: '10.0.0.1' };
  const result = normalizeEvent(event);
  assert.equal(result.custom_field, 'value');
  assert.equal(result.src_ip, '10.0.0.1');
});

test('normalizeEvent: canonical field wins over alias', () => {
  const event = { dst_ip: '10.0.0.1', dest_ip: '10.0.0.2' };
  const result = normalizeEvent(event);
  assert.equal(result.dst_ip, '10.0.0.1');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: Fail — module `sigma-engine.ts` does not exist yet.

- [ ] **Step 3: Implement normalizeEvent and types**

Create `src/services/sigma-engine.ts`:

```typescript
// ── Sigma Detection Engine for GATRA SOC ────────────────────────
// Pure TypeScript, stateless, Edge-compatible.
// Spec: docs/superpowers/specs/2026-04-03-sigma-rules-engine-design.md

import yaml from 'js-yaml';

// ── Types ────────────────────────────────────────────────────────

export interface SigmaRule {
  id: string;
  title: string;
  status: string;
  description: string;
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  logsource: { category?: string; product?: string };
  detection: {
    clauses: Record<string, FieldMatcher[]>;
    condition: string;
  };
  fields: string[];
  tags: string[];
  falsepositives: string[];
  recommended_actions: string[];
  gatra_agent?: string;
  mitre_technique?: string;
  kill_chain_phase?: string;
  _degraded?: boolean;
}

export interface FieldMatcher {
  field: string;
  modifier: string;
  values: unknown[];
}

export interface AssetRecord {
  host_id: string;
  ip_addresses: string[];
  hostnames: string[];
  aliases: string[];
  name: string;
  type: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  os: string;
  firmware: string;
  firmware_latest: string;
  firmware_upgrade_required: boolean;
  hardware_model: string;
  hardware_eol: string;
  location: string;
  owner: string;
  network_zone: string;
  patch_status: 'current' | 'behind' | 'critical';
  last_patched: string;
  cves: Array<{ id: string; cvss: number; epss: number; patched: boolean; kev: boolean }>;
  services: string[];
}

export interface AssetIndex {
  byHostId: Map<string, AssetRecord>;
  byIp: Map<string, AssetRecord>;
  byHostname: Map<string, AssetRecord>;
  byAlias: Map<string, AssetRecord>;
}

export interface SigmaMatch {
  rule_id: string;
  title: string;
  rule_level: string;
  effective_severity: string;
  description: string;
  rule_metadata: {
    tags: string[];
    mitre_technique?: string;
    gatra_agent?: string;
    kill_chain_phase?: string;
    falsepositives: string[];
    recommended_actions: string[];
  };
  enrichment: {
    matched_fields: Record<string, unknown>;
    risk_factors: string[];
    severity_reason: string;
  };
  asset_context?: {
    host_id: string;
    name: string;
    criticality: string;
    unpatched_cves: string[];
    firmware_outdated: boolean;
    patch_status: string;
    network_zone: string;
    hardware_eol: string;
  };
  recommendations: string[];
}

// ── Field Normalization ──────────────────────────────────────────

const FIELD_ALIASES: Record<string, string> = {
  'destination.ip': 'dst_ip',
  'dest_ip': 'dst_ip',
  'dst': 'dst_ip',
  'source.ip': 'src_ip',
  'src': 'src_ip',
  'destination.port': 'dst_port',
  'dport': 'dst_port',
  'source.port': 'src_port',
  'sport': 'src_port',
  'device_id': 'host_id',
  'asset_id': 'host_id',
  'event.action': 'action',
  'username': 'user',
  'login': 'user',
};

export function normalizeEvent(event: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // First pass: copy all fields
  for (const [key, value] of Object.entries(event)) {
    const canonical = FIELD_ALIASES[key];
    if (canonical) {
      // Only set alias-mapped field if canonical field not already set
      if (!(canonical in result)) {
        result[canonical] = value;
      }
    } else {
      result[key] = value;
    }
  }

  // Second pass: original canonical fields override aliases
  for (const [key, value] of Object.entries(event)) {
    if (!FIELD_ALIASES[key]) {
      result[key] = value;
    }
  }

  return result;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/services/sigma-engine.ts tests/sigma-engine.test.mjs
git commit -m "feat(sigma): add types and field normalization"
```

---

### Task 2: Sigma Engine — YAML Rule Parsing

**Files:**
- Modify: `src/services/sigma-engine.ts`
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write failing tests for loadRules**

Append to `tests/sigma-engine.test.mjs`:

```javascript
import { loadRules } from '../src/services/sigma-engine.ts';

const VALID_RULE_YAML = `
title: Test Rule
id: test-001
status: stable
description: A test rule
logsource:
  category: network_connection
  product: any
detection:
  selection:
    direction: outbound
    duration|gte: 60
  filter:
    dst_ip|cidr:
      - 10.0.0.0/8
  condition: selection and not filter
fields:
  - src_ip
  - dst_ip
falsepositives:
  - Test
level: high
tags:
  - attack.t1071
gatra_agent: taa
mitre_technique: T1071
kill_chain_phase: c2
recommended_actions:
  - Investigate
`;

test('loadRules: parses valid YAML rule', () => {
  const rules = loadRules([VALID_RULE_YAML]);
  assert.equal(rules.length, 1);
  const r = rules[0];
  assert.equal(r.id, 'test-001');
  assert.equal(r.title, 'Test Rule');
  assert.equal(r.level, 'high');
  assert.equal(r.gatra_agent, 'taa');
  assert.equal(r.mitre_technique, 'T1071');
  assert.deepEqual(r.recommended_actions, ['Investigate']);
});

test('loadRules: parses detection clauses with modifiers', () => {
  const rules = loadRules([VALID_RULE_YAML]);
  const clauses = rules[0].detection.clauses;
  assert.ok('selection' in clauses);
  assert.ok('filter' in clauses);

  const selectionMatchers = clauses.selection;
  assert.equal(selectionMatchers.length, 2);

  const dirMatcher = selectionMatchers.find(m => m.field === 'direction');
  assert.ok(dirMatcher);
  assert.equal(dirMatcher.modifier, '');
  assert.deepEqual(dirMatcher.values, ['outbound']);

  const durMatcher = selectionMatchers.find(m => m.field === 'duration');
  assert.ok(durMatcher);
  assert.equal(durMatcher.modifier, 'gte');
  assert.deepEqual(durMatcher.values, [60]);

  const cidrMatcher = clauses.filter[0];
  assert.equal(cidrMatcher.field, 'dst_ip');
  assert.equal(cidrMatcher.modifier, 'cidr');
  assert.deepEqual(cidrMatcher.values, ['10.0.0.0/8']);
});

test('loadRules: skips rule with missing required fields', () => {
  const badYaml = `
title: No ID Rule
level: high
detection:
  selection:
    foo: bar
  condition: selection
`;
  const rules = loadRules([badYaml]);
  assert.equal(rules.length, 0);
});

test('loadRules: skips malformed YAML', () => {
  const rules = loadRules(['not: valid: yaml: [[[']);
  assert.equal(rules.length, 0);
});

test('loadRules: keeps first-loaded on duplicate ID', () => {
  const yaml1 = VALID_RULE_YAML;
  const yaml2 = VALID_RULE_YAML.replace('Test Rule', 'Duplicate Rule');
  const rules = loadRules([yaml1, yaml2]);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].title, 'Test Rule');
});

test('loadRules: marks rule as degraded on invalid modifier', () => {
  const yamlWithBadMod = `
title: Bad Modifier Rule
id: test-bad-mod
status: stable
description: test
logsource:
  category: test
detection:
  selection:
    foo|invalid_modifier_xyz: bar
  condition: selection
level: medium
`;
  const rules = loadRules([yamlWithBadMod]);
  assert.equal(rules.length, 1);
  assert.equal(rules[0]._degraded, true);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: Fail — `loadRules` is not exported.

- [ ] **Step 3: Implement loadRules**

Add to `src/services/sigma-engine.ts`:

```typescript
// ── Valid modifiers ──────────────────────────────────────────────

const VALID_MODIFIERS = new Set([
  '', 'contains', 'startswith', 'endswith', 're',
  'gte', 'lte', 'gt', 'lt', 'cidr', 'exists',
  'asset_criticality', 'asset_has_cve', 'asset_cvss_gte',
  'asset_kev', 'asset_patch_status', 'asset_firmware_outdated', 'asset_zone',
]);

// ── Rule Parsing ─────────────────────────────────────────────────

function parseDetection(detection: Record<string, unknown>): { clauses: Record<string, FieldMatcher[]>; condition: string; degraded: boolean } | null {
  const condition = detection.condition;
  if (typeof condition !== 'string') return null;

  const clauses: Record<string, FieldMatcher[]> = {};
  let degraded = false;

  for (const [clauseName, clauseValue] of Object.entries(detection)) {
    if (clauseName === 'condition') continue;
    if (typeof clauseValue !== 'object' || clauseValue === null) continue;

    const matchers: FieldMatcher[] = [];
    for (const [rawKey, rawValue] of Object.entries(clauseValue as Record<string, unknown>)) {
      const parts = rawKey.split('|');
      const field = parts[0];
      const modifier = parts.length > 1 ? parts.slice(1).join('|') : '';

      if (!VALID_MODIFIERS.has(modifier)) {
        degraded = true;
      }

      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      matchers.push({ field, modifier, values });
    }
    clauses[clauseName] = matchers;
  }

  return { clauses, condition: condition.trim(), degraded };
}

export function loadRules(yamls: string[]): SigmaRule[] {
  const rules: SigmaRule[] = [];
  const seenIds = new Set<string>();

  for (const yamlStr of yamls) {
    let doc: Record<string, unknown>;
    try {
      doc = yaml.load(yamlStr) as Record<string, unknown>;
    } catch {
      continue; // skip malformed YAML
    }
    if (!doc || typeof doc !== 'object') continue;

    const id = doc.id;
    const title = doc.title;
    const level = doc.level;
    const detection = doc.detection;

    if (typeof id !== 'string' || typeof title !== 'string' || typeof level !== 'string' || !detection) {
      continue; // skip missing required fields
    }

    if (seenIds.has(id)) {
      continue; // keep first-loaded, skip duplicate
    }
    seenIds.add(id);

    const parsed = parseDetection(detection as Record<string, unknown>);
    if (!parsed) continue;

    const rule: SigmaRule = {
      id,
      title,
      status: typeof doc.status === 'string' ? doc.status : 'unknown',
      description: typeof doc.description === 'string' ? doc.description : '',
      level: level as SigmaRule['level'],
      logsource: (doc.logsource as SigmaRule['logsource']) || {},
      detection: { clauses: parsed.clauses, condition: parsed.condition },
      fields: Array.isArray(doc.fields) ? doc.fields : [],
      tags: Array.isArray(doc.tags) ? doc.tags : [],
      falsepositives: Array.isArray(doc.falsepositives) ? doc.falsepositives : [],
      recommended_actions: Array.isArray(doc.recommended_actions) ? doc.recommended_actions : [],
      gatra_agent: typeof doc.gatra_agent === 'string' ? doc.gatra_agent : undefined,
      mitre_technique: typeof doc.mitre_technique === 'string' ? doc.mitre_technique : undefined,
      kill_chain_phase: typeof doc.kill_chain_phase === 'string' ? doc.kill_chain_phase : undefined,
      _degraded: parsed.degraded || undefined,
    };

    rules.push(rule);
  }

  return rules;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/services/sigma-engine.ts tests/sigma-engine.test.mjs
git commit -m "feat(sigma): add YAML rule parsing with validation"
```

---

### Task 3: Sigma Engine — Asset Loading and Resolution

**Files:**
- Modify: `src/services/sigma-engine.ts`
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write failing tests for loadAssets and resolveAsset**

Append to `tests/sigma-engine.test.mjs`:

```javascript
import { loadAssets, resolveAsset } from '../src/services/sigma-engine.ts';

const ASSETS_JSON = JSON.stringify({
  'TELCO-CORE-JKT-01': {
    host_id: 'TELCO-CORE-JKT-01',
    ip_addresses: ['10.1.1.1', '203.0.113.10'],
    hostnames: ['core-rtr-jkt-01.indosat.net'],
    aliases: ['jkt-core-primary'],
    name: 'Core Router Jakarta Primary',
    type: 'network_device',
    criticality: 'critical',
    os: 'Cisco IOS XR 7.9.1',
    firmware: '7.9.1',
    firmware_latest: '7.11.2',
    firmware_upgrade_required: true,
    hardware_model: 'Cisco ASR 9000',
    hardware_eol: '2028-06-30',
    location: 'Jakarta',
    owner: 'NOC-Core',
    network_zone: 'core',
    patch_status: 'behind',
    last_patched: '2025-11-15',
    cves: [
      { id: 'CVE-2025-20188', cvss: 9.8, epss: 0.72, patched: false, kev: true },
      { id: 'CVE-2025-20156', cvss: 7.5, epss: 0.35, patched: false, kev: false },
    ],
    services: ['bgp', 'mpls', 'snmp'],
  },
});

test('loadAssets: builds index from JSON', () => {
  const index = loadAssets(ASSETS_JSON);
  assert.ok(index.byHostId.has('TELCO-CORE-JKT-01'));
  assert.ok(index.byIp.has('10.1.1.1'));
  assert.ok(index.byIp.has('203.0.113.10'));
  assert.ok(index.byHostname.has('core-rtr-jkt-01.indosat.net'));
  assert.ok(index.byAlias.has('jkt-core-primary'));
});

test('resolveAsset: resolves by host_id', () => {
  const index = loadAssets(ASSETS_JSON);
  const asset = resolveAsset('TELCO-CORE-JKT-01', index);
  assert.ok(asset);
  assert.equal(asset.name, 'Core Router Jakarta Primary');
});

test('resolveAsset: resolves by IP', () => {
  const index = loadAssets(ASSETS_JSON);
  const asset = resolveAsset('10.1.1.1', index);
  assert.ok(asset);
  assert.equal(asset.host_id, 'TELCO-CORE-JKT-01');
});

test('resolveAsset: resolves by hostname', () => {
  const index = loadAssets(ASSETS_JSON);
  const asset = resolveAsset('core-rtr-jkt-01.indosat.net', index);
  assert.ok(asset);
  assert.equal(asset.host_id, 'TELCO-CORE-JKT-01');
});

test('resolveAsset: resolves by alias', () => {
  const index = loadAssets(ASSETS_JSON);
  const asset = resolveAsset('jkt-core-primary', index);
  assert.ok(asset);
  assert.equal(asset.host_id, 'TELCO-CORE-JKT-01');
});

test('resolveAsset: returns null for unknown value', () => {
  const index = loadAssets(ASSETS_JSON);
  assert.equal(resolveAsset('UNKNOWN-HOST', index), null);
});

test('loadAssets: handles invalid JSON gracefully', () => {
  const index = loadAssets('not json');
  assert.equal(index.byHostId.size, 0);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: Fail — `loadAssets` and `resolveAsset` not exported.

- [ ] **Step 3: Implement loadAssets and resolveAsset**

Add to `src/services/sigma-engine.ts`:

```typescript
// ── Asset Loading ────────────────────────────────────────────────

export function loadAssets(jsonStr: string): AssetIndex {
  const index: AssetIndex = {
    byHostId: new Map(),
    byIp: new Map(),
    byHostname: new Map(),
    byAlias: new Map(),
  };

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return index;
  }

  if (!parsed || typeof parsed !== 'object') return index;

  for (const [key, value] of Object.entries(parsed)) {
    if (!value || typeof value !== 'object') continue;
    const asset = value as AssetRecord;
    asset.host_id = asset.host_id || key;

    index.byHostId.set(key, asset);

    if (Array.isArray(asset.ip_addresses)) {
      for (const ip of asset.ip_addresses) {
        if (!index.byIp.has(ip)) index.byIp.set(ip, asset);
      }
    }
    if (Array.isArray(asset.hostnames)) {
      for (const h of asset.hostnames) {
        if (!index.byHostname.has(h)) index.byHostname.set(h, asset);
      }
    }
    if (Array.isArray(asset.aliases)) {
      for (const a of asset.aliases) {
        if (!index.byAlias.has(a)) index.byAlias.set(a, asset);
      }
    }
  }

  return index;
}

export function resolveAsset(value: string, index: AssetIndex): AssetRecord | null {
  return index.byHostId.get(value)
    ?? index.byHostname.get(value)
    ?? index.byIp.get(value)
    ?? index.byAlias.get(value)
    ?? null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/services/sigma-engine.ts tests/sigma-engine.test.mjs
git commit -m "feat(sigma): add asset loading and resolution"
```

---

### Task 4: Sigma Engine — Modifier Evaluation

**Files:**
- Modify: `src/services/sigma-engine.ts`
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write failing tests for evaluateModifier**

Append to `tests/sigma-engine.test.mjs`:

```javascript
import { evaluateModifier } from '../src/services/sigma-engine.ts';

// ── Default (strict equality) ──
test('evaluateModifier: strict equality match', () => {
  assert.equal(evaluateModifier('outbound', '', ['outbound'], null), true);
  assert.equal(evaluateModifier('outbound', '', ['inbound'], null), false);
});

test('evaluateModifier: strict equality is case-sensitive', () => {
  assert.equal(evaluateModifier('Outbound', '', ['outbound'], null), false);
});

test('evaluateModifier: strict equality numeric', () => {
  assert.equal(evaluateModifier(443, '', [443], null), true);
  assert.equal(evaluateModifier(443, '', [80], null), false);
});

test('evaluateModifier: strict equality OR across values', () => {
  assert.equal(evaluateModifier('tcp', '', ['tcp', 'udp'], null), true);
  assert.equal(evaluateModifier('icmp', '', ['tcp', 'udp'], null), false);
});

// ── contains ──
test('evaluateModifier: contains (case-insensitive)', () => {
  assert.equal(evaluateModifier('PowerShell.exe', 'contains', ['powershell'], null), true);
  assert.equal(evaluateModifier('cmd.exe', 'contains', ['powershell'], null), false);
});

// ── startswith ──
test('evaluateModifier: startswith (case-insensitive)', () => {
  assert.equal(evaluateModifier('TELCO-CORE-JKT', 'startswith', ['TELCO'], null), true);
  assert.equal(evaluateModifier('telco-edge', 'startswith', ['TELCO'], null), true);
  assert.equal(evaluateModifier('OTHER-HOST', 'startswith', ['TELCO'], null), false);
});

// ── endswith ──
test('evaluateModifier: endswith (case-insensitive)', () => {
  assert.equal(evaluateModifier('admin_svc', 'endswith', ['_svc'], null), true);
  assert.equal(evaluateModifier('admin_usr', 'endswith', ['_svc'], null), false);
});

// ── Numeric comparisons ──
test('evaluateModifier: gte', () => {
  assert.equal(evaluateModifier(60, 'gte', [60], null), true);
  assert.equal(evaluateModifier(100, 'gte', [60], null), true);
  assert.equal(evaluateModifier(59, 'gte', [60], null), false);
});

test('evaluateModifier: lte', () => {
  assert.equal(evaluateModifier(60, 'lte', [60], null), true);
  assert.equal(evaluateModifier(59, 'lte', [60], null), true);
  assert.equal(evaluateModifier(61, 'lte', [60], null), false);
});

test('evaluateModifier: gt and lt', () => {
  assert.equal(evaluateModifier(61, 'gt', [60], null), true);
  assert.equal(evaluateModifier(60, 'gt', [60], null), false);
  assert.equal(evaluateModifier(59, 'lt', [60], null), true);
  assert.equal(evaluateModifier(60, 'lt', [60], null), false);
});

test('evaluateModifier: numeric comparison with non-numeric value returns false', () => {
  assert.equal(evaluateModifier('not_a_number', 'gte', [60], null), false);
});

// ── re ──
test('evaluateModifier: regex match', () => {
  assert.equal(evaluateModifier('base64_decode_exec', 're', ['base64.*exec'], null), true);
  assert.equal(evaluateModifier('normal_string', 're', ['base64.*exec'], null), false);
});

test('evaluateModifier: invalid regex returns false', () => {
  assert.equal(evaluateModifier('test', 're', ['[invalid('], null), false);
});

test('evaluateModifier: regex pattern exceeding 200 chars returns false', () => {
  const longPattern = 'a'.repeat(201);
  assert.equal(evaluateModifier('test', 're', [longPattern], null), false);
});

// ── cidr ──
test('evaluateModifier: CIDR match', () => {
  assert.equal(evaluateModifier('10.0.0.5', 'cidr', ['10.0.0.0/8'], null), true);
  assert.equal(evaluateModifier('192.168.1.1', 'cidr', ['10.0.0.0/8'], null), false);
});

test('evaluateModifier: CIDR OR across values', () => {
  assert.equal(evaluateModifier('172.16.5.1', 'cidr', ['10.0.0.0/8', '172.16.0.0/12'], null), true);
});

// ── exists ──
test('evaluateModifier: exists true', () => {
  assert.equal(evaluateModifier('anything', 'exists', [true], null), true);
  assert.equal(evaluateModifier(undefined, 'exists', [true], null), false);
});

test('evaluateModifier: exists false', () => {
  assert.equal(evaluateModifier(undefined, 'exists', [false], null), true);
  assert.equal(evaluateModifier('something', 'exists', [false], null), false);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: Fail — `evaluateModifier` not exported.

- [ ] **Step 3: Implement evaluateModifier**

Add to `src/services/sigma-engine.ts`:

```typescript
// ── CIDR matching ────────────────────────────────────────────────

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

function cidrMatch(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipInt = ipToInt(ip);
  const netInt = ipToInt(network);
  if (ipInt === null || netInt === null) return false;

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// ── Modifier Evaluation ──────────────────────────────────────────

const MAX_REGEX_LEN = 200;
const MAX_FIELD_LEN = 10_000;

export function evaluateModifier(
  fieldValue: unknown,
  modifier: string,
  values: unknown[],
  asset: AssetRecord | null,
): boolean {
  // exists modifier: check field presence
  if (modifier === 'exists') {
    const exists = fieldValue !== undefined && fieldValue !== null;
    return values[0] === true ? exists : !exists;
  }

  // If field is undefined/null, no match for other modifiers
  if (fieldValue === undefined || fieldValue === null) return false;

  switch (modifier) {
    case '': {
      // Strict equality, OR across values
      for (const v of values) {
        if (fieldValue === v) return true;
        // Also match string/number coercion: "443" == 443
        if (typeof fieldValue === 'number' && typeof v === 'string' && fieldValue === Number(v)) return true;
        if (typeof fieldValue === 'string' && typeof v === 'number' && Number(fieldValue) === v) return true;
      }
      return false;
    }

    case 'contains': {
      const str = String(fieldValue).toLowerCase();
      for (const v of values) {
        if (str.includes(String(v).toLowerCase())) return true;
      }
      return false;
    }

    case 'startswith': {
      const str = String(fieldValue).toLowerCase();
      for (const v of values) {
        if (str.startsWith(String(v).toLowerCase())) return true;
      }
      return false;
    }

    case 'endswith': {
      const str = String(fieldValue).toLowerCase();
      for (const v of values) {
        if (str.endsWith(String(v).toLowerCase())) return true;
      }
      return false;
    }

    case 'gte':
    case 'lte':
    case 'gt':
    case 'lt': {
      const num = typeof fieldValue === 'number' ? fieldValue : Number(fieldValue);
      if (isNaN(num)) return false;
      for (const v of values) {
        const target = typeof v === 'number' ? v : Number(v);
        if (isNaN(target)) continue;
        if (modifier === 'gte' && num >= target) return true;
        if (modifier === 'lte' && num <= target) return true;
        if (modifier === 'gt' && num > target) return true;
        if (modifier === 'lt' && num < target) return true;
      }
      return false;
    }

    case 're': {
      const str = String(fieldValue).slice(0, MAX_FIELD_LEN);
      for (const v of values) {
        const pattern = String(v);
        if (pattern.length > MAX_REGEX_LEN) return false;
        try {
          if (new RegExp(pattern, 'i').test(str)) return true;
        } catch {
          return false;
        }
      }
      return false;
    }

    case 'cidr': {
      const ip = String(fieldValue);
      for (const v of values) {
        if (cidrMatch(ip, String(v))) return true;
      }
      return false;
    }

    // Asset modifiers
    case 'asset_criticality':
      return asset !== null && values.some(v => asset.criticality === v);

    case 'asset_has_cve':
      if (!asset) return false;
      return asset.cves.some(c => !c.patched) === (values[0] === true || values[0] === 'true');

    case 'asset_cvss_gte': {
      if (!asset) return false;
      const threshold = Number(values[0]);
      if (isNaN(threshold)) return false;
      return asset.cves.some(c => !c.patched && c.cvss >= threshold);
    }

    case 'asset_kev':
      if (!asset) return false;
      return asset.cves.some(c => !c.patched && c.kev) === (values[0] === true || values[0] === 'true');

    case 'asset_patch_status':
      return asset !== null && values.some(v => asset.patch_status === v);

    case 'asset_firmware_outdated':
      if (!asset) return false;
      return asset.firmware_upgrade_required === (values[0] === true || values[0] === 'true');

    case 'asset_zone':
      return asset !== null && values.some(v => asset.network_zone === v);

    default:
      return false;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/services/sigma-engine.ts tests/sigma-engine.test.mjs
git commit -m "feat(sigma): add modifier evaluation with CIDR and asset support"
```

---

### Task 5: Sigma Engine — Condition Parser and matchEvent

**Files:**
- Modify: `src/services/sigma-engine.ts`
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write failing tests for condition parsing and matchEvent**

Append to `tests/sigma-engine.test.mjs`:

```javascript
import { matchEvent } from '../src/services/sigma-engine.ts';

function makeRule(overrides) {
  const base = {
    id: 'test-match-001', title: 'Test', status: 'stable', description: 'test',
    level: 'high', logsource: {}, fields: [], tags: [], falsepositives: [],
    recommended_actions: [], detection: { clauses: {}, condition: 'selection' },
  };
  return { ...base, ...overrides };
}

const emptyAssets = { byHostId: new Map(), byIp: new Map(), byHostname: new Map(), byAlias: new Map() };

test('matchEvent: simple selection match', () => {
  const rule = makeRule({
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const event = { direction: 'outbound' };
  const matches = matchEvent(event, [rule], emptyAssets);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].rule_id, 'test-match-001');
});

test('matchEvent: no match when field value differs', () => {
  const rule = makeRule({
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const event = { direction: 'inbound' };
  const matches = matchEvent(event, [rule], emptyAssets);
  assert.equal(matches.length, 0);
});

test('matchEvent: selection and not filter', () => {
  const rule = makeRule({
    detection: {
      clauses: {
        selection: [{ field: 'direction', modifier: '', values: ['outbound'] }],
        filter: [{ field: 'dst_ip', modifier: 'cidr', values: ['10.0.0.0/8'] }],
      },
      condition: 'selection and not filter',
    },
  });
  // Should match: outbound to public IP
  assert.equal(matchEvent({ direction: 'outbound', dst_ip: '203.0.113.5' }, [rule], emptyAssets).length, 1);
  // Should NOT match: outbound to private IP
  assert.equal(matchEvent({ direction: 'outbound', dst_ip: '10.5.5.5' }, [rule], emptyAssets).length, 0);
});

test('matchEvent: condition with or', () => {
  const rule = makeRule({
    detection: {
      clauses: {
        sel_a: [{ field: 'action', modifier: '', values: ['login'] }],
        sel_b: [{ field: 'action', modifier: '', values: ['exec'] }],
      },
      condition: 'sel_a or sel_b',
    },
  });
  assert.equal(matchEvent({ action: 'login' }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ action: 'exec' }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ action: 'read' }, [rule], emptyAssets).length, 0);
});

test('matchEvent: 1 of selection*', () => {
  const rule = makeRule({
    detection: {
      clauses: {
        selection_a: [{ field: 'action', modifier: '', values: ['login'] }],
        selection_b: [{ field: 'action', modifier: '', values: ['exec'] }],
      },
      condition: '1 of selection*',
    },
  });
  assert.equal(matchEvent({ action: 'login' }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ action: 'exec' }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ action: 'read' }, [rule], emptyAssets).length, 0);
});

test('matchEvent: all of check*', () => {
  const rule = makeRule({
    detection: {
      clauses: {
        check_a: [{ field: 'direction', modifier: '', values: ['outbound'] }],
        check_b: [{ field: 'port', modifier: 'gte', values: [1024] }],
      },
      condition: 'all of check*',
    },
  });
  assert.equal(matchEvent({ direction: 'outbound', port: 8080 }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ direction: 'outbound', port: 80 }, [rule], emptyAssets).length, 0);
});

test('matchEvent: precedence not > and > or', () => {
  const rule = makeRule({
    detection: {
      clauses: {
        a: [{ field: 'x', modifier: '', values: [1] }],
        b: [{ field: 'y', modifier: '', values: [2] }],
        c: [{ field: 'z', modifier: '', values: [3] }],
      },
      // a or b and not c => a or (b and (not c))
      condition: 'a or b and not c',
    },
  });
  // a=true => true regardless
  assert.equal(matchEvent({ x: 1, y: 0, z: 3 }, [rule], emptyAssets).length, 1);
  // a=false, b=true, c=false => true (b and not c)
  assert.equal(matchEvent({ x: 0, y: 2, z: 0 }, [rule], emptyAssets).length, 1);
  // a=false, b=true, c=true => false
  assert.equal(matchEvent({ x: 0, y: 2, z: 3 }, [rule], emptyAssets).length, 0);
});

test('matchEvent: matched_fields in enrichment', () => {
  const rule = makeRule({
    detection: {
      clauses: { selection: [
        { field: 'direction', modifier: '', values: ['outbound'] },
        { field: 'duration', modifier: 'gte', values: [60] },
      ]},
      condition: 'selection',
    },
  });
  const matches = matchEvent({ direction: 'outbound', duration: 120 }, [rule], emptyAssets);
  assert.equal(matches.length, 1);
  assert.deepEqual(matches[0].enrichment.matched_fields, { direction: 'outbound', duration: 120 });
});

test('matchEvent: AND semantics within a clause', () => {
  const rule = makeRule({
    detection: {
      clauses: { selection: [
        { field: 'direction', modifier: '', values: ['outbound'] },
        { field: 'port', modifier: '', values: [443] },
      ]},
      condition: 'selection',
    },
  });
  // Both must match
  assert.equal(matchEvent({ direction: 'outbound', port: 443 }, [rule], emptyAssets).length, 1);
  // Only one matches
  assert.equal(matchEvent({ direction: 'outbound', port: 80 }, [rule], emptyAssets).length, 0);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: Fail — `matchEvent` not exported.

- [ ] **Step 3: Implement condition parser and matchEvent**

Add to `src/services/sigma-engine.ts`:

```typescript
// ── Condition Parser ─────────────────────────────────────────────
// Grammar: expr := term (('and' | 'or') term)*
//          term := 'not'? atom
//          atom := clause_name | ('1'|'all') 'of' prefix '*'

type CondNode =
  | { type: 'clause'; name: string }
  | { type: 'not'; child: CondNode }
  | { type: 'and'; left: CondNode; right: CondNode }
  | { type: 'or'; left: CondNode; right: CondNode }
  | { type: '1of'; prefix: string }
  | { type: 'allof'; prefix: string };

function tokenize(condition: string): string[] {
  return condition.trim().split(/\s+/);
}

function parseCondition(condition: string): CondNode {
  const tokens = tokenize(condition);
  let pos = 0;

  function parseAtom(): CondNode {
    if (pos >= tokens.length) throw new Error('Unexpected end of condition');

    // '1 of prefix*' or 'all of prefix*'
    if ((tokens[pos] === '1' || tokens[pos] === 'all') && tokens[pos + 1] === 'of') {
      const quantifier = tokens[pos];
      pos += 2; // skip 'N' and 'of'
      const glob = tokens[pos++];
      const prefix = glob.endsWith('*') ? glob.slice(0, -1) : glob;
      return { type: quantifier === '1' ? '1of' : 'allof', prefix };
    }

    // clause name
    const name = tokens[pos++];
    return { type: 'clause', name };
  }

  function parseTerm(): CondNode {
    if (tokens[pos] === 'not') {
      pos++;
      const child = parseAtom();
      return { type: 'not', child };
    }
    return parseAtom();
  }

  function parseExpr(minPrec: number): CondNode {
    let left = parseTerm();

    while (pos < tokens.length) {
      const op = tokens[pos];
      if (op === 'and' && minPrec <= 1) {
        pos++;
        const right = parseExpr(2); // higher precedence for right
        left = { type: 'and', left, right };
      } else if (op === 'or' && minPrec <= 0) {
        pos++;
        const right = parseExpr(1); // and binds tighter than or
        left = { type: 'or', left, right };
      } else {
        break;
      }
    }

    return left;
  }

  return parseExpr(0);
}

function evaluateCondition(
  node: CondNode,
  clauseResults: Map<string, boolean>,
): boolean {
  switch (node.type) {
    case 'clause':
      return clauseResults.get(node.name) ?? false;
    case 'not':
      return !evaluateCondition(node.child, clauseResults);
    case 'and':
      return evaluateCondition(node.left, clauseResults) && evaluateCondition(node.right, clauseResults);
    case 'or':
      return evaluateCondition(node.left, clauseResults) || evaluateCondition(node.right, clauseResults);
    case '1of': {
      for (const [name, result] of clauseResults) {
        if (name.startsWith(node.prefix) && result) return true;
      }
      return false;
    }
    case 'allof': {
      let found = false;
      for (const [name, result] of clauseResults) {
        if (name.startsWith(node.prefix)) {
          found = true;
          if (!result) return false;
        }
      }
      return found;
    }
  }
}

// ── Event Matching ───────────────────────────────────────────────

function evaluateClause(
  matchers: FieldMatcher[],
  event: Record<string, unknown>,
  assets: AssetIndex,
): { match: boolean; matchedFields: Record<string, unknown> } {
  const matchedFields: Record<string, unknown> = {};

  for (const matcher of matchers) {
    const fieldValue = event[matcher.field];
    const isAssetMod = matcher.modifier.startsWith('asset_');
    const asset = isAssetMod ? resolveAsset(String(fieldValue ?? ''), assets) : null;

    const result = evaluateModifier(fieldValue, matcher.modifier, matcher.values, asset);
    if (!result) return { match: false, matchedFields: {} };
    matchedFields[matcher.field] = fieldValue;
  }

  return { match: true, matchedFields };
}

export function matchEvent(
  rawEvent: Record<string, unknown>,
  rules: SigmaRule[],
  assets: AssetIndex,
): SigmaMatch[] {
  const event = normalizeEvent(rawEvent);
  const matches: SigmaMatch[] = [];

  for (const rule of rules) {
    // Evaluate each clause
    const clauseResults = new Map<string, boolean>();
    let allMatchedFields: Record<string, unknown> = {};

    for (const [clauseName, matchers] of Object.entries(rule.detection.clauses)) {
      const { match, matchedFields } = evaluateClause(matchers, event, assets);
      clauseResults.set(clauseName, match);
      if (match) {
        allMatchedFields = { ...allMatchedFields, ...matchedFields };
      }
    }

    // Parse and evaluate condition
    let condResult: boolean;
    try {
      const ast = parseCondition(rule.detection.condition);
      condResult = evaluateCondition(ast, clauseResults);
    } catch {
      condResult = false;
    }

    if (!condResult) continue;

    // Resolve asset for enrichment (try common host fields)
    let resolvedAsset: AssetRecord | null = null;
    for (const field of ['host_id', 'dst_ip', 'src_ip', 'hostname']) {
      const val = event[field];
      if (typeof val === 'string') {
        resolvedAsset = resolveAsset(val, assets);
        if (resolvedAsset) break;
      }
    }

    // Compute effective severity
    const { effective, reason, riskFactors, assetActions } = computeSeverity(rule.level, resolvedAsset);

    // Build asset_context
    let assetContext: SigmaMatch['asset_context'];
    if (resolvedAsset) {
      const unpatchedCves = resolvedAsset.cves
        .filter(c => !c.patched)
        .map(c => `${c.id} (CVSS ${c.cvss}${c.kev ? ', KEV' : ''})`);

      assetContext = {
        host_id: resolvedAsset.host_id,
        name: resolvedAsset.name,
        criticality: resolvedAsset.criticality,
        unpatched_cves: unpatchedCves,
        firmware_outdated: resolvedAsset.firmware_upgrade_required,
        patch_status: resolvedAsset.patch_status,
        network_zone: resolvedAsset.network_zone,
        hardware_eol: resolvedAsset.hardware_eol,
      };
    }

    // Combine recommendations
    const recommendations = [
      ...rule.recommended_actions,
      ...assetActions,
    ];

    matches.push({
      rule_id: rule.id,
      title: rule.title,
      rule_level: rule.level,
      effective_severity: effective,
      description: rule.description,
      rule_metadata: {
        tags: rule.tags,
        mitre_technique: rule.mitre_technique,
        gatra_agent: rule.gatra_agent,
        kill_chain_phase: rule.kill_chain_phase,
        falsepositives: rule.falsepositives,
        recommended_actions: rule.recommended_actions,
      },
      enrichment: {
        matched_fields: allMatchedFields,
        risk_factors: riskFactors,
        severity_reason: reason,
      },
      asset_context: assetContext,
      recommendations,
    });
  }

  return matches;
}
```

- [ ] **Step 4: Implement computeSeverity helper**

Add to `src/services/sigma-engine.ts` (before `matchEvent`):

```typescript
// ── Severity Computation ─────────────────────────────────────────

const SEVERITY_TIERS = ['informational', 'low', 'medium', 'high', 'critical'] as const;

function computeSeverity(ruleLevel: string, asset: AssetRecord | null): {
  effective: string;
  reason: string;
  riskFactors: string[];
  assetActions: string[];
} {
  let tierIndex = SEVERITY_TIERS.indexOf(ruleLevel as typeof SEVERITY_TIERS[number]);
  if (tierIndex < 0) tierIndex = 2; // default to medium

  const riskFactors: string[] = [];
  const assetActions: string[] = [];
  const elevations: string[] = [];

  if (asset) {
    if (asset.criticality === 'critical') {
      tierIndex++;
      elevations.push('asset criticality=critical');
      riskFactors.push('Critical infrastructure asset');
    }

    const hasKev = asset.cves.some(c => !c.patched && c.kev);
    if (hasKev) {
      tierIndex++;
      elevations.push('KEV CVE unpatched');
      riskFactors.push('KEV-listed CVE unpatched');
      const kevCves = asset.cves.filter(c => !c.patched && c.kev);
      for (const c of kevCves) {
        assetActions.push(`Emergency patch ${c.id}`);
      }
    }

    if (asset.patch_status === 'critical') {
      tierIndex++;
      elevations.push('patch_status=critical');
      riskFactors.push('Patch status critical');
    }

    if (asset.firmware_upgrade_required) {
      const eolDate = new Date(asset.hardware_eol);
      const monthsToEol = (eolDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24 * 30);
      if (monthsToEol <= 12) {
        tierIndex++;
        elevations.push('firmware outdated + EOL within 12 months');
        riskFactors.push(`Firmware outdated, hardware EOL ${asset.hardware_eol}`);
      } else {
        riskFactors.push('Firmware upgrade required');
      }
      assetActions.push(`Firmware upgrade ${asset.firmware} -> ${asset.firmware_latest}`);
    }
  }

  // Cap at critical
  if (tierIndex >= SEVERITY_TIERS.length) tierIndex = SEVERITY_TIERS.length - 1;
  const effective = SEVERITY_TIERS[tierIndex];

  const reason = effective !== ruleLevel && elevations.length > 0
    ? `Elevated ${ruleLevel}->${effective}: ${elevations.join(', ')}`
    : '';

  return { effective, reason, riskFactors, assetActions };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/services/sigma-engine.ts tests/sigma-engine.test.mjs
git commit -m "feat(sigma): add condition parser, matchEvent, and severity computation"
```

---

### Task 6: Sigma Engine — Severity Elevation Tests

**Files:**
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write severity elevation tests**

Append to `tests/sigma-engine.test.mjs`:

```javascript
test('matchEvent: severity elevated with critical asset', () => {
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'high',
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const event = { direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' };
  const matches = matchEvent(event, [rule], assetIndex);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].rule_level, 'high');
  assert.equal(matches[0].effective_severity, 'critical');
  assert.ok(matches[0].enrichment.severity_reason.includes('critical'));
  assert.ok(matches[0].asset_context);
  assert.equal(matches[0].asset_context.host_id, 'TELCO-CORE-JKT-01');
});

test('matchEvent: no severity elevation without asset', () => {
  const rule = makeRule({
    level: 'medium',
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const matches = matchEvent({ direction: 'outbound' }, [rule], emptyAssets);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].rule_level, 'medium');
  assert.equal(matches[0].effective_severity, 'medium');
  assert.equal(matches[0].enrichment.severity_reason, '');
});

test('matchEvent: severity caps at critical', () => {
  // Asset has criticality=critical AND KEV CVE AND patch_status=behind
  // Rule level = high => high + 1 (critical asset) + 1 (KEV) = should cap at critical
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'high',
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const matches = matchEvent({ direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' }, [rule], assetIndex);
  assert.equal(matches[0].effective_severity, 'critical');
});

test('matchEvent: asset-derived recommendations are included', () => {
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'medium',
    recommended_actions: ['Investigate'],
    detection: {
      clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] },
      condition: 'selection',
    },
  });
  const matches = matchEvent({ direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' }, [rule], assetIndex);
  assert.ok(matches[0].recommendations.includes('Investigate'));
  assert.ok(matches[0].recommendations.some(r => r.includes('CVE-2025-20188')));
  assert.ok(matches[0].recommendations.some(r => r.includes('Firmware upgrade')));
});
```

- [ ] **Step 2: Run tests**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add tests/sigma-engine.test.mjs
git commit -m "test(sigma): add severity elevation and asset enrichment tests"
```

---

### Task 7: Static Rule Files — assets.json and index.json

**Files:**
- Create: `public/sigma-rules/assets.json`
- Create: `public/sigma-rules/index.json`

- [ ] **Step 1: Create assets.json**

Create `public/sigma-rules/assets.json` with ~15 telco infrastructure assets. Use host_id patterns matching the connector's infra prefixes. Include a mix of criticality levels, patch statuses, CVE exposure, and network zones.

The file should contain assets for:
- 3 core network devices (Jakarta, Surabaya, Bandung) — criticality: critical
- 2 edge gateways — criticality: high
- 2 firewalls — criticality: critical
- 2 DNS servers — criticality: high
- 2 SIEM collectors — criticality: medium
- 2 subscriber auth servers — criticality: critical
- 2 billing/BSS systems — criticality: high

Each asset must include: `host_id`, `ip_addresses[]`, `hostnames[]`, `aliases[]`, plus all metadata fields from the spec (os, firmware, cves, patch_status, etc.).

- [ ] **Step 2: Create index.json**

Create `public/sigma-rules/index.json` with the manifest:

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

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add public/sigma-rules/assets.json public/sigma-rules/index.json
git commit -m "feat(sigma): add asset inventory and rule manifest"
```

---

### Task 8: Static Rule Files — 12 Sigma YAML Rules

**Files:**
- Create: `public/sigma-rules/c2-beaconing.yml`
- Create: `public/sigma-rules/brute-force.yml`
- Create: `public/sigma-rules/dns-tunneling.yml`
- Create: `public/sigma-rules/lateral-movement.yml`
- Create: `public/sigma-rules/data-exfiltration.yml`
- Create: `public/sigma-rules/suspicious-port.yml`
- Create: `public/sigma-rules/credential-access.yml`
- Create: `public/sigma-rules/privilege-escalation.yml`
- Create: `public/sigma-rules/log-clearing.yml`
- Create: `public/sigma-rules/phishing-delivery.yml`
- Create: `public/sigma-rules/exploit-kev.yml`
- Create: `public/sigma-rules/recon-scanning.yml`

- [ ] **Step 1: Create all 12 rule files**

Each rule follows the format from the spec. Rules use canonical field names from the normalized event schema. Asset-aware rules (8 of 12) use `|asset_*` modifiers on `host_id`.

Rule contents per the spec table:

| File | Detection Logic |
|------|----------------|
| `c2-beaconing.yml` | direction=outbound AND duration>=60 AND host_id is critical asset with KEV |
| `brute-force.yml` | action contains "login" AND event_type=authentication AND host_id has CVSS>=8.0 |
| `dns-tunneling.yml` | protocol=dns AND bytes_sent>=5000 (no asset check) |
| `lateral-movement.yml` | direction=internal AND host_id asset_zone=core |
| `data-exfiltration.yml` | direction=outbound AND bytes_sent>=1000000 AND host_id criticality=critical |
| `suspicious-port.yml` | dst_port>=10000 AND host_id firmware_outdated |
| `credential-access.yml` | action contains "credential" or "dump" AND host_id patch_status=behind |
| `privilege-escalation.yml` | action contains "sudo" or "runas" or "escalat" (no asset check) |
| `log-clearing.yml` | action contains "clear" or "delete" AND event_type contains "log" AND host_id firmware_outdated |
| `phishing-delivery.yml` | action contains "click" AND details contains "http" AND host_id asset_zone in (core, management) |
| `exploit-kev.yml` | event_type=exploit AND host_id has KEV CVE |
| `recon-scanning.yml` | action contains "scan" AND host_id patch_status=behind |

- [ ] **Step 2: Validate rules load correctly**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx -e "
import { readFileSync, readdirSync } from 'fs';
import { loadRules } from './src/services/sigma-engine.ts';
const files = readdirSync('public/sigma-rules').filter(f => f.endsWith('.yml'));
const yamls = files.map(f => readFileSync('public/sigma-rules/' + f, 'utf-8'));
const rules = loadRules(yamls);
console.log('Loaded', rules.length, 'rules');
rules.forEach(r => console.log(' ', r.id, r.title, r.level, r._degraded ? 'DEGRADED' : 'OK'));
if (rules.length !== 12) process.exit(1);
if (rules.some(r => r._degraded)) { console.error('Degraded rules found!'); process.exit(1); }
console.log('All 12 rules loaded successfully');
"`

Expected: All 12 rules loaded, none degraded.

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add public/sigma-rules/*.yml
git commit -m "feat(sigma): add 12 seed Sigma detection rules"
```

---

### Task 9: Golden Tests — One Fixture Per Rule

**Files:**
- Modify: `tests/sigma-engine.test.mjs`

- [ ] **Step 1: Write golden tests**

Append to `tests/sigma-engine.test.mjs`. For each of the 12 rules, create a matching event and a non-matching event. Load the actual YAML files and assets.json.

```javascript
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const RULES_DIR = resolve(import.meta.dirname, '..', 'public', 'sigma-rules');

function loadAllRules() {
  const files = readdirSync(RULES_DIR).filter(f => f.endsWith('.yml'));
  const yamls = files.map(f => readFileSync(resolve(RULES_DIR, f), 'utf-8'));
  return loadRules(yamls);
}

function loadFullAssets() {
  return loadAssets(readFileSync(resolve(RULES_DIR, 'assets.json'), 'utf-8'));
}

// ── Golden tests: one match + one no-match per rule ──

test('golden: gatra-sigma-001 c2-beaconing matches outbound from critical KEV asset', () => {
  const rules = loadAllRules().filter(r => r.id === 'gatra-sigma-001');
  const assets = loadFullAssets();
  const event = { direction: 'outbound', duration: 120, host_id: 'TELCO-CORE-JKT-01' };
  const matches = matchEvent(event, rules, assets);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].effective_severity, 'critical');
});

test('golden: gatra-sigma-001 c2-beaconing no match for short duration', () => {
  const rules = loadAllRules().filter(r => r.id === 'gatra-sigma-001');
  const assets = loadFullAssets();
  const event = { direction: 'outbound', duration: 10, host_id: 'TELCO-CORE-JKT-01' };
  assert.equal(matchEvent(event, rules, assets).length, 0);
});

// Similar pairs for rules 002-012 — each test loads the specific rule by ID,
// provides a matching event and a non-matching event.
// The implementer should create tests for all 12 rules following this pattern.
// Each test should verify: match count, rule_id, and at least one enrichment field.
```

The implementer must create 24 total golden tests (2 per rule). Each test:
- Loads the real rule YAML from `public/sigma-rules/`
- Loads the real `assets.json`
- Tests one event that SHOULD match
- Tests one event that SHOULD NOT match
- Verifies `rule_id` and at least one enrichment/severity field

- [ ] **Step 2: Run golden tests**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All golden tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add tests/sigma-engine.test.mjs
git commit -m "test(sigma): add golden tests for all 12 rules"
```

---

### Task 10: API Endpoint — Edge Function

**Files:**
- Create: `api/sigma-scan.js`

- [ ] **Step 1: Create api/sigma-scan.js**

Follow the pattern from `api/ioc-lookup.js` (in-memory cache, CORS, error handling). The Edge Function:

1. Imports `getCorsHeaders` from `./_cors.js`
2. On GET `?action=rules`: fetches and caches `public/sigma-rules/index.json`, returns rule listing
3. On POST: parses JSON body, validates (events array, max 50, each must be object), fetches+caches rules and assets, runs `matchEvent` per event, returns results
4. Handles all error contract cases from spec (400, 405, 413, 503)
5. Uses `config = { runtime: 'edge' }`

Key implementation detail: since this is an Edge Function, it needs to fetch the YAML rule files via HTTP (from the same origin). Use the request URL's origin to build fetch URLs for `public/sigma-rules/` files.

```javascript
export const config = { runtime: 'edge' };

import { getCorsHeaders } from './_cors.js';
import { loadRules, loadAssets, matchEvent } from '../src/services/sigma-engine.ts';

const CACHE_TTL = 10 * 60_000;
let _rulesCache = null;
let _assetsCache = null;
// ... (full implementation follows the spec's error contract)
```

- [ ] **Step 2: Write API tests**

Create `tests/sigma-scan.test.mjs`:

```javascript
import { strict as assert } from 'node:assert';
import test from 'node:test';

// These tests validate the API contract by calling the endpoint structure.
// For full integration tests, use the dev server.

test('sigma-scan: module exports handler', async () => {
  // Verify the file can be imported without errors
  const mod = await import('../api/sigma-scan.js');
  assert.equal(typeof mod.default, 'function');
});
```

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add api/sigma-scan.js tests/sigma-scan.test.mjs
git commit -m "feat(sigma): add Edge Function API endpoint"
```

---

### Task 11: SOC Chat Integration

**Files:**
- Modify: `src/panels/soc-chat-panel.ts`

- [ ] **Step 1: Add Sigma trigger patterns to ADA agent**

In `src/panels/soc-chat-panel.ts`, add to ADA's `triggerPatterns` array (around line 56-73):

```typescript
/\bsigma\b/i,
/\bsigma\s+scan\b/i,
```

- [ ] **Step 2: Add JSON detection and Sigma scan function**

Add a new function `trySigmaScan` near the IOC extraction section (~line 215):

```typescript
function tryExtractJson(text: string): Record<string, unknown> | null {
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) return null;
  try {
    const parsed = JSON.parse(match[0]);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) return parsed;
  } catch { /* not valid JSON */ }
  return null;
}

async function runSigmaScan(event: Record<string, unknown>): Promise<string> {
  try {
    const res = await fetch('/api/sigma-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: [event] }),
    });
    if (!res.ok) return `Sigma scan failed: HTTP ${res.status}`;
    const data = await res.json();
    const result = data.results?.[0];
    if (!result || result.matches.length === 0) {
      return `Sigma scan complete \u2014 no matches (${data.rules_loaded} rules evaluated)`;
    }

    let output = `Sigma scan complete \u2014 ${result.matches.length} match${result.matches.length > 1 ? 'es' : ''}\n`;
    for (const m of result.matches) {
      const sev = m.effective_severity.toUpperCase();
      const elevated = m.rule_level !== m.effective_severity
        ? ` (elevated from ${m.rule_level.toUpperCase()})` : '';
      output += `\n  ${sev}${elevated}: ${m.title}\n`;
      output += `  Rule: ${m.rule_id}`;
      if (m.rule_metadata.mitre_technique) output += ` | MITRE: ${m.rule_metadata.mitre_technique}`;
      output += '\n';
      output += `  Matched: ${Object.entries(m.enrichment.matched_fields).map(([k, v]) => `${k}=${v}`).join(', ')}\n`;
      if (m.enrichment.severity_reason) output += `  Elevated because: ${m.enrichment.severity_reason.replace(/^Elevated [^:]+: /, '')}\n`;
      if (m.asset_context) {
        output += `\n  Asset: ${m.asset_context.host_id} (${m.asset_context.name})\n`;
        output += `  Criticality: ${m.asset_context.criticality.toUpperCase()} | Zone: ${m.asset_context.network_zone}\n`;
        if (m.asset_context.unpatched_cves.length > 0) {
          output += `  Unpatched: ${m.asset_context.unpatched_cves.join(', ')}\n`;
        }
        if (m.asset_context.firmware_outdated) output += `  Firmware: outdated\n`;
        output += `  Patch status: ${m.asset_context.patch_status.toUpperCase()}\n`;
      }
      if (m.recommendations.length > 0) {
        output += `\n  Recommendations:\n`;
        m.recommendations.forEach((r, i) => { output += `  ${i + 1}. ${r}\n`; });
      }
      const agent = m.rule_metadata.gatra_agent || (m.effective_severity === 'critical' ? 'cra' : 'taa');
      const agentAction = agent === 'cra' ? 'CRA containment candidate (requires analyst approval)' : `Escalate to @${agent}`;
      output += `\n  ${agentAction}`;
    }
    return output;
  } catch (err) {
    return `Sigma scan error: ${err instanceof Error ? err.message : 'Unknown error'}`;
  }
}
```

- [ ] **Step 3: Wire Sigma into ADA agent response**

In `generateAgentResponse`, inside the `case 'ada':` block, add Sigma detection BEFORE the IOC extraction block (~line 289). Add this check:

```typescript
// Sigma scan: triggered by "sigma" keyword or pasted JSON with scan intent
const sigmaKeyword = /\bsigma\b/i.test(message);
const scanIntent = /\b(scan|match|detect)\s+(this|against|threats)/i.test(message);
const jsonEvent = tryExtractJson(message);
if (jsonEvent && (sigmaKeyword || scanIntent)) {
  return runSigmaScan(jsonEvent);
}
```

- [ ] **Step 4: Update ADA capability description**

Update the signature matching line (~line 435):

```typescript
`  \u2014 Signature matching: YARA rules (${Math.floor(Math.random() * 500 + 2000)} rules, updated ${Math.floor(Math.random() * 4 + 1)}h ago), Sigma log detection (12 rules, asset-aware), and Snort/Suricata network signatures provide fast detection of known threats.\n` +
```

- [ ] **Step 5: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add src/panels/soc-chat-panel.ts
git commit -m "feat(sigma): integrate Sigma scanning into SOC chat ADA agent"
```

---

### Task 12: MCP Tool Documentation

**Files:**
- Modify: `docs/MCP/gatra_mcp_config.md`

- [ ] **Step 1: Add gatra_sigma_scan and gatra_sigma_rules tool documentation**

Add after the existing `gatra_yara_rules` section (after line ~340). Follow the exact format of the YARA tool docs:

```markdown
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
```

- [ ] **Step 2: Update the tool count in the overview section**

Update any references to "11 MCP tools" to "13 MCP tools" in the document header/overview.

- [ ] **Step 3: Commit**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add docs/MCP/gatra_mcp_config.md
git commit -m "docs(sigma): add Sigma MCP tool documentation"
```

---

### Task 13: Integration Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all unit tests**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx --test tests/sigma-engine.test.mjs`

Expected: All tests PASS (normalization, parsing, asset loading, modifiers, conditions, severity, golden tests).

- [ ] **Step 2: Verify rules load from disk**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && node --import tsx -e "
import { readFileSync, readdirSync } from 'fs';
import { loadRules, loadAssets } from './src/services/sigma-engine.ts';
const dir = 'public/sigma-rules';
const yamls = readdirSync(dir).filter(f => f.endsWith('.yml')).map(f => readFileSync(dir + '/' + f, 'utf-8'));
const rules = loadRules(yamls);
const assets = loadAssets(readFileSync(dir + '/assets.json', 'utf-8'));
console.log('Rules:', rules.length, '| Assets:', assets.byHostId.size);
console.log('Degraded:', rules.filter(r => r._degraded).length);
if (rules.length !== 12) process.exit(1);
console.log('OK');
"`

Expected: `Rules: 12 | Assets: 15 | Degraded: 0 | OK`

- [ ] **Step 3: Start dev server and test API endpoint**

Run: `cd /Users/raditio.ghifiardigmail.com/worldmonitor && npm run dev` (in background)

Then test:
```bash
# GET rules
curl -s http://localhost:5173/api/sigma-scan?action=rules | jq '.count'
# Expected: 12

# POST scan
curl -s -X POST http://localhost:5173/api/sigma-scan \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"direction":"outbound","duration":120,"host_id":"TELCO-CORE-JKT-01"}]}' | jq '.results[0].matches | length'
# Expected: >= 1
```

- [ ] **Step 4: Final commit (if any fixes needed)**

```bash
cd /Users/raditio.ghifiardigmail.com/worldmonitor
git add -A
git commit -m "fix(sigma): integration fixes from verification"
```

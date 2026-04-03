import { strict as assert } from 'node:assert';
import test from 'node:test';
import { normalizeEvent, loadRules, loadAssets, resolveAsset, evaluateModifier, matchEvent } from '../src/services/sigma-engine.ts';

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

// ── Task 2: loadRules tests ─────────────────────────────────────

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
  assert.equal(loadRules([badYaml]).length, 0);
});

test('loadRules: skips malformed YAML', () => {
  assert.equal(loadRules(['not: valid: yaml: [[[']).length, 0);
});

test('loadRules: keeps first-loaded on duplicate ID', () => {
  const yaml2 = VALID_RULE_YAML.replace('Test Rule', 'Duplicate Rule');
  const rules = loadRules([VALID_RULE_YAML, yaml2]);
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

// ── Task 3: loadAssets / resolveAsset tests ─────────────────────

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

// ── Task 4: evaluateModifier tests ──────────────────────────────

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
test('evaluateModifier: contains (case-insensitive)', () => {
  assert.equal(evaluateModifier('PowerShell.exe', 'contains', ['powershell'], null), true);
  assert.equal(evaluateModifier('cmd.exe', 'contains', ['powershell'], null), false);
});
test('evaluateModifier: startswith (case-insensitive)', () => {
  assert.equal(evaluateModifier('TELCO-CORE-JKT', 'startswith', ['TELCO'], null), true);
  assert.equal(evaluateModifier('telco-edge', 'startswith', ['TELCO'], null), true);
  assert.equal(evaluateModifier('OTHER-HOST', 'startswith', ['TELCO'], null), false);
});
test('evaluateModifier: endswith (case-insensitive)', () => {
  assert.equal(evaluateModifier('admin_svc', 'endswith', ['_svc'], null), true);
  assert.equal(evaluateModifier('admin_usr', 'endswith', ['_svc'], null), false);
});
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
test('evaluateModifier: numeric with non-numeric value returns false', () => {
  assert.equal(evaluateModifier('not_a_number', 'gte', [60], null), false);
});
test('evaluateModifier: regex match', () => {
  assert.equal(evaluateModifier('base64_decode_exec', 're', ['base64.*exec'], null), true);
  assert.equal(evaluateModifier('normal_string', 're', ['base64.*exec'], null), false);
});
test('evaluateModifier: invalid regex returns false', () => {
  assert.equal(evaluateModifier('test', 're', ['[invalid('], null), false);
});
test('evaluateModifier: regex pattern exceeding 200 chars returns false', () => {
  assert.equal(evaluateModifier('test', 're', ['a'.repeat(201)], null), false);
});
test('evaluateModifier: CIDR match', () => {
  assert.equal(evaluateModifier('10.0.0.5', 'cidr', ['10.0.0.0/8'], null), true);
  assert.equal(evaluateModifier('192.168.1.1', 'cidr', ['10.0.0.0/8'], null), false);
});
test('evaluateModifier: CIDR OR across values', () => {
  assert.equal(evaluateModifier('172.16.5.1', 'cidr', ['10.0.0.0/8', '172.16.0.0/12'], null), true);
});
test('evaluateModifier: exists true', () => {
  assert.equal(evaluateModifier('anything', 'exists', [true], null), true);
  assert.equal(evaluateModifier(undefined, 'exists', [true], null), false);
});
test('evaluateModifier: exists false', () => {
  assert.equal(evaluateModifier(undefined, 'exists', [false], null), true);
  assert.equal(evaluateModifier('something', 'exists', [false], null), false);
});

// ── Task 5: matchEvent tests ────────────────────────────────────

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
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  assert.equal(matchEvent({ direction: 'outbound' }, [rule], emptyAssets).length, 1);
});

test('matchEvent: no match when field value differs', () => {
  const rule = makeRule({
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  assert.equal(matchEvent({ direction: 'inbound' }, [rule], emptyAssets).length, 0);
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
  assert.equal(matchEvent({ direction: 'outbound', dst_ip: '203.0.113.5' }, [rule], emptyAssets).length, 1);
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
      condition: 'a or b and not c',
    },
  });
  assert.equal(matchEvent({ x: 1, y: 0, z: 3 }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ x: 0, y: 2, z: 0 }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ x: 0, y: 2, z: 3 }, [rule], emptyAssets).length, 0);
});

test('matchEvent: matched_fields in enrichment', () => {
  const rule = makeRule({
    detection: { clauses: { selection: [
      { field: 'direction', modifier: '', values: ['outbound'] },
      { field: 'duration', modifier: 'gte', values: [60] },
    ]}, condition: 'selection' },
  });
  const matches = matchEvent({ direction: 'outbound', duration: 120 }, [rule], emptyAssets);
  assert.equal(matches.length, 1);
  assert.deepEqual(matches[0].enrichment.matched_fields, { direction: 'outbound', duration: 120 });
});

test('matchEvent: AND semantics within a clause', () => {
  const rule = makeRule({
    detection: { clauses: { selection: [
      { field: 'direction', modifier: '', values: ['outbound'] },
      { field: 'port', modifier: '', values: [443] },
    ]}, condition: 'selection' },
  });
  assert.equal(matchEvent({ direction: 'outbound', port: 443 }, [rule], emptyAssets).length, 1);
  assert.equal(matchEvent({ direction: 'outbound', port: 80 }, [rule], emptyAssets).length, 0);
});

// ── Task 6: Severity Elevation tests ────────────────────────────

test('matchEvent: severity elevated with critical asset', () => {
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'high',
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  const matches = matchEvent({ direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' }, [rule], assetIndex);
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
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  const matches = matchEvent({ direction: 'outbound' }, [rule], emptyAssets);
  assert.equal(matches[0].rule_level, 'medium');
  assert.equal(matches[0].effective_severity, 'medium');
  assert.equal(matches[0].enrichment.severity_reason, '');
});

test('matchEvent: severity caps at critical', () => {
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'high',
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  const matches = matchEvent({ direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' }, [rule], assetIndex);
  assert.equal(matches[0].effective_severity, 'critical');
});

test('matchEvent: asset-derived recommendations are included', () => {
  const assetIndex = loadAssets(ASSETS_JSON);
  const rule = makeRule({
    level: 'medium',
    recommended_actions: ['Investigate'],
    detection: { clauses: { selection: [{ field: 'direction', modifier: '', values: ['outbound'] }] }, condition: 'selection' },
  });
  const matches = matchEvent({ direction: 'outbound', host_id: 'TELCO-CORE-JKT-01' }, [rule], assetIndex);
  assert.ok(matches[0].recommendations.includes('Investigate'));
  assert.ok(matches[0].recommendations.some(r => r.includes('CVE-2025-20188')));
  assert.ok(matches[0].recommendations.some(r => r.includes('Firmware upgrade')));
});

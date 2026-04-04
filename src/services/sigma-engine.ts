// Sigma Detection Engine for GATRA SOC
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

  // First pass: copy all fields, resolving aliases
  for (const [key, value] of Object.entries(event)) {
    const canonical = FIELD_ALIASES[key];
    if (canonical) {
      if (!(canonical in result)) {
        result[canonical] = value;
      }
    } else {
      result[key] = value;
    }
  }

  // Second pass: canonical (non-alias) fields always win
  for (const [key, value] of Object.entries(event)) {
    if (!FIELD_ALIASES[key]) {
      result[key] = value;
    }
  }

  return result;
}

// ── Task 2: YAML Rule Parsing ───────────────────────────────────

const VALID_MODIFIERS = new Set([
  '', 'contains', 'startswith', 'endswith', 're',
  'gte', 'lte', 'gt', 'lt', 'cidr', 'exists',
  'asset_criticality', 'asset_has_cve', 'asset_cvss_gte',
  'asset_kev', 'asset_patch_status', 'asset_firmware_outdated', 'asset_zone',
]);

function parseDetection(detection: Record<string, unknown>): {
  clauses: Record<string, FieldMatcher[]>;
  condition: string;
  degraded: boolean;
} {
  const condition = (detection.condition as string) || '';
  const clauses: Record<string, FieldMatcher[]> = {};
  let degraded = false;

  for (const [clauseName, clauseValue] of Object.entries(detection)) {
    if (clauseName === 'condition') continue;
    const matchers: FieldMatcher[] = [];
    if (typeof clauseValue === 'object' && clauseValue !== null && !Array.isArray(clauseValue)) {
      for (const [fieldSpec, rawValues] of Object.entries(clauseValue as Record<string, unknown>)) {
        const parts = fieldSpec.split('|');
        const field = parts[0];
        const modifier = parts.length > 1 ? parts.slice(1).join('|') : '';
        if (!VALID_MODIFIERS.has(modifier)) {
          degraded = true;
        }
        const values = Array.isArray(rawValues) ? rawValues : [rawValues];
        matchers.push({ field, modifier, values });
      }
    }
    clauses[clauseName] = matchers;
  }

  return { clauses, condition, degraded };
}

export function loadRules(yamls: string[]): SigmaRule[] {
  const rules: SigmaRule[] = [];
  const seenIds = new Set<string>();

  for (const yamlStr of yamls) {
    let doc: any;
    try {
      doc = yaml.load(yamlStr);
    } catch {
      continue;
    }

    if (!doc || typeof doc !== 'object') continue;
    if (!doc.id || !doc.title || !doc.level || !doc.detection) continue;

    if (seenIds.has(doc.id)) continue;
    seenIds.add(doc.id);

    const { clauses, condition, degraded } = parseDetection(doc.detection);

    const rule: SigmaRule = {
      id: doc.id,
      title: doc.title,
      status: doc.status || '',
      description: doc.description || '',
      level: doc.level,
      logsource: doc.logsource || {},
      detection: { clauses, condition },
      fields: doc.fields || [],
      tags: doc.tags || [],
      falsepositives: doc.falsepositives || [],
      recommended_actions: doc.recommended_actions || [],
      gatra_agent: doc.gatra_agent,
      mitre_technique: doc.mitre_technique,
      kill_chain_phase: doc.kill_chain_phase,
    };

    if (degraded) rule._degraded = true;

    rules.push(rule);
  }

  return rules;
}

// ── Task 3: Asset Loading and Resolution ────────────────────────

export function loadAssets(jsonStr: string): AssetIndex {
  const index: AssetIndex = {
    byHostId: new Map(),
    byIp: new Map(),
    byHostname: new Map(),
    byAlias: new Map(),
  };

  let data: Record<string, any>;
  try {
    data = JSON.parse(jsonStr);
  } catch {
    return index;
  }

  if (!data || typeof data !== 'object') return index;

  for (const [key, asset] of Object.entries(data)) {
    const rec = asset as AssetRecord;
    if (!rec.host_id) continue;

    index.byHostId.set(rec.host_id, rec);

    if (Array.isArray(rec.ip_addresses)) {
      for (const ip of rec.ip_addresses) {
        if (!index.byIp.has(ip)) index.byIp.set(ip, rec);
      }
    }
    if (Array.isArray(rec.hostnames)) {
      for (const hn of rec.hostnames) {
        if (!index.byHostname.has(hn)) index.byHostname.set(hn, rec);
      }
    }
    if (Array.isArray(rec.aliases)) {
      for (const alias of rec.aliases) {
        if (!index.byAlias.has(alias)) index.byAlias.set(alias, rec);
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

// ── Task 4: Modifier Evaluation ─────────────────────────────────

function ipToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return -1;
  let result = 0;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return -1;
    result = (result * 256) + n;
  }
  return result >>> 0;
}

function cidrMatch(ip: string, cidr: string): boolean {
  const [network, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(network);
  if (ipInt < 0 || netInt < 0) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

export function evaluateModifier(
  fieldValue: unknown,
  modifier: string,
  values: unknown[],
  asset: AssetRecord | null,
): boolean {
  switch (modifier) {
    case '': {
      // strict equality, OR across values
      return values.some(v => fieldValue === v);
    }
    case 'contains': {
      const fv = String(fieldValue).toLowerCase();
      return values.some(v => fv.includes(String(v).toLowerCase()));
    }
    case 'startswith': {
      const fv = String(fieldValue).toLowerCase();
      return values.some(v => fv.startsWith(String(v).toLowerCase()));
    }
    case 'endswith': {
      const fv = String(fieldValue).toLowerCase();
      return values.some(v => fv.endsWith(String(v).toLowerCase()));
    }
    case 'gte': case 'lte': case 'gt': case 'lt': {
      const fvNum = Number(fieldValue);
      if (isNaN(fvNum)) return false;
      const target = Number(values[0]);
      if (isNaN(target)) return false;
      if (modifier === 'gte') return fvNum >= target;
      if (modifier === 'lte') return fvNum <= target;
      if (modifier === 'gt') return fvNum > target;
      return fvNum < target; // lt
    }
    case 're': {
      const pattern = String(values[0]);
      if (pattern.length > 200) return false;
      try {
        const fvStr = String(fieldValue).slice(0, 10000);
        return new RegExp(pattern).test(fvStr);
      } catch {
        return false;
      }
    }
    case 'cidr': {
      const ip = String(fieldValue);
      return values.some(v => cidrMatch(ip, String(v)));
    }
    case 'exists': {
      const wantExists = values[0] === true;
      const exists = fieldValue !== undefined && fieldValue !== null;
      return wantExists ? exists : !exists;
    }
    case 'asset_criticality': {
      if (!asset) return false;
      return values.some(v => asset.criticality === v);
    }
    case 'asset_has_cve': {
      if (!asset) return false;
      return values.some(v => asset.cves.some(c => c.id === v));
    }
    case 'asset_cvss_gte': {
      if (!asset) return false;
      const threshold = Number(values[0]);
      return asset.cves.some(c => c.cvss >= threshold);
    }
    case 'asset_kev': {
      if (!asset) return false;
      return asset.cves.some(c => c.kev === true);
    }
    case 'asset_patch_status': {
      if (!asset) return false;
      return values.some(v => asset.patch_status === v);
    }
    case 'asset_firmware_outdated': {
      if (!asset) return false;
      return asset.firmware_upgrade_required === true;
    }
    case 'asset_zone': {
      if (!asset) return false;
      return values.some(v => asset.network_zone === v);
    }
    default:
      return false;
  }
}

// ── Task 5: Condition Parser and matchEvent ─────────────────────

type CondNode =
  | { type: 'clause'; name: string }
  | { type: 'not'; child: CondNode }
  | { type: 'and'; children: CondNode[] }
  | { type: 'or'; children: CondNode[] }
  | { type: '1of'; prefix: string }
  | { type: 'allof'; prefix: string };

function tokenize(condition: string): string[] {
  return condition.trim().split(/\s+/).filter(t => t.length > 0);
}

function parseCondition(condition: string): CondNode {
  const tokens = tokenize(condition);
  let pos = 0;

  function parseOr(): CondNode {
    const children: CondNode[] = [parseAnd()];
    while (pos < tokens.length && tokens[pos] === 'or') {
      pos++;
      children.push(parseAnd());
    }
    return children.length === 1 ? children[0] : { type: 'or', children };
  }

  function parseAnd(): CondNode {
    const children: CondNode[] = [parseNot()];
    while (pos < tokens.length && tokens[pos] === 'and') {
      pos++;
      children.push(parseNot());
    }
    return children.length === 1 ? children[0] : { type: 'and', children };
  }

  function parseNot(): CondNode {
    if (pos < tokens.length && tokens[pos] === 'not') {
      pos++;
      return { type: 'not', child: parseNot() };
    }
    return parsePrimary();
  }

  function parsePrimary(): CondNode {
    if (pos < tokens.length && tokens[pos] === '(') {
      pos++;
      const node = parseOr();
      if (pos < tokens.length && tokens[pos] === ')') pos++;
      return node;
    }

    // 1 of prefix* or all of prefix*
    if (pos < tokens.length && (tokens[pos] === '1' || tokens[pos] === 'all')) {
      const quantifier = tokens[pos];
      pos++;
      if (pos < tokens.length && tokens[pos] === 'of') {
        pos++;
        if (pos < tokens.length) {
          const pattern = tokens[pos];
          pos++;
          const prefix = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
          return { type: quantifier === '1' ? '1of' : 'allof', prefix };
        }
      }
    }

    // clause name
    const name = tokens[pos] || '';
    pos++;
    return { type: 'clause', name };
  }

  return parseOr();
}

function evaluateCondition(node: CondNode, clauseResults: Map<string, boolean>): boolean {
  switch (node.type) {
    case 'clause':
      return clauseResults.get(node.name) ?? false;
    case 'not':
      return !evaluateCondition(node.child, clauseResults);
    case 'and':
      return node.children.every(c => evaluateCondition(c, clauseResults));
    case 'or':
      return node.children.some(c => evaluateCondition(c, clauseResults));
    case '1of': {
      for (const [name, result] of clauseResults) {
        if (name.startsWith(node.prefix) && result) return true;
      }
      return false;
    }
    case 'allof': {
      for (const [name, result] of clauseResults) {
        if (name.startsWith(node.prefix) && !result) return false;
      }
      // Must have at least one matching clause
      return [...clauseResults.keys()].some(n => n.startsWith(node.prefix));
    }
  }
}

function evaluateClause(
  matchers: FieldMatcher[],
  event: Record<string, unknown>,
  assets: AssetIndex,
): { match: boolean; matchedFields: Record<string, unknown> } {
  const matchedFields: Record<string, unknown> = {};

  // Resolve asset for asset_* modifiers
  const assetValue = (event.host_id ?? event.src_ip ?? event.dst_ip) as string | undefined;
  const asset = assetValue ? resolveAsset(assetValue, assets) : null;

  for (const matcher of matchers) {
    const fieldValue = event[matcher.field];
    const result = evaluateModifier(fieldValue, matcher.modifier, matcher.values, asset);
    if (!result) return { match: false, matchedFields: {} };
    matchedFields[matcher.field] = fieldValue;
  }

  return { match: true, matchedFields };
}

const SEVERITY_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'] as const;

function computeSeverity(
  ruleLevel: string,
  asset: AssetRecord | null,
): { effective: string; reason: string; riskFactors: string[] } {
  let idx = SEVERITY_LEVELS.indexOf(ruleLevel as any);
  if (idx < 0) idx = 0;
  const reasons: string[] = [];
  const riskFactors: string[] = [];

  if (!asset) {
    return { effective: ruleLevel, reason: '', riskFactors: [] };
  }

  if (asset.criticality === 'critical') {
    idx++;
    reasons.push('critical asset');
    riskFactors.push('critical_asset');
  }

  if (asset.cves.some(c => c.kev)) {
    idx++;
    reasons.push('KEV vulnerability present');
    riskFactors.push('kev_present');
  }

  if (asset.patch_status === 'critical') {
    idx++;
    reasons.push('critical patch status');
    riskFactors.push('critical_patch_status');
  }

  if (asset.firmware_upgrade_required) {
    const eolDate = new Date(asset.hardware_eol);
    const now = new Date();
    const monthsToEol = (eolDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (monthsToEol <= 12) {
      idx++;
      reasons.push('firmware outdated + EOL within 12 months');
      riskFactors.push('firmware_eol_risk');
    }
  }

  // Cap at critical
  if (idx >= SEVERITY_LEVELS.length) idx = SEVERITY_LEVELS.length - 1;

  return {
    effective: SEVERITY_LEVELS[idx],
    reason: reasons.join(', '),
    riskFactors,
  };
}

export function matchEvent(
  rawEvent: Record<string, unknown>,
  rules: SigmaRule[],
  assets: AssetIndex,
): SigmaMatch[] {
  const event = normalizeEvent(rawEvent);
  const matches: SigmaMatch[] = [];

  for (const rule of rules) {
    if (rule._degraded) continue;

    const clauseResults = new Map<string, boolean>();
    let allMatchedFields: Record<string, unknown> = {};

    for (const [clauseName, matchers] of Object.entries(rule.detection.clauses)) {
      const { match, matchedFields } = evaluateClause(matchers, event, assets);
      clauseResults.set(clauseName, match);
      if (match) {
        allMatchedFields = { ...allMatchedFields, ...matchedFields };
      }
    }

    const condNode = parseCondition(rule.detection.condition);
    const condResult = evaluateCondition(condNode, clauseResults);

    if (!condResult) continue;

    // Resolve asset for enrichment
    const assetKey = (event.host_id ?? event.src_ip ?? event.dst_ip) as string | undefined;
    const asset = assetKey ? resolveAsset(assetKey, assets) : null;

    const { effective, reason, riskFactors } = computeSeverity(rule.level, asset);

    // Build recommendations
    const recommendations = [...(rule.recommended_actions || [])];
    if (asset) {
      const unpatchedCves = asset.cves.filter(c => !c.patched);
      for (const cve of unpatchedCves) {
        recommendations.push(`Patch ${cve.id} (CVSS ${cve.cvss}${cve.kev ? ', KEV' : ''})`);
      }
      if (asset.firmware_upgrade_required) {
        recommendations.push(`Firmware upgrade required: ${asset.firmware} → ${asset.firmware_latest}`);
      }
    }

    const sigmaMatch: SigmaMatch = {
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
      recommendations,
    };

    if (asset) {
      sigmaMatch.asset_context = {
        host_id: asset.host_id,
        name: asset.name,
        criticality: asset.criticality,
        unpatched_cves: asset.cves.filter(c => !c.patched).map(c => c.id),
        firmware_outdated: asset.firmware_upgrade_required,
        patch_status: asset.patch_status,
        network_zone: asset.network_zone,
        hardware_eol: asset.hardware_eol,
      };
    }

    matches.push(sigmaMatch);
  }

  return matches;
}

// Re-export yaml for use in other modules
export { yaml };

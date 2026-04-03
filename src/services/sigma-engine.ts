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

// Re-export yaml for use in other modules
export { yaml };

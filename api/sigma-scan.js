/**
 * Sigma Scan API — Vercel Edge Function
 *
 * Scans events against loaded Sigma detection rules.
 *
 * GET  /api/sigma-scan?action=rules  — List loaded rules
 * POST /api/sigma-scan               — Scan events array against rules
 */

export const config = { runtime: 'edge' };

import { getCorsHeaders } from './_cors.js';
import { loadRules, loadAssets, matchEvent } from '../src/services/sigma-engine.ts';

// ── In-memory caches ───────────────────────────────────────────
const CACHE_TTL = 10 * 60_000;

/** @type {{ rules: import('../src/services/sigma-engine.ts').SigmaRule[], ruleYamls: string[], loadedAt: number, failed: number, degraded: number } | null} */
let _rulesCache = null;

/** @type {{ assets: import('../src/services/sigma-engine.ts').AssetIndex, loadedAt: number } | null} */
let _assetsCache = null;

const ENGINE_VERSION = '1.0.0';

// ── Rule loading ───────────────────────────────────────────────

async function getRules(baseUrl) {
  if (_rulesCache && Date.now() - _rulesCache.loadedAt < CACHE_TTL) {
    return _rulesCache;
  }

  // Fetch index
  let indexData;
  try {
    const indexRes = await fetch(`${baseUrl}/sigma-rules/index.json`);
    if (!indexRes.ok) {
      throw new Error(`index.json fetch failed: ${indexRes.status}`);
    }
    indexData = await indexRes.json();
  } catch (err) {
    throw new Error(`Failed to fetch sigma-rules/index.json: ${err?.message || err}`);
  }

  const entries = Array.isArray(indexData) ? indexData : (indexData.rules ?? []);
  const enabled = entries.filter((e) => e.enabled !== false);

  // Fetch each rule YAML concurrently
  const results = await Promise.allSettled(
    enabled.map((entry) =>
      fetch(`${baseUrl}/sigma-rules/${entry.file}`).then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      })
    )
  );

  const ruleYamls = [];
  let failed = 0;

  for (const result of results) {
    if (result.status === 'fulfilled') {
      ruleYamls.push(result.value);
    } else {
      failed++;
    }
  }

  const rules = loadRules(ruleYamls);
  const degraded = rules.filter((r) => r._degraded).length;

  _rulesCache = { rules, ruleYamls, loadedAt: Date.now(), failed, degraded };
  return _rulesCache;
}

// ── Asset loading ──────────────────────────────────────────────

async function getAssets(baseUrl) {
  if (_assetsCache && Date.now() - _assetsCache.loadedAt < CACHE_TTL) {
    return _assetsCache;
  }

  const assetsRes = await fetch(`${baseUrl}/data/assets.json`);
  if (!assetsRes.ok) {
    throw new Error(`assets.json fetch failed: ${assetsRes.status}`);
  }
  const assetsText = await assetsRes.text();
  const assets = loadAssets(assetsText);

  _assetsCache = { assets, loadedAt: Date.now() };
  return _assetsCache;
}

// ── Empty asset index ──────────────────────────────────────────

function emptyAssetIndex() {
  return {
    byHostId: new Map(),
    byIp: new Map(),
    byHostname: new Map(),
    byAlias: new Map(),
  };
}

// ── JSON response helper ───────────────────────────────────────

function jsonResponse(body, status, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
  });
}

// ── Main handler ───────────────────────────────────────────────

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, POST, OPTIONS');

  // Preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Method guard
  if (req.method !== 'GET' && req.method !== 'POST') {
    return jsonResponse(
      { error: 'Method not allowed' },
      405,
      corsHeaders,
    );
  }

  const baseUrl = new URL(req.url).origin;
  const url = new URL(req.url);

  // ── GET ?action=rules ────────────────────────────────────────
  if (req.method === 'GET') {
    if (url.searchParams.get('action') !== 'rules') {
      return jsonResponse({ error: 'Missing or invalid action. Use ?action=rules' }, 400, corsHeaders);
    }

    let rulesData;
    try {
      rulesData = await getRules(baseUrl);
    } catch (err) {
      return jsonResponse(
        { error: 'Failed to load Sigma rules', details: err?.message || String(err) },
        503,
        corsHeaders,
      );
    }

    const listing = rulesData.rules.map((r) => ({
      id: r.id,
      title: r.title,
      level: r.level,
      status: r.status,
      enabled: !r._degraded,
      mitre_technique: r.mitre_technique ?? null,
      gatra_agent: r.gatra_agent ?? null,
      tags: r.tags,
    }));

    return jsonResponse(
      { rules: listing, count: listing.length, version: ENGINE_VERSION },
      200,
      {
        ...corsHeaders,
        'Cache-Control': 'public, max-age=60, s-maxage=60, stale-while-revalidate=30',
      },
    );
  }

  // ── POST — scan events ───────────────────────────────────────

  // Parse body
  let body;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400, corsHeaders);
  }

  if (!body || !Array.isArray(body.events)) {
    return jsonResponse({ error: "Request must include 'events' array" }, 400, corsHeaders);
  }

  if (body.events.length === 0) {
    return jsonResponse({ error: 'Events array must not be empty' }, 400, corsHeaders);
  }

  if (body.events.length > 50) {
    return jsonResponse(
      { error: 'Maximum 50 events per request', received: body.events.length },
      413,
      corsHeaders,
    );
  }

  // Load rules (required)
  let rulesData;
  try {
    rulesData = await getRules(baseUrl);
  } catch (err) {
    return jsonResponse(
      { error: 'Failed to load Sigma rules', details: err?.message || String(err) },
      503,
      corsHeaders,
    );
  }

  // Load assets (optional — degraded gracefully)
  const warnings = [];
  let assetIndex;
  try {
    const assetsData = await getAssets(baseUrl);
    assetIndex = assetsData.assets;
  } catch {
    warnings.push('Asset inventory unavailable');
    assetIndex = emptyAssetIndex();
  }

  // Scan each event
  const results = body.events.map((event, idx) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      return { event_index: idx, error: 'Event must be a non-null object', matches: [] };
    }
    try {
      const matches = matchEvent(event, rulesData.rules, assetIndex);
      return { event_index: idx, matches };
    } catch (err) {
      return { event_index: idx, error: err?.message || 'Evaluation error', matches: [] };
    }
  });

  return jsonResponse(
    {
      results,
      rules_loaded: rulesData.rules.length,
      rules_failed: rulesData.failed,
      rules_degraded: rulesData.degraded,
      warnings,
      scanned_at: new Date().toISOString(),
      engine_version: ENGINE_VERSION,
    },
    200,
    {
      ...corsHeaders,
      'Cache-Control': 'public, max-age=60, s-maxage=60, stale-while-revalidate=30',
    },
  );
}

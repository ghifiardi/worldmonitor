/**
 * Threat Intelligence Feeds Proxy — Vercel Edge Function
 *
 * Aggregates real-time threat data from three abuse.ch feeds:
 *   1. URLhaus  — active malware distribution URLs  (CSV download, no auth)
 *   2. Feodo Tracker — botnet C2 server IPs          (JSON download, no auth)
 *   3. ThreatFox — IOCs with malware attribution      (JSON export, no auth)
 *
 * All feeds are free and require no API key.
 *
 * GET /api/threat-feeds
 * Returns: { urlhaus[], feodo[], threatfox[], sources, errors, cachedAt }
 */

import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

const FETCH_TIMEOUT = 12_000;
const CACHE_TTL = 5 * 60_000; // 5 minutes
const URLHAUS_LIMIT = 20;
const FEODO_LIMIT = 25;
const THREATFOX_LIMIT = 15;

let cache = { data: null, timestamp: 0 };

async function fetchWithTimeout(url, opts = {}, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...opts,
      signal: controller.signal,
      headers: {
        'User-Agent': 'WorldMonitor/1.0 (threat-intelligence-dashboard)',
        ...(opts.headers || {}),
      },
    });
  } finally {
    clearTimeout(timeout);
  }
}

// ── URLhaus: active malware URLs (CSV download) ──────────────────

function parseUrlhausCsv(csvText) {
  const lines = csvText.split('\n');
  const entries = [];

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.startsWith('#') || line.trim() === '') continue;

    // CSV format: "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
    // Parse quoted CSV
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') { inQuotes = !inQuotes; continue; }
      if (ch === ',' && !inQuotes) { fields.push(current); current = ''; continue; }
      current += ch;
    }
    fields.push(current);

    if (fields.length < 9) continue;

    const [id, dateAdded, url, urlStatus, , threat, tagsStr, , reporter] = fields;
    if (urlStatus !== 'online') continue;

    // Extract host from URL
    let host = '';
    try { host = new URL(url).hostname; } catch { host = url.split('/')[2] || ''; }

    // Parse tags (comma-separated within the field)
    const tags = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(Boolean) : [];

    entries.push({ id, url, urlStatus, threat, tags, host, dateAdded, reporter });
    if (entries.length >= URLHAUS_LIMIT) break;
  }

  return entries;
}

async function fetchUrlhaus() {
  const res = await fetchWithTimeout('https://urlhaus.abuse.ch/downloads/csv_recent/');
  if (!res.ok) throw new Error(`URLhaus ${res.status}`);
  const text = await res.text();
  return parseUrlhausCsv(text);
}

// ── Feodo Tracker: botnet C2 servers (JSON download) ─────────────

async function fetchFeodo() {
  const res = await fetchWithTimeout(
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  );
  if (!res.ok) throw new Error(`Feodo ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data)) return [];

  // Sort by last_online descending (most recently active first)
  const sorted = data
    .filter(e => e.ip_address)
    .sort((a, b) => (b.last_online || '').localeCompare(a.last_online || ''));

  return sorted.slice(0, FEODO_LIMIT).map(e => ({
    ip: e.ip_address,
    port: e.port || 0,
    country: e.country || '',
    firstSeen: e.first_seen || '',
    lastOnline: e.last_online || null,
    malware: e.malware || '',
  }));
}

// ── ThreatFox: IOCs with malware attribution (JSON export) ───────

async function fetchThreatFox() {
  // Use the public JSON export endpoint (no auth required)
  const res = await fetchWithTimeout('https://threatfox.abuse.ch/export/json/recent/');
  if (!res.ok) throw new Error(`ThreatFox ${res.status}`);
  const data = await res.json();

  // Response is keyed by ID: { "123456": [{ ioc_value, ... }], ... }
  if (!data || typeof data !== 'object') return [];

  const entries = [];
  for (const [id, records] of Object.entries(data)) {
    if (!Array.isArray(records) || records.length === 0) continue;
    const e = records[0];
    if ((e.confidence_level || 0) < 50) continue;

    entries.push({
      id: String(id),
      ioc: e.ioc_value || e.ioc || '',
      iocType: e.ioc_type || '',
      threatType: e.threat_type || '',
      malware: e.malware || '',
      malwarePrintable: e.malware_printable || '',
      confidence: e.confidence_level || 0,
      tags: typeof e.tags === 'string' ? e.tags.split(',').map(t => t.trim()).filter(Boolean) : (e.tags || []),
      firstSeen: e.first_seen_utc || '',
    });

    if (entries.length >= THREATFOX_LIMIT) break;
  }

  return entries;
}

// ── Handler ──────────────────────────────────────────────────────

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Serve from cache if fresh
  if (cache.data && Date.now() - cache.timestamp < CACHE_TTL) {
    return new Response(cache.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300, s-maxage=300, stale-while-revalidate=120',
        'X-Cache': 'HIT',
        ...corsHeaders,
      },
    });
  }

  try {
    const results = await Promise.allSettled([
      fetchUrlhaus(),
      fetchFeodo(),
      fetchThreatFox(),
    ]);

    const errors = [];
    const urlhaus = results[0].status === 'fulfilled' ? results[0].value : (() => { errors.push(`urlhaus: ${results[0].reason}`); return []; })();
    const feodo = results[1].status === 'fulfilled' ? results[1].value : (() => { errors.push(`feodo: ${results[1].reason}`); return []; })();
    const threatfox = results[2].status === 'fulfilled' ? results[2].value : (() => { errors.push(`threatfox: ${results[2].reason}`); return []; })();

    const payload = JSON.stringify({
      urlhaus,
      feodo,
      threatfox,
      sources: {
        urlhaus: urlhaus.length,
        feodo: feodo.length,
        threatfox: threatfox.length,
      },
      errors,
      cachedAt: new Date().toISOString(),
    });

    cache = { data: payload, timestamp: Date.now() };

    return new Response(payload, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300, s-maxage=300, stale-while-revalidate=120',
        'X-Cache': 'MISS',
        ...corsHeaders,
      },
    });
  } catch (error) {
    console.error('[threat-feeds] Error:', error.message);

    // Serve stale cache if available
    if (cache.data) {
      return new Response(cache.data, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Cache': 'STALE',
          ...corsHeaders,
        },
      });
    }

    return new Response(JSON.stringify({
      error: 'Failed to fetch threat feeds',
      details: error.message,
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}

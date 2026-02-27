/**
 * Threat Intelligence API clients — VirusTotal + AbuseIPDB
 *
 * Used by the A2A IOC Scanner skill to return real enrichment data.
 * Gracefully falls back when API keys are not configured.
 *
 * Env vars:
 *   VIRUSTOTAL_API_KEY  — free tier: 4 req/min, 500/day
 *   ABUSEIPDB_API_KEY   — free tier: 1000 checks/day
 */

const VT_BASE = 'https://www.virustotal.com/api/v3';
const ABUSE_BASE = 'https://api.abuseipdb.com/api/v2';
const FETCH_TIMEOUT = 6000; // 6s per API call

// ── In-memory cache (5-minute TTL) ──────────────────────────────

/** @type {Map<string, {data: any, ts: number}>} */
const cache = new Map();
const CACHE_TTL = 5 * 60_000;

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { cache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  cache.set(key, { data, ts: Date.now() });
  if (cache.size > 300) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
}

// ── Helpers ─────────────────────────────────────────────────────

function timedFetch(url, opts) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  return fetch(url, { ...opts, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

function verdictFromScores(abuseConfidence, vtMalicious, vtTotal) {
  if (abuseConfidence > 70 || vtMalicious > 5) return 'malicious';
  if (abuseConfidence > 25 || vtMalicious > 0) return 'suspicious';
  return 'clean';
}

// ── IP Lookup ───────────────────────────────────────────────────

export async function checkIP(ip) {
  const cacheKey = `ip:${ip}`;
  const cached = getCached(cacheKey);
  if (cached) return { ...cached, cached: true };

  const result = {
    indicator: ip,
    type: 'ip',
    sources: [],
    verdict: 'unknown',
    confidence: 0,
    abuseipdb: null,
    virustotal: null,
    cached: false,
  };

  const promises = [];

  // AbuseIPDB
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  if (abuseKey) {
    promises.push(
      timedFetch(`${ABUSE_BASE}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
        headers: { Key: abuseKey, Accept: 'application/json' },
      })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          if (!data?.data) return;
          const d = data.data;
          result.sources.push('AbuseIPDB');
          result.abuseipdb = {
            abuseConfidence: d.abuseConfidenceScore,
            totalReports: d.totalReports,
            lastReported: d.lastReportedAt,
            isp: d.isp,
            domain: d.domain,
            countryCode: d.countryCode,
            usageType: d.usageType,
            isTor: d.isTor,
            isWhitelisted: d.isWhitelisted,
          };
        })
        .catch(() => {}),
    );
  }

  // VirusTotal
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey) {
    promises.push(
      timedFetch(`${VT_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
        headers: { 'x-apikey': vtKey },
      })
        .then(async r => {
          if (r.status === 429) {
            result.sources.push('VirusTotal');
            result.virustotal = { rateLimited: true, note: 'Rate limited (4 req/min free tier)' };
            return null;
          }
          if (!r.ok) {
            console.log(JSON.stringify({ _type: 'vt_error', status: r.status, ip }));
            return null;
          }
          return r.json();
        })
        .then(data => {
          if (!data?.data?.attributes) return;
          const attr = data.data.attributes;
          const stats = attr.last_analysis_stats || {};
          const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
          result.sources.push('VirusTotal');
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            totalEngines: total,
            asOwner: attr.as_owner || null,
            country: attr.country || null,
            reputation: attr.reputation ?? null,
            network: attr.network || null,
          };
        })
        .catch(e => { console.log(JSON.stringify({ _type: 'vt_catch', error: e?.message, ip })); }),
    );
  }

  await Promise.allSettled(promises);

  // Derive verdict
  const abuseConf = result.abuseipdb?.abuseConfidence ?? 0;
  const vtMal = result.virustotal?.malicious ?? 0;
  const vtTotal = result.virustotal?.totalEngines ?? 0;
  const vtRateLimited = result.virustotal?.rateLimited === true;

  if (result.sources.length === 0) {
    result.verdict = 'unchecked';
  } else if (vtRateLimited && !result.abuseipdb) {
    result.verdict = 'rate_limited';
  } else {
    result.verdict = verdictFromScores(abuseConf, vtMal, vtTotal);
  }
  result.confidence = Math.max(abuseConf, vtTotal > 0 ? Math.round((vtMal / vtTotal) * 100) : 0);

  // Only cache complete results (not rate-limited ones)
  if (result.sources.length > 0 && !vtRateLimited) setCache(cacheKey, result);
  return result;
}

// ── Hash Lookup ─────────────────────────────────────────────────

export async function checkHash(hash) {
  const cacheKey = `hash:${hash}`;
  const cached = getCached(cacheKey);
  if (cached) return { ...cached, cached: true };

  const result = {
    indicator: hash,
    type: hash.length <= 32 ? 'md5' : hash.length <= 40 ? 'sha1' : 'sha256',
    sources: [],
    verdict: 'unknown',
    confidence: 0,
    virustotal: null,
    cached: false,
  };

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey) {
    try {
      const res = await timedFetch(`${VT_BASE}/files/${encodeURIComponent(hash)}`, {
        headers: { 'x-apikey': vtKey },
      });
      if (res.status === 429) {
        result.sources.push('VirusTotal');
        result.virustotal = { rateLimited: true, note: 'Rate limited (4 req/min free tier)' };
      } else if (res.ok) {
        const data = await res.json();
        const attr = data.data?.attributes;
        if (attr) {
          const stats = attr.last_analysis_stats || {};
          const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
          result.sources.push('VirusTotal');
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            totalEngines: total,
            fileName: attr.meaningful_name || attr.names?.[0] || null,
            fileType: attr.type_description || null,
            fileSize: attr.size || null,
            tags: (attr.tags || []).slice(0, 5),
            reputation: attr.reputation ?? null,
            popularThreatName: attr.popular_threat_classification?.suggested_threat_label || null,
          };
          result.verdict = stats.malicious > 5 ? 'malicious'
            : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean';
          result.confidence = total > 0 ? Math.round((stats.malicious / total) * 100) : 0;
        }
      } else if (res.status === 404) {
        result.sources.push('VirusTotal');
        result.verdict = 'not_found';
        result.virustotal = { note: 'Hash not found in VirusTotal database' };
      }
    } catch { /* timeout or network error — leave as unknown */ }
  }

  if (result.sources.length > 0) setCache(cacheKey, result);
  return result;
}

// ── Domain Lookup ───────────────────────────────────────────────

export async function checkDomain(domain) {
  const cacheKey = `domain:${domain}`;
  const cached = getCached(cacheKey);
  if (cached) return { ...cached, cached: true };

  const result = {
    indicator: domain,
    type: 'domain',
    sources: [],
    verdict: 'unknown',
    confidence: 0,
    virustotal: null,
    cached: false,
  };

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (vtKey) {
    try {
      const res = await timedFetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
        headers: { 'x-apikey': vtKey },
      });
      if (res.status === 429) {
        result.sources.push('VirusTotal');
        result.virustotal = { rateLimited: true, note: 'Rate limited (4 req/min free tier)' };
      } else if (res.ok) {
        const data = await res.json();
        const attr = data.data?.attributes;
        if (attr) {
          const stats = attr.last_analysis_stats || {};
          const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
          result.sources.push('VirusTotal');
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            totalEngines: total,
            registrar: attr.registrar || null,
            creationDate: attr.creation_date ? new Date(attr.creation_date * 1000).toISOString().slice(0, 10) : null,
            reputation: attr.reputation ?? null,
            categories: attr.categories ? Object.values(attr.categories).slice(0, 3) : [],
          };
          result.verdict = stats.malicious > 5 ? 'malicious'
            : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean';
          result.confidence = total > 0 ? Math.round((stats.malicious / total) * 100) : 0;
        }
      } else if (res.status === 404) {
        result.sources.push('VirusTotal');
        result.verdict = 'not_found';
      }
    } catch { /* timeout or network error */ }
  }

  if (result.sources.length > 0) setCache(cacheKey, result);
  return result;
}

// ── Utility ─────────────────────────────────────────────────────

export function hasAnyKeys() {
  return !!(process.env.VIRUSTOTAL_API_KEY || process.env.ABUSEIPDB_API_KEY);
}

export function availableSources() {
  const sources = [];
  if (process.env.VIRUSTOTAL_API_KEY) sources.push('VirusTotal');
  if (process.env.ABUSEIPDB_API_KEY) sources.push('AbuseIPDB');
  return sources;
}

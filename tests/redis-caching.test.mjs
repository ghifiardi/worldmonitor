/**
 * Tests for infrastructure cost optimizations — Round 1 (PR #273).
 *
 * Covers:
 * - Request coalescing via cachedFetchJson (in-flight dedup)
 * - Bbox grid quantization for military flights cache
 * - Redis pipeline batch GET
 * - ETF parallel fetch (sequential → Promise.allSettled)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const readSrc = (relPath) => readFileSync(resolve(root, relPath), 'utf-8');

// ========================================================================
// 1. Request coalescing — cachedFetchJson
// ========================================================================

describe('cachedFetchJson request coalescing', () => {
  const src = readSrc('server/_shared/redis.ts');

  it('exports cachedFetchJson function', () => {
    assert.match(src, /export async function cachedFetchJson/,
      'Should export cachedFetchJson');
  });

  it('uses an in-flight map for deduplication', () => {
    assert.match(src, /const inflight = new Map/,
      'Should have in-flight dedup map');
  });

  it('checks cache before triggering fetch', () => {
    const fnBody = src.slice(src.indexOf('async function cachedFetchJson'));
    const cacheCheckIdx = fnBody.indexOf('getCachedJson(key)');
    const inflightCheckIdx = fnBody.indexOf('inflight.get(key)');
    assert.ok(cacheCheckIdx > -1, 'Should check cache');
    assert.ok(inflightCheckIdx > -1, 'Should check in-flight map');
    assert.ok(cacheCheckIdx < inflightCheckIdx,
      'Cache check should come before in-flight check');
  });

  it('returns existing in-flight promise for concurrent callers', () => {
    assert.match(src, /const existing = inflight\.get\(key\)/,
      'Should retrieve existing in-flight promise');
    assert.match(src, /if \(existing\) return existing/,
      'Should return existing promise to concurrent callers');
  });

  it('cleans up in-flight entry in finally block', () => {
    assert.match(src, /\.finally\(\(\) =>/,
      'Should use finally for cleanup');
    assert.match(src, /inflight\.delete\(key\)/,
      'Should delete in-flight entry after completion');
  });

  it('writes to cache on successful fetch', () => {
    const fnBody = src.slice(src.indexOf('async function cachedFetchJson'));
    assert.match(fnBody, /setCachedJson\(key, result, ttlSeconds\)/,
      'Should write result to Redis cache');
  });
});

// ========================================================================
// 2. Redis pipeline batch GET
// ========================================================================

describe('getCachedJsonBatch pipeline', () => {
  const src = readSrc('server/_shared/redis.ts');

  it('exports getCachedJsonBatch function', () => {
    assert.match(src, /export async function getCachedJsonBatch/,
      'Should export getCachedJsonBatch');
  });

  it('returns empty Map for empty key array', () => {
    assert.match(src, /if \(keys\.length === 0\) return result/,
      'Should short-circuit on empty keys');
  });

  it('uses Upstash pipeline API for single round-trip', () => {
    assert.match(src, /\/pipeline/,
      'Should call the /pipeline endpoint');
    assert.match(src, /keys\.map\(\(k\) => \['GET', prefixKey\(k\)\]\)/,
      'Should build pipeline array of GET commands');
  });

  it('gracefully skips malformed JSON values', () => {
    assert.match(src, /try \{ result\.set.*JSON\.parse.*\} catch/,
      'Should catch JSON parse errors for individual entries');
  });
});

// ========================================================================
// 3. Aircraft details batch uses pipeline
// ========================================================================

describe('aircraft details batch handler', () => {
  const src = readSrc('server/worldmonitor/military/v1/get-aircraft-details-batch.ts');

  it('imports getCachedJsonBatch', () => {
    assert.match(src, /getCachedJsonBatch/,
      'Should import pipeline batch function');
  });

  it('uses batch GET instead of sequential GETs', () => {
    const batchCallIdx = src.indexOf('getCachedJsonBatch(cacheKeys)');
    assert.ok(batchCallIdx > -1,
      'Should call getCachedJsonBatch with array of cache keys');
    // Should NOT have a loop of getCachedJson calls
    const loopGetCount = (src.match(/getCachedJson\(/g) || []).length;
    // getCachedJsonBatch has "getCachedJson" in its name, so filter those out
    const singleGetCount = (src.match(/getCachedJson\b(?!Batch)/g) || []).length;
    assert.equal(singleGetCount, 0,
      'Should not use individual getCachedJson calls for batch lookups');
  });
});

// ========================================================================
// 4. Military flights bbox quantization
// ========================================================================

describe('military flights bbox quantization', () => {
  const src = readSrc('server/worldmonitor/military/v1/list-military-flights.ts');

  it('defines a quantize function', () => {
    assert.match(src, /const quantize = \(v: number, step: number\) => Math\.round\(v \/ step\) \* step/,
      'Should have quantize helper');
  });

  it('uses a 1-degree grid step', () => {
    assert.match(src, /BBOX_GRID_STEP = 1/,
      'Grid step should be 1 degree');
  });

  it('builds cache key from quantized bbox', () => {
    assert.match(src, /quantize\(bb\.southWest\.latitude, BBOX_GRID_STEP\)/,
      'Should quantize southwest latitude');
    assert.match(src, /quantize\(bb\.northEast\.longitude, BBOX_GRID_STEP\)/,
      'Should quantize northeast longitude');
  });

  it('expands fetch bbox by half grid step for full coverage', () => {
    assert.match(src, /BBOX_GRID_STEP \/ 2/,
      'Should expand fetch bbox by half step');
    // Verify expansion direction: subtract from min, add to max
    assert.match(src, /lamin:.*- BBOX_GRID_STEP \/ 2/,
      'Should subtract from south boundary');
    assert.match(src, /lamax:.*\+ BBOX_GRID_STEP \/ 2/,
      'Should add to north boundary');
  });
});

// ========================================================================
// 5. ETF flows: parallel fetch
// ========================================================================

describe('ETF flows parallel fetch', () => {
  const src = readSrc('server/worldmonitor/market/v1/list-etf-flows.ts');

  it('uses Promise.allSettled for concurrent ETF fetches', () => {
    assert.match(src, /Promise\.allSettled\(\s*\n?\s*ETF_LIST\.map/,
      'Should use Promise.allSettled with ETF_LIST.map for parallel fetches');
  });

  it('does not have sequential for-loop fetch pattern', () => {
    // Old pattern: for (const etf of ETF_LIST) { ... await Promise.allSettled([fetchEtfChart(...)]) }
    assert.doesNotMatch(src, /for \(const etf of ETF_LIST\)/,
      'Should not loop sequentially over ETF_LIST');
  });
});

/**
 * Gulf Air Traffic Proxy — Vercel Edge Function
 *
 * Proxies live aircraft positions from airplanes.live (free ADS-B data).
 * Queries multiple points to cover the Gulf/MENA region and deduplicates.
 *
 * GET /api/flights
 * Returns: { ac: [...], now: timestamp, total: count }
 */

import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

const API_BASE = 'https://api.airplanes.live/v2';
const FETCH_TIMEOUT = 12000;

// Gulf/MENA coverage points (lat, lon, radius_nm)
// Each covers ~250nm radius. Combined covers: Persian Gulf, Red Sea, Levant, Turkey, Iran
const COVERAGE_POINTS = [
  { lat: 26, lon: 50, r: 250 },   // Persian Gulf core (UAE, Qatar, Bahrain, Kuwait)
  { lat: 25, lon: 44, r: 250 },   // Saudi Arabia + western Gulf
  { lat: 33, lon: 44, r: 250 },   // Iraq + Levant (Syria, Jordan, Lebanon)
  { lat: 38, lon: 42, r: 250 },   // Turkey + northern Iraq
  { lat: 32, lon: 53, r: 250 },   // Iran
  { lat: 15, lon: 45, r: 200 },   // Yemen + Red Sea south
];

// In-memory cache
let cache = { data: null, timestamp: 0 };
const CACHE_TTL = 45_000; // 45 seconds

async function fetchWithTimeout(url, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json' },
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchAllGulfFlights() {
  // Fetch all coverage points in parallel
  const results = await Promise.allSettled(
    COVERAGE_POINTS.map(async (pt) => {
      const resp = await fetchWithTimeout(`${API_BASE}/point/${pt.lat}/${pt.lon}/${pt.r}`);
      if (!resp.ok) throw new Error(`API ${resp.status}`);
      const data = await resp.json();
      return data.ac || [];
    })
  );

  // Deduplicate by hex (ICAO24 address)
  const seen = new Set();
  const aircraft = [];
  for (const result of results) {
    if (result.status === 'fulfilled') {
      for (const ac of result.value) {
        if (ac.hex && !seen.has(ac.hex)) {
          seen.add(ac.hex);
          aircraft.push(ac);
        }
      }
    }
  }

  return aircraft;
}

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Check cache
  if (cache.data && Date.now() - cache.timestamp < CACHE_TTL) {
    return new Response(cache.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=45, s-maxage=45, stale-while-revalidate=30',
        'X-Cache': 'HIT',
        ...corsHeaders,
      },
    });
  }

  try {
    const aircraft = await fetchAllGulfFlights();
    const payload = JSON.stringify({
      ac: aircraft,
      now: Date.now(),
      total: aircraft.length,
    });

    // Update cache
    cache = { data: payload, timestamp: Date.now() };

    return new Response(payload, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=45, s-maxage=45, stale-while-revalidate=30',
        'X-Cache': 'MISS',
        ...corsHeaders,
      },
    });
  } catch (error) {
    console.error('[flights] Error:', error.message);
    return new Response(JSON.stringify({
      error: 'Failed to fetch flight data',
      details: error.message,
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}

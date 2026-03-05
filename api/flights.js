/**
 * OpenSky Network Proxy — Vercel Edge Function
 *
 * Proxies live aircraft state vectors from OpenSky for the Gulf/CENTCOM region.
 * Accepts bounding-box params: lamin, lamax, lomin, lomax.
 * Optionally uses OPENSKY_CLIENT_ID / OPENSKY_CLIENT_SECRET for higher rate limits.
 *
 * GET /api/flights?lamin=13&lamax=43&lomin=27&lomax=57
 */

import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

const OPENSKY_API = 'https://opensky-network.org/api/states/all';
const FETCH_TIMEOUT = 15000;

// In-memory cache (edge instances are short-lived but cache helps within a region)
let cache = { data: null, timestamp: 0, key: '' };
const CACHE_TTL = 30_000; // 30 seconds

async function fetchWithTimeout(url, options, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

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

  const url = new URL(req.url);
  const lamin = parseFloat(url.searchParams.get('lamin'));
  const lamax = parseFloat(url.searchParams.get('lamax'));
  const lomin = parseFloat(url.searchParams.get('lomin'));
  const lomax = parseFloat(url.searchParams.get('lomax'));

  // Validate bounding box
  if ([lamin, lamax, lomin, lomax].some(isNaN)) {
    return new Response(JSON.stringify({ error: 'Missing or invalid bounding box params (lamin, lamax, lomin, lomax)' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Sanity check: prevent absurdly large bounding boxes
  if (lamax - lamin > 60 || lomax - lomin > 60) {
    return new Response(JSON.stringify({ error: 'Bounding box too large (max 60° span)' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Check cache
  const cacheKey = `${lamin},${lamax},${lomin},${lomax}`;
  if (cache.data && cache.key === cacheKey && Date.now() - cache.timestamp < CACHE_TTL) {
    return new Response(cache.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=30, s-maxage=30, stale-while-revalidate=15',
        'X-Cache': 'HIT',
        ...corsHeaders,
      },
    });
  }

  try {
    const openskyUrl = `${OPENSKY_API}?lamin=${lamin}&lamax=${lamax}&lomin=${lomin}&lomax=${lomax}`;

    // Build headers — add auth if credentials are configured
    const headers = { 'Accept': 'application/json' };
    const clientId = process.env.OPENSKY_CLIENT_ID;
    const clientSecret = process.env.OPENSKY_CLIENT_SECRET;
    if (clientId && clientSecret) {
      headers['Authorization'] = 'Basic ' + btoa(`${clientId}:${clientSecret}`);
    }

    const response = await fetchWithTimeout(openskyUrl, { headers }, FETCH_TIMEOUT);

    if (response.status === 429) {
      return new Response(JSON.stringify({ error: 'OpenSky rate limited', retryAfter: 60 }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', 'Retry-After': '60', ...corsHeaders },
      });
    }

    if (!response.ok) {
      console.error('[flights] OpenSky returned', response.status);
      return new Response(JSON.stringify({ error: 'OpenSky upstream error', status: response.status }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    const data = await response.text();

    // Update cache
    cache = { data, timestamp: Date.now(), key: cacheKey };

    return new Response(data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=30, s-maxage=30, stale-while-revalidate=15',
        'X-Cache': 'MISS',
        ...corsHeaders,
      },
    });
  } catch (error) {
    const isTimeout = error.name === 'AbortError';
    console.error('[flights] Error:', error.message);
    return new Response(JSON.stringify({
      error: isTimeout ? 'OpenSky timeout' : 'Failed to fetch flight data',
      details: error.message,
    }), {
      status: isTimeout ? 504 : 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}

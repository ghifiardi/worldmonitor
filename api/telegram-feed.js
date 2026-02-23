// Telegram feed proxy (web)
// Fetches Telegram Early Signals from the Railway relay (stateful MTProto lives there).

import { getCorsHeaders, isDisallowedOrigin } from './_cors.js';

export const config = { runtime: 'edge' };

async function fetchWithTimeout(url, options, timeoutMs = 12000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

export default async function handler(req) {
  const cors = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  if (isDisallowedOrigin(req)) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), { status: 403, headers: cors });
  }

  const relay = process.env.WS_RELAY_URL;
  if (!relay) {
    return new Response(JSON.stringify({ error: 'WS_RELAY_URL not configured' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const url = new URL(req.url);
  const limit = Math.max(1, Math.min(200, parseInt(url.searchParams.get('limit') || '50', 10) || 50));
  const topic = (url.searchParams.get('topic') || '').trim();
  const channel = (url.searchParams.get('channel') || '').trim();

  const relayUrl = new URL('/telegram/feed', relay);
  relayUrl.searchParams.set('limit', String(limit));
  if (topic) relayUrl.searchParams.set('topic', topic);
  if (channel) relayUrl.searchParams.set('channel', channel);

  try {
    const res = await fetchWithTimeout(relayUrl.toString(), {
      headers: { 'Accept': 'application/json' },
    }, 12000);

    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: {
        'Content-Type': res.headers.get('content-type') || 'application/json',
        // Short cache. Telegram is near-real-time.
        'Cache-Control': 'public, max-age=10',
        ...cors,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return new Response(JSON.stringify({ error: 'Telegram relay fetch failed', detail: msg }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }
}

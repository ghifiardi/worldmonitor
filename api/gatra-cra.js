/**
 * GATRA CRA Proxy — Relays SOC chat actions to the gatra-local backend.
 *
 * POST /api/gatra-cra
 * Body: { action: string, target: string, reason?: string, severity?: string, confidence?: number }
 *
 * Connects to the gatra-local FastAPI dashboard at GATRA_LOCAL_URL (default: http://127.0.0.1:8847).
 * Returns the response from the local backend including gate decisions.
 */

const GATRA_LOCAL_URL = process.env.GATRA_LOCAL_URL || 'http://127.0.0.1:8847';
const GATRA_API_TOKEN = process.env.GATRA_API_TOKEN || '';

const ACTION_MAP = {
  block: (t, b) => ({ url: `/api/cra/block?ip=${enc(t.target)}&reason=${enc(b.reason || 'SOC analyst')}&severity=${enc(b.severity || 'high')}&confidence=${b.confidence || 0.85}`, method: 'POST' }),
  unblock: (t) => ({ url: `/api/cra/unblock?ip=${enc(t.target)}`, method: 'POST' }),
  kill: (t, b) => ({ url: `/api/cra/kill?pid=${enc(t.target)}&reason=${enc(b.reason || 'SOC analyst')}&severity=${enc(b.severity || 'critical')}`, method: 'POST' }),
  suspend: (t) => ({ url: `/api/cra/suspend?pid=${enc(t.target)}`, method: 'POST' }),
  resume: (t) => ({ url: `/api/cra/resume?pid=${enc(t.target)}`, method: 'POST' }),
  approve: (t) => ({ url: `/api/gate/approve/${enc(t.target)}`, method: 'POST' }),
  'approve-all': () => ({ url: `/api/gate/approve-all`, method: 'POST' }),
  deny: (t) => ({ url: `/api/gate/deny/${enc(t.target)}`, method: 'POST' }),
  pending: () => ({ url: `/api/gate/pending`, method: 'GET' }),
  status: () => ({ url: `/api/status`, method: 'GET' }),
  blocked: () => ({ url: `/api/blocked`, method: 'GET' }),
  alerts: () => ({ url: `/api/alerts?limit=20`, method: 'GET' }),
  'yara-scan': (t) => ({ url: `/api/yara/scan-file?file_path=${enc(t.target)}`, method: 'POST' }),
  'yara-rules': () => ({ url: `/api/yara/rules`, method: 'GET' }),
};

function enc(s) { return encodeURIComponent(s || ''); }

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }

  try {
    const body = req.body || {};
    const { action, target, reason, severity, confidence } = body;

    if (!action) {
      return res.status(400).json({ error: 'action required' });
    }

    const mapper = ACTION_MAP[action];
    if (!mapper) {
      return res.status(400).json({ error: `unknown action: ${action}`, available: Object.keys(ACTION_MAP) });
    }

    const route = mapper({ target }, body);
    const url = `${GATRA_LOCAL_URL}${route.url}`;

    const headers = { 'Content-Type': 'application/json' };
    if (GATRA_API_TOKEN) headers['Authorization'] = `Bearer ${GATRA_API_TOKEN}`;

    const upstream = await fetch(url, {
      method: route.method,
      headers,
      signal: AbortSignal.timeout(10000),
    });

    const data = await upstream.json();
    return res.status(upstream.status).json({
      ...data,
      _gatra: { backend: 'local', action, target },
    });
  } catch (err) {
    // Connection refused = gatra-local not running
    if (err.cause?.code === 'ECONNREFUSED' || err.message?.includes('ECONNREFUSED')) {
      return res.status(503).json({
        error: 'gatra-local not reachable',
        hint: 'Start gatra-local: cd gatra-local && python main.py --foreground',
        backend_url: GATRA_LOCAL_URL,
      });
    }
    console.error('[gatra-cra] Error:', err.message);
    return res.status(502).json({ error: 'Backend error', message: err.message });
  }
}

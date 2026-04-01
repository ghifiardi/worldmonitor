/**
 * SOC Intent Classifier — Groq LLM fallback for natural language actions.
 *
 * Called only when regex-based detection fails and the message looks
 * like it might be an action request. Uses llama-3.3-70b on Groq (~200ms).
 *
 * POST /api/soc-intent
 * Body: { message: string, context?: { alerts: string[], pending: string[] } }
 * Returns: { intent: string|null, target: string, confidence: number, reasoning: string }
 */

// @ts-check

/** @typedef {{ command: string|null, target: string, confidence: number, reasoning: string }} IntentResult */

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = 'llama-3.3-70b-versatile';

const SYSTEM_PROMPT = `You are a SOC (Security Operations Center) intent classifier. Given an analyst's message, determine if they want to perform an action.

Available actions:
- block <ip:port> — Block an IP address or IP:port in the firewall
- unblock <ip> — Remove IP from blocklist
- kill <pid> — Terminate a process
- isolate <host> — Network-isolate an endpoint
- escalate <target> — Escalate alerts to CRITICAL (target can be technique ID like T1059, severity like "critical", alert ID, or description)
- investigate <target> — Move alerts to investigation queue
- dismiss <target> — Close/suppress alerts
- fp <target> — Mark alerts as false positive
- approve <id> — Approve a pending gated action (id like G001)
- approve-all — Approve all pending actions
- deny <id> — Reject a pending action
- deny-all — Reject all pending actions
- hold <target> — Pause automated containment
- release <target> — Resume automated containment
- report — Generate incident report
- status — Show agent status
- pending — Show pending approval queue

Rules:
1. If the message is clearly an action, return the command and target.
2. The target should be extracted from context: technique IDs (T1059), IPs (10.0.0.1), PIDs, hostnames, severity levels, or alert descriptions.
3. If they reference "it", "that", "those", "the last one" etc., use the context.alerts array to resolve the reference.
4. If the message is a question or general discussion (not an action), return command: null.
5. Be conservative — only classify as an action if the analyst clearly wants something done.

Respond with ONLY valid JSON, no markdown:
{"command":"<action or null>","target":"<extracted target>","confidence":<0.0-1.0>,"reasoning":"<brief explanation>"}`;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return res.status(503).json({ error: 'GROQ_API_KEY not configured' });
  }

  try {
    const { message, context } = req.body || {};
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message required' });
    }

    // Build context string from recent alerts and pending actions
    let contextStr = '';
    if (context?.alerts?.length) {
      contextStr += `\nRecent alerts: ${context.alerts.slice(0, 5).join('; ')}`;
    }
    if (context?.pending?.length) {
      contextStr += `\nPending actions: ${context.pending.join('; ')}`;
    }

    const userMessage = contextStr
      ? `Analyst message: "${message}"\n\nContext:${contextStr}`
      : `Analyst message: "${message}"`;

    const groqRes = await fetch(GROQ_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userMessage },
        ],
        temperature: 0.1,
        max_tokens: 150,
        response_format: { type: 'json_object' },
      }),
    });

    if (!groqRes.ok) {
      const errText = await groqRes.text();
      console.error('[soc-intent] Groq error:', groqRes.status, errText);
      return res.status(502).json({ error: 'LLM request failed', status: groqRes.status });
    }

    const data = await groqRes.json();
    const content = data.choices?.[0]?.message?.content ?? '{}';

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch {
      console.error('[soc-intent] Failed to parse LLM JSON:', content);
      return res.json({ command: null, target: '', confidence: 0, reasoning: 'parse error' });
    }

    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.json({
      command: parsed.command || null,
      target: parsed.target || '',
      confidence: parsed.confidence || 0,
      reasoning: parsed.reasoning || '',
      model: data.model,
      usage: data.usage,
    });
  } catch (err) {
    console.error('[soc-intent] Error:', err);
    return res.status(500).json({ error: 'Internal error' });
  }
}

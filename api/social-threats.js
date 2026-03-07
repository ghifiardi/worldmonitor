/**
 * Social Threat Intelligence Feed — Vercel Edge Function
 *
 * Aggregates cybersecurity-related posts from three free, open platforms:
 *   1. Bluesky (AT Protocol — no auth required)
 *   2. Hacker News (Algolia search API — no auth required)
 *   3. Mastodon infosec.exchange (hashtag timelines — no auth required)
 *
 * GET /api/social-threats
 * Returns: { posts: [...], count, sources, cachedAt }
 */

import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

const FETCH_TIMEOUT = 10_000;
const CACHE_TTL = 10 * 60_000; // 10 minutes
const MAX_POSTS = 50;

let cache = { data: null, timestamp: 0 };

// ── Threat keyword detection ───────────────────────────────────────

const THREAT_KEYWORDS_RE = /\b(CVE-\d{4}-\d{4,}|zero[- ]?day|ransomware|malware|APT\d+|phishing|exploit|botnet|backdoor|RCE|XSS|SQL injection|buffer overflow|privilege escalation|C2|command[- ]and[- ]control|data breach|credential stuffing|DDoS|supply chain attack)\b/gi;

function extractThreatKeywords(text) {
  if (!text) return [];
  const matches = text.match(THREAT_KEYWORDS_RE) || [];
  return [...new Set(matches.map((m) => m.toUpperCase()))].slice(0, 5);
}

// ── Bluesky fetch ──────────────────────────────────────────────────

async function fetchBluesky() {
  const q = encodeURIComponent('cybersecurity OR vulnerability OR breach OR ransomware OR CVE');
  const url = `https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=${q}&limit=25`;

  const res = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'WorldMonitor/1.0 (threat-intelligence-dashboard)',
    },
  });

  if (!res.ok) throw new Error(`Bluesky ${res.status}`);
  const data = await res.json();

  return (data.posts || []).map((post) => {
    const record = post.record || {};
    const author = post.author || {};
    const text = record.text || '';

    return {
      id: `bsky_${post.uri?.split('/').pop() || Date.now()}`,
      platform: 'bluesky',
      author: `@${author.handle || 'unknown'}`,
      authorDisplayName: author.displayName || author.handle || 'Unknown',
      content: text.slice(0, 500),
      url: `https://bsky.app/profile/${author.handle}/post/${post.uri?.split('/').pop() || ''}`,
      postedAt: record.createdAt || new Date().toISOString(),
      engagement: {
        likes: post.likeCount || 0,
        reposts: post.repostCount || 0,
        replies: post.replyCount || 0,
      },
      threatKeywords: extractThreatKeywords(text),
    };
  });
}

// ── Hacker News (Algolia) fetch ────────────────────────────────────

async function fetchHackerNews() {
  // Algolia uses AND for multi-word queries, so use a shorter, broader query.
  // Fetch two queries in parallel for better coverage.
  const queries = [
    'cybersecurity vulnerability',
    'security breach exploit',
  ];

  const responses = await Promise.all(
    queries.map((q) =>
      fetch(`https://hn.algolia.com/api/v1/search_by_date?query=${encodeURIComponent(q)}&tags=story&hitsPerPage=15`, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
        headers: { Accept: 'application/json' },
      }),
    ),
  );

  const allHits = [];
  const seenIds = new Set();
  for (const res of responses) {
    if (!res.ok) continue;
    const data = await res.json();
    for (const hit of data.hits || []) {
      if (!seenIds.has(hit.objectID)) {
        seenIds.add(hit.objectID);
        allHits.push(hit);
      }
    }
  }

  return allHits.map((hit) => {
    const title = hit.title || '';
    const storyText = hit.story_text || '';
    const combined = `${title} ${storyText}`;

    return {
      id: `hn_${hit.objectID}`,
      platform: 'hackernews',
      author: hit.author || 'anonymous',
      authorDisplayName: hit.author || 'anonymous',
      content: title + (storyText ? ` — ${storyText.slice(0, 300)}` : ''),
      url: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
      postedAt: hit.created_at || new Date().toISOString(),
      engagement: {
        likes: hit.points || 0,
        reposts: 0,
        replies: hit.num_comments || 0,
      },
      threatKeywords: extractThreatKeywords(combined),
    };
  });
}

// ── Mastodon fetch (mastodon.social + hachyderm.io) ────────────────

async function fetchMastodon() {
  // Fetch hashtag timelines from two large public instances
  // (infosec.exchange requires auth; mastodon.social + hachyderm.io don't)
  const [cyberRes, infosecRes, hachydermRes] = await Promise.all([
    fetch('https://mastodon.social/api/v1/timelines/tag/cybersecurity?limit=15', {
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
      headers: { Accept: 'application/json' },
    }),
    fetch('https://mastodon.social/api/v1/timelines/tag/infosec?limit=15', {
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
      headers: { Accept: 'application/json' },
    }),
    fetch('https://hachyderm.io/api/v1/timelines/tag/cybersecurity?limit=10', {
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
      headers: { Accept: 'application/json' },
    }),
  ]);

  const cyberPosts = cyberRes.ok ? await cyberRes.json() : [];
  const infosecPosts = infosecRes.ok ? await infosecRes.json() : [];
  const hachydermPosts = hachydermRes.ok ? await hachydermRes.json() : [];

  // Ensure arrays (APIs might return error objects)
  const safeArray = (v) => (Array.isArray(v) ? v : []);

  // Deduplicate by ID
  const seen = new Set();
  const allPosts = [...safeArray(cyberPosts), ...safeArray(infosecPosts), ...safeArray(hachydermPosts)].filter((p) => {
    if (seen.has(p.id)) return false;
    seen.add(p.id);
    return true;
  });

  return allPosts.map((post) => {
    const account = post.account || {};
    // Strip HTML tags from content
    const plainText = (post.content || '').replace(/<[^>]+>/g, '').slice(0, 500);

    return {
      id: `mast_${post.id}`,
      platform: 'mastodon',
      author: `@${account.acct || 'unknown'}`,
      authorDisplayName: account.display_name || account.acct || 'Unknown',
      content: plainText,
      url: post.url || post.uri || '',
      postedAt: post.created_at || new Date().toISOString(),
      engagement: {
        likes: post.favourites_count || 0,
        reposts: post.reblogs_count || 0,
        replies: post.replies_count || 0,
      },
      threatKeywords: extractThreatKeywords(plainText),
    };
  });
}

// ── Handler ────────────────────────────────────────────────────────

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

  // Check cache
  if (cache.data && Date.now() - cache.timestamp < CACHE_TTL) {
    return new Response(cache.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=600, s-maxage=600, stale-while-revalidate=120',
        'X-Cache': 'HIT',
        ...corsHeaders,
      },
    });
  }

  try {
    // Fetch all three sources in parallel — tolerate individual failures
    const results = await Promise.allSettled([
      fetchBluesky(),
      fetchHackerNews(),
      fetchMastodon(),
    ]);

    const blueskyPosts = results[0].status === 'fulfilled' ? results[0].value : [];
    const hnPosts = results[1].status === 'fulfilled' ? results[1].value : [];
    const mastodonPosts = results[2].status === 'fulfilled' ? results[2].value : [];

    // Log any failures
    results.forEach((r, i) => {
      if (r.status === 'rejected') {
        const names = ['Bluesky', 'HackerNews', 'Mastodon'];
        console.error(`[social-threats] ${names[i]} failed:`, r.reason?.message || r.reason);
      }
    });

    // Merge, sort by date descending, limit
    const allPosts = [...blueskyPosts, ...hnPosts, ...mastodonPosts];
    allPosts.sort((a, b) => new Date(b.postedAt).getTime() - new Date(a.postedAt).getTime());
    const posts = allPosts.slice(0, MAX_POSTS);

    const payload = JSON.stringify({
      posts,
      count: posts.length,
      sources: {
        bluesky: blueskyPosts.length,
        hackernews: hnPosts.length,
        mastodon: mastodonPosts.length,
      },
      errors: results
        .map((r, i) => r.status === 'rejected' ? ['bluesky', 'hackernews', 'mastodon'][i] : null)
        .filter(Boolean),
      cachedAt: new Date().toISOString(),
    });

    cache = { data: payload, timestamp: Date.now() };

    return new Response(payload, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=600, s-maxage=600, stale-while-revalidate=120',
        'X-Cache': 'MISS',
        ...corsHeaders,
      },
    });
  } catch (error) {
    console.error('[social-threats] Error:', error.message);

    // Return stale cache if available
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
      error: 'Failed to fetch social threat data',
      details: error.message,
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}

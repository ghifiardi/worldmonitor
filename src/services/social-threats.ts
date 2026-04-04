/**
 * Social Threat Intelligence Service
 *
 * Fetches aggregated cybersecurity posts from Bluesky, Hacker News,
 * and Mastodon via the /api/social-threats edge function.
 * Results are cached for 10 minutes.
 */

import type { SocialThreatPost, SocialPlatform } from '@/types';

// ── API response shape ─────────────────────────────────────────────

interface SocialThreatsApiResponse {
  posts: Array<{
    id: string;
    platform: SocialPlatform;
    author: string;
    authorDisplayName: string;
    content: string;
    url: string;
    postedAt: string;
    engagement: { likes: number; reposts: number; replies: number };
    threatKeywords: string[];
  }>;
  count: number;
  sources: { bluesky: number; hackernews: number; mastodon: number };
  errors: string[];
  cachedAt: string;
}

// ── Cache ──────────────────────────────────────────────────────────

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

interface Cache<T> {
  data: T;
  timestamp: number;
}

let _cache: Cache<SocialThreatPost[]> | null = null;
let _sourceCounts: { bluesky: number; hackernews: number; mastodon: number } | null = null;
let _fetching = false;

// ── Public API ─────────────────────────────────────────────────────

/**
 * Fetch social threat intelligence posts.
 * Returns cached data if available and fresh.
 */
export async function fetchSocialThreats(): Promise<SocialThreatPost[]> {
  // Return cached if fresh
  if (_cache && Date.now() - _cache.timestamp < CACHE_TTL_MS) {
    return _cache.data;
  }

  // Prevent concurrent fetches
  if (_fetching && _cache) return _cache.data;
  _fetching = true;

  try {
    const res = await fetch('/api/social-threats', {
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = (await res.json()) as SocialThreatsApiResponse;

    // Transform API posts → typed SocialThreatPost with Date objects
    const posts: SocialThreatPost[] = (data.posts || []).map((p) => ({
      ...p,
      postedAt: new Date(p.postedAt),
    }));

    // Sort by date descending (should already be sorted, but ensure)
    posts.sort((a, b) => b.postedAt.getTime() - a.postedAt.getTime());

    _cache = { data: posts, timestamp: Date.now() };
    _sourceCounts = data.sources || null;

    return posts;
  } catch (err) {
    console.error('[SocialThreats] fetch failed:', err);
    // Fall back to cached data if available
    if (_cache) return _cache.data;
    throw err;
  } finally {
    _fetching = false;
  }
}

/** Return source breakdown counts from last fetch. */
export function getSourceCounts(): { bluesky: number; hackernews: number; mastodon: number } | null {
  return _sourceCounts;
}

/** Clear the cache so next call fetches fresh data. */
export function clearSocialThreatsCache(): void {
  _cache = null;
  _sourceCounts = null;
}

/** Return cached data without fetching (may be null). */
export function getCachedSocialThreats(): SocialThreatPost[] | null {
  return _cache?.data ?? null;
}

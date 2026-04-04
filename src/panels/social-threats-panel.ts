/**
 * SocialThreatsPanel — Social Threat Intelligence feed panel.
 *
 * Renders:
 *   1. Platform filter tabs (All / Bluesky / HN / Mastodon)
 *   2. Stats row (total posts, source breakdown, trending keyword)
 *   3. Scrollable post list with platform badges and engagement metrics
 *
 * Data sourced from Bluesky, Hacker News, and Mastodon via
 * /api/social-threats edge function. Refreshes every 10 minutes.
 */

import { Panel } from '@/components/Panel';
import { escapeHtml } from '@/utils/sanitize';
import { fetchSocialThreats, getSourceCounts } from '@/services/social-threats';
import type { SocialThreatPost, SocialPlatform } from '@/types';

// ── Platform colors and labels ─────────────────────────────────────

const PLATFORM_COLORS: Record<SocialPlatform, string> = {
  bluesky: '#0085ff',
  hackernews: '#ff6600',
  mastodon: '#6364ff',
};

const PLATFORM_LABELS: Record<SocialPlatform, string> = {
  bluesky: 'Bluesky',
  hackernews: 'HN',
  mastodon: 'Mastodon',
};

type FilterValue = 'all' | SocialPlatform;

// ── Panel class ────────────────────────────────────────────────────

export class SocialThreatsPanel extends Panel {
  private posts: SocialThreatPost[] = [];
  private filteredPosts: SocialThreatPost[] = [];
  private loading = false;
  private lastFetchTime: Date | null = null;
  private activeFilter: FilterValue = 'all';

  constructor() {
    super({
      id: 'social-threats',
      title: 'Social Threat Intel',
      showCount: true,
      trackActivity: true,
      infoTooltip:
        'Real-time cybersecurity posts from Bluesky, Hacker News, and Mastodon (infosec.exchange). Monitors keywords: CVE, breach, ransomware, exploit, zero-day. Data refreshes every 10 min.',
    });
  }

  /** Called by App on a scheduled interval. */
  public async refresh(): Promise<void> {
    if (this.loading) return;
    this.loading = true;

    try {
      const items = await fetchSocialThreats();
      this.posts = items;
      this.lastFetchTime = new Date();

      this.applyFilter();
      this.setCount(items.length);

      const sources = getSourceCounts();
      const detail = sources
        ? `${sources.bluesky}B · ${sources.hackernews}HN · ${sources.mastodon}M`
        : `${items.length} posts`;
      this.setDataBadge('live', detail);

      // Pulse badge for posts with threat keywords
      const threatCount = items.filter((p) => p.threatKeywords.length > 0).length;
      if (threatCount > 0) {
        this.setNewBadge(threatCount, true);
      } else {
        this.clearNewBadge();
      }

      this.render();
    } catch (err) {
      console.error('[SocialThreatsPanel] refresh error:', err);
      if (this.posts.length === 0) {
        this.showError('Failed to load social threat data');
      }
      this.setDataBadge('unavailable');
    } finally {
      this.loading = false;
    }
  }

  // ── Filtering ───────────────────────────────────────────────────

  private applyFilter(): void {
    this.filteredPosts =
      this.activeFilter === 'all'
        ? this.posts
        : this.posts.filter((p) => p.platform === this.activeFilter);
  }

  // ── Rendering ───────────────────────────────────────────────────

  private render(): void {
    const html = [
      this.renderFilterTabs(),
      this.renderStatsRow(),
      this.renderPostList(),
      this.renderFooter(),
    ].join('');

    // Use direct innerHTML (not debounced setContent) so we can
    // attach filter event listeners immediately afterwards.
    this.content.innerHTML = html;
    this.bindFilterEvents();
  }

  // ── Filter tabs ─────────────────────────────────────────────────

  private renderFilterTabs(): string {
    const filters: { label: string; value: FilterValue; color?: string }[] = [
      { label: 'All', value: 'all' },
      { label: 'Bluesky', value: 'bluesky', color: PLATFORM_COLORS.bluesky },
      { label: 'HN', value: 'hackernews', color: PLATFORM_COLORS.hackernews },
      { label: 'Mastodon', value: 'mastodon', color: PLATFORM_COLORS.mastodon },
    ];

    const tabs = filters
      .map((f) => {
        const isActive = this.activeFilter === f.value;
        const count =
          f.value === 'all'
            ? this.posts.length
            : this.posts.filter((p) => p.platform === f.value).length;

        const bg = isActive ? (f.color || 'var(--accent)') : 'transparent';
        const fg = isActive ? '#fff' : 'var(--text-secondary)';
        const border = isActive ? 'none' : '1px solid var(--border-dim)';

        return `<button data-social-filter="${f.value}" style="
          background:${bg};color:${fg};border:${border};
          font-size:10px;font-weight:600;padding:3px 8px;border-radius:4px;
          cursor:pointer;white-space:nowrap;transition:all 0.15s;
        ">${f.label} <span style="opacity:0.7;font-weight:400;">${count}</span></button>`;
      })
      .join('');

    return `<div style="display:flex;gap:4px;padding:8px 12px;border-bottom:1px solid var(--border-dim);flex-wrap:wrap;">${tabs}</div>`;
  }

  private bindFilterEvents(): void {
    this.content.querySelectorAll<HTMLButtonElement>('[data-social-filter]').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.activeFilter = (btn.dataset.socialFilter as FilterValue) || 'all';
        this.applyFilter();
        this.render();
      });
    });
  }

  // ── Stats row ───────────────────────────────────────────────────

  private renderStatsRow(): string {
    const total = this.filteredPosts.length;
    const withThreats = this.filteredPosts.filter((p) => p.threatKeywords.length > 0).length;
    const totalEngagement = this.filteredPosts.reduce(
      (sum, p) => sum + p.engagement.likes + p.engagement.reposts + p.engagement.replies,
      0,
    );

    // Find trending keyword
    const kwCount: Record<string, number> = {};
    for (const p of this.filteredPosts) {
      for (const kw of p.threatKeywords) {
        kwCount[kw] = (kwCount[kw] || 0) + 1;
      }
    }
    const trending = Object.entries(kwCount).sort((a, b) => b[1] - a[1])[0];

    const stat = (label: string, value: string | number, color?: string) =>
      `<div style="text-align:center;flex:1;min-width:55px;">
        <div style="font-size:16px;font-weight:700;${color ? `color:${color};` : 'color:var(--text-primary);'}">${value}</div>
        <div style="font-size:9px;opacity:0.5;text-transform:uppercase;letter-spacing:0.3px;">${label}</div>
      </div>`;

    return `<div style="display:flex;padding:8px 12px;border-bottom:1px solid var(--border-dim);gap:4px;">
      ${stat('Posts', total)}
      ${stat('Threats', withThreats, withThreats > 0 ? '#ef4444' : undefined)}
      ${stat('Engage', totalEngagement > 1000 ? `${(totalEngagement / 1000).toFixed(1)}k` : totalEngagement)}
      ${stat(
        'Trending',
        trending ? trending[0].length > 12 ? trending[0].slice(0, 10) + '..' : trending[0] : '—',
        trending ? '#ef4444' : undefined,
      )}
    </div>`;
  }

  // ── Post list ───────────────────────────────────────────────────

  private renderPostList(): string {
    if (this.filteredPosts.length === 0) {
      return '<div style="padding:16px;opacity:0.5;font-size:12px;text-align:center;">No posts available</div>';
    }

    const rows = this.filteredPosts.map((post) => {
      const platformColor = PLATFORM_COLORS[post.platform] || '#6b7280';
      const platformLabel = PLATFORM_LABELS[post.platform] || post.platform;
      const ts = this.timeAgo(post.postedAt);

      // Platform badge
      const platformBadge = `<span style="
        background:${platformColor};color:#fff;font-size:9px;font-weight:700;
        padding:1px 5px;border-radius:3px;flex-shrink:0;letter-spacing:0.3px;
      ">${platformLabel}</span>`;

      // Threat keyword badges
      const kwBadges = post.threatKeywords.slice(0, 2)
        .map((kw) => `<span style="
          background:rgba(239,68,68,0.15);color:#ef4444;font-size:9px;font-weight:600;
          padding:1px 4px;border-radius:2px;
        ">${escapeHtml(kw)}</span>`)
        .join(' ');

      // Content with threat keywords highlighted
      let content = escapeHtml(post.content.slice(0, 200));
      for (const kw of post.threatKeywords) {
        const re = new RegExp(`(${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        content = content.replace(re, '<span style="color:#ef4444;font-weight:600;">$1</span>');
      }

      // Engagement bar
      const eng = post.engagement;
      const engText = [
        eng.likes > 0 ? `${eng.likes} likes` : '',
        eng.reposts > 0 ? `${eng.reposts} reposts` : '',
        eng.replies > 0 ? `${eng.replies} replies` : '',
      ]
        .filter(Boolean)
        .join(' · ');

      return `<a href="${escapeHtml(post.url)}" target="_blank" rel="noopener noreferrer" style="
        display:block;padding:8px 12px;border-bottom:1px solid var(--border-dim);
        font-size:12px;text-decoration:none;color:inherit;
        transition:background 0.15s;cursor:pointer;
      " onmouseover="this.style.background='var(--hover-bg,rgba(255,255,255,0.03))'" onmouseout="this.style.background='transparent'">
        <div style="display:flex;align-items:center;gap:5px;margin-bottom:3px;">
          ${platformBadge}
          <span style="font-weight:600;font-size:11px;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(post.authorDisplayName)}</span>
          <span style="opacity:0.35;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(post.author)}</span>
          <span style="margin-left:auto;opacity:0.4;flex-shrink:0;font-size:10px;">${ts}</span>
        </div>
        <div style="opacity:0.8;font-size:11px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.4;">${content}</div>
        <div style="display:flex;align-items:center;gap:4px;margin-top:3px;">
          ${kwBadges}
          ${engText ? `<span style="margin-left:auto;opacity:0.35;font-size:10px;">${engText}</span>` : ''}
        </div>
      </a>`;
    }).join('');

    return `<div style="max-height:400px;overflow-y:auto;">${rows}</div>`;
  }

  // ── Footer ──────────────────────────────────────────────────────

  private renderFooter(): string {
    const sourceInfo = this.lastFetchTime
      ? `Updated ${this.timeAgo(this.lastFetchTime)}`
      : 'Loading...';

    return `<div style="padding:6px 12px;font-size:10px;opacity:0.35;display:flex;justify-content:space-between;border-top:1px solid var(--border-dim);">
      <span>Bluesky · Hacker News · infosec.exchange</span>
      <span>${escapeHtml(sourceInfo)}</span>
    </div>`;
  }

  // ── Helpers ─────────────────────────────────────────────────────

  private timeAgo(date: Date): string {
    const ms = Date.now() - date.getTime();
    if (ms < 60_000) return 'just now';
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
    return `${Math.floor(ms / 86_400_000)}d ago`;
  }
}

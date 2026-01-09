import type { Feed } from '@/types';

// Source tier system for prioritization (lower = more authoritative)
// Tier 1: Wire services - fastest, most reliable breaking news
// Tier 2: Major outlets - high-quality journalism
// Tier 3: Specialty sources - domain expertise
// Tier 4: Aggregators & blogs - useful but less authoritative
export const SOURCE_TIERS: Record<string, number> = {
  // Tier 1 - Wire Services
  'Reuters': 1,
  'AP News': 1,
  'AFP': 1,
  'Bloomberg': 1,

  // Tier 2 - Major Outlets
  'BBC World': 2,
  'BBC Middle East': 2,
  'Guardian World': 2,
  'Guardian ME': 2,
  'NPR News': 2,
  'CNN Middle East': 2,
  'CNBC': 2,
  'MarketWatch': 2,
  'Al Jazeera': 2,

  // Tier 1.5 - Official Government Sources
  'White House': 1,
  'State Dept': 1,
  'Pentagon': 1,
  'Treasury': 2,
  'DOJ': 2,
  'DHS': 2,
  'CDC': 2,
  'FEMA': 2,

  // Tier 3 - Specialty
  'Defense One': 3,
  'Breaking Defense': 3,
  'The War Zone': 3,
  'Foreign Policy': 3,
  'The Diplomat': 3,
  'Bellingcat': 3,
  'Krebs Security': 3,
  'Federal Reserve': 3,
  'SEC': 3,
  'MIT Tech Review': 3,
  'Ars Technica': 3,

  // Tier 4 - Aggregators
  'Hacker News': 4,
  'The Verge': 4,
  'VentureBeat AI': 4,
  'Yahoo Finance': 4,
  'TechCrunch Layoffs': 4,
  'Hugging Face': 4,
  'ArXiv AI': 4,
};

export function getSourceTier(sourceName: string): number {
  return SOURCE_TIERS[sourceName] ?? 4; // Default to tier 4 if unknown
}

export const FEEDS: Record<string, Feed[]> = {
  politics: [
    { name: 'BBC World', url: '/rss/bbc/news/world/rss.xml' },
    { name: 'NPR News', url: '/rss/npr/1001/rss.xml' },
    { name: 'Guardian World', url: '/rss/guardian/world/rss' },
    { name: 'AP News', url: '/rss/apnews/feed' },
    { name: 'The Diplomat', url: '/rss/diplomat/feed/' },
  ],
  middleeast: [
    { name: 'BBC Middle East', url: '/rss/bbc/news/world/middle_east/rss.xml' },
    { name: 'Al Jazeera', url: '/rss/aljazeera/xml/rss/all.xml' },
    { name: 'Guardian ME', url: '/rss/guardian/world/middleeast/rss' },
    { name: 'CNN Middle East', url: '/rss/cnn/rss/edition_meast.rss' },
  ],
  tech: [
    { name: 'Hacker News', url: '/rss/hn/frontpage' },
    { name: 'Ars Technica', url: '/rss/arstechnica/arstechnica/technology-lab' },
    { name: 'The Verge', url: '/rss/verge/rss/index.xml' },
    { name: 'MIT Tech Review', url: '/rss/techreview/feed/' },
  ],
  ai: [
    { name: 'AI News', url: '/rss/googlenews/rss/search?q=artificial+intelligence+AI+news&hl=en-US&gl=US&ceid=US:en' },
    { name: 'Hugging Face', url: '/rss/huggingface/blog/feed.xml' },
    { name: 'ArXiv AI', url: '/rss/arxiv/rss/cs.AI' },
    { name: 'VentureBeat AI', url: '/rss/venturebeat/feed/' },
  ],
  finance: [
    { name: 'CNBC', url: '/rss/cnbc/id/100003114/device/rss/rss.html' },
    { name: 'MarketWatch', url: '/rss/marketwatch/marketwatch/topstories' },
    { name: 'Yahoo Finance', url: '/rss/yahoonews/news/rssindex' },
  ],
  gov: [
    { name: 'White House', url: '/rss/whitehouse/briefing-room/feed/' },
    { name: 'State Dept', url: '/rss/state/rss/feeds/documents/latest_news' },
    { name: 'Pentagon', url: '/rss/defense/DesktopModules/ArticleCS/RSS.ashx?ContentType=1&Site=945&max=10' },
    { name: 'Treasury', url: '/rss/treasury/press-center/news/pages/rss@xmlnewsbydate.aspx' },
    { name: 'DOJ', url: '/rss/justice/feeds/opa/justicenews.xml' },
    { name: 'Federal Reserve', url: '/rss/fedreserve/feeds/press_all.xml' },
    { name: 'SEC', url: '/rss/sec/news/pressreleases.rss' },
    { name: 'CDC', url: '/rss/cdc/rss/search.ashx?Search=&Channel=CDC_Media' },
    { name: 'FEMA', url: '/rss/fema/api/v2/news?format=rss' },
    { name: 'DHS', url: '/rss/dhs/news/rss/all' },
  ],
  layoffs: [
    { name: 'TechCrunch Layoffs', url: '/rss/techcrunch/tag/layoffs/feed/' },
    { name: 'Layoffs News', url: '/rss/googlenews/rss/search?q=tech+layoffs+2025+job+cuts&hl=en-US&gl=US&ceid=US:en' },
  ],
  congress: [
    { name: 'Congress Trades', url: '/rss/googlenews/rss/search?q=congress+stock+trading+pelosi+tuberville&hl=en-US&gl=US&ceid=US:en' },
  ],
  thinktanks: [
    { name: 'Foreign Policy', url: '/rss/foreignpolicy/feed/' },
    { name: 'Think Tank News', url: '/rss/googlenews/rss/search?q=brookings+CSIS+CFR+analysis&hl=en-US&gl=US&ceid=US:en' },
  ],
};

export const INTEL_SOURCES: Feed[] = [
  { name: 'Defense One', url: '/rss/defenseone/rss/all/', type: 'defense' },
  { name: 'Breaking Defense', url: '/rss/breakingdefense/feed/', type: 'defense' },
  { name: 'The War Zone', url: '/rss/warzone/the-war-zone/feed', type: 'defense' },
  { name: 'Defense News', url: '/rss/googlenews/rss/search?q=defense+military+pentagon&hl=en-US&gl=US&ceid=US:en', type: 'defense' },
  { name: 'Bellingcat', url: '/rss/bellingcat/feed/', type: 'osint' },
  { name: 'Krebs Security', url: '/rss/krebs/feed/', type: 'cyber' },
];

export const ALERT_KEYWORDS = [
  'war', 'invasion', 'military', 'nuclear', 'sanctions', 'missile',
  'attack', 'troops', 'conflict', 'strike', 'bomb', 'casualties',
  'ceasefire', 'treaty', 'nato', 'coup', 'martial law', 'emergency',
  'assassination', 'terrorist', 'hostage', 'evacuation', 'breaking',
];

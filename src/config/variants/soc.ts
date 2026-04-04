// SOC Demo variant — focused GATRA SOC dashboard for demonstrations
//
// Strips away all geopolitical/news panels and shows only:
//   - GATRA SOC Alert Panel + Agent Health
//   - CII Monitor (Country Instability Index)
//   - CVE Feed, IoC Lookup, Ransomware Tracker
//   - A2A Security Monitor, Prediction Signals
//   - Global map with GATRA alerts + cyber threats only
//
// Deploy with VITE_VARIANT=soc or switch via header bar.
import type { PanelConfig, MapLayers } from '@/types';
import type { VariantConfig } from './base';

// Re-export base config
export * from './base';

// SOC demo uses a minimal subset of cyber feeds — only threat intel and GATRA-relevant
import type { Feed } from '@/types';

const rss = (url: string) => `/api/rss-proxy?url=${encodeURIComponent(url)}`;

export const FEEDS: Record<string, Feed[]> = {
  // Core security news (minimal — just enough for the live-news panel)
  security: [
    { name: 'Krebs on Security', url: rss('https://krebsonsecurity.com/feed/') },
    { name: 'The Hacker News', url: rss('https://feeds.feedburner.com/TheHackersNews') },
    { name: 'Dark Reading', url: rss('https://www.darkreading.com/rss.xml') },
  ],

  // Threat Intelligence — directly relevant to SOC operations
  threats: [
    { name: 'CISA Advisories', url: rss('https://www.cisa.gov/cybersecurity-advisories/all.xml') },
    { name: 'Cyber Incidents', url: rss('https://news.google.com/rss/search?q=(cyber+attack+OR+data+breach+OR+ransomware+OR+hacking)+when:3d&hl=en-US&gl=US&ceid=US:en') },
  ],

  // Indonesian Cyber Sources — GATRA protects Indonesian telco
  indonesia: [
    { name: 'Keamanan Siber ID', url: rss('https://news.google.com/rss/search?q="keamanan+siber"+OR+"BSSN"+OR+"serangan+siber"+OR+"kebocoran+data"+when:3d&hl=id&gl=ID&ceid=ID:id') },
    { name: 'Indonesia Cyber', url: rss('https://news.google.com/rss/search?q=Indonesia+"data+breach"+OR+"cyber+attack"+OR+"BSSN"+when:7d&hl=en&gl=ID&ceid=ID:en') },
  ],
};

// Panel configuration — GATRA SOC operational panels only
export const DEFAULT_PANELS: Record<string, PanelConfig> = {
  map: { name: 'Cyber Threat Map', enabled: true, priority: 1 },
  'gatra-soc': { name: 'GATRA SOC', enabled: true, priority: 1 },
  'cii-score': { name: 'CII Monitor', enabled: true, priority: 1 },
  'prediction-signals': { name: 'Predictive Signals', enabled: true, priority: 1 },
  'cve-feed': { name: 'CVE Feed', enabled: true, priority: 1 },
  'ransomware-tracker': { name: 'Ransomware Tracker', enabled: true, priority: 1 },
  'a2a-security': { name: 'A2A Security Monitor', enabled: true, priority: 1 },
  'ioc-lookup': { name: 'IoC Lookup', enabled: true, priority: 1 },
  'social-threats': { name: 'Social Threat Intel', enabled: true, priority: 1 },
  'personal-security-posture': { name: 'Security Posture', enabled: true, priority: 1 },
  'live-news': { name: 'Threat Headlines', enabled: true, priority: 2 },
  security: { name: 'Cybersecurity News', enabled: true, priority: 2 },
  threats: { name: 'Threat Intelligence', enabled: true, priority: 2 },
  indonesia: { name: 'Indonesia Cyber (BSSN)', enabled: true, priority: 2 },
  monitors: { name: 'My Monitors', enabled: true, priority: 2 },
};

// SOC-focused map layers — minimal, GATRA alerts front and center
export const DEFAULT_MAP_LAYERS: MapLayers = {
  conflicts: false,
  bases: false,
  cables: true,
  pipelines: false,
  hotspots: false,
  ais: false,
  nuclear: false,
  irradiators: false,
  sanctions: false,
  weather: false,
  economic: false,
  waterways: false,
  outages: true,
  cyberThreats: true,
  datacenters: true,
  protests: false,
  flights: false,
  military: false,
  natural: false,
  spaceports: false,
  minerals: false,
  fires: false,
  // Data source layers
  ucdpEvents: false,
  displacement: false,
  climate: false,
  // Tech layers
  startupHubs: false,
  cloudRegions: false,
  accelerators: false,
  techHQs: false,
  techEvents: false,
  // Finance layers
  stockExchanges: false,
  financialCenters: false,
  centralBanks: false,
  commodityHubs: false,
  gulfInvestments: false,
  // GATRA SOC layer — the star of the show
  gatraAlerts: true,
};

// Mobile defaults for SOC variant
export const MOBILE_DEFAULT_MAP_LAYERS: MapLayers = {
  conflicts: false,
  bases: false,
  cables: false,
  pipelines: false,
  hotspots: false,
  ais: false,
  nuclear: false,
  irradiators: false,
  sanctions: false,
  weather: false,
  economic: false,
  waterways: false,
  outages: true,
  cyberThreats: true,
  datacenters: false,
  protests: false,
  flights: false,
  military: false,
  natural: false,
  spaceports: false,
  minerals: false,
  fires: false,
  // Data source layers
  ucdpEvents: false,
  displacement: false,
  climate: false,
  // Tech layers
  startupHubs: false,
  cloudRegions: false,
  accelerators: false,
  techHQs: false,
  techEvents: false,
  // Finance layers
  stockExchanges: false,
  financialCenters: false,
  centralBanks: false,
  commodityHubs: false,
  gulfInvestments: false,
  // GATRA SOC layer
  gatraAlerts: true,
};

export const VARIANT_CONFIG: VariantConfig = {
  name: 'soc',
  description: 'GATRA SOC demo — focused AI-driven security operations dashboard',
  panels: DEFAULT_PANELS,
  mapLayers: DEFAULT_MAP_LAYERS,
  mobileMapLayers: MOBILE_DEFAULT_MAP_LAYERS,
};

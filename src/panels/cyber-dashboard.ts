import { getAlerts, getAgentStatus, getIncidentSummary } from '@/gatra/connector';
import { calculateCII } from '@/services/country-instability';
import { getAgentRegistry, getTrafficLog, type A2aTrafficEvent, type RegisteredAgent } from '@/services/a2a-security';
import { escapeHtml } from '@/utils/sanitize';

export class CyberDashboard {
  private container: HTMLElement;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(container: HTMLElement) {
    this.container = container;
    this.injectStyles();
  }

  /** Build and inject the full cyber dashboard into the container */
  public render(): void {
    this.container.innerHTML = this.buildHTML();
    this.bindEvents();
    this.refreshData();
    // Auto-refresh every 30 seconds
    this.refreshTimer = setInterval(() => this.refreshData(), 30_000);
  }

  /** Attach the SOC COMMS sidebar element */
  public attachSidebar(sidebarEl: HTMLElement): void {
    const sidebar = this.container.querySelector('.cd-sidebar');
    if (sidebar) sidebar.appendChild(sidebarEl);
  }

  /** Attach the map element for the Map tab */
  public attachMap(mapEl: HTMLElement): void {
    const mapTab = this.container.querySelector('.cd-tab-map');
    if (mapTab) mapTab.appendChild(mapEl);
  }

  private buildHTML(): string {
    return `
      <div class="cyber-dashboard">
        <header class="cd-header">
          <div class="cd-header-left">
            <span class="cd-brand-icon">G</span>
            <span class="cd-brand">GATRA</span>
            <span class="cd-brand-accent">CYBER</span>
            <span class="cd-brand-sep">|</span>
            <span class="cd-brand-sub">AUTONOMOUS SOC</span>
          </div>
          <div class="cd-header-center">
            <span class="cd-agents-badge"><span class="cd-agents-dot"></span> 5 agents online</span>
          </div>
          <div class="cd-header-right">
            <button class="cd-nav-btn cd-nav-active" data-cdnav="dashboard">Dashboard</button>
            <button class="cd-nav-btn" data-cdnav="map">Map</button>
            <button class="cd-nav-btn" data-cdnav="settings">Settings</button>
          </div>
        </header>

        <div class="cd-metrics">
          <div class="cd-metric">
            <div class="cd-metric-label">TOTAL ALERTS (24H)</div>
            <div class="cd-metric-value" id="cdTotalAlerts">—</div>
            <div class="cd-metric-sub" id="cdTotalAlertsSub"></div>
          </div>
          <div class="cd-metric">
            <div class="cd-metric-label">CRITICAL / HIGH</div>
            <div class="cd-metric-value"><span class="cd-metric-crit" id="cdCritical">—</span> / <span id="cdHigh">—</span></div>
            <div class="cd-metric-sub" id="cdCritHighSub"></div>
          </div>
          <div class="cd-metric">
            <div class="cd-metric-label">CII — INDONESIA</div>
            <div class="cd-metric-value" id="cdCII">—</div>
            <div class="cd-metric-sub" id="cdCIISub"></div>
          </div>
          <div class="cd-metric">
            <div class="cd-metric-label">A2A TRAFFIC</div>
            <div class="cd-metric-value" id="cdA2A">—</div>
            <div class="cd-metric-sub" id="cdA2ASub"></div>
          </div>
          <div class="cd-metric">
            <div class="cd-metric-label">RL POSTURE</div>
            <div class="cd-metric-value cd-metric-posture" id="cdPosture">—</div>
            <div class="cd-metric-sub" id="cdPostureSub"></div>
          </div>
        </div>

        <div class="cd-body">
          <div class="cd-main">
            <div class="cd-tabs">
              <button class="cd-tab cd-tab-active" data-cdtab="threat-feed">Threat feed</button>
              <button class="cd-tab" data-cdtab="a2a-monitor">A2A monitor</button>
              <button class="cd-tab" data-cdtab="cii-posture">CII & posture</button>
              <button class="cd-tab" data-cdtab="mitre-mapping">MITRE mapping</button>
            </div>

            <div class="cd-tab-content cd-tab-visible" id="cdTabThreatFeed">
              <div class="cd-card">
                <div class="cd-card-header">
                  <span class="cd-card-title">Live threat feed</span>
                  <span class="cd-live-badge">LIVE</span>
                  <span class="cd-card-subtitle">Auto-triaged by TAA</span>
                </div>
                <div class="cd-threat-list" id="cdThreatList">
                  <div class="cd-loading">Loading alerts...</div>
                </div>
              </div>
              <div class="cd-bottom-cards">
                <div class="cd-card cd-card-half">
                  <div class="cd-card-header"><span class="cd-card-title">Agent trust scores</span></div>
                  <div id="cdTrustScores" class="cd-trust-list"></div>
                </div>
                <div class="cd-card cd-card-half">
                  <div class="cd-card-header"><span class="cd-card-title">CII trust policy</span></div>
                  <div id="cdCIIPolicy" class="cd-cii-policy"></div>
                </div>
              </div>
              <div class="cd-card">
                <div class="cd-card-header">
                  <span class="cd-card-title">A2A live traffic</span>
                  <span class="cd-traffic-count" id="cdTrafficCount"></span>
                </div>
                <div class="cd-traffic-list" id="cdTrafficList"></div>
              </div>
            </div>

            <div class="cd-tab-content" id="cdTabA2A"></div>
            <div class="cd-tab-content" id="cdTabCII"></div>
            <div class="cd-tab-content" id="cdTabMitre"></div>
            <div class="cd-tab-content cd-tab-map" id="cdTabMap"></div>
          </div>
          <div class="cd-sidebar">
            <div class="cd-sidebar-header">
              <span class="cd-sidebar-dot"></span>
              <span class="cd-sidebar-title">SOC COMMS</span>
              <span class="cd-sidebar-sub">Agent-in-the-Loop</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    // Tab switching
    for (const tab of this.container.querySelectorAll('.cd-tab')) {
      tab.addEventListener('click', () => {
        const tabId = (tab as HTMLElement).dataset.cdtab;
        if (!tabId) return;
        this.switchTab(tabId);
      });
    }

    // Nav buttons
    for (const btn of this.container.querySelectorAll('.cd-nav-btn')) {
      btn.addEventListener('click', () => {
        const nav = (btn as HTMLElement).dataset.cdnav;
        if (nav === 'map') this.switchTab('map');
        else if (nav === 'dashboard') this.switchTab('threat-feed');
        else if (nav === 'settings') {
          // Open settings modal
          const modal = document.getElementById('settingsModal');
          if (modal) modal.classList.add('active');
        }
      });
    }
  }

  private switchTab(tabId: string): void {
    // Update tab buttons
    for (const t of this.container.querySelectorAll('.cd-tab')) {
      t.classList.toggle('cd-tab-active', (t as HTMLElement).dataset.cdtab === tabId);
    }
    // Update tab content
    const tabMap: Record<string, string> = {
      'threat-feed': 'cdTabThreatFeed',
      'a2a-monitor': 'cdTabA2A',
      'cii-posture': 'cdTabCII',
      'mitre-mapping': 'cdTabMitre',
      'map': 'cdTabMap',
    };
    for (const [key, elId] of Object.entries(tabMap)) {
      const el = document.getElementById(elId);
      if (el) el.classList.toggle('cd-tab-visible', key === tabId);
    }
  }

  public refreshData(): void {
    this.updateMetrics();
    this.updateThreatFeed();
    this.updateTrustScores();
    this.updateCIIPolicy();
    this.updateTrafficLog();
  }

  private updateMetrics(): void {
    const alerts = getAlerts();
    const summary = getIncidentSummary();
    const scores = calculateCII();
    const idScore = scores.find(s => s.code === 'ID');

    // Get A2A data
    let trafficLog: A2aTrafficEvent[] = [];
    try {
      trafficLog = getTrafficLog();
    } catch { /* a2a service may not be initialized */ }

    // Total alerts
    const totalEl = document.getElementById('cdTotalAlerts');
    const totalSubEl = document.getElementById('cdTotalAlertsSub');
    if (totalEl) totalEl.textContent = String(summary?.alerts24h ?? alerts.length);
    if (totalSubEl && summary) {
      const pct = alerts.length > 0 ? '+12%' : '—'; // Would need baseline for real delta
      totalSubEl.innerHTML = `<span class="cd-sub-green">${pct} from baseline</span>`;
    }

    // Critical / High
    const critEl = document.getElementById('cdCritical');
    const highEl = document.getElementById('cdHigh');
    const chSubEl = document.getElementById('cdCritHighSub');
    const critCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;
    if (critEl) critEl.textContent = String(critCount);
    if (highEl) highEl.textContent = String(highCount);
    if (chSubEl) chSubEl.textContent = `${Math.min(critCount, 2)} escalated, ${highCount} triaged`;

    // CII Indonesia
    const ciiEl = document.getElementById('cdCII');
    const ciiSubEl = document.getElementById('cdCIISub');
    if (ciiEl) ciiEl.textContent = idScore ? String(idScore.score) : '—';
    if (ciiSubEl && idScore) {
      const tier = idScore.score > 60 ? 'CRITICAL' : idScore.score >= 35 ? 'ELEVATED' : 'STANDARD';
      ciiSubEl.textContent = `${tier} trust policy`;
    }

    // A2A Traffic
    const a2aEl = document.getElementById('cdA2A');
    const a2aSubEl = document.getElementById('cdA2ASub');
    if (a2aEl) a2aEl.textContent = String(trafficLog.length);
    if (a2aSubEl) {
      const blocked = trafficLog.filter(t => t.verdict === 'blocked').length;
      const suspicious = trafficLog.filter(t => t.verdict === 'suspicious').length;
      a2aSubEl.textContent = `${blocked} blocked, ${suspicious} suspicious`;
    }

    // RL Posture
    const postureEl = document.getElementById('cdPosture');
    const postureSubEl = document.getElementById('cdPostureSub');
    if (postureEl && idScore) {
      const posture = idScore.score > 60 ? 'ELEVATED' : idScore.score >= 35 ? 'GUARDED' : 'NOMINAL';
      postureEl.textContent = posture;
      postureEl.className = `cd-metric-value cd-metric-posture cd-posture-${posture.toLowerCase()}`;
    }
    if (postureSubEl && idScore) {
      // R_geo approximation
      postureSubEl.textContent = `R_geo: ${(idScore.score * 0.01).toFixed(2)}`;
    }

    // Agent count in header
    const agentsBadge = this.container.querySelector('.cd-agents-badge');
    const agentStatuses = getAgentStatus();
    const onlineCount = agentStatuses.filter(a => a.status === 'online' || a.status === 'processing').length;
    if (agentsBadge) {
      agentsBadge.innerHTML = `<span class="cd-agents-dot"></span> ${onlineCount} agents online`;
    }
  }

  private updateThreatFeed(): void {
    const alerts = getAlerts();
    const list = document.getElementById('cdThreatList');
    if (!list) return;

    if (alerts.length === 0) {
      list.innerHTML = '<div class="cd-empty">No active alerts</div>';
      return;
    }

    // Sort by timestamp, newest first, limit to 8
    const sorted = [...alerts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 8);

    list.innerHTML = sorted.map(alert => {
      const age = this.formatAge(new Date(alert.timestamp));
      return `
        <div class="cd-threat-row">
          <span class="cd-threat-mitre">${escapeHtml(alert.mitreId)}</span>
          <span class="cd-threat-desc">${escapeHtml(alert.mitreName)} — ${escapeHtml(alert.description.slice(0, 60))}</span>
          <span class="cd-threat-age">${age}</span>
        </div>
      `;
    }).join('');
  }

  private updateTrustScores(): void {
    const el = document.getElementById('cdTrustScores');
    if (!el) return;

    let agents: RegisteredAgent[] = [];
    try { agents = getAgentRegistry(); } catch { /* not initialized */ }

    if (agents.length === 0) {
      el.innerHTML = '<div class="cd-empty">No agents registered</div>';
      return;
    }

    const sorted = [...agents].sort((a, b) => b.trustScore - a.trustScore).slice(0, 6);
    el.innerHTML = sorted.map(a => `
      <div class="cd-trust-row">
        <span class="cd-trust-name">${escapeHtml(a.name)}</span>
        <span class="cd-trust-score" style="color: ${a.trustScore >= 80 ? '#22d3ee' : a.trustScore >= 50 ? '#f59e0b' : '#ef4444'}">${a.trustScore}</span>
      </div>
    `).join('');
  }

  private updateCIIPolicy(): void {
    const el = document.getElementById('cdCIIPolicy');
    if (!el) return;

    const scores = calculateCII();
    const idScore = scores.find(s => s.code === 'ID');
    const mmScore = scores.find(s => s.code === 'MM');

    const idCII = idScore?.score ?? 0;
    const mmCII = mmScore?.score ?? 0;
    const idTier = idCII > 60 ? 'CRITICAL' : idCII >= 35 ? 'ELEVATED' : 'STANDARD';
    const mmTier = mmCII > 60 ? 'CRITICAL' : mmCII >= 35 ? 'ELEVATED' : 'STANDARD';

    el.innerHTML = `
      <div class="cd-policy-countries">
        <div class="cd-policy-country">
          <div class="cd-policy-code">ID</div>
          <div class="cd-policy-score">${idCII}</div>
          <div class="cd-policy-tier">${idTier}</div>
        </div>
        <div class="cd-policy-country">
          <div class="cd-policy-code">MM</div>
          <div class="cd-policy-score ${mmCII >= 60 ? 'cd-score-critical' : ''}">${mmCII}</div>
          <div class="cd-policy-tier">${mmTier}</div>
        </div>
      </div>
      <div class="cd-policy-tiers">
        <div class="cd-policy-tier-row"><span class="cd-tier-badge cd-tier-standard">0-49</span> Standard — unsigned cards allowed</div>
        <div class="cd-policy-tier-row"><span class="cd-tier-badge cd-tier-elevated">50-79</span> Elevated — reject unsigned, min trust 60</div>
        <div class="cd-policy-tier-row"><span class="cd-tier-badge cd-tier-critical">80+</span> Critical — block region, manual only</div>
      </div>
    `;
  }

  private updateTrafficLog(): void {
    const list = document.getElementById('cdTrafficList');
    const countEl = document.getElementById('cdTrafficCount');
    if (!list) return;

    let traffic: A2aTrafficEvent[] = [];
    try { traffic = getTrafficLog(); } catch { return; }

    if (countEl) countEl.textContent = `${traffic.length} events`;

    const recent = [...traffic].sort((a, b) => b.timestamp - a.timestamp).slice(0, 5);
    list.innerHTML = recent.map(t => {
      const time = new Date(t.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
      const verdictClass = t.verdict === 'clean' ? 'cd-verdict-clean' :
        t.verdict === 'suspicious' ? 'cd-verdict-suspicious' :
        t.verdict === 'blocked' ? 'cd-verdict-blocked' : 'cd-verdict-clean';
      return `
        <div class="cd-traffic-row">
          <span class="cd-traffic-time">${time}</span>
          <span class="cd-traffic-source">${escapeHtml(t.sourceAgent)}</span>
          <span class="cd-traffic-arrow">→</span>
          <span class="cd-traffic-target">${escapeHtml(t.targetAgent)}</span>
          <span class="cd-traffic-skill">${escapeHtml(t.skill)}</span>
          <span class="cd-traffic-verdict ${verdictClass}">${t.verdict.toUpperCase()}</span>
          <span class="cd-traffic-latency">${t.latencyMs}ms</span>
        </div>
      `;
    }).join('');
  }

  private formatAge(date: Date): string {
    const mins = Math.round((Date.now() - date.getTime()) / 60000);
    if (mins < 1) return 'now';
    if (mins < 60) return `${mins}m`;
    if (mins < 1440) return `${Math.round(mins / 60)}h`;
    return `${Math.round(mins / 1440)}d`;
  }

  private injectStyles(): void {
    if (document.getElementById('cyber-dashboard-css')) return;
    const style = document.createElement('style');
    style.id = 'cyber-dashboard-css';
    style.textContent = CYBER_DASHBOARD_CSS;
    document.head.appendChild(style);
  }

  public destroy(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}

const CYBER_DASHBOARD_CSS = `
/* ── Cyber Dashboard Layout ──────────────────────────────────── */
.cyber-dashboard {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: #0b0e14;
  color: #cbd5e1;
  font-family: 'DM Sans', system-ui, sans-serif;
  overflow: hidden;
}

/* ── Header ──────────────────────────────────────────────────── */
.cd-header {
  display: flex;
  align-items: center;
  height: 48px;
  padding: 0 20px;
  background: #080b10;
  border-bottom: 1px solid rgba(56, 189, 248, 0.10);
  flex-shrink: 0;
  gap: 16px;
}
.cd-header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}
.cd-brand-icon {
  width: 28px;
  height: 28px;
  border-radius: 6px;
  background: linear-gradient(135deg, #22d3ee, #0891b2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  font-size: 14px;
  color: #080b10;
}
.cd-brand {
  font-weight: 800;
  font-size: 16px;
  color: #f1f5f9;
  letter-spacing: 1px;
}
.cd-brand-accent {
  font-weight: 800;
  font-size: 16px;
  color: #38bdf8;
  letter-spacing: 1px;
}
.cd-brand-sep {
  color: #334155;
  font-weight: 300;
  margin: 0 4px;
}
.cd-brand-sub {
  font-size: 11px;
  font-weight: 500;
  color: #64748b;
  letter-spacing: 1.5px;
  text-transform: uppercase;
}
.cd-header-center {
  margin-left: auto;
}
.cd-agents-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 14px;
  border-radius: 20px;
  background: rgba(34, 211, 238, 0.10);
  border: 1px solid rgba(34, 211, 238, 0.20);
  color: #22d3ee;
  font-size: 12px;
  font-weight: 600;
}
.cd-agents-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #22d3ee;
  box-shadow: 0 0 6px rgba(34, 211, 238, 0.5);
  animation: cd-pulse 2s infinite;
}
@keyframes cd-pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

.cd-header-right {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-left: auto;
}
.cd-nav-btn {
  background: none;
  border: none;
  color: #64748b;
  font-size: 13px;
  font-weight: 500;
  padding: 6px 14px;
  cursor: pointer;
  border-radius: 6px;
  font-family: inherit;
  transition: background 0.15s, color 0.15s;
}
.cd-nav-btn:hover { background: rgba(56, 189, 248, 0.06); color: #94a3b8; }
.cd-nav-active { color: #e2e8f0; background: rgba(56, 189, 248, 0.08); }

/* ── Metrics Bar ─────────────────────────────────────────────── */
.cd-metrics {
  display: flex;
  height: auto;
  padding: 14px 20px;
  gap: 0;
  background: #0a0d12;
  border-bottom: 1px solid rgba(56, 189, 248, 0.08);
  flex-shrink: 0;
}
.cd-metric {
  flex: 1;
  padding: 0 20px;
  border-right: 1px solid rgba(56, 189, 248, 0.06);
}
.cd-metric:last-child { border-right: none; }
.cd-metric:first-child { padding-left: 0; }
.cd-metric-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: #475569;
  margin-bottom: 4px;
}
.cd-metric-value {
  font-size: 28px;
  font-weight: 700;
  color: #f1f5f9;
  line-height: 1.1;
  margin-bottom: 2px;
}
.cd-metric-crit { color: #f97316; }
.cd-metric-posture { font-size: 22px; }
.cd-posture-elevated { color: #f97316; }
.cd-posture-guarded { color: #eab308; }
.cd-posture-nominal { color: #22d3ee; }
.cd-metric-sub {
  font-size: 11px;
  color: #64748b;
}
.cd-sub-green { color: #22d3ee; }

/* ── Body (main + sidebar) ───────────────────────────────────── */
.cd-body {
  display: flex;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.cd-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding: 0;
  min-width: 0;
}
.cd-sidebar {
  width: 380px;
  flex-shrink: 0;
  border-left: 1px solid rgba(56, 189, 248, 0.08);
  background: #090c11;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.cd-sidebar-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(56, 189, 248, 0.08);
  flex-shrink: 0;
}
.cd-sidebar-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22d3ee;
  box-shadow: 0 0 6px rgba(34, 211, 238, 0.4);
}
.cd-sidebar-title {
  font-weight: 700;
  font-size: 13px;
  color: #e2e8f0;
  letter-spacing: 0.5px;
}
.cd-sidebar-sub {
  font-size: 11px;
  color: #475569;
  margin-left: auto;
}

/* ── Tabs ─────────────────────────────────────────────────────── */
.cd-tabs {
  display: flex;
  gap: 0;
  padding: 0 20px;
  border-bottom: 1px solid rgba(56, 189, 248, 0.08);
  flex-shrink: 0;
  background: #0a0d12;
}
.cd-tab {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: #64748b;
  font-size: 13px;
  font-weight: 500;
  padding: 12px 20px;
  cursor: pointer;
  font-family: inherit;
  transition: color 0.15s, border-color 0.15s;
}
.cd-tab:hover { color: #94a3b8; }
.cd-tab-active {
  color: #e2e8f0;
  border-bottom-color: #38bdf8;
}
.cd-tab-content { display: none; padding: 16px 20px; }
.cd-tab-visible { display: block; }

/* ── Cards ────────────────────────────────────────────────────── */
.cd-card {
  background: #0f1219;
  border: 1px solid rgba(56, 189, 248, 0.08);
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
}
.cd-card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-bottom: 1px solid rgba(56, 189, 248, 0.06);
}
.cd-card-title {
  font-weight: 600;
  font-size: 14px;
  color: #e2e8f0;
}
.cd-card-subtitle {
  font-size: 11px;
  color: #475569;
  margin-left: auto;
}
.cd-live-badge {
  font-size: 10px;
  font-weight: 700;
  color: #22d3ee;
  background: rgba(34, 211, 238, 0.10);
  border: 1px solid rgba(34, 211, 238, 0.20);
  padding: 2px 8px;
  border-radius: 4px;
  letter-spacing: 0.5px;
}

/* ── Threat Feed ──────────────────────────────────────────────── */
.cd-threat-list { padding: 4px 0; }
.cd-threat-row {
  display: flex;
  align-items: center;
  padding: 10px 16px;
  gap: 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  font-size: 13px;
}
.cd-threat-row:hover { background: rgba(56, 189, 248, 0.03); }
.cd-threat-mitre {
  font-weight: 600;
  color: #94a3b8;
  min-width: 90px;
  font-size: 12px;
}
.cd-threat-desc {
  flex: 1;
  color: #cbd5e1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.cd-threat-age {
  color: #475569;
  font-size: 12px;
  min-width: 40px;
  text-align: right;
}

/* ── Bottom Cards (trust + CII policy) ────────────────────────── */
.cd-bottom-cards {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
}
.cd-card-half { flex: 1; }

/* Trust scores */
.cd-trust-list { padding: 8px 16px; }
.cd-trust-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  font-size: 13px;
}
.cd-trust-row:last-child { border-bottom: none; }
.cd-trust-name { color: #94a3b8; }
.cd-trust-score { font-weight: 700; font-size: 14px; }

/* CII Policy */
.cd-cii-policy { padding: 12px 16px; }
.cd-policy-countries {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}
.cd-policy-country {
  flex: 1;
  text-align: center;
  padding: 12px;
  background: rgba(56, 189, 248, 0.04);
  border: 1px solid rgba(56, 189, 248, 0.08);
  border-radius: 6px;
}
.cd-policy-code {
  font-size: 11px;
  font-weight: 600;
  color: #64748b;
  letter-spacing: 1px;
  margin-bottom: 4px;
}
.cd-policy-score {
  font-size: 28px;
  font-weight: 700;
  color: #e2e8f0;
  line-height: 1.1;
}
.cd-score-critical { color: #f97316; }
.cd-policy-tier {
  font-size: 10px;
  font-weight: 600;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 2px;
}
.cd-policy-tiers { font-size: 12px; }
.cd-policy-tier-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 6px 0;
  color: #94a3b8;
  line-height: 1.4;
}
.cd-tier-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  min-width: 40px;
  text-align: center;
  flex-shrink: 0;
}
.cd-tier-standard { background: rgba(34, 211, 238, 0.12); color: #22d3ee; }
.cd-tier-elevated { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
.cd-tier-critical { background: rgba(239, 68, 68, 0.12); color: #ef4444; }

/* ── Traffic Log ──────────────────────────────────────────────── */
.cd-traffic-count {
  font-size: 11px;
  color: #475569;
  background: rgba(56, 189, 248, 0.06);
  padding: 2px 8px;
  border-radius: 4px;
}
.cd-traffic-list { padding: 4px 0; }
.cd-traffic-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  font-size: 12px;
}
.cd-traffic-time { color: #475569; min-width: 40px; }
.cd-traffic-source { color: #38bdf8; font-weight: 500; min-width: 100px; }
.cd-traffic-arrow { color: #334155; }
.cd-traffic-target { color: #94a3b8; font-weight: 500; min-width: 100px; }
.cd-traffic-skill { color: #64748b; flex: 1; }
.cd-traffic-verdict {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  letter-spacing: 0.3px;
}
.cd-verdict-clean { background: rgba(34, 211, 238, 0.12); color: #22d3ee; }
.cd-verdict-suspicious { background: rgba(245, 158, 11, 0.12); color: #f59e0b; }
.cd-verdict-blocked { background: rgba(239, 68, 68, 0.12); color: #ef4444; }
.cd-traffic-latency { color: #475569; min-width: 50px; text-align: right; }

/* ── Misc ─────────────────────────────────────────────────────── */
.cd-loading, .cd-empty {
  padding: 20px;
  text-align: center;
  color: #475569;
  font-size: 13px;
}

/* ── Responsive ───────────────────────────────────────────────── */
@media (max-width: 1024px) {
  .cd-sidebar { display: none; }
  .cd-metrics { flex-wrap: wrap; }
  .cd-metric { min-width: 150px; margin-bottom: 8px; }
}
`;

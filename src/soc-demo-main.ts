/**
 * SOC Demo — Standalone entry point with orchestrated pipeline visualization.
 *
 * Three sections:
 *   1. Pipeline strip: animated 7-stage visualization (Ingest → ADA → TAA → CRA → CLA → RVA → Learn)
 *   2. GATRA SOC Dashboard panel (left): agent health, alerts, CRA actions, TAA analysis
 *   3. SOC COMMS Chat panel (right): interactive agent chat with playbook support
 *
 * "Run Scenario" button triggers a narrated walkthrough of a simulated incident.
 */

import './styles/main.css';
import { GatraSOCDashboardPanel } from './panels/gatra-soc-panel';
import { SocChatPanel } from './panels/soc-chat-panel';

// ── Pipeline orchestration ─────────────────────────────────────────

interface ScenarioStep {
  node: string;           // pipeline-node data-step
  msg: string;            // orchestration log message
  duration: number;       // ms to stay on this step
  chatInput?: string;     // optional: inject a message into the SOC chat
}

const RANSOMWARE_SCENARIO: ScenarioStep[] = [
  { node: 'ingest', msg: 'SIEM event received — 847 suspicious file modification events from subnet 10.45.x.x in 90 seconds', duration: 2500 },
  { node: 'ingest', msg: 'BigQuery ingestion: event_type=FILE_MODIFY, process=enc.exe, extension=.locked, entropy=7.98/8.0', duration: 2000 },
  // ADA Detection Phase
  { node: 'ada', msg: 'ADA: Isolation Forest anomaly score 0.94 (threshold 0.72) — CRITICAL deviation from baseline', duration: 3000 },
  { node: 'ada', msg: 'ADA: LSTM autoencoder reconstruction error 4.2x normal — behavioral anomaly confirmed', duration: 2500,
    chatInput: '@ada Explain why these ransomware anomalies were flagged — give me a breakdown of the critical alerts' },
  { node: 'ada', msg: 'ADA: Alert published → T1486 (Data Encrypted for Impact), confidence 96%, source: 10.45.12.89', duration: 4000 },

  // TAA Analysis Phase
  { node: 'taa', msg: 'TAA: Actor-Critic RL triage — V(s)=0.91, action=ESCALATE, priority=CRITICAL', duration: 2500 },
  { node: 'taa', msg: 'TAA: MITRE ATT&CK mapping — TA0040 (Impact) → T1486 + T1490 + T1489', duration: 2500,
    chatInput: '@taa Why was this escalated? What threat actor TTPs match this attack and what MITRE techniques are involved?' },
  { node: 'taa', msg: 'TAA: Attribution — TTPs match LockBit 3.0 affiliate, StealBit exfil tool detected', duration: 4000 },

  // CRA Response Phase
  { node: 'cra', msg: 'CRA: Executing NIST 800-61 Phase 2 — Containment, Eradication, Recovery', duration: 2000 },
  { node: 'cra', msg: 'CRA: ACTION ip_blocked → 10.45.12.89 (patient zero), 185.220.101.x (C2 server)', duration: 2500,
    chatInput: '@cra What containment actions were taken? Show me the incident response status and rollback options' },
  { node: 'cra', msg: 'CRA: ACTION endpoint_isolated → 3 endpoints in VLAN 45 quarantined', duration: 2500 },
  { node: 'cra', msg: 'CRA: ACTION credential_rotated → 12 service accounts with access to encrypted shares', duration: 3500 },

  // CLA Compliance Phase
  { node: 'cla', msg: 'CLA: Audit trail recorded — 47 immutable log entries, SHA-256 chain verified', duration: 2000 },
  { node: 'cla', msg: 'CLA: GDPR 72-hour notification clock started — breach involves PII of 2,400 subscribers', duration: 2500,
    chatInput: '@cla Generate an incident report with audit trail and compliance status for GDPR and NIST' },
  { node: 'cla', msg: 'CLA: Generating NIST 800-61 incident report with timeline, IOCs, containment actions', duration: 4000 },

  // RVA Assessment Phase
  { node: 'rva', msg: 'RVA: Initial access vector — CVE-2024-1709 (ConnectWise ScreenConnect auth bypass, CVSS 10.0)', duration: 3000,
    chatInput: '@rva Scan for CVE vulnerabilities — what is our exposure and patch status for this attack surface?' },
  { node: 'rva', msg: 'RVA: 14 additional endpoints running unpatched ScreenConnect — remediation tickets created', duration: 2500 },
  { node: 'rva', msg: 'RVA: EPSS score 0.97 — this CVE is actively exploited by 6+ ransomware groups', duration: 3500 },

  // Self-Learning Phase
  { node: 'learn', msg: 'Self-Learning: RETRIEVE — 3 similar past incidents found via HNSW vector search (384-dim)', duration: 2000 },
  { node: 'learn', msg: 'Self-Learning: JUDGE — PPO reward signal +0.87 (fast detection, successful containment)', duration: 2000 },
  { node: 'learn', msg: 'Self-Learning: DISTILL — new detection pattern consolidated into semantic memory tier', duration: 2000 },
  { node: 'learn', msg: 'Self-Learning: CONSOLIDATE — EWC++ protecting learned weights, model hot-reloaded', duration: 2500 },
];

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

class PipelineOrchestrator {
  private nodes: Map<string, HTMLElement>;
  private arrows: HTMLElement[];
  private msgEl: HTMLElement;
  private timeEl: HTMLElement;
  private running = false;

  constructor() {
    this.nodes = new Map();
    document.querySelectorAll<HTMLElement>('.pipeline-node').forEach(n => {
      const step = n.dataset.step;
      if (step) this.nodes.set(step, n);
    });
    this.arrows = Array.from(document.querySelectorAll<HTMLElement>('.pipeline-arrow'));
    this.msgEl = document.getElementById('orchMsg')!;
    this.timeEl = document.getElementById('orchTime')!;
  }

  private activateNode(step: string): void {
    // Reset all
    this.nodes.forEach(n => n.classList.remove('active'));
    // Mark previous as done
    let found = false;
    const nodeSteps = ['ingest', 'ada', 'taa', 'cra', 'cla', 'rva', 'learn'];
    const idx = nodeSteps.indexOf(step);
    let i = -1;
    for (const key of nodeSteps) {
      i++;
      const n = this.nodes.get(key);
      if (!n) continue;
      if (i < idx) {
        n.classList.add('done');
        n.classList.remove('active');
      } else if (i === idx) {
        n.classList.remove('done');
        n.classList.add('active');
        found = true;
      } else {
        n.classList.remove('done', 'active');
      }
    }
    // Light up arrows up to current
    this.arrows.forEach((a, i) => {
      a.classList.toggle('lit', i < idx);
    });
    if (!found) this.nodes.get(step)?.classList.add('active');
  }

  private setMsg(msg: string): void {
    this.msgEl.textContent = msg;
    this.timeEl.textContent = new Date().toLocaleTimeString();
  }

  async runScenario(scenario: ScenarioStep[], onChat?: (input: string) => void): Promise<void> {
    if (this.running) return;
    this.running = true;

    for (const step of scenario) {
      this.activateNode(step.node);
      this.setMsg(step.msg);
      if (step.chatInput && onChat) {
        onChat(step.chatInput);
      }
      await sleep(step.duration);
    }

    // Completion
    this.nodes.forEach(n => { n.classList.add('done'); n.classList.remove('active'); });
    this.arrows.forEach(a => a.classList.add('lit'));
    this.setMsg('Scenario complete — MTTD: 1.8 min, MTTR: 4.2 min, 3 endpoints contained, 0 data exfiltrated');
    this.running = false;
  }

  reset(): void {
    this.nodes.forEach(n => n.classList.remove('active', 'done'));
    this.arrows.forEach(a => a.classList.remove('lit'));
    this.setMsg('Idle — click "Run Scenario" to start a live demonstration');
    this.timeEl.textContent = '';
  }
}

// ── Inject chat message helper ────────────────────────────────────

function injectChatMessage(text: string): void {
  // Find the SOC chat input and simulate user typing + send
  const input = document.querySelector('.soc-chat-input') as HTMLTextAreaElement | null;
  const sendBtn = document.querySelector('.soc-chat-send') as HTMLButtonElement | null;
  if (input && sendBtn) {
    input.value = text;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    sendBtn.click();
  }
}

// ── Boot ───────────────────────────────────────────────────────────

async function boot() {
  const socMount = document.getElementById('gatra-soc-mount')!;
  const chatMount = document.getElementById('soc-chat-mount')!;

  // 1. GATRA SOC Panel
  const gatraPanel = new GatraSOCDashboardPanel();
  socMount.replaceChildren(gatraPanel.getElement());
  await gatraPanel.refresh();
  setInterval(() => gatraPanel.refresh(), 60_000);

  // 2. SOC Chat Panel — mount inline
  void new SocChatPanel();

  const overlay = document.querySelector('.soc-chat-overlay') as HTMLElement | null;
  if (overlay) {
    const drawer = overlay.querySelector('.soc-chat-drawer') as HTMLElement | null;
    if (drawer) {
      drawer.style.position = 'relative';
      drawer.style.height = '100%';
      drawer.style.width = '100%';
      drawer.style.transform = 'none';
      drawer.style.maxWidth = 'none';
      drawer.style.borderRadius = '0';
      drawer.style.display = 'flex';
      drawer.style.flexDirection = 'column';

      const hdr = drawer.querySelector('.soc-chat-hdr') as HTMLElement | null;
      if (hdr) hdr.style.display = 'none';

      chatMount.replaceChildren(drawer);
    }
    overlay.remove();
  }

  // Hide floating toggle button
  const toggleBtn = document.querySelector('.soc-chat-toggle') as HTMLElement | null;
  if (toggleBtn) toggleBtn.style.display = 'none';

  // 3. Pipeline orchestrator
  const pipeline = new PipelineOrchestrator();

  const demoBtn = document.getElementById('demoBtn') as HTMLButtonElement;
  demoBtn.addEventListener('click', async () => {
    if (demoBtn.disabled) return;
    demoBtn.disabled = true;
    demoBtn.classList.add('running');
    demoBtn.textContent = 'Running...';
    pipeline.reset();
    await sleep(500);
    await pipeline.runScenario(RANSOMWARE_SCENARIO, (msg) => {
      // On mobile, switch to chat tab when injecting a message
      const isMobile = window.matchMedia('(max-width: 768px)').matches;
      if (isMobile) switchMobileTab('chat');
      injectChatMessage(msg);
    });
    demoBtn.disabled = false;
    demoBtn.classList.remove('running');
    demoBtn.textContent = 'Run Again';
  });

  // 4. Mobile tab switching
  initMobileTabs();
}

function switchMobileTab(tab: string): void {
  // Update tab buttons
  document.querySelectorAll<HTMLElement>('.mobile-tabs button').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  // Show/hide panels
  document.querySelectorAll<HTMLElement>('.soc-panel-wrapper').forEach(panel => {
    panel.classList.toggle('mobile-active', panel.dataset.tab === tab);
  });
}

function initMobileTabs(): void {
  const tabBar = document.getElementById('mobileTabs');
  if (!tabBar) return;
  tabBar.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest('button');
    if (!btn?.dataset.tab) return;
    switchMobileTab(btn.dataset.tab);
  });
}

boot().catch(console.error);

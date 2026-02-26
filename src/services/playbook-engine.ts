/**
 * PlaybookEngine — YAML-based investigation & threat hunting playbooks.
 *
 * Loads YAML playbook definitions from /playbooks/, manages execution as a
 * state machine, routes steps to GATRA agents, handles analyst input at
 * interactive steps, and generates completion summaries.
 *
 * State machine: idle → loading → running → waiting_input → running → ... → completed | aborted
 */

import yaml from 'js-yaml';

// ── Types ────────────────────────────────────────────────────────

export type PlaybookCategory = 'hunt' | 'investigate' | 'respond' | 'assess';
export type PlaybookSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type PlaybookState = 'idle' | 'loading' | 'running' | 'waiting_input' | 'completed' | 'aborted';
export type StepInputSource = 'analyst' | 'previous_step' | 'auto';
export type StepOutputFormat = 'text' | 'json' | 'table' | 'list';
export type ConditionOp = 'eq' | 'neq' | 'gt' | 'lt' | 'contains' | 'exists';

export interface PlaybookCondition {
  field: string;
  operator: ConditionOp;
  value: unknown;
}

export interface PlaybookStepDef {
  id: string;
  name: string;
  description: string;
  agent: string;
  action: string;
  input?: {
    source: StepInputSource;
    prompt?: string;
    stepRef?: string;
  };
  params?: Record<string, unknown>;
  conditions?: PlaybookCondition[];
  output?: {
    name: string;
    format: StepOutputFormat;
  };
  onFailure?: string; // 'continue' | 'abort' | 'skip_to:<step_id>'
}

export interface PlaybookVariable {
  name: string;
  type: string;
  description: string;
  required: boolean;
  default?: unknown;
}

export interface PlaybookMetadata {
  name: string;
  displayName: string;
  description: string;
  author: string;
  version: string;
  tags: string[];
  mitre: {
    tactics: string[];
    techniques: string[];
  };
  severity: PlaybookSeverity;
  estimatedMinutes: number;
  category: PlaybookCategory;
}

export interface PlaybookDef {
  apiVersion: string;
  kind: string;
  metadata: PlaybookMetadata;
  spec: {
    variables: PlaybookVariable[];
    steps: PlaybookStepDef[];
  };
}

export interface StepResult {
  stepId: string;
  agentId: string;
  response: string;
  userInput?: string;
  skipped: boolean;
  timestamp: number;
}

export interface PlaybookSession {
  playbook: PlaybookDef;
  state: PlaybookState;
  currentStepIndex: number;
  results: StepResult[];
  startedAt: number;
  completedAt?: number;
  variables: Record<string, string>;
}

// ── Callback types ───────────────────────────────────────────────

export type EmitMessageFn = (
  senderId: string,
  senderName: string,
  senderColor: string,
  content: string,
  type: 'system' | 'agent' | 'input_prompt',
) => void;

export type AgentResponseFn = (agentId: string, prompt: string) => Promise<string>;

// ── Playbook catalog ─────────────────────────────────────────────

const PLAYBOOK_FILES = [
  'cobalt-strike-hunt.yaml',
  'phishing-investigation.yaml',
  'ransomware-response.yaml',
  'credential-compromise.yaml',
  'zero-trust-assessment.yaml',
];

let catalog: PlaybookDef[] | null = null;

export async function loadPlaybookCatalog(): Promise<PlaybookDef[]> {
  if (catalog) return catalog;
  const results = await Promise.allSettled(
    PLAYBOOK_FILES.map(async (file) => {
      const resp = await fetch(`/playbooks/${file}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      return yaml.load(text) as PlaybookDef;
    }),
  );
  catalog = results
    .filter((r): r is PromiseFulfilledResult<PlaybookDef> => r.status === 'fulfilled')
    .map(r => r.value);
  return catalog;
}

export function getCatalog(): PlaybookDef[] | null { return catalog; }

// ── Agent color map ──────────────────────────────────────────────

const AGENT_META: Record<string, { name: string; color: string }> = {
  'ada': { name: 'ADA', color: '#4caf50' },
  'taa': { name: 'TAA', color: '#ff9800' },
  'cra': { name: 'CRA', color: '#f44336' },
  'cla': { name: 'CLA', color: '#2196f3' },
  'rva': { name: 'RVA', color: '#9c27b0' },
  'ioc': { name: 'IOC', color: '#e040fb' },
  'soc-kb': { name: 'SOC', color: '#22c55e' },
};

// ── PlaybookEngine ───────────────────────────────────────────────

export class PlaybookEngine {
  private session: PlaybookSession | null = null;
  private emitMessage: EmitMessageFn | null = null;
  private getAgentResponse: AgentResponseFn | null = null;

  bind(emit: EmitMessageFn, agentFn: AgentResponseFn): void {
    this.emitMessage = emit;
    this.getAgentResponse = agentFn;
  }

  getState(): PlaybookState {
    return this.session?.state ?? 'idle';
  }

  getSession(): PlaybookSession | null {
    return this.session;
  }

  isWaitingInput(): boolean {
    return this.session?.state === 'waiting_input';
  }

  isRunning(): boolean {
    const s = this.session?.state;
    return s === 'running' || s === 'waiting_input' || s === 'loading';
  }

  // ── Start ────────────────────────────────────────────────────

  async start(playbookId: string): Promise<void> {
    if (!this.emitMessage || !this.getAgentResponse) return;
    if (this.isRunning()) {
      this.emit('playbook', 'PLAYBOOK', '#f59e0b',
        'A playbook is already running. Type /abort to stop it first.', 'system');
      return;
    }

    this.session = {
      playbook: null!,
      state: 'loading',
      currentStepIndex: 0,
      results: [],
      startedAt: Date.now(),
      variables: {},
    };

    const books = await loadPlaybookCatalog();
    const pb = books.find(b => b.metadata.name === playbookId);
    if (!pb) {
      this.emit('playbook', 'PLAYBOOK', '#f59e0b',
        `Playbook "${playbookId}" not found. Type /playbooks to see available playbooks.`, 'system');
      this.session = null;
      return;
    }

    this.session.playbook = pb;
    this.session.state = 'running';

    // Emit playbook header
    const m = pb.metadata;
    const mitreStr = m.mitre.techniques.slice(0, 6).join(', ');
    this.emit('playbook', 'PLAYBOOK', '#f59e0b',
      `${categoryIcon(m.category)} ${m.category.toUpperCase()}: ${m.displayName}\n` +
      `${'━'.repeat(44)}\n` +
      `Playbook: ${m.name} v${m.version}\n` +
      `Steps: ${pb.spec.steps.length} | Est: ${m.estimatedMinutes} min | Severity: ${m.severity}\n` +
      `MITRE: ${mitreStr}\n` +
      `${'━'.repeat(44)}\n` +
      `${m.description}\n\n` +
      `Type "abort" at any time to stop.`,
      'system');

    // Execute first step
    await this.executeStep(0);
  }

  // ── Analyst input ────────────────────────────────────────────

  async handleInput(text: string): Promise<void> {
    if (!this.session || this.session.state !== 'waiting_input') return;
    if (text.toLowerCase() === 'abort') {
      this.abort();
      return;
    }

    const idx = this.session.currentStepIndex;
    const step = this.session.playbook.spec.steps[idx];
    if (!step) return;

    // Store input in results
    const existing = this.session.results.find(r => r.stepId === step.id);
    if (existing) existing.userInput = text;

    // Store as variable for interpolation
    if (step.output?.name) {
      this.session.variables[step.output.name] = text;
    }
    this.session.variables['_last_input'] = text;

    this.session.state = 'running';

    // Now execute agent action with the analyst's input
    const agentId = step.agent;
    const meta = AGENT_META[agentId] ?? { name: agentId.toUpperCase(), color: '#888' };
    const prompt = this.interpolate(step.action + ' ' + text);

    try {
      const response = await this.getAgentResponse!(agentId, prompt);
      this.emit(agentId, meta.name, meta.color, response, 'agent');

      // Store response
      if (existing) existing.response = response;
      if (step.output?.name) {
        this.session.variables[step.output.name] = response;
      }
      this.session.variables['_last_result'] = response;
    } catch {
      this.emit(agentId, meta.name, meta.color,
        `${meta.name} encountered an error processing this step.`, 'agent');
    }

    // Advance to next step
    await this.executeStep(idx + 1);
  }

  // ── Abort ────────────────────────────────────────────────────

  abort(): void {
    if (!this.session) return;
    this.session.state = 'aborted';
    this.session.completedAt = Date.now();
    const elapsed = Math.round((this.session.completedAt - this.session.startedAt) / 60000);
    const completed = this.session.results.filter(r => !r.skipped).length;
    const total = this.session.playbook.spec.steps.length;

    this.emit('playbook', 'PLAYBOOK', '#f59e0b',
      `${'━'.repeat(44)}\n` +
      `\u26D4 ABORTED: ${this.session.playbook.metadata.displayName}\n` +
      `Duration: ${elapsed} min | Steps: ${completed}/${total} completed\n` +
      `${'━'.repeat(44)}`,
      'system');

    this.session = null;
  }

  // ── Step execution ───────────────────────────────────────────

  private async executeStep(idx: number): Promise<void> {
    if (!this.session || this.session.state === 'aborted') return;
    const steps = this.session.playbook.spec.steps;

    if (idx >= steps.length) {
      this.complete();
      return;
    }

    this.session.currentStepIndex = idx;
    const step = steps[idx]!;
    const total = steps.length;

    // Check conditions
    if (step.conditions && !this.evaluateConditions(step.conditions)) {
      this.session.results.push({
        stepId: step.id, agentId: step.agent, response: '', skipped: true, timestamp: Date.now(),
      });
      await this.executeStep(idx + 1);
      return;
    }

    // Emit step header
    this.emit('playbook', 'PLAYBOOK', '#f59e0b',
      `\n[Step ${idx + 1}/${total}] ${step.name}\n` +
      `${'─'.repeat(40)}\n` +
      step.description,
      'system');

    const result: StepResult = {
      stepId: step.id, agentId: step.agent, response: '', skipped: false, timestamp: Date.now(),
    };
    this.session.results.push(result);

    // If step needs analyst input, pause
    if (step.input?.source === 'analyst') {
      this.session.state = 'waiting_input';
      this.emit('playbook', 'PLAYBOOK', '#f59e0b',
        `\u2328\uFE0F ${step.input.prompt || 'Provide input to continue:'}`,
        'input_prompt');
      return; // Wait for handleInput()
    }

    // Auto/previous_step input — build prompt and execute
    const agentId = step.agent;
    const meta = AGENT_META[agentId] ?? { name: agentId.toUpperCase(), color: '#888' };
    const prompt = this.interpolate(step.action);

    try {
      const response = await this.getAgentResponse!(agentId, prompt);
      result.response = response;
      this.emit(agentId, meta.name, meta.color, response, 'agent');

      if (step.output?.name) {
        this.session.variables[step.output.name] = response;
      }
      this.session.variables['_last_result'] = response;
    } catch {
      result.response = `${meta.name} error on this step.`;
      this.emit(agentId, meta.name, meta.color, result.response, 'agent');
      if (step.onFailure === 'abort') {
        this.abort();
        return;
      }
      if (step.onFailure?.startsWith('skip_to:')) {
        const targetId = step.onFailure.split(':')[1];
        const targetIdx = steps.findIndex(s => s.id === targetId);
        if (targetIdx >= 0) { await this.executeStep(targetIdx); return; }
      }
    }

    // Small delay between steps for readability
    await delay(600);
    await this.executeStep(idx + 1);
  }

  // ── Completion ───────────────────────────────────────────────

  private complete(): void {
    if (!this.session) return;
    this.session.state = 'completed';
    this.session.completedAt = Date.now();

    const pb = this.session.playbook;
    const elapsed = Math.round((this.session.completedAt - this.session.startedAt) / 60000);
    const completed = this.session.results.filter(r => !r.skipped).length;
    const total = pb.spec.steps.length;
    const skipped = this.session.results.filter(r => r.skipped).length;

    this.emit('playbook', 'PLAYBOOK', '#f59e0b',
      `${'━'.repeat(44)}\n` +
      `\u2705 ${pb.metadata.category.toUpperCase()} COMPLETE: ${pb.metadata.displayName}\n` +
      `Duration: ${elapsed} min | Steps: ${completed}/${total}${skipped > 0 ? ` (${skipped} skipped)` : ''}\n` +
      `Severity: ${pb.metadata.severity} | Status: Completed\n` +
      `${'━'.repeat(44)}\n` +
      `Investigation documented. Type /playbooks to run another.`,
      'system');

    this.session = null;
  }

  // ── Helpers ──────────────────────────────────────────────────

  private emit(
    senderId: string, senderName: string, color: string,
    content: string, type: 'system' | 'agent' | 'input_prompt',
  ): void {
    this.emitMessage?.(senderId, senderName, color, content, type);
  }

  private interpolate(template: string): string {
    if (!this.session) return template;
    let out = template;
    for (const [k, v] of Object.entries(this.session.variables)) {
      out = out.split(`{{${k}}}`).join(v);
    }
    return out;
  }

  private evaluateConditions(conditions: PlaybookCondition[]): boolean {
    if (!this.session) return false;
    for (const c of conditions) {
      const val = this.session.variables[c.field];
      switch (c.operator) {
        case 'exists': if (!val) return false; break;
        case 'eq': if (val !== String(c.value)) return false; break;
        case 'neq': if (val === String(c.value)) return false; break;
        case 'contains': if (!val?.includes(String(c.value))) return false; break;
        case 'gt': if (Number(val) <= Number(c.value)) return false; break;
        case 'lt': if (Number(val) >= Number(c.value)) return false; break;
      }
    }
    return true;
  }
}

function categoryIcon(cat: PlaybookCategory): string {
  switch (cat) {
    case 'hunt': return '\uD83D\uDD0D';
    case 'investigate': return '\uD83D\uDD0E';
    case 'respond': return '\uD83D\uDEA8';
    case 'assess': return '\uD83D\uDCCB';
    default: return '\uD83D\uDCD6';
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

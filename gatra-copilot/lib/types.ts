export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AgentName = "ADA" | "TAA" | "CRA" | "CLA" | "RVA";
export type PipelineStage = "idle" | "detecting" | "triaging" | "responding" | "assessing" | "logging";
export type ActionType = "notify" | "unblock" | "resume" | "suspend" | "block" | "kill" | "isolate";
export type ExecutionMode = "dry_run" | "enforced";

export interface Alert {
  id: string;
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  description: string;
  confidence: number;
  lat?: number;
  lon?: number;
  location_name?: string;
  infrastructure?: string;
  timestamp: string;
  agent: AgentName;
}

export interface ProposedAction {
  action_id: string;
  incident_id: string;
  action_type: ActionType;
  target_type: string;
  target_value: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  requires_approval: boolean;
  gate_reason?: string;
  status: string;
  expires_at: string;
}

export interface ExecutedAction {
  action_id: string;
  action_type: string;
  target_value: string;
  success: boolean;
  error?: string;
  executed_at: string;
  approved_by: string;
  executed_by: string;
  execution_mode: ExecutionMode;
  rollback_available: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  trace_id: string;
  event_type: string;
  agent: string;
  actor?: string;
  summary: string;
}

export interface GatraAgentState {
  session_id: string;
  incident_id: string;
  trace_id: string;
  pipeline_stage: PipelineStage;
  current_agent: string;
  alerts: Alert[];
  proposed_actions: ProposedAction[];
  executed_actions: ExecutedAction[];
  audit_log: AuditEntry[];
  approval_pending: boolean;
  last_updated_at?: string;
}

export interface ResponseGateEvent {
  type: "response_gate";
  action: ActionType;
  target: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  expires_at: string;
}

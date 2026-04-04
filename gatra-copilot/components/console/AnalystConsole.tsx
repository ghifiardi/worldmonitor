"use client";
import { useState } from "react";
import { CopilotChat } from "@copilotkit/react-ui";
import "@copilotkit/react-ui/styles.css";
import { AgentHealth } from "@/components/sidebar/AgentHealth";
import { IncidentTimeline } from "@/components/sidebar/IncidentTimeline";
import { ActiveAlerts } from "@/components/sidebar/ActiveAlerts";
import type { GatraAgentState } from "@/lib/types";

const INITIAL_STATE: GatraAgentState = {
  session_id: "",
  incident_id: "",
  trace_id: "",
  pipeline_stage: "idle",
  current_agent: "",
  alerts: [],
  proposed_actions: [],
  executed_actions: [],
  audit_log: [],
  approval_pending: false,
};

export function AnalystConsole() {
  const [state] = useState<GatraAgentState>(INITIAL_STATE);

  return (
    <div className="flex h-screen bg-gray-950 text-white">
      <div className="flex flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-gray-800 px-6 py-3">
          <h1 className="text-lg font-semibold">GATRA Analyst Console</h1>
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <span className={`h-2 w-2 rounded-full ${state.pipeline_stage === "idle" ? "bg-gray-600" : "animate-pulse bg-green-400"}`} />
            {state.pipeline_stage}
          </div>
        </header>
        <div className="flex-1 overflow-hidden">
          <CopilotChat className="h-full" labels={{
            title: "GATRA SOC",
            initial: "How can I help with your SOC investigation?",
            placeholder: "Ask about alerts, threats, or request containment actions...",
          }} />
        </div>
      </div>
      <aside className="w-72 space-y-3 overflow-y-auto border-l border-gray-800 p-4">
        <AgentHealth currentAgent={state.current_agent} pipelineStage={state.pipeline_stage} />
        <IncidentTimeline auditLog={state.audit_log} />
        <ActiveAlerts alerts={state.alerts} />
      </aside>
    </div>
  );
}

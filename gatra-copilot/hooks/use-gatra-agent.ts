"use client";
import { useCoAgent } from "@copilotkit/react-core";
import type { GatraAgentState } from "@/lib/types";

export function useGatraAgent() {
  const { state, setState, run, running } = useCoAgent<GatraAgentState>({
    name: "gatra_soc",
    initialState: {
      session_id: "", incident_id: "", trace_id: "", pipeline_stage: "idle",
      current_agent: "", alerts: [], proposed_actions: [], executed_actions: [],
      audit_log: [], approval_pending: false,
    },
  });
  return { state, setState, run, running };
}

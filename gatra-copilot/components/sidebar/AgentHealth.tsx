"use client";
import type { AgentName, PipelineStage } from "@/lib/types";
const AGENTS: AgentName[] = ["ADA", "TAA", "CRA", "CLA", "RVA"];
interface AgentHealthProps { currentAgent: string; pipelineStage: PipelineStage; }
export function AgentHealth({ currentAgent, pipelineStage }: AgentHealthProps) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">Agent Health</h3>
      <div className="space-y-1">
        {AGENTS.map((agent) => {
          const isActive = (currentAgent ?? "").toUpperCase() === agent;
          return (
            <div key={agent} className="flex items-center gap-2 text-sm">
              <span className={`h-2 w-2 rounded-full ${isActive ? "animate-pulse bg-green-400" : "bg-gray-600"}`} />
              <span className={isActive ? "text-white font-medium" : "text-gray-500"}>{agent}</span>
              {isActive && <span className="text-xs text-green-400">{pipelineStage}</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

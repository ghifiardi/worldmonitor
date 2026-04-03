"use client";
import type { ExecutionMode } from "@/lib/types";
interface ActionResultCardProps {
  action_type: string; target_value: string; success: boolean; error?: string;
  execution_mode: ExecutionMode; rollback_available: boolean; executed_at: string;
  status: "complete" | "inProgress";
}
export function ActionResultCard(props: ActionResultCardProps) {
  if (props.status !== "complete") {
    return <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4"><div className="h-4 w-32 rounded bg-gray-700" /></div>;
  }
  return (
    <div className={`rounded-lg border p-4 ${props.success ? "border-green-700 bg-gray-900" : "border-red-700 bg-gray-900"}`}>
      <div className="flex items-center gap-2 text-sm">
        <span className={props.success ? "text-green-400" : "text-red-400"}>{props.success ? "SUCCESS" : "FAILED"}</span>
        <strong className="text-white">{props.action_type.toUpperCase()}</strong>
        <code className="text-gray-400">{props.target_value}</code>
      </div>
      {props.error && <p className="mt-1 text-sm text-red-400">{props.error}</p>}
      <div className="mt-2 flex gap-3 text-xs text-gray-500">
        <span>Mode: {props.execution_mode}</span>
        <span>Rollback: {props.rollback_available ? "available" : "none"}</span>
        <span>{new Date(props.executed_at).toLocaleTimeString()}</span>
      </div>
    </div>
  );
}

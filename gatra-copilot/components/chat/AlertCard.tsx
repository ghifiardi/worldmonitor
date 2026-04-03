"use client";
import type { Severity } from "@/lib/types";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
};

interface AlertCardProps {
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  confidence: number;
  description: string;
  location_name?: string;
  infrastructure?: string;
  timestamp: string;
  status: "complete" | "inProgress";
}

export function AlertCard(props: AlertCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-24 rounded bg-gray-700" />
        <div className="mt-2 h-3 w-48 rounded bg-gray-700" />
      </div>
    );
  }
  const colorClass = SEVERITY_COLORS[props.severity] ?? "bg-gray-500 text-white";
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
      <div className="flex items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-bold ${colorClass}`}>{props.severity}</span>
        <code className="text-sm text-gray-400">{props.mitre_id}</code>
        <span className="text-sm text-gray-300">{props.mitre_name}</span>
      </div>
      <p className="mt-2 text-sm text-gray-300">{props.description}</p>
      <div className="mt-2 flex gap-4 text-xs text-gray-500">
        <span>Confidence: {Math.round(props.confidence * 100)}%</span>
        {props.location_name && <span>{props.location_name}</span>}
        {props.infrastructure && <span>{props.infrastructure}</span>}
        <span>{new Date(props.timestamp).toLocaleTimeString()}</span>
      </div>
    </div>
  );
}

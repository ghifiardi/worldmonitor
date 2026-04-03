"use client";
import { useState } from "react";
import type { ActionType, Severity } from "@/lib/types";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "border-red-600", HIGH: "border-orange-500",
  MEDIUM: "border-yellow-500", LOW: "border-blue-500",
};

interface ApprovalCardProps {
  action: ActionType;
  target: string;
  severity: Severity;
  confidence: number;
  expiresAt: string;
  onApprove: () => void;
  onDeny: (reason: string) => void;
}

export function ApprovalCard(props: ApprovalCardProps) {
  const [denyReason, setDenyReason] = useState("");
  const [resolved, setResolved] = useState(false);
  const borderColor = SEVERITY_COLORS[props.severity] ?? "border-gray-500";
  const expired = new Date() > new Date(props.expiresAt);

  if (resolved) {
    return <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 text-sm text-gray-400">Action resolved.</div>;
  }

  return (
    <div className={`rounded-lg border-2 ${borderColor} bg-gray-900 p-4`}>
      <div className="text-sm font-bold text-yellow-400">APPROVAL REQUIRED</div>
      <div className="mt-2 text-sm text-gray-300">
        <p><strong>{props.action.toUpperCase()}</strong> target <code className="rounded bg-gray-800 px-1">{props.target}</code></p>
        <p className="mt-1">Severity: <strong>{props.severity}</strong> | Confidence: {Math.round(props.confidence * 100)}%</p>
        {!expired && <p className="mt-1 text-xs text-gray-500">Expires: {new Date(props.expiresAt).toLocaleTimeString()}</p>}
        {expired && <p className="mt-1 text-xs text-red-400">EXPIRED</p>}
      </div>
      {!expired && (
        <div className="mt-3 flex gap-2">
          <button onClick={() => { setResolved(true); props.onApprove(); }}
            className="rounded bg-green-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-green-700">Approve</button>
          <input type="text" placeholder="Reason (optional)" value={denyReason}
            onChange={(e) => setDenyReason(e.target.value)}
            className="flex-1 rounded border border-gray-700 bg-gray-800 px-2 text-sm text-gray-300" />
          <button onClick={() => { setResolved(true); props.onDeny(denyReason); }}
            className="rounded bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700">Deny</button>
        </div>
      )}
    </div>
  );
}

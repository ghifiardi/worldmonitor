"use client";
import type { AuditEntry } from "@/lib/types";
interface IncidentTimelineProps { auditLog: AuditEntry[]; }
export function IncidentTimeline({ auditLog }: IncidentTimelineProps) {
  const recent = auditLog.slice(-20);
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">Incident Timeline</h3>
      {recent.length === 0 && <p className="text-xs text-gray-600">No events yet.</p>}
      <div className="max-h-64 space-y-1 overflow-y-auto">
        {recent.map((entry) => (
          <div key={entry.id} className="flex gap-2 text-xs">
            <span className="shrink-0 text-gray-600">{new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
            <span className="text-gray-500">{entry.agent}</span>
            <span className="text-gray-400">{entry.summary}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

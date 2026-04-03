"use client";
import type { Alert, Severity } from "@/lib/types";
const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "text-red-400", HIGH: "text-orange-400", MEDIUM: "text-yellow-400", LOW: "text-blue-400",
};
interface ActiveAlertsProps { alerts: Alert[]; }
export function ActiveAlerts({ alerts }: ActiveAlertsProps) {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const alert of alerts) { counts[alert.severity] = (counts[alert.severity] || 0) + 1; }
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">Active Alerts</h3>
      <div className="grid grid-cols-2 gap-2">
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((sev) => (
          <div key={sev} className="flex items-center gap-1">
            <span className={`text-lg font-bold ${SEVERITY_COLORS[sev]}`}>{counts[sev]}</span>
            <span className="text-xs text-gray-500">{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

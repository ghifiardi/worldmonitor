"use client";
interface AuditCardProps {
  event_type: string; agent: string; summary: string; timestamp: string;
  compliance_frameworks?: string[]; status: "complete" | "inProgress";
}
export function AuditCard(props: AuditCardProps) {
  if (props.status !== "complete") {
    return <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4"><div className="h-4 w-20 rounded bg-gray-700" /></div>;
  }
  return (
    <div className="rounded-lg border border-gray-600 bg-gray-900 p-4">
      <div className="flex items-center gap-2 text-sm">
        <span className="font-bold text-gray-400">{props.event_type}</span>
        <span className="text-gray-500">{props.agent}</span>
        <span className="text-xs text-gray-600">{new Date(props.timestamp).toLocaleTimeString()}</span>
      </div>
      <p className="mt-1 text-sm text-gray-300">{props.summary}</p>
      {props.compliance_frameworks && props.compliance_frameworks.length > 0 && (
        <div className="mt-1 flex gap-1">
          {props.compliance_frameworks.map((fw) => (
            <span key={fw} className="rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-400">{fw}</span>
          ))}
        </div>
      )}
    </div>
  );
}

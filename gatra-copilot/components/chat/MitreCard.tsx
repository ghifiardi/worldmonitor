"use client";
interface MitreCardProps {
  kill_chain_phase: string; actor_attribution: string; campaign?: string;
  iocs: string[]; confidence: number; status: "complete" | "inProgress";
}
export function MitreCard(props: MitreCardProps) {
  if (props.status !== "complete") {
    return <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4"><div className="h-4 w-32 rounded bg-gray-700" /></div>;
  }
  return (
    <div className="rounded-lg border border-purple-700 bg-gray-900 p-4">
      <div className="text-sm font-bold text-purple-400">MITRE ATT&amp;CK Analysis</div>
      <div className="mt-2 space-y-1 text-sm text-gray-300">
        <p>Kill Chain: <strong>{props.kill_chain_phase}</strong></p>
        <p>Attribution: <strong>{props.actor_attribution}</strong></p>
        {props.campaign && <p>Campaign: {props.campaign}</p>}
        <p>Confidence: {Math.round(props.confidence * 100)}%</p>
      </div>
      {props.iocs.length > 0 && (
        <div className="mt-2">
          <span className="text-xs font-medium text-gray-500">IOCs:</span>
          <ul className="mt-1 space-y-0.5">
            {props.iocs.map((ioc, i) => <li key={i} className="text-xs font-mono text-gray-400">{ioc}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

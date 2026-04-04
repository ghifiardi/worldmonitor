"use client";
interface VulnCardProps {
  cve_id: string; cvss_v4_score: number; epss_percentile: number;
  affected_products: string[]; patch_available: boolean; cisa_kev: boolean;
  recommendation: string; status: "complete" | "inProgress";
}
export function VulnCard(props: VulnCardProps) {
  if (props.status !== "complete") {
    return <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4"><div className="h-4 w-28 rounded bg-gray-700" /></div>;
  }
  return (
    <div className="rounded-lg border border-cyan-700 bg-gray-900 p-4">
      <div className="flex items-center gap-2">
        <code className="text-sm font-bold text-cyan-400">{props.cve_id}</code>
        {props.cisa_kev && <span className="rounded bg-red-700 px-1.5 py-0.5 text-xs font-bold text-white">CISA KEV</span>}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2 text-sm text-gray-300">
        <span>CVSS v4: <strong>{props.cvss_v4_score.toFixed(1)}</strong></span>
        <span>EPSS: <strong>{(props.epss_percentile * 100).toFixed(1)}%</strong></span>
        <span>Patch: {props.patch_available ? "Available" : "None"}</span>
      </div>
      <p className="mt-2 text-sm text-gray-400">{props.recommendation}</p>
    </div>
  );
}

import { Badge, Tone } from "./ui";

const STATUS: Record<string, [string, Tone]> = {
  compliant: ["Compliant", "green"], non_compliant: ["Non-compliant", "red"], partial: ["Partially compliant", "amber"],
  not_configured: ["Not configured", "gray"], not_applicable: ["Not applicable", "gray"], unknown: ["Unknown", "violet"],
  no_baseline: ["Configured (no baseline)", "blue"], not_assessed: ["Not assessed", "gray"],
  open: ["Open", "red"], assigned: ["Assigned", "amber"], in_progress: ["In progress", "blue"], pending_verification: ["Pending verification", "violet"],
  closed: ["Closed", "green"], accepted_risk: ["Accepted risk", "violet"], draft: ["Draft", "gray"], in_review: ["In review", "amber"], approved: ["Approved", "green"],
};
const RISK: Record<string, Tone> = { critical: "red", high: "red", medium: "amber", low: "blue", informational: "gray" };

export function ComplianceBadge({ status }: { status: string }) {
  const [label, tone] = STATUS[status] || [status.replace(/_/g, " "), "gray" as Tone];
  return <Badge tone={tone} className="whitespace-nowrap">{label}</Badge>;
}

export function Risk({ risk }: { risk: string | null | undefined }) {
  if (!risk) return <span className="text-slate-400">—</span>;
  return <Badge tone={RISK[risk] || "gray"} className={risk === "critical" ? "font-bold uppercase" : "capitalize"}>{risk}</Badge>;
}

export function ScoreRing({ score, label }: { score: number | null | undefined; label: string }) {
  const v = score ?? 0;
  const color = score == null ? "#94a3b8" : v >= 80 ? "#059669" : v >= 60 ? "#d97706" : "#dc2626";
  const c = 2 * Math.PI * 34;
  return (
    <div className="flex items-center gap-3">
      <svg width="84" height="84" viewBox="0 0 84 84" role="img" aria-label={`${label}: ${score == null ? "not available" : `${score}%`}`}>
        <circle cx="42" cy="42" r="34" fill="none" stroke="currentColor" strokeWidth="9" className="text-slate-100 dark:text-slate-800" />
        <circle cx="42" cy="42" r="34" fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${(c * v) / 100} ${c}`}
          transform="rotate(-90 42 42)" />
        <text x="42" y="47" textAnchor="middle" className="fill-slate-800 text-[17px] font-semibold dark:fill-slate-100">{score == null ? "n/a" : `${score}%`}</text>
      </svg>
      <span className="text-sm text-slate-500">{label}</span>
    </div>
  );
}

/** Horizontal stacked bar for status counts. */
export function StackBar({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" role="img"
        aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
        {parts.map((p) => p.value > 0 && <div key={p.label} style={{ width: `${(100 * p.value) / total}%`, background: p.color }} title={`${p.label}: ${p.value}`} />)}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        {parts.map((p) => <span key={p.label} className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: p.color }} />{p.label} <b className="text-slate-700 dark:text-slate-200">{p.value}</b></span>)}
      </div>
    </div>
  );
}

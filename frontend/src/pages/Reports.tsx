import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { AlertOctagon, DatabaseBackup, FileSpreadsheet, FileText, History, Lock, Server, ShieldAlert, Workflow } from "lucide-react";
import { ReactNode, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Badge, Button, Card, EmptyState, ErrorBox, PageHeader, Skeleton } from "../components/ui";
import { api } from "../lib/api";
import { fmtDate } from "../lib/format";

type ReportMeta = { key: string; title: string; permission: string; allowed: boolean };
type ReportData = { key: string; title: string; days: number; columns: string[]; rows: (string | number | null)[][]; generated_at: string };

const ICON: Record<string, ReactNode> = {
  inventory: <Server className="h-5 w-5" />, "backup-coverage": <DatabaseBackup className="h-5 w-5" />, "firewall-risk": <ShieldAlert className="h-5 w-5" />,
  changes: <History className="h-5 w-5" />, alerts: <AlertOctagon className="h-5 w-5" />, jobs: <Workflow className="h-5 w-5" />,
};
const HINT: Record<string, string> = {
  inventory: "Every device with type, vendor, OS, site, status and owner.",
  "backup-coverage": "Switches and firewalls with the age of their latest configuration backup.",
  "firewall-risk": "Overly broad (ANY) rules from the latest analysis of each firewall. Run “Analyse policies” to refresh.",
  changes: "Change-control events from the tamper-evident audit log.",
  alerts: "Alerts raised in the period with acknowledgement and resolution times.",
  jobs: "All jobs with outcome, risk and requester.",
};
const TIMED = new Set(["changes", "alerts", "jobs"]);

function cellTone(col: string, v: unknown): string {
  const s = String(v ?? "");
  if (/^(Status|Severity)$/i.test(col)) {
    if (/^(missing|critical|high|failed|down)$/i.test(s)) return "text-red-600 font-medium";
    if (/^(stale|warning|medium|partial|degraded)$/i.test(s)) return "text-amber-600 font-medium";
    if (/^(ok|up|succeeded|none|resolved)$/i.test(s)) return "text-emerald-600";
  }
  return "";
}

export default function Reports({ embedded = false }: { embedded?: boolean }) {
  const [sp, setSp] = useSearchParams();
  const key = sp.get("r") || "inventory";
  const [days, setDays] = useState(30);
  const { data: list } = useQuery({ queryKey: ["reports"], queryFn: () => api<ReportMeta[]>("/api/reports") });
  const cur = list?.find((r) => r.key === key);
  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ["report", key, days], enabled: !!cur?.allowed, queryFn: () => api<ReportData>(`/api/reports/${key}?days=${days}`),
  });
  const dl = (fmt: "csv" | "xlsx") => { window.location.href = `/api/reports/${key}?days=${days}&format=${fmt}`; };
  return (
    <div>
      {!embedded && <PageHeader title="Reports" subtitle="Operational and compliance reports. Exports are recorded in the audit log." />}
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {(list || []).map((r) => (
          <button key={r.key} disabled={!r.allowed} onClick={() => setSp({ r: r.key })} title={r.allowed ? HINT[r.key] : `Requires ${r.permission}`}
            className={clsx("rounded-xl border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50",
              r.key === key ? "border-brand-500 bg-brand-50 ring-1 ring-brand-500 dark:bg-brand-900/30" : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900")}>
            <span className={clsx("inline-flex rounded-lg p-1.5", r.key === key ? "bg-brand-600 text-white" : "bg-slate-100 text-slate-500 dark:bg-slate-800")}>{r.allowed ? ICON[r.key] : <Lock className="h-5 w-5" />}</span>
            <p className="mt-2 text-sm font-semibold leading-tight">{r.title}</p>
          </button>
        ))}
      </div>
      <Card padded={false} title={<span className="flex items-center gap-2">{cur?.title || "Report"} {data && <Badge>{data.rows.length} rows</Badge>}</span>}
        actions={<>
          {TIMED.has(key) && <select className="input w-auto py-1 text-xs" aria-label="Period" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} days</option>)}</select>}
          <Button size="sm" variant="outline" icon={<FileText className="h-4 w-4" />} disabled={!data} onClick={() => dl("csv")}>CSV</Button>
          <Button size="sm" variant="outline" icon={<FileSpreadsheet className="h-4 w-4" />} disabled={!data} onClick={() => dl("xlsx")}>Excel</Button>
        </>}>
        <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">{HINT[key]}{data && <> · generated {fmtDate(data.generated_at)}</>}</p>
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading || isFetching && !data ? <Skeleton rows={8} /> : !data?.rows.length ? (
          <EmptyState title="Nothing to report for this period" />
        ) : (
          <div className="max-h-[65vh] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-slate-50 dark:bg-slate-900"><tr>{data.columns.map((c) => <th key={c} className="th whitespace-nowrap">{c}</th>)}</tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.rows.slice(0, 2000).map((r, i) => (
                  <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    {r.map((v, j) => <td key={j} className={clsx("td max-w-xs truncate", cellTone(data.columns[j], v))} title={String(v ?? "")}>
                      {typeof v === "string" && /^\d{4}-\d\d-\d\dT/.test(v) ? fmtDate(v) : String(v ?? "")}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
            {data.rows.length > 2000 && <p className="p-3 text-center text-xs text-slate-500">Showing 2000 of {data.rows.length} rows — export for the full report.</p>}
          </div>
        )}
      </Card>
    </div>
  );
}

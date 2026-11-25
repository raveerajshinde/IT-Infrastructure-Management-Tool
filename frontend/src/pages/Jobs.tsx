import { useQuery } from "@tanstack/react-query";
import { PlayCircle } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Card, EmptyState, ErrorBox, PageHeader, Pagination, RiskBadge, Skeleton, StatusBadge } from "../components/ui";
import { api, qs } from "../lib/api";
import { duration, fmtDate } from "../lib/format";
import type { Job, Paged } from "../lib/types";

const STATUSES = ["", "pending_approval", "queued", "running", "succeeded", "partial", "failed", "unsupported", "cancelled", "rejected", "expired", "timed_out"];

export default function Jobs() {
  const [status, setStatus] = useState("");
  const [mine, setMine] = useState(false);
  const [page, setPage] = useState(1);
  const { data, isLoading, error } = useQuery({
    queryKey: ["jobs", status, mine, page], placeholderData: (p) => p,
    queryFn: () => api<Paged<Job>>(`/api/jobs${qs({ status, mine: mine || "", page, page_size: 25 })}`),
    refetchInterval: (q) => (q.state.data?.items.some((j) => ["queued", "running"].includes(j.status)) ? 3000 : 20000),
  });
  return (
    <div>
      <PageHeader title="Jobs" subtitle="Execution queue and history: every operation, its output, verification and approval trail." />
      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 p-3 dark:border-slate-800">
          <select className="input w-auto" aria-label="Status filter" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            {STATUSES.map((s) => <option key={s} value={s}>{s ? s.replace(/_/g, " ") : "All statuses"}</option>)}
          </select>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={mine} onChange={(e) => { setMine(e.target.checked); setPage(1); }} /> Only my jobs</label>
        </div>
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading ? <Skeleton /> : !data?.items.length ? (
          <EmptyState icon={<PlayCircle className="h-6 w-6" />} title="No jobs yet" hint="Run an operation from a device page, or a template from Automation." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[800px]">
              <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">#</th><th className="th">Job</th><th className="th">Risk</th><th className="th">Status</th><th className="th">Requested by</th><th className="th">Created</th><th className="th">Duration</th></tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {data.items.map((j) => (
                  <tr key={j.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="td"><Link className="text-brand-600 hover:underline" to={`/jobs/${j.id}`}>#{j.id}</Link></td>
                    <td className="td"><Link to={`/jobs/${j.id}`} className="font-medium hover:underline">{j.title}</Link>
                      <div className="mt-0.5 flex gap-1">{j.check_mode && <Badge tone="blue">dry-run</Badge>}{j.emergency && <Badge tone="red">emergency</Badge>}<span className="font-mono text-[11px] text-slate-400">{j.operation_id}</span></div></td>
                    <td className="td"><RiskBadge risk={j.risk} /></td>
                    <td className="td"><StatusBadge status={j.status} />{j.summary && <div className="mt-0.5 text-[11px] text-slate-500">{j.summary}</div>}</td>
                    <td className="td">{j.requested_by}</td>
                    <td className="td text-xs text-slate-500">{fmtDate(j.created_at)}</td>
                    <td className="td text-xs text-slate-500">{duration(j.started_at, j.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <Pagination page={page} pageSize={25} total={data.total} onPage={setPage} />}
      </Card>
    </div>
  );
}

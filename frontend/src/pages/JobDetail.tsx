import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowLeft, ChevronDown, ChevronRight, Ban } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Badge, Button, Callout, Card, DiffView, ErrorBox, KeyValue, RiskBadge, Skeleton, StatusBadge, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { duration, fmtDate } from "../lib/format";
import type { Execution, Job } from "../lib/types";

function DataView({ data }: { data: unknown }) {
  if (data === null || data === undefined) return null;
  if (Array.isArray(data) && data.length && typeof data[0] === "object" && data[0] !== null) {
    const cols = Object.keys(data[0] as object).slice(0, 10);
    return (
      <div className="max-h-96 overflow-auto rounded border border-slate-200 dark:border-slate-800">
        <table className="w-full text-xs"><thead className="sticky top-0 bg-slate-50 dark:bg-slate-900"><tr>{cols.map((c) => <th key={c} className="th">{c}</th>)}</tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{(data as Record<string, unknown>[]).slice(0, 1000).map((r, i) => (
            <tr key={i}>{cols.map((c) => <td key={c} className="px-3 py-1.5 align-top">{typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c] ?? "")}</td>)}</tr>
          ))}</tbody></table>
      </div>
    );
  }
  return <pre className="code max-h-96 overflow-auto">{JSON.stringify(data, null, 2)}</pre>;
}

function ExecutionRow({ e, initiallyOpen }: { e: Execution; initiallyOpen: boolean }) {
  const [open, setOpen] = useState(initiallyOpen);
  return (
    <div className="border-b border-slate-100 last:border-0 dark:border-slate-800">
      <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40" aria-expanded={open}>
        <span className="flex items-center gap-2 text-sm font-medium">{open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <Link to={`/devices/${e.device_id}`} onClick={(ev) => ev.stopPropagation()} className="hover:underline">{e.hostname || `device ${e.device_id}`}</Link></span>
        <span className="flex items-center gap-3"><span className="text-xs text-slate-500">{duration(e.started_at, e.finished_at)}</span><StatusBadge status={e.status} /></span>
      </button>
      {open && (
        <div className="space-y-3 px-4 pb-4">
          {e.status === "unsupported" && <Callout tone="info" title="Not supported by this device/driver">{e.error}</Callout>}
          {e.error && e.status !== "unsupported" && <Callout tone="danger" title="Error">{e.error}</Callout>}
          {e.verification && <Callout tone="success" title="Verification"><pre className="whitespace-pre-wrap font-mono text-xs">{e.verification}</pre></Callout>}
          {e.rollback_hint && ["succeeded", "partial"].includes(e.status) && <Callout tone="info" title="Rollback instructions">{e.rollback_hint}</Callout>}
          <DataView data={e.data} />
          {e.output && <div><p className="label">Output</p><pre className="code max-h-[28rem] overflow-auto">{e.output}</pre></div>}
          {!e.output && !e.error && !e.data && ["queued", "running"].includes(e.status) && <p className="text-sm text-slate-500">Waiting for output…</p>}
        </div>
      )}
    </div>
  );
}

export default function JobDetail() {
  const { id } = useParams();
  const { user, can } = useAuth();
  const qc = useQueryClient(); const toast = useToast(); const confirm = useConfirm();
  const { data: j, isLoading, error } = useQuery({
    queryKey: ["job", id], queryFn: () => api<Job>(`/api/jobs/${id}`),
    refetchInterval: (q) => (["queued", "running", "pending_approval"].includes(q.state.data?.status || "") ? 2500 : false),
  });
  if (isLoading) return <Card><Skeleton rows={8} /></Card>;
  if (error || !j) return <ErrorBox error={error} />;
  const cancellable = ["queued", "running", "pending_approval"].includes(j.status) && (j.requested_by === user?.username || can("jobs.cancel"));
  const cancel = async () => {
    if (!(await confirm({ title: "Cancel job?", message: j.status === "running" ? "Running steps are asked to stop at the next safe point; work already done on a device is not reverted." : "The job will not run.", danger: true, confirmLabel: "Cancel job" }))) return;
    try { await api(`/api/jobs/${j.id}/cancel`, { method: "POST" }); qc.invalidateQueries({ queryKey: ["job", id] }); toast({ tone: "success", title: "Cancellation requested" }); }
    catch (e) { toast({ tone: "error", title: "Could not cancel", body: (e as Error).message }); }
  };
  const params = Object.entries(j.params || {});
  return (
    <div className="space-y-4">
      <Link to="/jobs" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800"><ArrowLeft className="h-4 w-4" />Jobs</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold">#{j.id} {j.title} <StatusBadge status={j.status} /></h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-slate-500"><span className="font-mono">{j.operation_id}</span><RiskBadge risk={j.risk} />
            {j.check_mode && <Badge tone="blue">dry-run</Badge>}{j.emergency && <Badge tone="red">emergency</Badge>}</p>
        </div>
        {cancellable && <Button variant="outline" icon={<Ban className="h-4 w-4" />} onClick={cancel}>Cancel job</Button>}
      </div>
      {j.status === "pending_approval" && <Callout tone={j.waiting?.kind === "no_approver" ? "danger" : "warning"} title="Waiting for approval">This change has not been executed. An authorised approver must approve it{j.approval?.expires_at ? ` before ${fmtDate(j.approval.expires_at)}` : ""}.{j.waiting && <span className="mt-1 block">{j.waiting.message}</span>}</Callout>}
      {j.status === "waiting_window" && <Callout tone="info" title="Waiting for a maintenance window">{j.waiting?.message || "It will run automatically when the next maintenance window opens."}</Callout>}
      {j.status === "queued" && j.waiting && <Callout tone={j.waiting.kind === "worker_down" ? "danger" : "info"} title={j.waiting.kind === "worker_down" ? "Not running: the job worker is down" : "Queued"}>{j.waiting.message}</Callout>}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Change" className="xl:col-span-2">
          <p className="mb-3 text-sm">{j.change_summary}</p>
          {params.length > 0 && <table className="w-full text-sm"><tbody>{params.map(([k, v]) => (
            <tr key={k} className="border-t border-slate-100 dark:border-slate-800"><td className="w-48 py-1.5 pr-3 font-mono text-xs text-slate-500">{k}</td>
              <td className="py-1.5 font-mono text-xs">{typeof v === "object" ? JSON.stringify(v) : String(v)}</td></tr>))}</tbody></table>}
        </Card>
        <Card title="Timeline">
          <KeyValue items={[["Requested by", j.requested_by], ["Created", fmtDate(j.created_at)], ["Started", fmtDate(j.started_at)], ["Finished", fmtDate(j.finished_at)],
            ["Duration", duration(j.started_at, j.finished_at)], ["Result", j.summary || "—"]]} />
          {j.approval && (
            <div className="mt-4 rounded-md border border-slate-200 p-3 text-sm dark:border-slate-800">
              <p className="mb-1 flex items-center gap-2 font-medium">Approval <StatusBadge status={j.approval.status} /></p>
              <p className="text-xs text-slate-500">Reason: {j.approval.reason || "—"}</p>
              {j.approval.decided_by && <p className="text-xs text-slate-500">Decided by {j.approval.decided_by} · {fmtDate(j.approval.decided_at)}{j.approval.decision_note && ` — “${j.approval.decision_note}”`}</p>}
            </div>
          )}
        </Card>
      </div>
      <Card title={`Executions (${j.executions?.length || 0} device(s))`} padded={false}>
        {(j.executions || []).map((e, i) => <ExecutionRow key={e.id} e={e} initiallyOpen={i === 0 || ["failed", "unsupported"].includes(e.status)} />)}
      </Card>
      {!!j.config_changes?.length && (
        <Card title="Configuration changes (before → after)">
          <div className="space-y-4">{j.config_changes.map((c) => (
            <div key={c.id}><p className={clsx("mb-1 text-sm font-medium")}>{c.hostname}</p><DiffView diff={c.diff} /></div>
          ))}</div>
        </Card>
      )}
    </div>
  );
}

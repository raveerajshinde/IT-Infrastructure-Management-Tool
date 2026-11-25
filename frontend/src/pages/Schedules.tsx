import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { DevicePicker } from "../components/DevicePicker";
import { SchemaForm, cleanValues, initialValues } from "../components/SchemaForm";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, RiskBadge, Skeleton, StatusBadge, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, fmtDate } from "../lib/format";
import type { Job, Operation, Schedule, Template } from "../lib/types";

const PRESETS: [string, string][] = [
  ["@hourly", "Every hour"], ["0 2 * * *", "Daily 02:00 UTC"], ["0 22 * * 1-5", "Weekdays 22:00 UTC"],
  ["0 3 * * 0", "Sundays 03:00 UTC"], ["30 1 1 * *", "Monthly, 1st at 01:30 UTC"],
];
type Form = { id?: number; name: string; description: string; kind: "operation" | "playbook"; operation_id: string; template_id: string;
  device_ids: number[]; params: Record<string, unknown>; check_mode: boolean; cron: string; enabled: boolean };
const EMPTY: Form = { name: "", description: "", kind: "operation", operation_id: "", template_id: "", device_ids: [], params: {}, check_mode: false, cron: "0 2 * * *", enabled: true };

function Editor({ initial, onClose }: { initial: Form; onClose: () => void }) {
  const [f, setF] = useState<Form>(initial);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient(); const toast = useToast();
  const { data: ops } = useQuery({ queryKey: ["operations"], queryFn: () => api<Operation[]>("/api/operations") });
  const { data: templates } = useQuery({ queryKey: ["templates"], queryFn: () => api<Template[]>("/api/templates") });
  const [preview, setPreview] = useState<{ text: string; next_runs: string[] } | null>(null);
  const [cronErr, setCronErr] = useState("");
  useEffect(() => {
    const t = setTimeout(async () => {
      try { setPreview(await api(`/api/schedules/preview?cron=${encodeURIComponent(f.cron)}`)); setCronErr(""); }
      catch (e) { setPreview(null); setCronErr((e as Error).message); }
    }, 300);
    return () => clearTimeout(t);
  }, [f.cron]);
  const op = useMemo(() => ops?.find((o) => o.id === f.operation_id), [ops, f.operation_id]);
  const secret = op && Object.values(op.schema.properties || {}).some((p) => p.writeOnly);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null); setBusy(true);
    const body = { name: f.name, description: f.description, kind: f.kind, device_ids: f.device_ids, cron: f.cron, enabled: f.enabled, check_mode: f.check_mode,
      operation_id: f.kind === "operation" ? f.operation_id : null, template_id: f.kind === "playbook" ? Number(f.template_id) : null,
      params: f.kind === "operation" && op ? cleanValues(op.schema, f.params) : f.params };
    try {
      await api(f.id ? `/api/schedules/${f.id}` : "/api/schedules", { method: f.id ? "PUT" : "POST", body });
      qc.invalidateQueries({ queryKey: ["schedules"] }); toast({ tone: "success", title: "Schedule saved" }); onClose();
    } catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  return (
    <Modal open size="lg" onClose={onClose} title={f.id ? "Edit schedule" : "New schedule"}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="sch" type="submit" loading={busy} disabled={!!secret || !!cronErr}>Save schedule</Button></>}>
      <form id="sch" onSubmit={submit} className="space-y-4">
        <ErrorBox error={err} />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Name" required><input className="input" required minLength={2} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Nightly switch backup" /></Field>
          <Field label="What to run"><select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as Form["kind"] })}>
            <option value="operation">Operation</option><option value="playbook">Playbook template</option></select></Field>
        </div>
        {f.kind === "operation" ? (
          <Field label="Operation" required><select className="input" required value={f.operation_id} onChange={(e) => {
            const o = ops?.find((x) => x.id === e.target.value); setF({ ...f, operation_id: e.target.value, params: o ? initialValues(o.schema) : {} });
          }}><option value="">Choose…</option>
            {(ops || []).filter((o) => o.allowed).map((o) => <option key={o.id} value={o.id}>{o.name} — {o.id}{o.mutating ? ` (${o.risk})` : ""}</option>)}</select></Field>
        ) : (
          <Field label="Playbook template" required><select className="input" required value={f.template_id} onChange={(e) => setF({ ...f, template_id: e.target.value })}>
            <option value="">Choose…</option>{(templates || []).filter((t) => t.kind !== "operation").map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></Field>
        )}
        {secret && <Callout tone="warning" title="Cannot be scheduled">This operation takes a secret (password). Secrets are never stored in schedules — run it by hand instead.</Callout>}
        {op && Object.keys(op.schema.properties || {}).length > 0 && !secret && (
          <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800"><SchemaForm schema={op.schema} values={f.params} onChange={(v) => setF({ ...f, params: v })} /></div>
        )}
        {op?.mutating && (
          <Callout tone="info" title={<span className="flex items-center gap-2">Changing operation <RiskBadge risk={op.risk} /></span>}>
            Each run is created as you and goes through approval policies — a run that needs approval waits for an approver.
            {op.check_mode && <label className="mt-2 flex items-center gap-2"><input type="checkbox" checked={f.check_mode} onChange={(e) => setF({ ...f, check_mode: e.target.checked })} /> Dry-run only (check mode)</label>}
          </Callout>
        )}
        <Field label="Devices" required><DevicePicker value={f.device_ids} onChange={(ids) => setF({ ...f, device_ids: ids })} /></Field>
        <Field label="When (cron, UTC)" required hint={cronErr ? <span className="text-red-600">{cronErr}</span> : preview ? <>{preview.text} · next: {preview.next_runs.slice(0, 3).map(fmtDate).join(", ")}</> : "minute hour day month weekday"}>
          <div className="flex flex-wrap gap-2">
            <input className="input w-48 font-mono" value={f.cron} onChange={(e) => setF({ ...f, cron: e.target.value })} aria-label="Cron expression" />
            {PRESETS.map(([c, l]) => <Button key={c} type="button" size="sm" variant={f.cron === c ? "secondary" : "ghost"} onClick={() => setF({ ...f, cron: c })}>{l}</Button>)}
          </div>
        </Field>
        <Field label="Description"><input className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
      </form>
    </Modal>
  );
}

export default function Schedules() {
  const { can, user } = useAuth();
  const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast(); const nav = useNavigate();
  const { data, isLoading, error } = useQuery({ queryKey: ["schedules"], queryFn: () => api<Schedule[]>("/api/schedules"), refetchInterval: 30000 });
  const [edit, setEdit] = useState<Form | null>(null);
  const canRun = can("automation.run");
  const mine = (s: Schedule) => s.owner_id === user?.id || can("automation.manage");
  const refresh = () => qc.invalidateQueries({ queryKey: ["schedules"] });
  return (
    <div>
      <PageHeader title="Schedules" subtitle="Recurring operations and playbooks. Runs execute as the schedule owner with normal permissions, approval policies and audit."
        actions={canRun && <Button icon={<Plus className="h-4 w-4" />} onClick={() => setEdit({ ...EMPTY })}>New schedule</Button>} />
      <ErrorBox error={error} />
      {isLoading ? <Card><Skeleton /></Card> : !data?.length ? (
        <Card><EmptyState icon={<CalendarClock className="h-6 w-6" />} title="No schedules yet"
          hint="Examples: nightly configuration backup of all switches, weekly pending-updates report for Linux servers, monthly firewall rule analysis."
          action={canRun && <Button onClick={() => setEdit({ ...EMPTY })}>Create a schedule</Button>} /></Card>
      ) : (
        <Card padded={false}>
          <div className="overflow-x-auto"><table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Schedule</th><th className="th">Runs</th><th className="th">Targets</th><th className="th">Next run</th><th className="th">Last run</th><th className="th">Owner</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((s) => (
              <tr key={s.id} className={s.enabled ? "" : "opacity-60"}>
                <td className="td"><p className="font-medium">{s.name} {!s.enabled && <Badge>paused</Badge>}{s.check_mode && <Badge tone="blue" className="ml-1">dry-run</Badge>}</p>
                  <p className="font-mono text-xs text-slate-500">{s.operation_id || s.template_name}</p></td>
                <td className="td text-sm">{s.cron_text}<p className="font-mono text-[11px] text-slate-500">{s.cron}</p></td>
                <td className="td text-sm" title={s.devices.join(", ")}>{s.devices.length <= 2 ? s.devices.join(", ") : `${s.devices.slice(0, 2).join(", ")} +${s.devices.length - 2}`}</td>
                <td className="td text-sm">{s.next_run_at ? fmtDate(s.next_run_at) : "—"}</td>
                <td className="td text-sm">{s.last_run_at ? <div className="flex flex-col gap-0.5"><span>{ago(s.last_run_at)}</span>
                  {s.last_job_id && <Link to={`/jobs/${s.last_job_id}`}>{s.last_job_status ? <StatusBadge status={s.last_job_status} /> : `#${s.last_job_id}`}</Link>}
                  {s.last_error && <span className="max-w-xs truncate text-xs text-red-600" title={s.last_error}>{s.last_error}</span>}</div> : "never"}</td>
                <td className="td text-sm">{s.owner}</td>
                <td className="td whitespace-nowrap text-right">{mine(s) && <div className="flex justify-end gap-1">
                  <Button size="sm" variant="ghost" title="Run now" aria-label={`Run ${s.name} now`} icon={<Play className="h-4 w-4" />} onClick={async () => {
                    try { const j = await api<Job>(`/api/schedules/${s.id}/run`, { method: "POST" }); toast({ tone: "success", title: `Job #${j.id} created` }); refresh(); nav(`/jobs/${j.id}`); }
                    catch (e) { toast({ tone: "error", title: "Run failed", body: (e as Error).message }); }
                  }} />
                  <Button size="sm" variant="ghost" aria-label={`Edit ${s.name}`} icon={<Pencil className="h-4 w-4" />} onClick={() => setEdit({ id: s.id, name: s.name, description: s.description, kind: s.kind,
                    operation_id: s.operation_id || "", template_id: s.template_id ? String(s.template_id) : "", device_ids: s.device_ids, params: s.params, check_mode: s.check_mode, cron: s.cron, enabled: s.enabled })} />
                  <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`} icon={<Trash2 className="h-4 w-4" />} onClick={async () => {
                    if (await confirm({ title: `Delete schedule “${s.name}”?`, message: "Future runs stop. Jobs already created are kept.", danger: true, confirmLabel: "Delete" })) {
                      await api(`/api/schedules/${s.id}`, { method: "DELETE" }); refresh();
                    }
                  }} /></div>}</td>
              </tr>))}</tbody>
          </table></div>
        </Card>
      )}
      {edit && <Editor initial={edit} onClose={() => setEdit(null)} />}
    </div>
  );
}

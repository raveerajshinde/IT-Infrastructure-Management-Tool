import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Check, Plus, Trash2, X } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, RiskBadge, Skeleton, StatusBadge, Tabs, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";
import type { Approval, Group, Paged } from "../lib/types";

function Decide({ a, approve, onClose }: { a: Approval; approve: boolean; onClose: () => void }) {
  const [note, setNote] = useState(""); const qc = useQueryClient(); const toast = useToast();
  const m = useMutation({
    mutationFn: () => api(`/api/approvals/${a.id}/decide`, { body: { approve, note } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["approvals"] }); toast({ tone: "success", title: approve ? (a.status === "post_review" ? "Review recorded" : "Approved — job queued") : "Rejected" }); onClose(); },
  });
  return (
    <Modal open onClose={onClose} size="sm" title={`${approve ? "Approve" : "Reject"} change #${a.job_id}`}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button variant={approve ? "primary" : "danger"} loading={m.isPending} onClick={() => m.mutate()}>{approve ? "Approve" : "Reject"}</Button></>}>
      <div className="space-y-3"><ErrorBox error={m.error} /><p className="text-sm">{a.job?.change_summary}</p>
        <Field label="Note (recorded in the audit trail)"><textarea className="input" rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></Field></div>
    </Modal>
  );
}

function ApprovalList({ status }: { status: string }) {
  const { user } = useAuth();
  const [decide, setDecide] = useState<{ a: Approval; approve: boolean } | null>(null);
  const { data, isLoading, error } = useQuery({ queryKey: ["approvals", status], queryFn: () => api<Paged<Approval>>(`/api/approvals?status=${status}&page_size=100`), refetchInterval: 15000 });
  if (error) return <ErrorBox error={error} />;
  if (isLoading) return <Skeleton />;
  if (!data?.items.length) return <EmptyState title={status.includes("pending") ? "Nothing waiting for a decision" : "No history yet"} />;
  return (
    <div className="space-y-3">
      {data.items.map((a) => (
        <Card key={a.id}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="flex flex-wrap items-center gap-2 font-medium"><Link to={`/jobs/${a.job_id}`} className="hover:underline">#{a.job_id} {a.job?.title}</Link>
                {a.job && <RiskBadge risk={a.job.risk} />}<StatusBadge status={a.status} />{a.job?.emergency && <Badge tone="red">emergency</Badge>}</p>
              <p className="mt-1 text-sm">{a.job?.change_summary}</p>
              <p className="mt-1 text-xs text-slate-500">Requested by <b>{a.requested_by}</b> · {fmtDate(a.created_at)}{a.expires_at && a.status === "pending" && ` · expires ${fmtDate(a.expires_at)}`}</p>
              {a.reason && <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">Reason: {a.reason}</p>}
              {a.decided_by && <p className="mt-1 text-xs text-slate-500">Decided by {a.decided_by} · {fmtDate(a.decided_at)} {a.decision_note && `— “${a.decision_note}”`}</p>}
            </div>
            {a.can_decide && (
              a.requested_by_id === user?.id ? <Badge>Your request — another approver must decide</Badge> : (
                <div className="flex gap-2">
                  <Button variant="danger" size="sm" icon={<X className="h-4 w-4" />} onClick={() => setDecide({ a, approve: false })}>{a.status === "post_review" ? "Flag" : "Reject"}</Button>
                  <Button size="sm" icon={<Check className="h-4 w-4" />} onClick={() => setDecide({ a, approve: true })}>{a.status === "post_review" ? "Accept review" : "Approve"}</Button>
                </div>)
            )}
          </div>
        </Card>
      ))}
      {decide && <Decide a={decide.a} approve={decide.approve} onClose={() => setDecide(null)} />}
    </div>
  );
}

function Windows() {
  const { can } = useAuth();
  const qc = useQueryClient(); const confirm = useConfirm();
  const { data } = useQuery({ queryKey: ["windows"], queryFn: () => api<{ id: number; name: string; starts_at: string; ends_at: string; group_id: number | null; auto_approve_medium: boolean }[]>("/api/maintenance-windows") });
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", starts_at: "", ends_at: "", group_id: "", auto_approve_medium: false });
  const [err, setErr] = useState<unknown>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      await api("/api/maintenance-windows", { body: { ...f, starts_at: new Date(f.starts_at).toISOString(), ends_at: new Date(f.ends_at).toISOString(), group_id: f.group_id ? Number(f.group_id) : null } });
      setOpen(false); qc.invalidateQueries({ queryKey: ["windows"] });
    } catch (e2) { setErr(e2); }
  };
  const now = Date.now();
  return (
    <Card title="Maintenance windows" actions={can("maintenance.manage") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setOpen(true)}>Schedule window</Button>} padded={false}>
      <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">During an active window, medium-risk changes on covered devices can be auto-approved. High and critical changes always need approval.</p>
      {!data?.length ? <EmptyState icon={<CalendarClock className="h-6 w-6" />} title="No maintenance windows" /> : (
        <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Name</th><th className="th">Start</th><th className="th">End</th><th className="th">Scope</th><th className="th">Auto-approve medium</th><th className="th" /></tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((w) => {
            const active = new Date(w.starts_at).getTime() <= now && new Date(w.ends_at).getTime() >= now;
            return (<tr key={w.id}><td className="td font-medium">{w.name} {active && <Badge tone="green">active</Badge>}</td><td className="td">{fmtDate(w.starts_at)}</td><td className="td">{fmtDate(w.ends_at)}</td>
              <td className="td">{w.group_id ? groups?.find((g) => g.id === w.group_id)?.name : "All devices"}</td><td className="td">{w.auto_approve_medium ? "Yes" : "No"}</td>
              <td className="td text-right">{can("maintenance.manage") && <Button size="sm" variant="ghost" aria-label="Delete window" onClick={async () => {
                if (await confirm({ title: "Delete maintenance window?", message: w.name, danger: true })) { await api(`/api/maintenance-windows/${w.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["windows"] }); }
              }}><Trash2 className="h-4 w-4" /></Button>}</td></tr>);
          })}</tbody></table>)}
      <Modal open={open} onClose={() => setOpen(false)} title="Schedule maintenance window" footer={<><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button form="mw" type="submit">Save</Button></>}>
        <form id="mw" onSubmit={submit} className="space-y-3"><ErrorBox error={err} />
          <Field label="Name" required><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Starts (local time)" required><input type="datetime-local" className="input" required value={f.starts_at} onChange={(e) => setF({ ...f, starts_at: e.target.value })} /></Field>
            <Field label="Ends (local time)" required><input type="datetime-local" className="input" required value={f.ends_at} onChange={(e) => setF({ ...f, ends_at: e.target.value })} /></Field>
          </div>
          <Field label="Device group"><select className="input" value={f.group_id} onChange={(e) => setF({ ...f, group_id: e.target.value })}><option value="">All devices</option>
            {(groups || []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.auto_approve_medium} onChange={(e) => setF({ ...f, auto_approve_medium: e.target.checked })} /> Auto-approve medium-risk changes inside this window</label>
        </form>
      </Modal>
    </Card>
  );
}

type Policy = { id: number; name: string; risk: string | null; category: string | null; environment: string | null; require_approval: boolean; require_maintenance_window: boolean; enabled: boolean };
const EMPTY_POLICY = { name: "", risk: "", category: "", environment: "", require_approval: true, require_maintenance_window: false, enabled: true };

function Policies() {
  const { can } = useAuth();
  const manage = can("approvals.manage");
  const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const { data, isLoading } = useQuery({ queryKey: ["policies"], queryFn: () => api<Policy[]>("/api/approval-policies") });
  const [edit, setEdit] = useState<(typeof EMPTY_POLICY & { id?: number }) | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["policies"] });
  const save = async (e: FormEvent) => {
    e.preventDefault(); if (!edit) return; setErr(null);
    const body = { ...edit, risk: edit.risk || null, category: edit.category || null, environment: edit.environment || null };
    try {
      await api(edit.id ? `/api/approval-policies/${edit.id}` : "/api/approval-policies", { method: edit.id ? "PUT" : "POST", body });
      setEdit(null); refresh(); toast({ tone: "success", title: "Policy saved" });
    } catch (e2) { setErr(e2); }
  };
  const toggle = async (p: Policy) => { await api(`/api/approval-policies/${p.id}`, { method: "PUT", body: { ...p, enabled: !p.enabled } }); refresh(); };
  const scope = (p: Policy) => [p.risk ? `${p.risk === "change" ? "medium" : p.risk}-risk` : "any risk", p.category || "any platform", p.environment || "any environment"].join(" · ");
  if (isLoading) return <Card><Skeleton /></Card>;
  return (
    <Card title="Approval policies" padded={false} actions={manage && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setEdit({ ...EMPTY_POLICY })}>New policy</Button>}>
      <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">A change needs approval when any enabled policy matching its risk, platform and environment requires it. Empty fields match everything. Read-only operations never need approval.</p>
      {!data?.length ? <EmptyState title="No policies" hint="Without policies, changes run without approval." /> : (
        <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Policy</th><th className="th">Applies to</th><th className="th">Requires</th><th className="th">Enabled</th><th className="th" /></tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((p) => (
            <tr key={p.id} className={p.enabled ? "" : "opacity-60"}>
              <td className="td font-medium">{p.name}</td><td className="td text-sm">{scope(p)}</td>
              <td className="td"><div className="flex flex-wrap gap-1">{p.require_approval && <Badge tone="amber">approval</Badge>}{p.require_maintenance_window && <Badge tone="blue">maintenance window</Badge>}{!p.require_approval && !p.require_maintenance_window && <Badge>nothing</Badge>}</div></td>
              <td className="td"><label className="inline-flex items-center gap-2 text-sm"><input type="checkbox" disabled={!manage} checked={p.enabled} onChange={() => toggle(p)} aria-label={`Enable ${p.name}`} />{p.enabled ? "On" : "Off"}</label></td>
              <td className="td text-right">{manage && <div className="flex justify-end gap-1">
                <Button size="sm" variant="ghost" onClick={() => setEdit({ ...p, risk: p.risk || "", category: p.category || "", environment: p.environment || "" })}>Edit</Button>
                <Button size="sm" variant="ghost" aria-label={`Delete ${p.name}`} onClick={async () => {
                  if (!(await confirm({ title: "Delete approval policy?", message: <>Changes matching <b>{scope(p)}</b> will no longer need approval because of this policy.</>, danger: true, confirmLabel: "Delete" }))) return;
                  try { await api(`/api/approval-policies/${p.id}`, { method: "DELETE" }); refresh(); toast({ tone: "success", title: "Policy deleted" }); }
                  catch (e2) { toast({ tone: "error", title: "Cannot delete", body: (e2 as Error).message }); }
                }}><Trash2 className="h-4 w-4" /></Button></div>}</td>
            </tr>))}</tbody></table>)}
      <Modal open={!!edit} onClose={() => setEdit(null)} title={edit?.id ? "Edit approval policy" : "New approval policy"}
        footer={<><Button variant="outline" onClick={() => setEdit(null)}>Cancel</Button><Button form="pol" type="submit">Save</Button></>}>
        {edit && <form id="pol" onSubmit={save} className="space-y-3"><ErrorBox error={err} />
          <Field label="Name" required><input className="input" required minLength={2} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Field label="Risk"><select className="input" value={edit.risk} onChange={(e) => setEdit({ ...edit, risk: e.target.value })}><option value="">Any</option><option value="change">Medium (change)</option><option value="critical">Critical</option></select></Field>
            <Field label="Platform"><select className="input" value={edit.category} onChange={(e) => setEdit({ ...edit, category: e.target.value })}><option value="">Any</option>
              {["windows", "linux", "network", "firewall", "virtualization"].map((c) => <option key={c} value={c}>{c}</option>)}</select></Field>
            <Field label="Environment"><select className="input" value={edit.environment} onChange={(e) => setEdit({ ...edit, environment: e.target.value })}><option value="">Any</option>
              {["production", "staging", "test", "development", "dr"].map((c) => <option key={c} value={c}>{c}</option>)}</select></Field>
          </div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.require_approval} onChange={(e) => setEdit({ ...edit, require_approval: e.target.checked })} /> Require approval by another authorised user</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.require_maintenance_window} onChange={(e) => setEdit({ ...edit, require_maintenance_window: e.target.checked })} /> Only run inside a maintenance window</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} /> Enabled</label>
        </form>}
      </Modal>
    </Card>
  );
}

export default function Approvals() {
  const [tab, setTab] = useState<"pending" | "review" | "history" | "windows" | "policies">("pending");
  return (
    <div>
      <PageHeader title="Approvals & change control" subtitle="Separation of duties: requesters cannot approve their own changes. Every decision is audited." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "pending", label: "Pending" }, { id: "review", label: "Emergency reviews" }, { id: "history", label: "History" }, { id: "windows", label: "Maintenance windows" }, { id: "policies", label: "Policies" }]} />
      {tab === "pending" && <ApprovalList status="pending" />}
      {tab === "review" && <><div className="mb-3"><Callout tone="info">Emergency changes executed without pre-approval must be reviewed here.</Callout></div><ApprovalList status="post_review" /></>}
      {tab === "history" && <ApprovalList status="approved,rejected,expired" />}
      {tab === "windows" && <Windows />}
      {tab === "policies" && <Policies />}
    </div>
  );
}

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, Check, CheckCheck, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, Pagination, Skeleton, StatusBadge, Tabs, useConfirm, useToast } from "../components/ui";
import { api, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, fmtDate } from "../lib/format";
import type { Alert, Group, Paged } from "../lib/types";

type Rule = { id: number; name: string; metric: string; operator: string; threshold: number; severity: string; device_group_id: number | null; enabled: boolean;
  escalate_after_s: number; notify_emails: string; escalation_emails: string };
const METRICS = { availability: "Availability (1 = up, 0 = down)", cpu_pct: "CPU %", mem_pct: "Memory %", disk_pct: "Disk %", latency_ms: "Latency (ms)", uptime_hours: "Uptime (hours)", load1: "Load average (1 min)" };

function RuleForm({ rule, onClose }: { rule?: Rule; onClose: () => void }) {
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const [f, setF] = useState<Omit<Rule, "id">>(rule || { name: "", metric: "cpu_pct", operator: ">", threshold: 90, severity: "warning", device_group_id: null, enabled: true,
    escalate_after_s: 1800, notify_emails: "", escalation_emails: "" });
  const [err, setErr] = useState<unknown>(null); const qc = useQueryClient();
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api(rule ? `/api/alert-rules/${rule.id}` : "/api/alert-rules", { method: rule ? "PUT" : "POST", body: { ...f, threshold: Number(f.threshold), escalate_after_s: Number(f.escalate_after_s) } });
      qc.invalidateQueries({ queryKey: ["rules"] }); onClose(); } catch (e2) { setErr(e2); }
  };
  return (
    <Modal open onClose={onClose} title={rule ? "Edit alert rule" : "New alert rule"} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="rf" type="submit">Save</Button></>}>
      <form id="rf" onSubmit={submit} className="grid grid-cols-1 gap-3 sm:grid-cols-2"><div className="sm:col-span-2"><ErrorBox error={err} /></div>
        <div className="sm:col-span-2"><Field label="Name" required><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field></div>
        <Field label="Metric"><select className="input" value={f.metric} onChange={(e) => setF({ ...f, metric: e.target.value })}>{Object.entries(METRICS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Operator"><select className="input" value={f.operator} onChange={(e) => setF({ ...f, operator: e.target.value })}>{[">", ">=", "<", "<=", "=="].map((o) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Threshold"><input type="number" step="any" className="input" value={f.threshold} onChange={(e) => setF({ ...f, threshold: Number(e.target.value) })} /></Field>
        </div>
        <Field label="Severity"><select className="input" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>{["info", "warning", "critical"].map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Scope"><select className="input" value={f.device_group_id ?? ""} onChange={(e) => setF({ ...f, device_group_id: e.target.value ? Number(e.target.value) : null })}>
          <option value="">All devices</option>{(groups || []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>
        <Field label="Escalate if unacknowledged after (minutes)"><input type="number" min={0} className="input" value={Math.round(f.escalate_after_s / 60)} onChange={(e) => setF({ ...f, escalate_after_s: Number(e.target.value) * 60 })} /></Field>
        <label className="flex items-center gap-2 pt-6 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        <Field label="Notify e-mails (comma-separated)"><input className="input" value={f.notify_emails} onChange={(e) => setF({ ...f, notify_emails: e.target.value })} /></Field>
        <Field label="Escalation e-mails"><input className="input" value={f.escalation_emails} onChange={(e) => setF({ ...f, escalation_emails: e.target.value })} /></Field>
      </form>
    </Modal>
  );
}

function Rules() {
  const { can } = useAuth(); const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const { data } = useQuery({ queryKey: ["rules"], queryFn: () => api<Rule[]>("/api/alert-rules") });
  const [edit, setEdit] = useState<Rule | null | undefined>(undefined);
  return (
    <Card title="Alert rules" padded={false} actions={can("alerts.manage") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setEdit(null)}>New rule</Button>}>
      <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Rule</th><th className="th">Condition</th><th className="th">Severity</th><th className="th">Escalation</th><th className="th">State</th><th className="th" /></tr></thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{(data || []).map((r) => (
          <tr key={r.id}><td className="td font-medium">{r.name}</td><td className="td font-mono text-xs">{r.metric} {r.operator} {r.threshold}</td><td className="td"><StatusBadge status={r.severity} /></td>
            <td className="td text-xs">{r.escalate_after_s ? `after ${Math.round(r.escalate_after_s / 60)} min` : "—"}</td><td className="td">{r.enabled ? <Badge tone="green">enabled</Badge> : <Badge>disabled</Badge>}</td>
            <td className="td text-right">{can("alerts.manage") && <div className="flex justify-end gap-1">
              <Button size="sm" variant="ghost" aria-label="Edit rule" onClick={() => setEdit(r)}><Pencil className="h-4 w-4" /></Button>
              <Button size="sm" variant="ghost" aria-label="Delete rule" onClick={async () => {
                if (await confirm({ title: "Delete rule?", message: r.name, danger: true })) { const x = await api<{ message: string }>(`/api/alert-rules/${r.id}`, { method: "DELETE" }); toast({ tone: "info", title: x.message }); qc.invalidateQueries({ queryKey: ["rules"] }); }
              }}><Trash2 className="h-4 w-4" /></Button></div>}</td></tr>))}</tbody></table>
      {edit !== undefined && <RuleForm rule={edit || undefined} onClose={() => setEdit(undefined)} />}
    </Card>
  );
}

export default function Alerts() {
  const { can } = useAuth(); const qc = useQueryClient(); const toast = useToast();
  const [tab, setTab] = useState<"alerts" | "rules">("alerts");
  const [status, setStatus] = useState("open,acknowledged");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const { data, isLoading, error } = useQuery({ queryKey: ["alerts", status, severity, page], placeholderData: (p) => p, refetchInterval: 30000,
    queryFn: () => api<Paged<Alert>>(`/api/alerts${qs({ status, severity, page, page_size: 25 })}`) });
  const act = async (a: Alert, action: "acknowledge" | "resolve") => {
    try { await api(`/api/alerts/${a.id}/${action}`, { body: { note: "" } }); qc.invalidateQueries({ queryKey: ["alerts"] }); toast({ tone: "success", title: action === "resolve" ? "Alert resolved" : "Alert acknowledged" }); }
    catch (e) { toast({ tone: "error", title: "Action failed", body: (e as Error).message }); }
  };
  return (
    <div>
      <PageHeader title="Alerts" subtitle="Threshold breaches, availability failures and imported events from Zabbix, LibreNMS and webhooks." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "alerts", label: "Alerts" }, { id: "rules", label: "Rules & thresholds" }]} />
      {tab === "rules" ? <Rules /> : (
        <Card padded={false}>
          <div className="flex flex-wrap gap-2 border-b border-slate-200 p-3 dark:border-slate-800">
            <select className="input w-auto" aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
              <option value="open,acknowledged">Active</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option><option value="">All</option></select>
            <select className="input w-auto" aria-label="Severity" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
              <option value="">All severities</option><option value="critical">Critical</option><option value="warning">Warning</option><option value="info">Info</option></select>
          </div>
          {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading ? <Skeleton /> : !data?.items.length ? (
            <EmptyState icon={<ShieldCheck className="h-6 w-6" />} title="No alerts" hint="Nothing matches the current filter." />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {data.items.map((a) => (
                <li key={a.id} className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-2 text-sm font-medium"><StatusBadge status={a.severity} />{a.title}{a.escalated_at && <Badge tone="red"><BellRing className="h-3 w-3" />escalated</Badge>}
                      {a.source !== "infrapilot" && <Badge tone="violet">{a.source}</Badge>}</p>
                    <p className="mt-1 whitespace-pre-wrap text-xs text-slate-500">{a.detail}</p>
                    <p className="mt-1 text-xs text-slate-400">Opened {ago(a.opened_at)} ({fmtDate(a.opened_at)}){a.device_id && <> · <Link className="text-brand-600 hover:underline" to={`/devices/${a.device_id}`}>{a.hostname}</Link></>}
                      {a.acknowledged_by && ` · acknowledged by ${a.acknowledged_by}`}{a.resolved_at && ` · resolved ${fmtDate(a.resolved_at)}`}</p>
                  </div>
                  <div className="flex items-center gap-2"><StatusBadge status={a.status} />
                    {can("alerts.ack") && a.status === "open" && <Button size="sm" variant="outline" icon={<Check className="h-3.5 w-3.5" />} onClick={() => act(a, "acknowledge")}>Acknowledge</Button>}
                    {can("alerts.ack") && a.status !== "resolved" && <Button size="sm" variant="secondary" icon={<CheckCheck className="h-3.5 w-3.5" />} onClick={() => act(a, "resolve")}>Resolve</Button>}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {data && data.total > 0 && <Pagination page={page} pageSize={25} total={data.total} onPage={setPage} />}
        </Card>
      )}
    </div>
  );
}

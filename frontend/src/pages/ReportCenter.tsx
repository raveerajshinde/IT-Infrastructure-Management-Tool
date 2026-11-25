import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { CalendarClock, FileBarChart, FileCode2, FileSpreadsheet, FileText, Lock, Mail, Play, Plus } from "lucide-react";
import { ReactNode, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { DataTable } from "../components/DataTable";
import { Badge, Button, Callout, Card, ErrorBox, Field, Modal, PageHeader, Tabs, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { download, openInline, qs } from "../lib/download";
import { DEVICE_TYPE_LABEL, fmtDate } from "../lib/format";
import OperationalReports from "./Reports";

type Tpl = { key: string; title: string; description: string; permission: string; filters: string[]; default_days: number; allowed: boolean };
type Schedule = { id: number; name: string; report_key: string; report_title: string; params: Record<string, string | number>; format: string; cron: string; recipients: string;
  enabled: boolean; owner: string | null; next_run_at: string | null; last_run_at: string | null; last_status: string | null; last_message: string | null };
type Run = { id: number; report_key: string; title: string; format: string; params: Record<string, unknown>; generated_at: string; generated_by: string; size: number; sha256: string; emailed_to: string; allowed: boolean };
type TabId = "center" | "operational" | "schedules" | "history";
const TABS: { id: TabId; label: ReactNode }[] = [{ id: "center", label: "Report Center" }, { id: "operational", label: "Operational reports" },
  { id: "schedules", label: "Scheduled Reports" }, { id: "history", label: "Historical Reports" }];
const CRONS = [["0 6 * * *", "Daily 06:00 UTC"], ["0 6 * * 1", "Weekly, Monday 06:00 UTC"], ["0 6 1 * *", "Monthly, 1st 06:00 UTC"], ["0 */6 * * *", "Every 6 hours"]];

export default function ReportCenter() {
  const { tab = "center" } = useParams();
  const nav = useNavigate();
  return (
    <div>
      <PageHeader title="Reports" subtitle="Professional reports from live data in PDF, Excel, CSV and HTML. Every export is kept with its SHA-256 and recorded in the audit log." />
      <Tabs tabs={TABS} value={tab as TabId} onChange={(t) => nav(`/reports/${t}`)} />
      {tab === "center" && <Center />}
      {tab === "operational" && <OperationalReports embedded />}
      {tab === "schedules" && <Schedules />}
      {tab === "history" && <History />}
    </div>
  );
}

function Filters({ t, p, set }: { t: Tpl; p: Record<string, string>; set: (k: string, v: string) => void }) {
  const { data: sites } = useQuery({ queryKey: ["sites"], queryFn: () => api<{ id: number; name: string }[]>("/api/sites"), enabled: t.filters.includes("site_id") });
  const { data: doms } = useQuery({ queryKey: ["ad-domains"], queryFn: () => api<{ id: number; name: string }[]>("/api/ad/domains"), enabled: t.filters.includes("domain_id") });
  const { data: gdoms } = useQuery({ queryKey: ["gpo-domains"], queryFn: () => api<{ domain: string }[]>("/api/gpo/domains"), enabled: t.filters.includes("gpo_domain") });
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {t.key !== "gpo-complete" && <Field label="Period"><select className="input" value={p.days || String(t.default_days)} onChange={(e) => set("days", e.target.value)}>
        {[1, 7, 30, 90, 180, 365].map((d) => <option key={d} value={d}>Last {d} day{d > 1 ? "s" : ""}</option>)}</select></Field>}
      {t.filters.includes("site_id") && <Field label="Site"><select className="input" value={p.site_id || ""} onChange={(e) => set("site_id", e.target.value)}><option value="">All sites</option>{sites?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>}
      {t.filters.includes("department") && <Field label="Department"><input className="input" value={p.department || ""} onChange={(e) => set("department", e.target.value)} placeholder="Any" /></Field>}
      {t.filters.includes("device_type") && <Field label="Device type"><select className="input" value={p.device_type || ""} onChange={(e) => set("device_type", e.target.value)}><option value="">All types</option>
        {Object.entries(DEVICE_TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>}
      {t.filters.includes("asset") && <Field label="Asset (name or IP contains)"><input className="input" value={p.asset || ""} onChange={(e) => set("asset", e.target.value)} /></Field>}
      {t.filters.includes("severity") && <Field label="Severity"><select className="input" value={p.severity || ""} onChange={(e) => set("severity", e.target.value)}><option value="">All</option>
        <option value="critical,high">Critical + high</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}</select></Field>}
      {t.filters.includes("domain_id") && <Field label="AD domain"><select className="input" value={p.domain_id || ""} onChange={(e) => set("domain_id", e.target.value)}><option value="">All domains</option>{doms?.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select></Field>}
      {t.filters.includes("gpo_domain") && <Field label="GPO domain"><select className="input" value={p.gpo_domain || ""} onChange={(e) => set("gpo_domain", e.target.value)}><option value="">Latest collected</option>{gdoms?.map((d) => <option key={d.domain}>{d.domain}</option>)}</select></Field>}
    </div>
  );
}

function Center() {
  const { data: tpls } = useQuery({ queryKey: ["report-templates"], queryFn: () => api<Tpl[]>("/api/report-center/templates") });
  const [sp, setSp] = useSearchParams();
  const key = sp.get("r") || "executive-summary";
  const setKey = (k: string) => setSp({ r: k }, { replace: true });
  const [p, setP] = useState<Record<string, string>>({});
  const [sched, setSched] = useState(false);
  const { can } = useAuth();
  const t = tpls?.find((x) => x.key === key);
  const url = (fmt: string) => `/api/report-center/reports/${key}${qs({ ...p, format: fmt })}`;
  return (
    <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
      <Card padded={false}>
        <nav className="max-h-[70vh] overflow-y-auto p-2" aria-label="Report templates">
          {tpls?.map((x) => (
            <button key={x.key} disabled={!x.allowed} onClick={() => { setKey(x.key); setP({}); }} title={x.allowed ? x.description : `Requires ${x.permission}`}
              className={clsx("flex w-full items-start gap-2 rounded-md px-3 py-2 text-left text-sm disabled:cursor-not-allowed disabled:opacity-50",
                x.key === key ? "bg-brand-50 text-brand-800 dark:bg-brand-900/30 dark:text-brand-100" : "hover:bg-slate-50 dark:hover:bg-slate-800")}>
              {x.allowed ? <FileBarChart className="mt-0.5 h-4 w-4 shrink-0 text-brand-600" /> : <Lock className="mt-0.5 h-4 w-4 shrink-0" />}<span className="font-medium">{x.title}</span>
            </button>
          ))}
        </nav>
      </Card>
      {t && (
        <Card title={t.title} actions={can("reports.manage") && <Button size="sm" variant="outline" icon={<CalendarClock className="h-4 w-4" />} onClick={() => setSched(true)}>Schedule…</Button>}>
          <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">{t.description}</p>
          <Filters t={t} p={p} set={(k, v) => setP((o) => ({ ...o, [k]: v }))} />
          <div className="mt-5 flex flex-wrap gap-2">
            <Button icon={<FileText className="h-4 w-4" />} onClick={() => download(url("pdf"))}>Download PDF</Button>
            <Button variant="outline" icon={<FileSpreadsheet className="h-4 w-4" />} onClick={() => download(url("xlsx"))}>Excel</Button>
            <Button variant="outline" onClick={() => download(url("csv"))}>CSV</Button>
            <Button variant="outline" icon={<FileCode2 className="h-4 w-4" />} onClick={() => openInline(url("html"))}>Open HTML</Button>
          </div>
          <p className="mt-4 text-xs text-slate-500">All figures come from InfraPilot's live data. Where a data source is not set up (e.g. no AD domain or no patch scans), the report states it instead of showing zeros.</p>
        </Card>
      )}
      {sched && t && <ScheduleForm initial={{ report_key: t.key, params: p, name: `${t.title} (${new Date().toISOString().slice(0, 10)})` }} onClose={() => setSched(false)} />}
    </div>
  );
}

function Schedules() {
  const { data, isLoading } = useQuery({ queryKey: ["report-schedules"], queryFn: () => api<Schedule[]>("/api/report-center/schedules") });
  const [edit, setEdit] = useState<Partial<Schedule> | null>(null);
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const run = useMutation({ mutationFn: (id: number) => api<Schedule>(`/api/report-center/schedules/${id}/run`, { method: "POST" }),
    onSuccess: (s) => { qc.invalidateQueries({ queryKey: ["report-schedules"] }); toast({ tone: s.last_status === "succeeded" ? "success" : "info", title: "Report generated", body: s.last_message || "" }); },
    onError: (e) => toast({ tone: "error", title: (e as Error).message }) });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/report-center/schedules/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["report-schedules"] }) });
  return (
    <Card padded={false} title="Scheduled reports" actions={can("reports.manage") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setEdit({})}>New schedule</Button>}>
      <Callout tone="info">Scheduled reports run with the permissions of their owner and are e-mailed as attachments (SMTP settings under Settings → E-mail). Times are UTC.</Callout>
      <DataTable id="report-schedules" rows={data} loading={isLoading} rowKey={(s) => s.id} empty="No scheduled reports" columns={[
        { key: "name", label: "Schedule", render: (s) => <div><p className="font-medium">{s.name}</p><p className="text-xs text-slate-500">{s.report_title} · {s.format.toUpperCase()}</p></div> },
        { key: "cron", label: "When", render: (s) => <span className="text-xs">{CRONS.find((c) => c[0] === s.cron)?.[1] || <code>{s.cron}</code>}</span> },
        { key: "recipients", label: "Recipients", render: (s) => <span className="text-xs">{s.recipients || "—"}</span> },
        { key: "enabled", label: "Enabled", render: (s) => s.enabled ? <Badge tone="green">On</Badge> : <Badge>Off</Badge> },
        { key: "next_run_at", label: "Next run", render: (s) => <span className="text-xs">{fmtDate(s.next_run_at)}</span> },
        { key: "last", label: "Last run", value: (s) => s.last_run_at || "", render: (s) => <div className="text-xs">{fmtDate(s.last_run_at)}{s.last_status && <Badge tone={s.last_status === "succeeded" ? "green" : s.last_status === "failed" ? "red" : "amber"} className="ml-1">{s.last_status}</Badge>}
          {s.last_message && <p className="text-slate-500">{s.last_message}</p>}</div> },
        { key: "owner", label: "Owner", hidden: true },
        { key: "act", label: "", sortable: false, render: (s) => can("reports.manage") && <div className="flex gap-1">
          <Button size="sm" variant="ghost" icon={<Play className="h-3.5 w-3.5" />} loading={run.isPending && run.variables === s.id} onClick={() => run.mutate(s.id)}>Run now</Button>
          <Button size="sm" variant="ghost" onClick={() => setEdit(s)}>Edit</Button>
          <Button size="sm" variant="ghost" onClick={async () => { if (await confirm({ title: "Delete schedule", message: `Delete “${s.name}”? Reports already generated are kept.`, danger: true })) del.mutate(s.id); }}>Delete</Button></div> },
      ]} />
      {edit && <ScheduleForm initial={edit} onClose={() => setEdit(null)} />}
    </Card>
  );
}

function ScheduleForm({ initial, onClose }: { initial: Partial<Schedule>; onClose: () => void }) {
  const { data: tpls } = useQuery({ queryKey: ["report-templates"], queryFn: () => api<Tpl[]>("/api/report-center/templates") });
  const [v, setV] = useState({ name: initial.name || "", report_key: initial.report_key || "executive-summary", params: (initial.params || {}) as Record<string, string>,
    format: initial.format || "pdf", cron: initial.cron || "0 6 * * 1", recipients: initial.recipients || "", enabled: initial.enabled ?? true });
  const qc = useQueryClient();
  const nav = useNavigate();
  const save = useMutation({ mutationFn: () => api(initial.id ? `/api/report-center/schedules/${initial.id}` : "/api/report-center/schedules", { method: initial.id ? "PUT" : "POST", body: v }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["report-schedules"] }); onClose(); nav("/reports/schedules"); } });
  const t = tpls?.find((x) => x.key === v.report_key);
  const set = (k: string, x: unknown) => setV((o) => ({ ...o, [k]: x }));
  return (
    <Modal open onClose={onClose} size="lg" title={initial.id ? "Edit scheduled report" : "Schedule a report"}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={save.isPending} icon={<Mail className="h-4 w-4" />} onClick={() => save.mutate()}>Save schedule</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" required><input className="input" value={v.name} onChange={(e) => set("name", e.target.value)} /></Field>
        <Field label="Report"><select className="input" value={v.report_key} onChange={(e) => { set("report_key", e.target.value); set("params", {}); }}>{tpls?.filter((x) => x.allowed).map((x) => <option key={x.key} value={x.key}>{x.title}</option>)}</select></Field>
        <Field label="Format"><select className="input" value={v.format} onChange={(e) => set("format", e.target.value)}>{["pdf", "xlsx", "csv", "html"].map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}</select></Field>
        <Field label="When (UTC)" hint="Preset or a 5-field cron expression"><div className="flex gap-2"><select className="input" value={CRONS.some((c) => c[0] === v.cron) ? v.cron : ""} onChange={(e) => e.target.value && set("cron", e.target.value)}>
          <option value="">Custom</option>{CRONS.map(([c, l]) => <option key={c} value={c}>{l}</option>)}</select><input className="input w-36 font-mono" value={v.cron} onChange={(e) => set("cron", e.target.value)} /></div></Field>
      </div>
      <Field label="E-mail recipients" hint="Comma-separated; leave empty to only keep the report in the history"><input className="input" value={v.recipients} onChange={(e) => set("recipients", e.target.value)} placeholder="cio@example.com, itsec@example.com" /></Field>
      {t && <div className="mt-2"><p className="label">Filters</p><Filters t={t} p={v.params} set={(k, x) => set("params", { ...v.params, [k]: x })} /></div>}
      <label className="mt-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Enabled</label>
      {save.error && <ErrorBox error={save.error} />}
    </Modal>
  );
}

function History() {
  const [page, setPage] = useState(1);
  const { data, isLoading } = useQuery({ queryKey: ["report-runs", page], placeholderData: (p) => p, queryFn: () => api<{ items: Run[]; total: number }>(`/api/report-runs?page=${page}&page_size=50`) });
  return (
    <Card padded={false} title="Historical reports">
      <DataTable id="report-runs" rows={data?.items} loading={isLoading} rowKey={(r) => r.id} empty="No reports generated yet"
        server={{ total: data?.total || 0, page, pageSize: 50, onPage: setPage }}
        columns={[
          { key: "generated_at", label: "Generated", sortable: false, render: (r) => <span className="whitespace-nowrap text-xs">{fmtDate(r.generated_at)}</span> },
          { key: "title", label: "Report", sortable: false, render: (r) => r.allowed ? <button className="text-left font-medium text-brand-700 hover:underline dark:text-brand-300" onClick={() => download(`/api/report-runs/${r.id}/download`)}>{r.title}</button> : <span className="text-slate-400"><Lock className="mr-1 inline h-3 w-3" />{r.title}</span> },
          { key: "format", label: "Format", sortable: false, render: (r) => <Badge>{r.format.toUpperCase()}</Badge> },
          { key: "generated_by", label: "By", sortable: false }, { key: "size", label: "Size", sortable: false, render: (r) => `${(r.size / 1024).toFixed(0)} KB` },
          { key: "emailed_to", label: "E-mailed to", sortable: false, render: (r) => <span className="text-xs">{r.emailed_to || "—"}</span> },
          { key: "sha256", label: "SHA-256", sortable: false, hidden: true, render: (r) => <code className="text-[11px]">{r.sha256}</code> },
        ]} />
    </Card>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCheck, FileCheck2, Plus, RefreshCw, Upload } from "lucide-react";
import { ReactNode, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ComplianceBadge, Risk, ScoreRing, StackBar } from "../../components/badges";
import { DataTable } from "../../components/DataTable";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, Skeleton, Stat, Tabs, useToast } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { download, qs } from "../../lib/download";
import { fmtDate } from "../../lib/format";

export type Framework = { id: number; code: string; name: string; version: string; description: string; builtin: boolean; controls: number; automated_controls: number };
export type ASummary = { total_controls: number; counts: Record<string, number>; assessed: number; score: number | null; findings_by_severity: Record<string, number>; findings_by_status: Record<string, number> };
export type Assessment = { id: number; title: string; framework: string; framework_code: string; framework_id: number; status: string; period_start: string | null; period_end: string | null;
  scope: Record<string, unknown>; summary: ASummary; executive_summary: string; created_by: string; created_by_id: number; created_at: string; approved_by: string | null; approved_at: string | null; approval_comment: string };
export type Finding = { id: number; assessment_id: number | null; title: string; description: string; severity: string; status: string; source: string; asset: string; root_cause: string;
  business_impact: string; recommendation: string; owner_department: string; owner_user_id: number | null; owner: string | null; due_date: string | null; overdue: boolean;
  risk_acceptance: Record<string, string>; created_by: string | null; created_at: string; control_ref: string | null; closed_at: string | null };
export type EvidenceRow = { id: number; title: string; description: string; filename: string; content_type: string; size: number; sha256: string; source: string;
  assessment_id: number | null; finding_id: number | null; control_ref: string | null; uploaded_by: string; uploaded_at: string; withdrawn_at: string | null; withdrawn_reason: string | null };
type TabId = "dashboard" | "assessments" | "findings" | "evidence" | "frameworks";
const TABS: { id: TabId; label: ReactNode }[] = [{ id: "dashboard", label: "Audit Dashboard" }, { id: "assessments", label: "Assessments" }, { id: "findings", label: "Findings" },
  { id: "evidence", label: "Evidence Repository" }, { id: "frameworks", label: "Compliance Frameworks" }];
export const SEV_COLORS: Record<string, string> = { critical: "#991b1b", high: "#dc2626", medium: "#d97706", low: "#2563eb", informational: "#94a3b8" };

export default function CompliancePage() {
  const { tab = "dashboard" } = useParams();
  const nav = useNavigate();
  return (
    <div>
      <PageHeader title="IT Audit" subtitle="Assessments against ISO 27001, CIS, NIST CSF and RBI controls with evidence, findings and approvals. Results support an audit; they do not certify compliance." />
      <Tabs tabs={TABS} value={tab as TabId} onChange={(t) => nav(`/compliance/${t}`)} />
      {tab === "dashboard" && <Dashboard />}
      {tab === "assessments" && <Assessments />}
      {tab === "findings" && <FindingsList />}
      {tab === "evidence" && <EvidenceList />}
      {tab === "frameworks" && <Frameworks />}
    </div>
  );
}

function Dashboard() {
  const { data, error } = useQuery({ queryKey: ["compliance-dashboard"], queryFn: () => api<{ frameworks: (ASummary & { framework: string; code: string; assessment_id: number; title: string; status: string; date: string })[];
    open_findings: number; overdue: number; by_severity: Record<string, number>; by_status: Record<string, number>; evidence: number }>("/api/compliance/dashboard") });
  const [run, setRun] = useState(false);
  const { data: checks, isFetching } = useQuery({ queryKey: ["compliance-preview"], enabled: run, queryFn: () => api<{ key: string; title: string; status: string; summary: string; findings: number }[]>("/api/compliance/checks/preview") });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Card><Skeleton /></Card>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Open findings" value={data.open_findings} tone="red" icon={<ClipboardCheck className="h-5 w-5" />} />
        <Stat label="Overdue" value={data.overdue} tone={data.overdue ? "red" : "gray"} sub="past target date" />
        <Stat label="Critical + high open" value={(data.by_severity.critical || 0) + (data.by_severity.high || 0)} tone="amber" />
        <Stat label="Evidence items" value={data.evidence} tone="blue" icon={<FileCheck2 className="h-5 w-5" />} />
      </div>
      <Card title="Open findings by severity">
        <StackBar parts={["critical", "high", "medium", "low", "informational"].map((s) => ({ label: s[0].toUpperCase() + s.slice(1), value: data.by_severity[s] || 0, color: SEV_COLORS[s] }))} />
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        {data.frameworks.length ? data.frameworks.map((f) => (
          <Card key={f.code} title={f.framework} actions={<Link className="text-sm text-brand-700 hover:underline dark:text-brand-300" to={`/compliance/assessments/${f.assessment_id}`}>Open</Link>}>
            <div className="flex flex-wrap items-center gap-6">
              <ScoreRing score={f.score} label={`${f.title} · ${fmtDate(f.date)}`} />
              <div className="flex-1"><StackBar parts={[{ label: "Compliant", value: f.counts.compliant, color: "#059669" }, { label: "Partial", value: f.counts.partial, color: "#d97706" },
                { label: "Non-compliant", value: f.counts.non_compliant, color: "#dc2626" }, { label: "Not assessed", value: f.counts.not_assessed, color: "#cbd5e1" },
                { label: "N/A", value: f.counts.not_applicable, color: "#94a3b8" }]} /><p className="mt-2"><ComplianceBadge status={f.status} /></p></div>
            </div>
          </Card>
        )) : <Card className="lg:col-span-2"><EmptyState title="No assessments yet" hint="Create an assessment to evaluate a framework. Automated checks fill in what InfraPilot can verify; you record the rest with evidence." /></Card>}
      </div>
      <Card title="Current technical posture (automated checks, live)" actions={<Button size="sm" variant="outline" loading={isFetching} icon={<RefreshCw className="h-4 w-4" />} onClick={() => setRun(true)}>{checks ? "Refresh" : "Run checks"}</Button>}>
        {!checks ? <p className="text-sm text-slate-500">Runs every automated check against current data without creating an assessment.</p> : (
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {checks.map((c) => <div key={c.key} className="flex flex-wrap items-start gap-3 py-2 text-sm"><div className="w-44 shrink-0"><ComplianceBadge status={c.status} /></div>
              <div className="min-w-0 flex-1"><p className="font-medium">{c.title}</p><p className="text-xs text-slate-500">{c.summary}</p></div>{c.findings > 0 && <Badge tone="amber">{c.findings} issue(s)</Badge>}</div>)}
          </div>
        )}
      </Card>
    </div>
  );
}

function Assessments() {
  const nav = useNavigate();
  const { can } = useAuth();
  const [create, setCreate] = useState(false);
  const { data, isLoading } = useQuery({ queryKey: ["assessments"], queryFn: () => api<Assessment[]>("/api/compliance/assessments") });
  return (
    <Card padded={false} title="Assessments" actions={can("compliance.manage") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setCreate(true)}>New assessment</Button>}>
      <DataTable id="assessments" rows={data} loading={isLoading} rowKey={(a) => a.id} onRowClick={(a) => nav(`/compliance/assessments/${a.id}`)} empty="No assessments yet" columns={[
        { key: "title", label: "Assessment", render: (a) => <span className="font-medium">{a.title}</span> }, { key: "framework", label: "Framework" },
        { key: "period", label: "Period", value: (a) => a.period_end || "", render: (a) => <span className="text-xs">{a.period_start ? fmtDate(a.period_start).split(",")[0] : "…"} – {fmtDate(a.period_end).split(",")[0]}</span> },
        { key: "status", label: "Status", render: (a) => <ComplianceBadge status={a.status} /> },
        { key: "score", label: "Score", value: (a) => a.summary?.score ?? -1, render: (a) => a.summary?.score != null ? `${a.summary.score}%` : "n/a" },
        { key: "nc", label: "Non-compliant", value: (a) => a.summary?.counts?.non_compliant ?? 0 },
        { key: "created_by", label: "Prepared by" }, { key: "approved_by", label: "Approved by", render: (a) => a.approved_by || "—" },
        { key: "created_at", label: "Created", hidden: true, render: (a) => fmtDate(a.created_at) },
      ]} />
      {create && <NewAssessment onClose={() => setCreate(false)} />}
    </Card>
  );
}

function NewAssessment({ onClose }: { onClose: () => void }) {
  const { data: fws } = useQuery({ queryKey: ["frameworks"], queryFn: () => api<Framework[]>("/api/compliance/frameworks") });
  const { data: sites } = useQuery({ queryKey: ["sites"], queryFn: () => api<{ id: number; name: string }[]>("/api/sites") });
  const [v, setV] = useState({ framework_id: 0, title: "", period_start: "", period_end: new Date().toISOString().slice(0, 10), description: "", site_id: "", run_checks: true });
  const nav = useNavigate();
  const m = useMutation({ mutationFn: () => api<Assessment>("/api/compliance/assessments", { body: {
    framework_id: v.framework_id || fws?.[0]?.id, title: v.title, period_start: v.period_start ? `${v.period_start}T00:00:00` : null, period_end: v.period_end ? `${v.period_end}T23:59:59` : null,
    scope: { description: v.description, ...(v.site_id ? { site_ids: [Number(v.site_id)] } : {}) }, run_checks: v.run_checks } }), onSuccess: (a) => nav(`/compliance/assessments/${a.id}`) });
  const set = (k: string, x: unknown) => setV((o) => ({ ...o, [k]: x }));
  return (
    <Modal open onClose={onClose} title="New assessment" size="lg" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={m.isPending} disabled={v.title.length < 3} onClick={() => m.mutate()}>Create</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Framework"><select className="input" value={v.framework_id || fws?.[0]?.id || ""} onChange={(e) => set("framework_id", Number(e.target.value))}>{fws?.map((f) => <option key={f.id} value={f.id}>{f.name}</option>)}</select></Field>
        <Field label="Title" required><input className="input" value={v.title} onChange={(e) => set("title", e.target.value)} placeholder="Q4 2026 ISO 27001 internal audit" /></Field>
        <Field label="Audit period start"><input className="input" type="date" value={v.period_start} onChange={(e) => set("period_start", e.target.value)} /></Field>
        <Field label="Audit period end"><input className="input" type="date" value={v.period_end} onChange={(e) => set("period_end", e.target.value)} /></Field>
        <Field label="Scope description"><input className="input" value={v.description} onChange={(e) => set("description", e.target.value)} placeholder="Head office data centre and branch network" /></Field>
        <Field label="Limit to site (optional)"><select className="input" value={v.site_id} onChange={(e) => set("site_id", e.target.value)}><option value="">All sites</option>{sites?.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
      </div>
      <label className="mt-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={v.run_checks} onChange={(e) => set("run_checks", e.target.checked)} />Run automated checks now (evidence snapshot is stored with a SHA-256)</label>
      {m.error && <ErrorBox error={m.error} />}
    </Modal>
  );
}

export function FindingsList({ assessmentId }: { assessmentId?: number }) {
  const nav = useNavigate();
  const { can } = useAuth();
  const [status, setStatus] = useState("open,assigned,in_progress,pending_verification");
  const [sev, setSev] = useState("");
  const [overdue, setOverdue] = useState(false);
  const [mine, setMine] = useState(false);
  const [create, setCreate] = useState(false);
  const { data, isLoading } = useQuery({ queryKey: ["findings", status, sev, overdue, mine, assessmentId],
    queryFn: () => api<{ items: Finding[]; total: number }>(`/api/compliance/findings${qs({ status, severity: sev, overdue, mine, assessment_id: assessmentId, page_size: 500 })}`) });
  return (
    <Card padded={false} title={<span>Findings <Badge>{data?.total ?? 0}</Badge></span>} actions={can("compliance.manage") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setCreate(true)}>New finding</Button>}>
      <DataTable id="findings" rows={data?.items} loading={isLoading} rowKey={(f) => f.id} onRowClick={(f) => nav(`/compliance/findings/${f.id}`)} empty="No findings match"
        toolbar={<>
          <select className="input w-auto py-1.5 text-sm" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
            <option value="open,assigned,in_progress,pending_verification">Active</option><option value="">All statuses</option>
            {["open", "assigned", "in_progress", "pending_verification", "closed", "accepted_risk"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}</select>
          <select className="input w-auto py-1.5 text-sm" value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity"><option value="">All severities</option>
            {["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
          <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={overdue} onChange={(e) => setOverdue(e.target.checked)} />Overdue</label>
          <label className="flex items-center gap-1 text-xs"><input type="checkbox" checked={mine} onChange={(e) => setMine(e.target.checked)} />Assigned to me</label>
        </>}
        columns={[
          { key: "id", label: "ID", render: (f) => `F-${f.id}` }, { key: "severity", label: "Severity", value: (f) => ["critical", "high", "medium", "low", "informational"].indexOf(f.severity), render: (f) => <Risk risk={f.severity} /> },
          { key: "title", label: "Finding", render: (f) => <div><p className="font-medium">{f.title}</p>{f.asset && <p className="truncate text-xs text-slate-500" style={{ maxWidth: 420 }}>{f.asset}</p>}</div> },
          { key: "status", label: "Status", render: (f) => <ComplianceBadge status={f.status} /> },
          { key: "owner", label: "Owner", value: (f) => f.owner || f.owner_department, render: (f) => f.owner || f.owner_department || <span className="text-slate-400">Unassigned</span> },
          { key: "due_date", label: "Target date", render: (f) => <span className={f.overdue ? "font-medium text-red-600" : ""}>{f.due_date ? fmtDate(f.due_date).split(",")[0] : "—"}{f.overdue && " (overdue)"}</span> },
          { key: "control_ref", label: "Control", hidden: true }, { key: "source", label: "Source", hidden: true, render: (f) => f.source.startsWith("automated") ? "Automated check" : "Manual" },
        ]} />
      {create && <NewFinding assessmentId={assessmentId} onClose={() => setCreate(false)} />}
    </Card>
  );
}

function NewFinding({ onClose, assessmentId }: { onClose: () => void; assessmentId?: number }) {
  const [v, setV] = useState({ title: "", severity: "medium", asset: "", description: "", root_cause: "", business_impact: "", recommendation: "", owner_department: "" });
  const nav = useNavigate();
  const m = useMutation({ mutationFn: () => api<Finding>("/api/compliance/findings", { body: { ...v, assessment_id: assessmentId ?? null } }), onSuccess: (f) => nav(`/compliance/findings/${f.id}`) });
  const set = (k: string, x: string) => setV((o) => ({ ...o, [k]: x }));
  return (
    <Modal open onClose={onClose} title="New finding" size="lg" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={m.isPending} disabled={v.title.length < 3} onClick={() => m.mutate()}>Create</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Title" required><input className="input" value={v.title} onChange={(e) => set("title", e.target.value)} /></Field>
        <Field label="Severity"><select className="input" value={v.severity} onChange={(e) => set("severity", e.target.value)}>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Asset(s)"><input className="input" value={v.asset} onChange={(e) => set("asset", e.target.value)} /></Field>
        <Field label="Responsible department"><input className="input" value={v.owner_department} onChange={(e) => set("owner_department", e.target.value)} /></Field>
      </div>
      {(["description", "root_cause", "business_impact", "recommendation"] as const).map((k) => <Field key={k} label={k.replace(/_/g, " ")}><textarea className="input" rows={2} value={v[k]} onChange={(e) => set(k, e.target.value)} /></Field>)}
      {m.error && <ErrorBox error={m.error} />}
    </Modal>
  );
}

export function EvidenceList({ assessmentId, findingId, compact }: { assessmentId?: number; findingId?: number; compact?: boolean }) {
  const { can } = useAuth();
  const [up, setUp] = useState(false);
  const { data, isLoading } = useQuery({ queryKey: ["evidence", assessmentId, findingId], queryFn: () => api<{ items: EvidenceRow[]; total: number }>(`/api/compliance/evidence${qs({ assessment_id: assessmentId, finding_id: findingId, page_size: 500 })}`) });
  return (
    <Card padded={false} title={<span>{compact ? "Evidence" : "Evidence repository"} <Badge>{data?.total ?? 0}</Badge></span>}
      actions={can("compliance.manage") && <Button size="sm" variant="outline" icon={<Upload className="h-4 w-4" />} onClick={() => setUp(true)}>Upload evidence</Button>}>
      {!compact && <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">Files are immutable. The SHA-256 recorded at upload is verified on every download; evidence is withdrawn with a reason, never deleted.</p>}
      <DataTable id={`evidence-${compact ? "c" : "all"}`} rows={data?.items} loading={isLoading} rowKey={(e) => e.id} empty="No evidence yet" columns={[
        { key: "id", label: "ID", render: (e) => `E-${e.id}` },
        { key: "title", label: "Evidence", render: (e) => <div><button className="font-medium text-brand-700 hover:underline dark:text-brand-300" onClick={() => download(`/api/compliance/evidence/${e.id}/download`)}>{e.title}</button>
          <p className="text-xs text-slate-500">{e.filename} · {(e.size / 1024).toFixed(1)} KB{e.control_ref && ` · ${e.control_ref}`}</p>{e.withdrawn_at && <Badge tone="gray">Withdrawn: {e.withdrawn_reason}</Badge>}</div> },
        { key: "source", label: "Source", render: (e) => <Badge tone={e.source === "system" ? "blue" : "gray"}>{e.source === "system" ? "System snapshot" : "Upload"}</Badge> },
        { key: "uploaded_by", label: "By" }, { key: "uploaded_at", label: "When", render: (e) => <span className="text-xs">{fmtDate(e.uploaded_at)}</span> },
        { key: "sha256", label: "SHA-256", render: (e) => <code className="text-[11px]" title={e.sha256}>{e.sha256.slice(0, 16)}…</code> },
        { key: "links", label: "Linked to", value: (e) => `${e.assessment_id ?? ""}${e.finding_id ?? ""}`, render: (e) => <span className="text-xs">{e.assessment_id && <Link className="text-brand-700 dark:text-brand-300" to={`/compliance/assessments/${e.assessment_id}`}>Assessment #{e.assessment_id}</Link>}{e.finding_id && <Link className="ml-1 text-brand-700 dark:text-brand-300" to={`/compliance/findings/${e.finding_id}`}>F-{e.finding_id}</Link>}</span> },
      ]} />
      {up && <UploadEvidence assessmentId={assessmentId} findingId={findingId} onClose={() => setUp(false)} />}
    </Card>
  );
}

export function UploadEvidence({ assessmentId, findingId, controlRef, onClose, onUploaded }: { assessmentId?: number; findingId?: number; controlRef?: string; onClose: () => void; onUploaded?: (e: EvidenceRow) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const qc = useQueryClient();
  const toast = useToast();
  const m = useMutation({ mutationFn: () => { const f = new FormData(); f.append("file", file as File); f.append("title", title || file?.name || ""); f.append("description", desc);
    if (assessmentId) f.append("assessment_id", String(assessmentId)); if (findingId) f.append("finding_id", String(findingId)); if (controlRef) f.append("control_ref", controlRef);
    return api<EvidenceRow>("/api/compliance/evidence", { form: f }); },
  onSuccess: (e) => { qc.invalidateQueries({ queryKey: ["evidence"] }); toast({ tone: "success", title: "Evidence stored", body: `SHA-256 ${e.sha256.slice(0, 16)}…` }); onUploaded?.(e); onClose(); } });
  return (
    <Modal open onClose={onClose} title="Upload evidence" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={m.isPending} disabled={!file} onClick={() => m.mutate()}>Upload</Button></>}>
      <Field label="File (max 25 MB)" hint="PDF, images, logs, CSV/Excel, Word, JSON/XML, HTML, ZIP, EVTX, config files"><input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} /></Field>
      <Field label="Title"><input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder={file?.name} /></Field>
      <Field label="Description"><textarea className="input" rows={2} value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
      {controlRef && <p className="text-xs text-slate-500">Linked to control {controlRef}</p>}
      {m.error && <ErrorBox error={m.error} />}
    </Modal>
  );
}

function Frameworks() {
  const { data: fws } = useQuery({ queryKey: ["frameworks"], queryFn: () => api<Framework[]>("/api/compliance/frameworks") });
  const [open, setOpen] = useState<number | null>(null);
  const { data: controls } = useQuery({ queryKey: ["controls", open], enabled: !!open, queryFn: () => api<{ id: number; ref: string; title: string; domain: string; description: string; checks: string[]; check_titles: string[] }[]>(`/api/compliance/frameworks/${open}/controls`) });
  return (
    <div className="space-y-4">
      <Callout tone="info">Built-in frameworks list the controls with an IT-infrastructure component and map them to InfraPilot's automated checks. Control text is summarised, not the licensed standard.
        For RBI, confirm which requirements apply to your regulated activities and mark the others Not applicable in each assessment.</Callout>
      <div className="grid gap-4 md:grid-cols-2">
        {fws?.map((f) => (
          <Card key={f.id} title={f.name} actions={<Button size="sm" variant={open === f.id ? "primary" : "outline"} onClick={() => setOpen(open === f.id ? null : f.id)}>Controls</Button>}>
            <p className="text-sm text-slate-600 dark:text-slate-300">{f.description}</p>
            <p className="mt-2 text-xs text-slate-500">{f.controls} controls · {f.automated_controls} with automated evidence · version {f.version}{f.builtin && " · built-in"}</p>
          </Card>
        ))}
      </div>
      {open && controls && (
        <Card padded={false} title="Controls">
          <DataTable id="controls" rows={controls} rowKey={(c) => c.id} pageSize={100} columns={[
            { key: "ref", label: "Ref" }, { key: "title", label: "Control", render: (c) => <div><p className="font-medium">{c.title}</p>{c.description && <p className="text-xs text-slate-500">{c.description}</p>}</div> },
            { key: "domain", label: "Domain" }, { key: "checks", label: "Automated evidence", value: (c) => c.check_titles.join(", "), render: (c) => c.check_titles.length ? <div className="flex flex-wrap gap-1">{c.check_titles.map((t) => <Badge key={t} tone="blue">{t}</Badge>)}</div> : <span className="text-xs text-slate-400">Manual assessment</span> },
          ]} />
        </Card>
      )}
    </div>
  );
}

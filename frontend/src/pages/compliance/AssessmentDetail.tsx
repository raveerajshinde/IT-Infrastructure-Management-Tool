import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle, FileCode2, FileSpreadsheet, FileText, RefreshCw, Send } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ComplianceBadge, ScoreRing, StackBar } from "../../components/badges";
import { DataTable } from "../../components/DataTable";
import { Badge, Button, Callout, Card, ErrorBox, Field, KeyValue, Modal, PageHeader, Skeleton, Tabs, useToast } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { download, openInline } from "../../lib/download";
import { fmtDate } from "../../lib/format";
import { Assessment, EvidenceList, EvidenceRow, FindingsList, UploadEvidence } from "./CompliancePage";

type Result = { control_id: number; ref: string; title: string; domain: string; description: string; checks: string[]; status: string; source: string; evidence_summary: string;
  evidence: { type: string; evidence_id?: number; label?: string; sha256?: string; check?: string; status?: string }[]; assessed_at: string | null; assessed_by: string | null; auditor_notes: string };

export default function AssessmentDetail() {
  const { id = "" } = useParams();
  const { can, user } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const [tab, setTab] = useState<"controls" | "findings" | "evidence" | "summary">("controls");
  const [edit, setEdit] = useState<Result | null>(null);
  const [st, setSt] = useState("");
  const [approve, setApprove] = useState(false);
  const { data: a, error } = useQuery({ queryKey: ["assessment", id], queryFn: () => api<Assessment & { results: Result[] }>(`/api/compliance/assessments/${id}`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["assessment", id] }); qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["evidence"] }); };
  const rerun = useMutation({ mutationFn: () => api<{ controls_updated: number; findings_created: number }>(`/api/compliance/assessments/${id}/run`, { method: "POST" }),
    onSuccess: (r) => { refresh(); toast({ tone: "success", title: "Automated checks re-run", body: `${r.controls_updated} control(s) updated, ${r.findings_created} new finding(s)` }); },
    onError: (e) => toast({ tone: "error", title: (e as Error).message }) });
  const move = useMutation({ mutationFn: (b: { to: string; comment?: string }) => api(`/api/compliance/assessments/${id}/status`, { body: b }),
    onSuccess: () => { refresh(); setApprove(false); }, onError: (e) => toast({ tone: "error", title: (e as Error).message }) });
  if (error) return <ErrorBox error={error} />;
  if (!a) return <Card><Skeleton rows={12} /></Card>;
  const s = a.summary;
  const locked = a.status === "approved";
  const manage = can("compliance.manage") && !locked;
  const url = (f: string) => `/api/compliance/assessments/${id}/report?format=${f}`;
  const rows = a.results.filter((r) => !st || r.status === st);
  return (
    <div>
      <Link to="/compliance/assessments" className="mb-2 inline-flex items-center gap-1 text-sm text-brand-700 hover:underline dark:text-brand-300"><ArrowLeft className="h-4 w-4" />Assessments</Link>
      <PageHeader title={a.title} subtitle={<span className="flex flex-wrap items-center gap-2">{a.framework}<ComplianceBadge status={a.status} /></span>} actions={<>
        <Button variant="outline" icon={<FileText className="h-4 w-4" />} onClick={() => download(url("pdf"))}>PDF</Button>
        <Button variant="outline" icon={<FileSpreadsheet className="h-4 w-4" />} onClick={() => download(url("xlsx"))}>Excel</Button>
        <Button variant="ghost" onClick={() => download(url("csv"))}>CSV</Button>
        <Button variant="ghost" icon={<FileCode2 className="h-4 w-4" />} onClick={() => openInline(url("html"))}>HTML</Button>
        {manage && <Button variant="outline" icon={<RefreshCw className="h-4 w-4" />} loading={rerun.isPending} onClick={() => rerun.mutate()}>Re-run checks</Button>}
        {manage && a.status === "draft" && <Button icon={<Send className="h-4 w-4" />} onClick={() => move.mutate({ to: "in_review" })}>Submit for review</Button>}
        {a.status === "in_review" && can("compliance.approve") && a.created_by_id !== user?.id && <Button icon={<CheckCircle className="h-4 w-4" />} onClick={() => setApprove(true)}>Approve</Button>}
        {a.status === "in_review" && can("compliance.manage") && <Button variant="ghost" onClick={() => move.mutate({ to: "draft" })}>Back to draft</Button>}
      </>} />
      {locked && <div className="mb-4"><Callout tone="success" title="Approved and locked">Approved by {a.approved_by} on {fmtDate(a.approved_at)}{a.approval_comment && `: “${a.approval_comment}”`}. Start a new assessment to re-assess.</Callout></div>}
      {a.status === "in_review" && a.created_by_id === user?.id && <div className="mb-4"><Callout tone="info">Waiting for approval by an auditor other than the author.</Callout></div>}
      <div className="mb-4 grid gap-4 lg:grid-cols-3">
        <Card className="flex items-center"><ScoreRing score={s.score} label={`${s.assessed} of ${s.total_controls} controls assessed`} /></Card>
        <Card className="lg:col-span-2">
          <StackBar parts={[{ label: "Compliant", value: s.counts.compliant, color: "#059669" }, { label: "Partially", value: s.counts.partial, color: "#d97706" },
            { label: "Non-compliant", value: s.counts.non_compliant, color: "#dc2626" }, { label: "Not assessed", value: s.counts.not_assessed, color: "#cbd5e1" }, { label: "N/A", value: s.counts.not_applicable, color: "#94a3b8" }]} />
          <div className="mt-3 flex flex-wrap gap-2 text-xs">{Object.entries(s.findings_by_severity).filter(([, v]) => v).map(([k, v]) => <Badge key={k} tone={k === "critical" || k === "high" ? "red" : k === "medium" ? "amber" : "gray"}>{v} {k}</Badge>)}
            <span className="text-slate-500">Period {a.period_start ? fmtDate(a.period_start).split(",")[0] : "…"} – {fmtDate(a.period_end).split(",")[0]} · prepared by {a.created_by}</span></div>
        </Card>
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "controls", label: `Controls (${a.results.length})` }, { id: "findings", label: "Findings" }, { id: "evidence", label: "Evidence" }, { id: "summary", label: "Executive summary & scope" }]} />
      {tab === "controls" && (
        <Card padded={false}>
          <DataTable id="assessment-controls" rows={rows} rowKey={(r) => r.control_id} pageSize={100} onRowClick={manage ? (r) => setEdit(r) : undefined}
            toolbar={<select className="input w-auto py-1.5 text-sm" value={st} onChange={(e) => setSt(e.target.value)} aria-label="Status"><option value="">All statuses</option>
              {["compliant", "partial", "non_compliant", "not_assessed", "not_applicable"].map((x) => <option key={x} value={x}>{x.replace(/_/g, " ")}</option>)}</select>}
            columns={[
              { key: "ref", label: "Ref" }, { key: "title", label: "Control", render: (r) => <div><p className="font-medium">{r.title}</p><p className="text-xs text-slate-500">{r.domain}</p></div> },
              { key: "status", label: "Status", render: (r) => <ComplianceBadge status={r.status} /> },
              { key: "source", label: "Source", render: (r) => r.source.startsWith("automated") ? <Badge tone="blue">Automated</Badge> : r.source === "manual" ? <Badge>Auditor</Badge> : <span className="text-xs text-slate-400">—</span> },
              { key: "evidence_summary", label: "Evidence", render: (r) => <div className="max-w-xl whitespace-pre-line text-xs">{r.evidence_summary || <span className="text-slate-400">No evidence recorded</span>}
                {r.evidence.filter((e) => e.type === "file").map((e) => <button key={e.evidence_id} className="mt-1 block text-brand-700 hover:underline dark:text-brand-300" onClick={(ev) => { ev.stopPropagation(); download(`/api/compliance/evidence/${e.evidence_id}/download`); }}>📎 {e.label}</button>)}</div> },
              { key: "auditor_notes", label: "Auditor notes", render: (r) => <span className="text-xs">{r.auditor_notes}</span> },
              { key: "assessed_at", label: "Assessed", render: (r) => <span className="text-xs">{r.assessed_at ? `${fmtDate(r.assessed_at)}${r.assessed_by ? ` · ${r.assessed_by}` : ""}` : "—"}</span> },
            ]} />
          {manage && <p className="border-t border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">Click a control to record the auditor's result. Auditor results are never overwritten by re-running automated checks.</p>}
        </Card>
      )}
      {tab === "findings" && <FindingsList assessmentId={a.id} />}
      {tab === "evidence" && <EvidenceList assessmentId={a.id} compact />}
      {tab === "summary" && <SummaryEditor a={a} editable={manage} onSaved={refresh} />}
      {edit && <ResultEditor a={a} r={edit} onClose={() => setEdit(null)} onSaved={refresh} />}
      <Modal open={approve} onClose={() => setApprove(false)} title="Approve assessment"
        footer={<><Button variant="outline" onClick={() => setApprove(false)}>Cancel</Button><ApproveButton onApprove={(c) => move.mutate({ to: "approved", comment: c })} loading={move.isPending} /></>}>
        <p className="text-sm">Approval locks the assessment and its results. Approval is recorded with your name in the audit trail.</p>
      </Modal>
    </div>
  );
}

function ApproveButton({ onApprove, loading }: { onApprove: (c: string) => void; loading: boolean }) {
  const [c, setC] = useState("");
  return <div className="flex flex-1 items-center gap-2"><input className="input" placeholder="Approval comment" value={c} onChange={(e) => setC(e.target.value)} /><Button loading={loading} onClick={() => onApprove(c)}>Approve</Button></div>;
}

function SummaryEditor({ a, editable, onSaved }: { a: Assessment; editable: boolean; onSaved: () => void }) {
  const [text, setText] = useState(a.executive_summary);
  const save = useMutation({ mutationFn: () => api(`/api/compliance/assessments/${a.id}`, { method: "PUT", body: { executive_summary: text } }), onSuccess: onSaved });
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Executive summary (auditor)" actions={editable && <Button size="sm" loading={save.isPending} onClick={() => save.mutate()}>Save</Button>}>
        <textarea className="input min-h-[220px]" value={text} readOnly={!editable} onChange={(e) => setText(e.target.value)} placeholder="Overall opinion, key risks and management actions. An automatic factual summary is added in the report." />
      </Card>
      <Card title="Scope"><KeyValue items={[["Description", String(a.scope.description || "All assets managed by InfraPilot")], ["Sites", JSON.stringify(a.scope.site_ids || "all")],
        ["Framework", a.framework], ["Created", fmtDate(a.created_at)]]} /></Card>
    </div>
  );
}

function ResultEditor({ a, r, onClose, onSaved }: { a: Assessment; r: Result; onClose: () => void; onSaved: () => void }) {
  const [status, setStatus] = useState(r.status);
  const [notes, setNotes] = useState(r.auditor_notes);
  const [summary, setSummary] = useState(r.evidence_summary);
  const [ev, setEv] = useState<EvidenceRow[]>([]);
  const [up, setUp] = useState(false);
  const save = useMutation({ mutationFn: () => api(`/api/compliance/assessments/${a.id}/results/${r.control_id}`, { method: "PUT", body: { status, auditor_notes: notes, evidence_summary: summary, evidence_ids: ev.map((e) => e.id) } }),
    onSuccess: () => { onSaved(); onClose(); } });
  return (
    <Modal open onClose={onClose} size="lg" title={`${r.ref} — ${r.title}`} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={save.isPending} onClick={() => save.mutate()}>Save result</Button></>}>
      {r.description && <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">{r.description}</p>}
      {r.source.startsWith("automated") && <Callout tone="info">Automated evidence is kept. Saving here records your assessment as the auditor's result; it will no longer be changed by re-running checks.</Callout>}
      <Field label="Status"><div className="flex flex-wrap gap-2">{["compliant", "partial", "non_compliant", "not_applicable", "not_assessed"].map((x) => (
        <button key={x} onClick={() => setStatus(x)} className={`rounded-md border px-2.5 py-1 text-xs ${status === x ? "border-brand-500 bg-brand-50 dark:bg-brand-900/30" : "border-slate-200 dark:border-slate-700"}`}><ComplianceBadge status={x} /></button>))}</div></Field>
      <Field label="Evidence summary (what was verified)"><textarea className="input" rows={4} value={summary} onChange={(e) => setSummary(e.target.value)} /></Field>
      <Field label="Auditor notes"><textarea className="input" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => setUp(true)}>Attach evidence file</Button>
        {ev.map((e) => <Badge key={e.id} tone="blue">📎 {e.filename}</Badge>)}
      </div>
      {save.error && <div className="mt-3"><ErrorBox error={save.error} /></div>}
      {up && <UploadEvidence assessmentId={a.id} controlRef={r.ref} onClose={() => setUp(false)} onUploaded={(e) => setEv((x) => [...x, e])} />}
    </Modal>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ComplianceBadge, Risk } from "../../components/badges";
import { Button, Callout, Card, ErrorBox, Field, KeyValue, Modal, PageHeader, Skeleton } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { fmtDate } from "../../lib/format";
import { EvidenceList, Finding } from "./CompliancePage";

type Detail = Finding & { events: { ts: string; user: string | null; from: string | null; to: string | null; comment: string }[]; allowed_transitions: string[] };
const LABEL: Record<string, string> = { open: "Reopen", assigned: "Assign", in_progress: "Start remediation", pending_verification: "Submit for verification", closed: "Verify & close", accepted_risk: "Accept risk" };

export default function FindingDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [move, setMove] = useState<string | null>(null);
  const [edit, setEdit] = useState(false);
  const { data: f, error } = useQuery({ queryKey: ["finding", id], queryFn: () => api<Detail>(`/api/compliance/findings/${id}`) });
  const { data: users } = useQuery({ queryKey: ["users-lite"], enabled: edit, queryFn: () => api<{ items?: { id: number; username: string }[] } | { id: number; username: string }[]>("/api/users?page_size=500") });
  if (error) return <ErrorBox error={error} />;
  if (!f) return <Card><Skeleton rows={10} /></Card>;
  const manage = can("compliance.manage");
  const userList = Array.isArray(users) ? users : users?.items || [];
  return (
    <div>
      <Link to="/compliance/findings" className="mb-2 inline-flex items-center gap-1 text-sm text-brand-700 hover:underline dark:text-brand-300"><ArrowLeft className="h-4 w-4" />Findings</Link>
      <PageHeader title={`F-${f.id}: ${f.title}`} subtitle={<span className="flex flex-wrap items-center gap-2"><Risk risk={f.severity} /><ComplianceBadge status={f.status} />{f.overdue && <span className="text-xs font-medium text-red-600">Overdue</span>}</span>}
        actions={manage && <>
          <Button variant="outline" onClick={() => setEdit(true)}>Edit</Button>
          {f.allowed_transitions.filter((t) => t !== "accepted_risk" || can("compliance.approve")).map((t) => <Button key={t} variant={t === "accepted_risk" ? "outline" : "primary"} onClick={() => setMove(t)}>{LABEL[t]}</Button>)}
        </>} />
      {f.status === "accepted_risk" && <div className="mb-4"><Callout tone="warning" title="Risk accepted">{f.risk_acceptance.reason} — accepted by {f.risk_acceptance.accepted_by}, review by {f.risk_acceptance.review_by?.slice(0, 10)}.</Callout></div>}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Details" className="lg:col-span-2">
          <KeyValue items={[["Asset", f.asset], ["Control", f.control_ref || ""], ["Source", f.source.startsWith("automated") ? `Automated check (${f.source.split(":")[1]})` : "Manual"],
            ["Responsible owner", f.owner || ""], ["Department", f.owner_department], ["Target completion", f.due_date ? fmtDate(f.due_date) : ""], ["Created", `${fmtDate(f.created_at)} by ${f.created_by || "system"}`], ["Closed", fmtDate(f.closed_at)]]} />
          {(["description", "root_cause", "business_impact", "recommendation"] as const).map((k) => f[k] && (
            <div key={k} className="mt-4"><p className="text-xs font-medium uppercase tracking-wide text-slate-500">{k === "recommendation" ? "Recommended corrective action" : k.replace(/_/g, " ")}</p>
              <p className="mt-0.5 whitespace-pre-line text-sm">{f[k]}</p></div>))}
        </Card>
        <Card title="Lifecycle">
          <ol className="space-y-3 text-sm">{f.events.map((e, i) => (
            <li key={i} className="border-l-2 border-slate-200 pl-3 dark:border-slate-700"><p className="text-xs text-slate-500">{fmtDate(e.ts)} · {e.user || "system"}</p>
              <p>{e.from ? <><ComplianceBadge status={e.from} /> → </> : null}{e.to && <ComplianceBadge status={e.to} />}</p>{e.comment && <p className="mt-0.5 text-xs">{e.comment}</p>}</li>))}</ol>
          <p className="mt-4 text-xs text-slate-500">Open → Assigned → In progress → Pending verification → Closed (verified by someone other than the owner). Accepted risk requires an approver and a review date.</p>
        </Card>
      </div>
      <div className="mt-4"><EvidenceList findingId={f.id} compact /></div>
      {move && <MoveModal f={f} to={move} onClose={() => setMove(null)} onDone={() => qc.invalidateQueries({ queryKey: ["finding", id] })} />}
      {edit && <EditModal f={f} users={userList} onClose={() => setEdit(false)} onDone={() => qc.invalidateQueries({ queryKey: ["finding", id] })} />}
    </div>
  );
}

function MoveModal({ f, to, onClose, onDone }: { f: Detail; to: string; onClose: () => void; onDone: () => void }) {
  const [comment, setComment] = useState("");
  const [until, setUntil] = useState("");
  const m = useMutation({ mutationFn: () => api(`/api/compliance/findings/${f.id}/status`, { body: { to, comment, accepted_until: until ? `${until}T00:00:00` : null } }), onSuccess: () => { onDone(); onClose(); } });
  return (
    <Modal open onClose={onClose} title={LABEL[to]} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={m.isPending} onClick={() => m.mutate()}>{LABEL[to]}</Button></>}>
      <Field label={["closed", "accepted_risk", "open"].includes(to) ? "Comment (required)" : "Comment"}><textarea className="input" rows={3} value={comment} onChange={(e) => setComment(e.target.value)}
        placeholder={to === "closed" ? "How was the fix verified? Reference evidence." : to === "accepted_risk" ? "Business justification and compensating controls" : ""} /></Field>
      {to === "accepted_risk" && <Field label="Review risk acceptance by" required><input className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} /></Field>}
      {m.error && <ErrorBox error={m.error} />}
    </Modal>
  );
}

function EditModal({ f, users, onClose, onDone }: { f: Detail; users: { id: number; username: string }[]; onClose: () => void; onDone: () => void }) {
  const [v, setV] = useState({ title: f.title, severity: f.severity, asset: f.asset, description: f.description, root_cause: f.root_cause, business_impact: f.business_impact,
    recommendation: f.recommendation, owner_department: f.owner_department, owner_user_id: f.owner_user_id, due_date: f.due_date ? f.due_date.slice(0, 10) : "" });
  const m = useMutation({ mutationFn: () => api(`/api/compliance/findings/${f.id}`, { method: "PUT", body: { ...v, due_date: v.due_date ? `${v.due_date}T00:00:00` : null } }), onSuccess: () => { onDone(); onClose(); } });
  const set = (k: string, x: unknown) => setV((o) => ({ ...o, [k]: x }));
  return (
    <Modal open onClose={onClose} size="lg" title="Edit finding" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={m.isPending} onClick={() => m.mutate()}>Save</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Title"><input className="input" value={v.title} onChange={(e) => set("title", e.target.value)} /></Field>
        <Field label="Severity"><select className="input" value={v.severity} onChange={(e) => set("severity", e.target.value)}>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select></Field>
        <Field label="Responsible owner"><select className="input" value={v.owner_user_id ?? ""} onChange={(e) => set("owner_user_id", e.target.value ? Number(e.target.value) : null)}><option value="">—</option>{users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}</select></Field>
        <Field label="Department"><input className="input" value={v.owner_department} onChange={(e) => set("owner_department", e.target.value)} /></Field>
        <Field label="Target completion date"><input className="input" type="date" value={v.due_date} onChange={(e) => set("due_date", e.target.value)} /></Field>
        <Field label="Asset"><input className="input" value={v.asset} onChange={(e) => set("asset", e.target.value)} /></Field>
      </div>
      {(["description", "root_cause", "business_impact", "recommendation"] as const).map((k) => <Field key={k} label={k.replace(/_/g, " ")}><textarea className="input" rows={2} value={v[k]} onChange={(e) => set(k, e.target.value)} /></Field>)}
      {m.error && <ErrorBox error={m.error} />}
    </Modal>
  );
}

import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Archive, CheckCircle2, Code2, Eye, Pencil, Play, Plus, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { DevicePicker } from "../components/DevicePicker";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, RiskBadge, Skeleton, StatusBadge, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, fmtDate } from "../lib/format";
import type { Job } from "../lib/types";

type ParamDef = { name: string; label: string; type: string; required: boolean; default: unknown; choices: string[]; max_length: number; help: string };
type Script = {
  id: number; name: string; description: string; target: "windows" | "linux" | "network" | "fortigate"; target_label: string; category: string;
  mode: "read" | "change"; risk: "read" | "change" | "critical"; risk_ui: string; body: string; params: ParamDef[]; run_as_root: boolean;
  save_config: boolean; timeout_seconds: number; version: number; sha256: string; status: string; runnable: boolean; review_comment: string;
  created_by: string | null; updated_by: string | null; approved_by: string | null; approved_at: string | null; updated_at: string; can_review: boolean;
};
const TYPES = ["string", "int", "bool", "ipv4", "cidr", "hostname", "interface", "vlan", "choice"];
const TARGETS: { id: Script["target"]; label: string; hint: string; example: string }[] = [
  { id: "windows", label: "Windows — PowerShell", hint: "Parameters arrive as PowerShell variables ($name). Don't write param() — InfraPilot declares and binds them, so values can never change the script.",
    example: "# Example: restart a service and show its state\nRestart-Service -Name $service -Force\nGet-Service -Name $service | Format-List Name, Status, StartType" },
  { id: "linux", label: "Linux — shell (bash)", hint: "Parameters arrive as shell variables; always quote them: \"$name\". Tick 'Run with sudo' if it needs root.",
    example: "# Example: rotate a log and show disk usage\nset -euo pipefail\nlogrotate -f \"/etc/logrotate.d/$app\"\ndf -h /var/log" },
  { id: "network", label: "Switch / router — CLI", hint: "Configuration lines as you'd type them in config mode (or show commands in read-only mode). Insert values with {{name}}; lines starting with ! are comments.",
    example: "! Example: access port\ninterface {{port}}\n description {{description}}\n switchport mode access\n switchport access vlan {{vlan}}\n no shutdown" },
  { id: "fortigate", label: "FortiGate — CLI script", hint: "FortiOS CLI, uploaded and run as a configuration script. Insert values with {{name}}. FortiOS doesn't return CLI output, so the result is shown as a configuration diff.",
    example: "config firewall address\n    edit \"{{name}}\"\n        set subnet {{subnet}}\n        set comment \"{{comment}}\"\n    next\nend" },
];
const tgt = (id: string) => TARGETS.find((t) => t.id === id)!;
const statusTone: Record<string, "green" | "amber" | "red" | "gray"> = { approved: "green", pending: "amber", rejected: "red", retired: "gray" };

type Form = Omit<Script, "id" | "target_label" | "category" | "risk_ui" | "version" | "sha256" | "status" | "runnable" | "review_comment" | "created_by" | "updated_by" | "approved_by" | "approved_at" | "updated_at" | "can_review"> & { id?: number };
const EMPTY: Form = { name: "", description: "", target: "network", mode: "change", risk: "change", body: "", params: [], run_as_root: false, save_config: true, timeout_seconds: 300 };

function Editor({ initial, onClose }: { initial: Form; onClose: () => void }) {
  const [f, setF] = useState<Form>(initial);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient(); const toast = useToast();
  const t = tgt(f.target);
  const placeholders = useMemo(() => [...new Set([...f.body.matchAll(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g)].map((m) => m[1]))], [f.body]);
  const missing = (f.target === "network" || f.target === "fortigate") ? placeholders.filter((p) => !f.params.some((d) => d.name === p)) : [];
  const setParam = (i: number, patch: Partial<ParamDef>) => setF({ ...f, params: f.params.map((p, j) => (i === j ? { ...p, ...patch } : p)) });
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    const body = { ...f, risk: f.target === "network" && f.mode === "read" ? "read" : f.risk === "read" ? "change" : f.risk };
    delete (body as { id?: number }).id;
    try {
      await api(f.id ? `/api/scripts/${f.id}` : "/api/scripts", { method: f.id ? "PUT" : "POST", body });
      qc.invalidateQueries({ queryKey: ["scripts"] });
      toast({ tone: "success", title: f.id ? "Script saved — it needs review before it can run" : "Script created — ask a reviewer to approve it" });
      onClose();
    } catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  return (
    <Modal open size="xl" onClose={onClose} title={f.id ? `Edit script` : "New script"}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="scr" type="submit" loading={busy}>Save for review</Button></>}>
      <form id="scr" onSubmit={submit} className="space-y-4">
        <ErrorBox error={err} />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field label="Name" required><input className="input" required minLength={2} maxLength={150} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Set access port VLAN" /></Field>
          <Field label="Runs on"><select className="input" value={f.target} disabled={!!f.id && false} onChange={(e) => setF({ ...f, target: e.target.value as Script["target"], body: f.body || "" })}>
            {TARGETS.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}</select></Field>
        </div>
        <Field label="Description" hint="What it does, when to use it, and how to undo it — reviewers and operators read this."><textarea className="input" rows={2} maxLength={1000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {f.target === "network" && <Field label="Mode"><select className="input" value={f.mode} onChange={(e) => setF({ ...f, mode: e.target.value as Form["mode"] })}>
            <option value="change">Configuration (changes)</option><option value="read">Show commands (read-only)</option></select></Field>}
          {!(f.target === "network" && f.mode === "read") && <Field label="Risk" hint="Critical needs approval for every run"><select className="input" value={f.risk === "read" ? "change" : f.risk} onChange={(e) => setF({ ...f, risk: e.target.value as Form["risk"] })}>
            <option value="change">Medium (change)</option><option value="critical">Critical</option></select></Field>}
          <Field label="Timeout (seconds)"><input className="input" type="number" min={10} max={3600} value={f.timeout_seconds} onChange={(e) => setF({ ...f, timeout_seconds: Number(e.target.value) })} /></Field>
          {f.target === "linux" && <label className="mt-6 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.run_as_root} onChange={(e) => setF({ ...f, run_as_root: e.target.checked })} />Run with sudo</label>}
          {f.target === "network" && f.mode === "change" && <label className="mt-6 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.save_config} onChange={(e) => setF({ ...f, save_config: e.target.checked })} />Save config afterwards</label>}
        </div>
        <Field label="Script" required hint={t.hint}>
          <textarea className="input min-h-[16rem] font-mono text-xs leading-5" spellCheck={false} required value={f.body} placeholder={t.example}
            onChange={(e) => setF({ ...f, body: e.target.value })} />
        </Field>
        {!f.body && <Button type="button" size="sm" variant="ghost" icon={<Code2 className="h-4 w-4" />} onClick={() => setF({ ...f, body: t.example.replace(/^[#!] Example[^\n]*\n/, "") })}>Insert example</Button>}
        <div>
          <div className="mb-2 flex items-center justify-between">
            <p className="label mb-0">Parameters (asked when the script runs)</p>
            <Button type="button" size="sm" variant="outline" icon={<Plus className="h-4 w-4" />} onClick={() => setF({ ...f, params: [...f.params, { name: missing[0] || "", label: "", type: "string", required: true, default: "", choices: [], max_length: 200, help: "" }] })}>Add parameter</Button>
          </div>
          {missing.length > 0 && <p className="mb-2 text-xs text-amber-700 dark:text-amber-400">Placeholders without a parameter: {missing.map((m) => `{{${m}}}`).join(", ")}</p>}
          {f.params.length === 0 ? <p className="text-xs text-slate-500">No parameters — the script always runs the same way.</p> : (
            <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-800">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 dark:bg-slate-900"><tr><th className="th">Name</th><th className="th">Label</th><th className="th">Type</th><th className="th">Choices / default</th><th className="th">Required</th><th className="th" /></tr></thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{f.params.map((p, i) => (
                  <tr key={i}>
                    <td className="td"><input className="input w-32 py-1 font-mono text-xs" value={p.name} pattern="[a-z][a-z0-9_]{0,30}" title="lower-case letters, digits, _" onChange={(e) => setParam(i, { name: e.target.value })} aria-label="Parameter name" /></td>
                    <td className="td"><input className="input w-40 py-1 text-xs" value={p.label} onChange={(e) => setParam(i, { label: e.target.value })} aria-label="Label" /></td>
                    <td className="td"><select className="input w-28 py-1 text-xs" value={p.type} onChange={(e) => setParam(i, { type: e.target.value })} aria-label="Type">{TYPES.map((x) => <option key={x}>{x}</option>)}</select></td>
                    <td className="td">{p.type === "choice"
                      ? <input className="input w-48 py-1 text-xs" placeholder="comma,separated" value={p.choices.join(",")} onChange={(e) => setParam(i, { choices: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} aria-label="Choices" />
                      : <input className="input w-48 py-1 text-xs" placeholder="default (optional)" value={String(p.default ?? "")} onChange={(e) => setParam(i, { default: e.target.value })} aria-label="Default" />}</td>
                    <td className="td"><input type="checkbox" checked={p.required} onChange={(e) => setParam(i, { required: e.target.checked })} aria-label="Required" /></td>
                    <td className="td"><Button type="button" size="sm" variant="ghost" aria-label="Remove parameter" icon={<Trash2 className="h-4 w-4" />} onClick={() => setF({ ...f, params: f.params.filter((_, j) => j !== i) })} /></td>
                  </tr>))}</tbody>
              </table>
            </div>
          )}
          <p className="mt-1.5 text-xs text-slate-500">Values are checked by type and can never contain line breaks, so they cannot add commands. Use <b>choice</b> to limit to a fixed list.</p>
        </div>
        <Callout tone="info" title="Review before use">After saving, someone with the reviewer permission (not you) must approve this exact version. Any later change to the script or its parameters needs approval again.</Callout>
      </form>
    </Modal>
  );
}

function ValueInput({ d, value, onChange }: { d: ParamDef; value: unknown; onChange: (v: unknown) => void }) {
  if (d.type === "bool") return <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />{d.label || d.name}</label>;
  const input = d.type === "choice"
    ? <select id={`v-${d.name}`} className="input" value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}><option value="">Choose…</option>{d.choices.map((c) => <option key={c}>{c}</option>)}</select>
    : <input id={`v-${d.name}`} className="input" type={d.type === "int" || d.type === "vlan" ? "number" : "text"} value={String(value ?? "")} maxLength={d.max_length}
      placeholder={{ ipv4: "10.0.0.5", cidr: "10.0.0.0/24", interface: "GigabitEthernet1/0/5", hostname: "srv01", vlan: "1-4094" }[d.type] || ""}
      onChange={(e) => onChange(e.target.value)} />;
  return <Field label={d.label || d.name} htmlFor={`v-${d.name}`} required={d.required} hint={d.help || d.type}>{input}</Field>;
}

function RunDialog({ s, onClose }: { s: Script; onClose: () => void }) {
  const nav = useNavigate();
  const [ids, setIds] = useState<number[]>([]);
  const [vals, setVals] = useState<Record<string, unknown>>(() => Object.fromEntries(s.params.map((d) => [d.name, d.default ?? (d.type === "bool" ? false : "")])));
  const [reason, setReason] = useState("");
  const [check, setCheck] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const doPreview = async () => {
    setErr(null);
    try { setPreview((await api<{ rendered: string }>(`/api/scripts/${s.id}/preview`, { body: { values: vals } })).rendered); } catch (e) { setErr(e); setPreview(null); }
  };
  const run = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    try { const j = await api<Job>(`/api/scripts/${s.id}/run`, { body: { device_ids: ids, values: vals, reason, check_mode: check } }); onClose(); nav(`/jobs/${j.id}`); }
    catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  const platforms = s.target === "fortigate" ? ["fortigate"] : undefined;
  return (
    <Modal open size="lg" onClose={onClose} title={<span className="flex items-center gap-2">Run “{s.name}” <RiskBadge risk={s.risk_ui} /></span>}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button variant="outline" onClick={doPreview}>Preview</Button>
        <Button form="run" type="submit" loading={busy} disabled={!ids.length}>{check ? "Dry run" : s.risk === "read" ? "Run" : "Submit change"}</Button></>}>
      <form id="run" onSubmit={run} className="space-y-4">
        <ErrorBox error={err} />
        {s.description && <p className="text-sm text-slate-600 dark:text-slate-300">{s.description}</p>}
        <Field label="Devices" required hint={`Only ${s.target_label} devices are listed.`}><DevicePicker value={ids} onChange={setIds} category={s.category} platforms={platforms} /></Field>
        {s.params.length > 0 && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">{s.params.map((d) => <ValueInput key={d.name} d={d} value={vals[d.name]} onChange={(v) => { setVals({ ...vals, [d.name]: v }); setPreview(null); }} />)}</div>}
        {preview !== null && <div><p className="label">Exactly what will run</p><pre className="code max-h-72 overflow-auto">{preview}</pre></div>}
        {s.risk !== "read" && <>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={check} onChange={(e) => setCheck(e.target.checked)} />Dry run — show what would be sent without changing anything</label>
          <Field label="Reason / change ticket" hint="Required when an approval policy applies"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="CHG-1234 move printer to VLAN 20" /></Field>
        </>}
      </form>
    </Modal>
  );
}

function Detail({ s, onEdit, onRun }: { s: Script; onEdit: () => void; onRun: () => void }) {
  const { can } = useAuth(); const qc = useQueryClient(); const toast = useToast(); const confirm = useConfirm();
  const [comment, setComment] = useState("");
  const [err, setErr] = useState<unknown>(null);
  const { data: runs } = useQuery({ queryKey: ["script-runs", s.id], queryFn: () => api<Job[]>(`/api/scripts/${s.id}/runs`) });
  const review = async (approve: boolean) => {
    setErr(null);
    try { await api(`/api/scripts/${s.id}/review`, { body: { approve, comment } }); qc.invalidateQueries({ queryKey: ["scripts"] }); toast({ tone: approve ? "success" : "info", title: approve ? "Script approved" : "Script rejected" }); setComment(""); }
    catch (e) { setErr(e); }
  };
  return (
    <div className="space-y-4">
      <Card title={<span className="flex flex-wrap items-center gap-2">{s.name}<Badge tone={statusTone[s.status]}>{s.status}</Badge><RiskBadge risk={s.risk_ui} /><Badge>v{s.version}</Badge></span>}
        actions={<div className="flex gap-2">
          {can("scripts.manage") && s.status !== "retired" && <Button size="sm" variant="outline" icon={<Pencil className="h-4 w-4" />} onClick={onEdit}>Edit</Button>}
          {can("automation.run") && <Button size="sm" icon={<Play className="h-4 w-4" />} disabled={!s.runnable} title={s.runnable ? "" : "Needs approval first"} onClick={onRun}>Run</Button>}
        </div>}>
        <p className="text-sm text-slate-500">{s.target_label}{s.target === "network" ? ` · ${s.mode === "read" ? "show commands" : "configuration"}${s.save_config ? " · saves config" : ""}` : ""}{s.run_as_root ? " · sudo" : ""} · timeout {s.timeout_seconds}s</p>
        {s.description && <p className="mt-2 whitespace-pre-line text-sm">{s.description}</p>}
        <pre className="code mt-3 max-h-96 overflow-auto">{s.body.split("\n").map((ln, i) => <div key={i}><span className="mr-3 inline-block w-6 select-none text-right text-slate-500">{i + 1}</span>{ln}</div>)}</pre>
        {s.params.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{s.params.map((p) => <Badge key={p.name} tone="blue">{p.name}: {p.type}{p.required ? "" : " (optional)"}</Badge>)}</div>}
        <p className="mt-3 text-xs text-slate-500">Written by {s.created_by}, last edited by {s.updated_by} {ago(s.updated_at)}{s.approved_by && <> · approved by <b>{s.approved_by}</b> {fmtDate(s.approved_at)}</>}{s.review_comment && <> · “{s.review_comment}”</>}</p>
      </Card>
      {s.can_review && (
        <Card title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" />Review version {s.version}</span>}>
          <ErrorBox error={err} />
          <p className="mb-2 text-sm text-slate-500">Check what the script does on every device it could run on, that parameters can't be misused, and that the description explains how to undo it.</p>
          <textarea className="input" rows={2} placeholder="Review comment (required for critical scripts)" value={comment} onChange={(e) => setComment(e.target.value)} />
          <div className="mt-2 flex gap-2">
            <Button size="sm" icon={<CheckCircle2 className="h-4 w-4" />} onClick={() => review(true)}>Approve</Button>
            <Button size="sm" variant="outline" icon={<XCircle className="h-4 w-4" />} onClick={() => review(false)}>Reject</Button>
          </div>
        </Card>
      )}
      {s.status === "pending" && !s.can_review && <Callout tone="warning" title="Waiting for review">A user with the script reviewer permission, other than {s.updated_by}, must approve this version before it can run.</Callout>}
      <Card title="Recent runs" padded={false}>
        {!runs?.length ? <EmptyState title="Not run yet" /> : (
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">{runs.map((j) => (
            <li key={j.id} className="flex items-center gap-3 px-4 py-2"><Link to={`/jobs/${j.id}`} className="text-brand-600 hover:underline">#{j.id}</Link>
              <span className="min-w-0 flex-1 truncate">{j.requested_by} · {j.device_count} device(s){j.check_mode ? " · dry run" : ""}</span><StatusBadge status={j.status} /><span className="w-16 text-right text-xs text-slate-500">{ago(j.created_at)}</span></li>))}</ul>
        )}
      </Card>
      {can("scripts.manage") && s.status !== "retired" && (
        <Button size="sm" variant="ghost" icon={<Archive className="h-4 w-4" />} onClick={async () => {
          if (await confirm({ title: `Retire “${s.name}”?`, message: "It stays in the library for audit but can no longer run.", confirmLabel: "Retire", danger: true })) {
            await api(`/api/scripts/${s.id}/retire`, { method: "POST" }); qc.invalidateQueries({ queryKey: ["scripts"] });
          }
        }}>Retire script</Button>
      )}
    </div>
  );
}

export default function Scripts() {
  const { can } = useAuth();
  const { data, isLoading, error } = useQuery({ queryKey: ["scripts"], queryFn: () => api<Script[]>("/api/scripts") });
  const [sel, setSel] = useState<number | null>(null);
  const [edit, setEdit] = useState<Form | null>(null);
  const [run, setRun] = useState<Script | null>(null);
  const [filter, setFilter] = useState("");
  const list = (data || []).filter((s) => !filter || `${s.name} ${s.target_label} ${s.status}`.toLowerCase().includes(filter.toLowerCase()));
  const cur = data?.find((s) => s.id === sel) || list[0];
  const pendingReview = (data || []).filter((s) => s.can_review && s.status === "pending").length;
  return (
    <div>
      <PageHeader title="Scripts" subtitle="Reviewed PowerShell, shell, switch and FortiGate CLI scripts. Written once, approved by a second person, then run on any number of devices with approval policies and audit."
        actions={can("scripts.manage") && <Button icon={<Plus className="h-4 w-4" />} onClick={() => setEdit({ ...EMPTY })}>New script</Button>} />
      <ErrorBox error={error} />
      {pendingReview > 0 && <div className="mb-4"><Callout tone="warning" title={`${pendingReview} script(s) waiting for your review`}>Open them below and approve or reject.</Callout></div>}
      {isLoading ? <Card><Skeleton /></Card> : !data?.length ? (
        <Card><EmptyState icon={<Code2 className="h-6 w-6" />} title="No scripts yet"
          hint="Examples: set an access port VLAN on Cisco switches, add a FortiGate address object, clear a Windows print queue, rotate logs on Linux servers."
          action={can("scripts.manage") && <Button onClick={() => setEdit({ ...EMPTY })}>Write the first script</Button>} /></Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[20rem_1fr]">
          <Card padded={false}>
            <div className="border-b border-slate-200 p-2 dark:border-slate-800"><input className="input py-1.5 text-xs" placeholder="Filter scripts…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter scripts" /></div>
            <ul className="max-h-[70vh] divide-y divide-slate-100 overflow-y-auto dark:divide-slate-800">{list.map((s) => (
              <li key={s.id}><button onClick={() => setSel(s.id)} className={clsx("w-full px-3 py-2.5 text-left", cur?.id === s.id ? "bg-brand-50 dark:bg-brand-900/30" : "hover:bg-slate-50 dark:hover:bg-slate-800/50")}>
                <span className="flex items-center justify-between gap-2"><span className="truncate text-sm font-medium">{s.name}</span><Badge tone={statusTone[s.status]}>{s.status}</Badge></span>
                <span className="mt-0.5 block text-xs text-slate-500">{s.target_label} · v{s.version}{s.can_review && s.status === "pending" ? " · needs your review" : ""}</span>
              </button></li>))}</ul>
          </Card>
          {cur ? <Detail key={cur.id} s={cur} onRun={() => setRun(cur)} onEdit={() => setEdit({ id: cur.id, name: cur.name, description: cur.description, target: cur.target, mode: cur.mode, risk: cur.risk,
            body: cur.body, params: cur.params, run_as_root: cur.run_as_root, save_config: cur.save_config, timeout_seconds: cur.timeout_seconds })} /> : <Card><EmptyState icon={<Eye className="h-6 w-6" />} title="No script matches the filter" /></Card>}
        </div>
      )}
      {edit && <Editor initial={edit} onClose={() => setEdit(null)} />}
      {run && <RunDialog s={run} onClose={() => setRun(null)} />}
    </div>
  );
}

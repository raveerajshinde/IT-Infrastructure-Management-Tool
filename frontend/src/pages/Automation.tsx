import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Plus, Terminal, Trash2, Workflow } from "lucide-react";
import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { DevicePicker } from "../components/DevicePicker";
import { SchemaForm, cleanValues, initialValues } from "../components/SchemaForm";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, RiskBadge, Skeleton, Tabs, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Job, Operation, Template } from "../lib/types";

function RunTemplate({ t, onClose }: { t: Template; onClose: () => void }) {
  const { data: ops } = useQuery({ queryKey: ["operations"], queryFn: () => api<Operation[]>("/api/operations") });
  const op = ops?.find((o) => o.id === (t.kind === "ansible" ? "automation.ansible" : t.operation_id));
  const [ids, setIds] = useState<number[]>([]);
  const [values, setValues] = useState<Record<string, unknown> | null>(null);
  const [vars, setVars] = useState(Object.entries(t.default_params || {}).map(([k, v]) => `${k}=${v}`).join("\n"));
  // Only operations that implement dry-run can run in check mode; read-only templates never need it.
  const canCheck = t.supports_check_mode && t.risk !== "low";
  const [check, setCheck] = useState(canCheck);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<unknown>(null);
  const nav = useNavigate(); const toast = useToast();
  const vals = values ?? (op && t.kind === "operation" ? initialValues(op.schema, t.default_params) : {});
  const run = useMutation({
    mutationFn: () => {
      const params = t.kind === "ansible"
        ? Object.fromEntries(vars.split("\n").filter((l) => l.includes("=")).map((l) => { const [k, ...r] = l.split("="); const v = r.join("=").trim();
          return [k.trim(), v === "true" ? true : v === "false" ? false : /^\d+$/.test(v) ? Number(v) : v]; }))
        : cleanValues(op!.schema, vals);
      return api<Job>(`/api/templates/${t.id}/run`, { body: { device_ids: ids, params, check_mode: check && canCheck, reason } });
    },
    onSuccess: (j) => { toast({ tone: "success", title: j.status === "pending_approval" ? "Submitted for approval" : "Job queued" }); onClose(); nav(`/jobs/${j.id}`); },
    onError: setErr,
  });
  return (
    <Modal open onClose={onClose} size="lg" title={<span className="flex items-center gap-2">{t.name}<RiskBadge risk={t.risk} /></span>}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button disabled={!ids.length} loading={run.isPending} icon={<Play className="h-4 w-4" />} onClick={() => run.mutate()}>
        {check && canCheck ? "Run in check mode" : "Run"}</Button></>}>
      <div className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">{t.description}</p>
        <ErrorBox error={err} />
        <Field label="Target devices" required hint={`Only ${t.category} devices are listed.`}><DevicePicker value={ids} onChange={setIds} category={t.category} /></Field>
        {t.kind === "operation" && op && <SchemaForm schema={op.schema} values={vals} onChange={setValues} />}
        {t.kind === "ansible" && <Field label={`Variables for ${t.playbook}`} hint="One key=value per line. Connection variables (ansible_*) are managed by InfraPilot and cannot be set.">
          <textarea className="input font-mono" rows={4} value={vars} onChange={(e) => setVars(e.target.value)} /></Field>}
        {canCheck && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={check} onChange={(e) => setCheck(e.target.checked)} /> Check mode (dry-run — no changes)</label>}
        {t.risk === "low" && <Callout tone="info">Read-only: this template collects information and changes nothing on the devices.</Callout>}
        {!check && t.risk !== "low" && <><Callout tone="warning">Changes on production devices require approval. Provide a reason or change ticket.</Callout>
          <Field label="Reason / change ticket"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></Field></>}
      </div>
    </Modal>
  );
}

function NewTemplate({ onClose }: { onClose: () => void }) {
  const { data: ops } = useQuery({ queryKey: ["operations"], queryFn: () => api<Operation[]>("/api/operations") });
  const { data: pbs } = useQuery({ queryKey: ["playbooks"], queryFn: () => api<{ name: string; description: string }[]>("/api/playbooks") });
  const [f, setF] = useState({ name: "", description: "", kind: "operation", operation_id: "", playbook: "" });
  const [err, setErr] = useState<unknown>(null);
  const qc = useQueryClient();
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      await api("/api/templates", { body: { ...f, operation_id: f.kind === "operation" ? f.operation_id : null, playbook: f.kind === "ansible" ? f.playbook : null } });
      qc.invalidateQueries({ queryKey: ["templates"] }); onClose();
    } catch (e2) { setErr(e2); }
  };
  return (
    <Modal open onClose={onClose} title="New job template" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="nt" type="submit">Create</Button></>}>
      <form id="nt" onSubmit={submit} className="space-y-3">
        <ErrorBox error={err} />
        <Field label="Name" required><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Description"><input className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <Field label="Type"><select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="operation">Catalog operation</option><option value="ansible">Ansible playbook</option></select></Field>
        {f.kind === "operation" ? <Field label="Operation" required><select className="input" required value={f.operation_id} onChange={(e) => setF({ ...f, operation_id: e.target.value })}>
          <option value="">Select…</option>{(ops || []).filter((o) => o.id !== "automation.ansible").map((o) => <option key={o.id} value={o.id}>{o.family} · {o.name}</option>)}</select></Field>
          : <Field label="Playbook" required hint="Only playbooks shipped in automation/playbooks can be used."><select className="input" required value={f.playbook} onChange={(e) => setF({ ...f, playbook: e.target.value })}>
            <option value="">Select…</option>{(pbs || []).map((p) => <option key={p.name} value={p.name}>{p.name} — {p.description}</option>)}</select></Field>}
      </form>
    </Modal>
  );
}

function Commands() {
  const { data } = useQuery({ queryKey: ["commands"], queryFn: () => api<{ id: number; name: string; description: string; command: string; risk: string; sudo: boolean }[]>("/api/approved-commands") });
  return (
    <Card title="Approved maintenance commands (Linux)" padded={false}>
      <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">Only these commands can be run through the “Run approved command” operation. They execute as fixed argument lists (no shell interpolation of user input) and are defined server-side, so adding one goes through code review and change control rather than the UI.</p>
      <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Name</th><th className="th">Command</th><th className="th">Privilege</th><th className="th">Risk</th></tr></thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{(data || []).map((c) => (
          <tr key={c.id}><td className="td"><p className="font-mono text-sm font-medium">{c.name}</p><p className="text-xs text-slate-500">{c.description}</p></td><td className="td font-mono text-xs">{c.command}</td>
            <td className="td text-xs">{c.sudo ? "sudo" : "user"}</td><td className="td"><RiskBadge risk={c.risk} /></td></tr>))}</tbody></table>
    </Card>
  );
}

export default function Automation() {
  const { can } = useAuth();
  const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const [tab, setTab] = useState<"templates" | "commands">("templates");
  const [run, setRun] = useState<Template | null>(null);
  const [create, setCreate] = useState(false);
  const { data, isLoading, error } = useQuery({ queryKey: ["templates"], queryFn: () => api<Template[]>("/api/templates") });
  return (
    <div>
      <PageHeader title="Automation" subtitle="Reusable job templates and Ansible playbooks for bulk operations. All runs go through validation, approval and audit."
        actions={can("templates.manage") && tab === "templates" && <Button icon={<Plus className="h-4 w-4" />} onClick={() => setCreate(true)}>New template</Button>} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "templates", label: "Job templates" }, { id: "commands", label: "Approved commands" }]} />
      {tab === "templates" && (error ? <ErrorBox error={error} /> : isLoading ? <Skeleton /> : !data?.length ? <EmptyState title="No templates" /> : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {data.map((t) => (
            <Card key={t.id}>
              <div className="flex h-full flex-col">
                <div className="mb-2 flex items-start justify-between gap-2">
                  <p className="flex items-center gap-2 font-medium">{t.kind === "ansible" ? <Workflow className="h-4 w-4 text-brand-600" /> : <Terminal className="h-4 w-4 text-brand-600" />}{t.name}</p>
                  <RiskBadge risk={t.risk} />
                </div>
                <p className="flex-1 text-sm text-slate-500">{t.description}</p>
                <div className="mt-3 flex items-center justify-between">
                  <span className="font-mono text-[11px] text-slate-400">{t.kind === "ansible" ? t.playbook : t.operation_id}{t.is_builtin && <Badge className="ml-2">built-in</Badge>}</span>
                  <div className="flex gap-1">
                    {can("templates.manage") && !t.is_builtin && <Button size="sm" variant="ghost" aria-label="Delete template" onClick={async () => {
                      if (await confirm({ title: "Delete template?", message: t.name, danger: true })) {
                        try { await api(`/api/templates/${t.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["templates"] }); } catch (e) { toast({ tone: "error", title: "Cannot delete", body: (e as Error).message }); }
                      }
                    }}><Trash2 className="h-4 w-4" /></Button>}
                    <Button size="sm" icon={<Play className="h-3.5 w-3.5" />} onClick={() => setRun(t)}>Run</Button>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ))}
      {tab === "commands" && <Commands />}
      {run && <RunTemplate t={run} onClose={() => setRun(null)} />}
      {create && <NewTemplate onClose={() => setCreate(false)} />}
    </div>
  );
}

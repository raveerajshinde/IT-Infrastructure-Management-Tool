import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plug, Plus, RefreshCw, Trash2 } from "lucide-react";
import { FormEvent, useState } from "react";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { ago } from "../lib/format";
import type { Credential } from "../lib/types";

type Integration = { id: number; kind: string; name: string; base_url: string; credential_id: number | null; enabled: boolean; settings: { verify_tls?: boolean };
  last_sync_at: string | null; last_status: string | null };

export default function Integrations() {
  const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const { data } = useQuery({ queryKey: ["integrations"], queryFn: () => api<Integration[]>("/api/integrations") });
  const { data: creds } = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/api/credentials") });
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ kind: "zabbix", name: "", base_url: "", credential_id: "", verify_tls: true });
  const [err, setErr] = useState<unknown>(null);
  const [created, setCreated] = useState<{ webhook_secret: string; webhook_url: string } | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      const r = await api<Integration & { webhook_secret?: string; webhook_url?: string }>("/api/integrations", { body: { kind: f.kind, name: f.name, base_url: f.kind === "webhook" ? null : f.base_url,
        credential_id: f.credential_id ? Number(f.credential_id) : null, settings: { verify_tls: f.verify_tls } } });
      qc.invalidateQueries({ queryKey: ["integrations"] }); setOpen(false);
      if (r.webhook_secret) setCreated({ webhook_secret: r.webhook_secret, webhook_url: r.webhook_url! });
    } catch (e2) { setErr(e2); }
  };
  const sync = async (i: Integration) => {
    setBusy(i.id);
    try { const r = await api<{ message: string }>(`/api/integrations/${i.id}/sync`, { method: "POST" }); toast({ tone: "success", title: "Sync complete", body: r.message }); }
    catch (e) { toast({ tone: "error", title: "Sync failed", body: (e as Error).message }); }
    finally { setBusy(null); qc.invalidateQueries({ queryKey: ["integrations"] }); }
  };
  return (
    <div>
      <PageHeader title="Integrations" subtitle="Import problems/alerts from Zabbix and LibreNMS (polled every 5 minutes). Problems become alerts here and resolve automatically when they clear."
        actions={<Button icon={<Plus className="h-4 w-4" />} onClick={() => setOpen(true)}>Add integration</Button>} />
      {created && <div className="mb-4"><Callout tone="warning" title="Webhook created — copy the secret now, it will not be shown again">
        <p className="mt-1">URL: <span className="select-all font-mono">{created.webhook_url}</span></p>
        <p>Secret: <span className="select-all font-mono">{created.webhook_secret}</span></p>
        <p className="mt-1 text-xs">Sign the raw JSON body with HMAC-SHA256 and send header <span className="font-mono">X-InfraPilot-Signature: sha256=&lt;hex&gt;</span>.</p>
        <Button size="sm" variant="outline" className="mt-2" onClick={() => setCreated(null)}>I have stored it</Button></Callout></div>}
      <Card padded={false}>
        {!data?.length ? <EmptyState icon={<Plug className="h-6 w-6" />} title="No integrations configured" /> : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <div><p className="flex items-center gap-2 font-medium">{i.name}<Badge tone="blue">{i.kind}</Badge>{!i.enabled && <Badge>disabled</Badge>}</p>
                <p className="text-xs text-slate-500">{i.base_url || "inbound webhook"} · last sync {ago(i.last_sync_at)}</p>
                {i.last_status && <p className={`text-xs ${i.last_status.startsWith("ERROR") ? "text-red-600" : "text-emerald-600"}`}>{i.last_status}</p>}</div>
              <div className="flex gap-2">
                {i.kind !== "webhook" && <Button size="sm" variant="outline" loading={busy === i.id} icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={() => sync(i)}>Test & sync now</Button>}
                <Button size="sm" variant="ghost" aria-label="Delete integration" onClick={async () => {
                  if (await confirm({ title: "Delete integration?", message: i.name, danger: true })) { await api(`/api/integrations/${i.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["integrations"] }); }
                }}><Trash2 className="h-4 w-4" /></Button>
              </div>
            </li>))}</ul>)}
      </Card>
      <Modal open={open} onClose={() => setOpen(false)} title="Add integration" footer={<><Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button form="if" type="submit">Create</Button></>}>
        <form id="if" onSubmit={submit} className="space-y-3"><ErrorBox error={err} />
          <Field label="Type"><select className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
            <option value="zabbix">Zabbix (API token, 5.4+)</option><option value="librenms">LibreNMS (API token)</option></select></Field>
          <Field label="Name" required><input className="input" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          {f.kind !== "webhook" && <>
            <Field label="Base URL" required hint={f.kind === "zabbix" ? "e.g. https://zabbix.corp.local/zabbix" : "e.g. https://librenms.corp.local"}><input className="input" required type="url" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} /></Field>
            <Field label="API token credential" required><select className="input" required value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: e.target.value })}>
              <option value="">Select…</option>{(creds || []).filter((c) => c.kind === "api_token").map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.verify_tls} onChange={(e) => setF({ ...f, verify_tls: e.target.checked })} /> Verify TLS certificate</label>
          </>}
        </form>
      </Modal>
    </div>
  );
}

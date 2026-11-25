import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, RotateCw, Trash2 } from "lucide-react";
import { FormEvent, useState } from "react";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, Skeleton, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";

const OPTION_LABEL: Record<string, string> = {
  "use_ssl:": "Automatic — from the device's port (5985 HTTP / 5986 HTTPS)", "use_ssl:true": "Always HTTPS", "use_ssl:false": "Always HTTP (message-encrypted)",
};
import type { Credential } from "../lib/types";

const KINDS: Record<string, { label: string; user: string | null; fields: { k: string; label: string; textarea?: boolean; optional?: boolean; select?: string[] }[]; hint: string }> = {
  password: { label: "Username + password (SSH / CLI / API)", user: "Username", hint: "Linux SSH, network CLI, Sophos, MikroTik, vCenter.",
    fields: [{ k: "password", label: "Password" }, { k: "enable_secret", label: "Enable secret (Cisco, optional)", optional: true }] },
  winrm: { label: "Windows (WinRM/PSRP)", user: "Username (DOMAIN\\user or user@domain)", hint: "Use a dedicated service account with only the rights it needs. HTTPS (5986) is strongly recommended.",
    fields: [{ k: "password", label: "Password" }, { k: "transport", label: "Authentication", select: ["negotiate", "kerberos", "ntlm", "credssp"] },
      { k: "use_ssl", label: "WinRM protocol", select: ["", "true", "false"] }] },
  ssh_key: { label: "SSH private key", user: "Username", hint: "OpenSSH or PEM format. Ed25519 recommended.",
    fields: [{ k: "private_key", label: "Private key", textarea: true }, { k: "passphrase", label: "Key passphrase", optional: true },
      { k: "host_key_policy", label: "Unknown SSH host keys", select: ["tofu", "reject"] }] },
  api_token: { label: "API token", user: "Token ID / user (Proxmox: user@realm!tokenid)", hint: "FortiGate REST API admin token, Proxmox API token, Zabbix/LibreNMS token.", fields: [{ k: "token", label: "Token" }] },
  snmpv3: { label: "SNMPv3 (authPriv)", user: "Security name", hint: "Only authPriv is supported. Used for monitoring.",
    fields: [{ k: "auth_protocol", label: "Auth protocol", select: ["SHA", "SHA256", "SHA512", "MD5"] }, { k: "auth_key", label: "Auth passphrase" },
      { k: "priv_protocol", label: "Privacy protocol", select: ["AES", "AES256", "DES"] }, { k: "priv_key", label: "Privacy passphrase" }] },
};

function CredForm({ cred, onClose }: { cred?: Credential; onClose: () => void }) {
  const [kind, setKind] = useState(cred?.kind || "password");
  const [name, setName] = useState(cred?.name || ""); const [username, setUsername] = useState(cred?.username || "");
  const [description, setDescription] = useState(cred?.description || "");
  const [secret, setSecret] = useState<Record<string, string>>({ auth_protocol: "SHA", priv_protocol: "AES" });
  const [err, setErr] = useState<unknown>(null); const [busy, setBusy] = useState(false);
  const qc = useQueryClient(); const toast = useToast();
  const spec = KINDS[kind];
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    const clean = Object.fromEntries(Object.entries(secret).filter(([k, v]) => v && spec.fields.some((f) => f.k === k)));
    try {
      if (cred) await api(`/api/credentials/${cred.id}`, { method: "PATCH", body: { username, description, secret: Object.keys(clean).length > (kind === "snmpv3" ? 2 : 0) ? clean : null } });
      else await api("/api/credentials", { body: { name, kind, username: username || null, description, secret: clean } });
      qc.invalidateQueries({ queryKey: ["credentials"] }); toast({ tone: "success", title: cred ? "Credential updated" : "Credential stored", body: "The secret is encrypted in the vault and will never be shown again." }); onClose();
    } catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title={cred ? `Rotate “${cred.name}”` : "Add credential"} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="cf" type="submit" loading={busy}>Save</Button></>}>
      <form id="cf" onSubmit={submit} className="space-y-3" autoComplete="off">
        <ErrorBox error={err} />
        <Callout>Secrets are encrypted with AES-256-GCM before storage, are never returned by the API and are never written to logs.</Callout>
        {!cred && <Field label="Name" required><input className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. linux-svc-ansible" /></Field>}
        {!cred && <Field label="Kind" hint={spec.hint}><select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}</select></Field>}
        {spec.user && <Field label={spec.user}><input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" /></Field>}
        {spec.fields.map((f) => (
          <Field key={f.k} label={f.label + (cred ? " (leave blank to keep)" : "")} required={!f.optional && !cred && !f.select}>
            {f.select ? <select className="input" value={secret[f.k] || f.select[0]} onChange={(e) => setSecret({ ...secret, [f.k]: e.target.value })}>{f.select.map((o) => <option key={o} value={o}>{OPTION_LABEL[`${f.k}:${o}`] ?? o}</option>)}</select>
              : f.textarea ? <textarea className="input font-mono text-xs" rows={6} value={secret[f.k] || ""} onChange={(e) => setSecret({ ...secret, [f.k]: e.target.value })} spellCheck={false} />
                : <input type="password" className="input" autoComplete="new-password" value={secret[f.k] || ""} onChange={(e) => setSecret({ ...secret, [f.k]: e.target.value })} />}
          </Field>
        ))}
        <Field label="Description"><input className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      </form>
    </Modal>
  );
}

export default function Credentials() {
  const { can } = useAuth(); const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const [form, setForm] = useState<Credential | null | undefined>(undefined);
  const { data, isLoading, error } = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/api/credentials") });
  return (
    <div>
      <PageHeader title="Credentials vault" subtitle="Device and integration credentials. Only metadata is ever displayed."
        actions={can("credentials.manage") && <Button icon={<Plus className="h-4 w-4" />} onClick={() => setForm(null)}>Add credential</Button>} />
      <Card padded={false}>
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading ? <Skeleton /> : !data?.length ? (
          <EmptyState icon={<KeyRound className="h-6 w-6" />} title="No credentials stored" hint="Add a credential, then assign it to devices." />
        ) : (
          <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Name</th><th className="th">Kind</th><th className="th">Username</th><th className="th">Used by</th><th className="th">Updated</th><th className="th">Key</th><th className="th" /></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((c) => (
              <tr key={c.id}><td className="td"><p className="font-medium">{c.name}</p><p className="text-xs text-slate-500">{c.description}</p></td><td className="td"><Badge>{c.kind}</Badge></td>
                <td className="td font-mono text-xs">{c.username || "—"}</td><td className="td">{c.in_use}</td><td className="td text-xs text-slate-500">{fmtDate(c.updated_at)}</td><td className="td text-xs">{c.key_version}</td>
                <td className="td text-right">{can("credentials.manage") && <div className="flex justify-end gap-1">
                  <Button size="sm" variant="outline" icon={<RotateCw className="h-3.5 w-3.5" />} onClick={() => setForm(c)}>Rotate</Button>
                  <Button size="sm" variant="ghost" aria-label={`Delete ${c.name}`} disabled={c.in_use > 0} title={c.in_use ? "In use" : "Delete"} onClick={async () => {
                    if (await confirm({ title: "Delete credential?", message: `“${c.name}” will be permanently destroyed.`, danger: true, confirmLabel: "Delete" })) {
                      try { await api(`/api/credentials/${c.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["credentials"] }); } catch (e) { toast({ tone: "error", title: "Delete failed", body: (e as Error).message }); }
                    }
                  }}><Trash2 className="h-4 w-4" /></Button></div>}</td></tr>
            ))}</tbody></table>
        )}
      </Card>
      {form !== undefined && <CredForm cred={form || undefined} onClose={() => setForm(undefined)} />}
    </div>
  );
}

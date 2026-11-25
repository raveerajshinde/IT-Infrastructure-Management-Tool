import { useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { CheckCircle2, KeyRound, PlugZap, Server, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { DeviceForm } from "../components/DeviceForm";
import { Button, Callout, Card, ErrorBox, Field } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Device } from "../lib/types";

const STEPS = [
  { t: "Organization & policy", icon: ShieldCheck }, { t: "Store a credential", icon: KeyRound },
  { t: "Register a device", icon: Server }, { t: "Test connectivity", icon: PlugZap },
];

export default function Onboarding() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [step, setStep] = useState(0);
  const [org, setOrg] = useState(""); const [mfa, setMfa] = useState(false);
  const [cred, setCred] = useState({ name: "", kind: "password", username: "", secret: "" });
  const [device, setDevice] = useState<Device | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);
  const [err, setErr] = useState<unknown>(null); const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<void>) => { setBusy(true); setErr(null); try { await fn(); } catch (e) { setErr(e); } finally { setBusy(false); } };
  const secretKey = { password: "password", winrm: "password", api_token: "token", ssh_key: "private_key" }[cred.kind] || "password";
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-semibold">Infrastructure onboarding</h1>
      <ol className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {STEPS.map((s, i) => (
          <li key={s.t} className={clsx("flex items-center gap-2 rounded-md border px-3 py-2 text-xs font-medium",
            i === step ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-200" : i < step ? "border-emerald-300 text-emerald-700" : "border-slate-200 text-slate-500 dark:border-slate-700")}>
            {i < step ? <CheckCircle2 className="h-4 w-4" /> : <s.icon className="h-4 w-4" />}{s.t}</li>))}
      </ol>
      <ErrorBox error={err} />
      {step === 0 && <Card title="Organization & security policy">
        {can("settings.manage") ? <div className="space-y-3">
          <Field label="Organization name"><input className="input" value={org} onChange={(e) => setOrg(e.target.value)} /></Field>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={mfa} onChange={(e) => setMfa(e.target.checked)} /> Require two-factor authentication for every local user (recommended)</label>
          <div className="flex justify-end gap-2"><Button variant="ghost" onClick={() => setStep(1)}>Skip</Button>
            <Button loading={busy} onClick={() => run(async () => { await api("/api/settings", { method: "PUT", body: { values: { "ui.organization_name": org, "security.mfa_required": mfa } } }); setStep(1); })}>Save & continue</Button></div>
        </div> : <div className="flex justify-between"><p className="text-sm text-slate-500">Only administrators can change policy.</p><Button onClick={() => setStep(1)}>Continue</Button></div>}
      </Card>}
      {step === 1 && <Card title="Store a management credential">
        <div className="space-y-3">
          <Callout>Credentials are encrypted (AES-256-GCM) and never shown again. For SNMPv3 or SSH keys use the Credentials page.</Callout>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Name" required><input className="input" value={cred.name} onChange={(e) => setCred({ ...cred, name: e.target.value })} placeholder="linux-admin" /></Field>
            <Field label="Kind"><select className="input" value={cred.kind} onChange={(e) => setCred({ ...cred, kind: e.target.value })}>
              <option value="password">Username + password (SSH/CLI)</option><option value="winrm">Windows (WinRM)</option><option value="api_token">API token</option></select></Field>
            <Field label="Username"><input className="input" value={cred.username} onChange={(e) => setCred({ ...cred, username: e.target.value })} autoComplete="off" /></Field>
            <Field label={secretKey === "token" ? "Token" : "Password"}><input type="password" className="input" autoComplete="new-password" value={cred.secret} onChange={(e) => setCred({ ...cred, secret: e.target.value })} /></Field>
          </div>
          <div className="flex justify-end gap-2"><Button variant="ghost" onClick={() => setStep(2)}>Skip</Button>
            <Button loading={busy} disabled={!cred.name || !cred.secret || !can("credentials.manage")} onClick={() => run(async () => {
              await api("/api/credentials", { body: { name: cred.name, kind: cred.kind, username: cred.username || null, secret: { [secretKey]: cred.secret } } });
              qc.invalidateQueries({ queryKey: ["credentials"] }); setCred({ ...cred, secret: "" }); setStep(2);
            })}>Save credential</Button></div>
        </div>
      </Card>}
      {step === 2 && <Card title="Register your first device">
        {device ? <Callout tone="success" title={`${device.hostname} registered`}>Continue to test connectivity.</Callout> :
          <p className="text-sm text-slate-500">Choose the driver that matches the device; assign the credential you just stored.</p>}
        <div className="mt-3 flex justify-end gap-2">{!device && <Button onClick={() => setShowForm(true)}>Register device</Button>}
          {device && <Button onClick={() => setStep(3)}>Continue</Button>}</div>
        {showForm && <DeviceForm onClose={() => setShowForm(false)} onSaved={(d) => setDevice(d)} />}
      </Card>}
      {step === 3 && device && <Card title={`Test connectivity to ${device.hostname}`}>
        <div className="space-y-3">
          {test && <Callout tone={test.ok ? "success" : "danger"} title={test.ok ? "Connection successful" : "Connection failed"}>{test.message}</Callout>}
          {test && !test.ok && <p className="text-sm text-slate-500">Check network reachability from the InfraPilot server, the port, the credential, and (for SSH) the pinned host key. See the Troubleshooting Guide.</p>}
          <div className="flex justify-end gap-2">
            <Button variant="outline" loading={busy} onClick={() => run(async () => { setTest(await api(`/api/devices/${device.id}/test`, { method: "POST" })); })}>Run test</Button>
            {test?.ok && <Button loading={busy} onClick={() => run(async () => {
              if (can("settings.manage")) await api("/api/settings", { method: "PUT", body: { values: { "setup.completed": true } } });
              setStep(4);
            })}>Finish</Button>}
          </div>
        </div>
      </Card>}
      {step === 4 && <Card><div className="space-y-2 text-center"><CheckCircle2 className="mx-auto h-10 w-10 text-emerald-500" /><p className="font-medium">Onboarding complete</p>
        <p className="text-sm text-slate-500">Next: import the rest of your inventory, configure Active Directory sign-in and SMTP alerts, and assign roles to your team.</p>
        <div className="flex justify-center gap-2 pt-2"><Link to="/devices"><Button variant="outline">Go to devices</Button></Link><Link to="/"><Button>Open dashboard</Button></Link></div></div></Card>}
    </div>
  );
}

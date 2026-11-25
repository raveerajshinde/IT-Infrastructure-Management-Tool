import { KeyRound, ShieldCheck } from "lucide-react";
import { FormEvent, useState } from "react";
import { Button, Callout, Card, ErrorBox, Field, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";

export function ChangePasswordForm({ onDone }: { onDone?: () => void }) {
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState("");
  const [busy, setBusy] = useState(false); const [err, setErr] = useState<unknown>(null);
  const toast = useToast();
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    if (n1 !== n2) { setErr(new Error("The new passwords do not match")); return; }
    setBusy(true);
    try {
      await api("/api/auth/password", { body: { current_password: cur, new_password: n1 } });
      toast({ tone: "success", title: "Password changed", body: "Other sessions were signed out." });
      setCur(""); setN1(""); setN2(""); onDone?.();
    } catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  return (
    <form onSubmit={submit} className="space-y-3">
      <ErrorBox error={err} />
      <Field label="Current password" htmlFor="cp"><input id="cp" type="password" className="input" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required /></Field>
      <Field label="New password" htmlFor="np" hint="At least 12 characters with three of: lowercase, uppercase, digit, symbol.">
        <input id="np" type="password" className="input" autoComplete="new-password" value={n1} onChange={(e) => setN1(e.target.value)} required /></Field>
      <Field label="Confirm new password" htmlFor="np2"><input id="np2" type="password" className="input" autoComplete="new-password" value={n2} onChange={(e) => setN2(e.target.value)} required /></Field>
      <Button type="submit" loading={busy} icon={<KeyRound className="h-4 w-4" />}>Change password</Button>
    </form>
  );
}

export function MfaEnrol({ onDone }: { onDone?: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState<unknown>(null);
  const toast = useToast();
  const start = async () => { setErr(null); try { setSetup(await api("/api/auth/mfa/setup", { method: "POST" })); } catch (e) { setErr(e); } };
  const enable = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr(null);
    try { await api("/api/auth/mfa/enable", { body: { code } }); toast({ tone: "success", title: "Two-factor authentication enabled" }); onDone?.(); }
    catch (e2) { setErr(e2); } finally { setBusy(false); }
  };
  if (!setup) return (<div className="space-y-3"><ErrorBox error={err} /><p className="text-sm text-slate-600 dark:text-slate-300">Protect your account with a time-based one-time password (TOTP) app such as Microsoft Authenticator, Google Authenticator or FreeOTP.</p>
    <Button onClick={start} icon={<ShieldCheck className="h-4 w-4" />}>Set up authenticator</Button></div>);
  return (
    <form onSubmit={enable} className="space-y-3">
      <ErrorBox error={err} />
      <Callout title="Add this account to your authenticator app">
        <p className="mt-1">Enter the key manually (type: time-based):</p>
        <p className="mt-1 select-all break-all rounded bg-white/60 px-2 py-1 font-mono text-sm dark:bg-black/30">{setup.secret.match(/.{1,4}/g)?.join(" ")}</p>
        <p className="mt-2 text-xs">Or copy the setup URI into an app that accepts it: <span className="select-all break-all font-mono">{setup.otpauth_uri}</span></p>
      </Callout>
      <Field label="Code from the app" htmlFor="mfa"><input id="mfa" className="input max-w-[12rem] font-mono tracking-widest" inputMode="numeric" maxLength={6}
        value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required /></Field>
      <Button type="submit" loading={busy}>Verify and enable</Button>
    </form>
  );
}

export default function SetupRequired() {
  const { user, reload, logout } = useAuth();
  const needPw = user?.must_change_password;
  const needMfa = user?.mfa_required_by_policy && !user?.mfa_enabled;
  return (
    <div className="mx-auto max-w-lg space-y-4 p-6">
      <h1 className="text-xl font-semibold">Secure your account</h1>
      <p className="text-sm text-slate-500">Before you can continue, complete the following required steps.</p>
      {needPw && <Card title="1. Change your temporary password"><ChangePasswordForm onDone={reload} /></Card>}
      {!needPw && needMfa && <Card title="Enable two-factor authentication (required by policy)"><MfaEnrol onDone={reload} /></Card>}
      <Button variant="ghost" onClick={logout}>Sign out</Button>
    </div>
  );
}

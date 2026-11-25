import { Network, ShieldCheck } from "lucide-react";
import { FormEvent, useState } from "react";
import { Button, ErrorBox, Field } from "../components/ui";
import { useAuth } from "../lib/auth";
import { BrandMark, useBranding } from "../lib/branding";

export default function Login() {
  const { login, verifyMfa } = useAuth();
  const brand = useBranding();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      if (mfaToken) await verifyMfa(code);
      else {
        const r = await login(username, password);
        if (r.mfa_required) setMfaToken(true);
      }
    } catch (err) { setError(err); } finally { setBusy(false); }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-900 via-slate-900 to-brand-900 p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-1 text-white">
          <div className="flex items-center gap-2">
            <BrandMark className="h-10 w-10 bg-white p-1" fallback={<span className="rounded-lg bg-brand-600 p-2"><Network className="h-6 w-6" /></span>} />
            <span className="text-2xl font-semibold tracking-tight">{brand.product_name}</span>
          </div>
          {(brand.organization || brand.tagline) && <p className="text-sm text-slate-300">{[brand.organization, brand.tagline].filter(Boolean).join(" · ")}</p>}
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-lg bg-white p-6 shadow-xl dark:bg-slate-900" aria-label="Sign in">
          <div>
            <h1 className="text-lg font-semibold">{mfaToken ? "Two-factor verification" : "Sign in"}</h1>
            <p className="text-sm text-slate-500">{mfaToken ? "Enter the 6-digit code from your authenticator app." : "Use your local or Active Directory account."}</p>
          </div>
          <ErrorBox error={error} title="Sign-in failed" />
          {!mfaToken ? (
            <>
              <Field label="Username" htmlFor="u"><input id="u" className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus /></Field>
              <Field label="Password" htmlFor="p"><input id="p" type="password" className="input" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
            </>
          ) : (
            <Field label="Verification code" htmlFor="c">
              <input id="c" className="input text-center font-mono text-lg tracking-[0.4em]" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required autoFocus />
            </Field>
          )}
          <Button type="submit" className="w-full" loading={busy} icon={mfaToken ? <ShieldCheck className="h-4 w-4" /> : undefined}>
            {mfaToken ? "Verify" : "Sign in"}
          </Button>
          {mfaToken && <button type="button" className="w-full text-center text-xs text-slate-500 hover:underline" onClick={() => { setMfaToken(false); setCode(""); }}>Back</button>}
        </form>
        {brand.login_message && <p className="mt-4 whitespace-pre-line rounded-md bg-white/10 p-3 text-center text-xs text-slate-200">{brand.login_message}</p>}
        <p className="mt-4 text-center text-xs text-slate-400">Access is logged and audited. Unauthorized use is prohibited.</p>
      </div>
    </div>
  );
}

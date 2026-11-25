import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ImageUp, Network, RotateCcw, Save } from "lucide-react";
import { useEffect, useState } from "react";
import { Button, Callout, Card, ErrorBox, Field, KeyValue, PageHeader, Skeleton, Tabs, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";
import { applyBrandColor, useBranding } from "../lib/branding";
import type { Role } from "../lib/types";
import { ChangePasswordForm, MfaEnrol } from "./AccountSecurity";
import { Diagnostics } from "./Diagnostics";

type S = Record<string, unknown>;

function Profile() {
  const { user, reload } = useAuth();
  const [code, setCode] = useState(""); const [pw, setPw] = useState(""); const [err, setErr] = useState<unknown>(null);
  const toast = useToast();
  const disable = async () => {
    setErr(null);
    try { await api("/api/auth/mfa/disable", { body: { password: pw, code } }); toast({ tone: "success", title: "MFA disabled" }); reload(); } catch (e) { setErr(e); }
  };
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {user?.auth_source === "local" ? <Card title="Change password"><ChangePasswordForm /></Card> : <Card title="Password"><p className="text-sm text-slate-500">Your account is managed by Active Directory. Change your password there.</p></Card>}
      <Card title="Two-factor authentication">
        {user?.mfa_enabled ? (
          <div className="space-y-3"><Callout tone="success">Two-factor authentication is enabled for your account.</Callout>
            {!user.mfa_required_by_policy && <><ErrorBox error={err} />
              <div className="grid grid-cols-2 gap-2"><Field label="Password"><input type="password" className="input" value={pw} onChange={(e) => setPw(e.target.value)} /></Field>
                <Field label="Current code"><input className="input" value={code} onChange={(e) => setCode(e.target.value)} maxLength={6} /></Field></div>
              <Button variant="outline" onClick={disable}>Disable MFA</Button></>}
          </div>
        ) : <MfaEnrol onDone={reload} />}
      </Card>
    </div>
  );
}

const BRAND_KEYS = ["branding.product_name", "branding.tagline", "ui.organization_name", "branding.primary_color", "branding.logo", "branding.login_message", "branding.dashboard_title"];
const SWATCHES = ["#2148e0", "#0f766e", "#7c3aed", "#be123c", "#c2410c", "#0369a1", "#15803d", "#334155"];

function BrandingCard({ s, set, save, saving }: { s: S; set: (k: string, v: unknown) => void; save: (keys: string[]) => Promise<void>; saving: boolean }) {
  const current = useBranding();
  const qc = useQueryClient(); const toast = useToast();
  const color = String(s["branding.primary_color"] || "#2148e0");
  const logo = String(s["branding.logo"] || "");
  const name = String(s["branding.product_name"] || "InfraPilot");
  useEffect(() => { applyBrandColor(color); return () => applyBrandColor(current.primary_color); }, [color, current.primary_color]);  // live preview
  const upload = (f: File | undefined) => {
    if (!f) return;
    if (!/^image\/(png|jpeg|webp|svg\+xml)$/.test(f.type)) { toast({ tone: "error", title: "Use a PNG, JPEG, WebP or SVG image" }); return; }
    if (f.size > 300 * 1024) { toast({ tone: "error", title: "Logo must be smaller than 300 KB" }); return; }
    const r = new FileReader(); r.onload = () => set("branding.logo", String(r.result)); r.readAsDataURL(f);
  };
  return (
    <Card title="Branding" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />}
      onClick={async () => { await save(BRAND_KEYS); qc.invalidateQueries({ queryKey: ["branding"] }); }}>Save</Button>}>
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_16rem]">
        <div className="space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Product name" htmlFor="bp"><input id="bp" className="input" maxLength={40} value={String(s["branding.product_name"] ?? "")} onChange={(e) => set("branding.product_name", e.target.value)} /></Field>
            <Field label="Organization" htmlFor="bo"><input id="bo" className="input" maxLength={120} value={String(s["ui.organization_name"] ?? "")} onChange={(e) => set("ui.organization_name", e.target.value)} /></Field>
            <Field label="Tagline (sign-in page)" htmlFor="bt"><input id="bt" className="input" maxLength={80} value={String(s["branding.tagline"] ?? "")} onChange={(e) => set("branding.tagline", e.target.value)} placeholder="IT Infrastructure Operations" /></Field>
            <Field label="Dashboard title" htmlFor="bd"><input id="bd" className="input" maxLength={60} value={String(s["branding.dashboard_title"] ?? "")} onChange={(e) => set("branding.dashboard_title", e.target.value)} /></Field>
          </div>
          <Field label="Brand colour" hint="Used for buttons, links, highlights and charts. Preview applies immediately; Save to keep it.">
            <div className="flex flex-wrap items-center gap-2">
              <input type="color" aria-label="Pick brand colour" className="h-9 w-12 cursor-pointer rounded border border-slate-300 bg-white p-0.5 dark:border-slate-700" value={color} onChange={(e) => set("branding.primary_color", e.target.value)} />
              <input className="input w-28 font-mono" value={color} onChange={(e) => set("branding.primary_color", e.target.value)} aria-label="Brand colour hex" />
              {SWATCHES.map((c) => <button key={c} type="button" aria-label={`Use ${c}`} onClick={() => set("branding.primary_color", c)}
                className="h-7 w-7 rounded-full ring-2 ring-offset-2 ring-offset-white dark:ring-offset-slate-900" style={{ background: c, ["--tw-ring-color" as string]: c === color ? c : "transparent" }} />)}
            </div>
          </Field>
          <Field label="Logo" hint="PNG, JPEG, WebP or SVG, under 300 KB. A square image works best.">
            <div className="flex flex-wrap items-center gap-2">
              <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-slate-300 px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800">
                <ImageUp className="h-4 w-4" />Upload<input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml" className="sr-only" onChange={(e) => upload(e.target.files?.[0])} /></label>
              {logo && <Button size="sm" variant="ghost" icon={<RotateCcw className="h-4 w-4" />} onClick={() => set("branding.logo", "")}>Remove logo</Button>}
            </div>
          </Field>
          <Field label="Sign-in notice" htmlFor="bl" hint="Shown under the sign-in form, e.g. an acceptable-use statement or helpdesk contact.">
            <textarea id="bl" className="input" rows={3} maxLength={500} value={String(s["branding.login_message"] ?? "")} onChange={(e) => set("branding.login_message", e.target.value)} />
          </Field>
          <Button size="sm" variant="ghost" icon={<RotateCcw className="h-4 w-4" />} onClick={() => { set("branding.primary_color", "#2148e0"); set("branding.product_name", "InfraPilot"); }}>Reset name and colour</Button>
        </div>
        <div>
          <p className="label">Preview</p>
          <div className="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2 bg-slate-900 p-3">
              {logo ? <img src={logo} alt="" className="h-8 w-8 rounded-md bg-white object-contain p-0.5" /> : <span className="rounded-md bg-brand-600 p-1.5 text-white"><Network className="h-5 w-5" /></span>}
              <span className="min-w-0"><span className="block truncate font-semibold text-white">{name}</span>
                {s["ui.organization_name"] ? <span className="block truncate text-[11px] text-slate-400">{String(s["ui.organization_name"])}</span> : null}</span>
            </div>
            <div className="space-y-2 bg-white p-3 dark:bg-slate-900">
              <p className="text-sm font-semibold">{String(s["branding.dashboard_title"] || "Operations overview")}</p>
              <div className="flex gap-2"><Button size="sm">Primary</Button><Button size="sm" variant="outline">Secondary</Button></div>
              <a className="text-xs text-brand-600 underline">Link colour</a>
              <div className="h-1.5 rounded-full bg-brand-100"><div className="h-1.5 w-2/3 rounded-full bg-brand-600" /></div>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

const FOLDER_KEYS = ["devexport.enabled", "devexport.path", "devexport.mode", "devexport.keep_days", "devexport.write_latest"];
type FolderStatus = { status: Record<string, string | number | boolean | null>; enabled: boolean; roots: string[] };

function BackupFolderCard({ s, set, save, saving, txt, chk }: {
  s: S; set: (k: string, v: unknown) => void; save: (keys: string[]) => Promise<void>; saving: boolean;
  txt: (k: string, label: string, props?: Record<string, unknown>) => JSX.Element; chk: (k: string, label: string) => JSX.Element;
}) {
  const qc = useQueryClient();
  const { data, refetch } = useQuery({ queryKey: ["backup-folder"], queryFn: () => api<FolderStatus>("/api/backup-folder"), refetchInterval: 30000 });
  const [busy, setBusy] = useState<"" | "test" | "export" | "all">("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const st = data?.status || {};
  const roots = data?.roots || ["/srv/infrapilot-exports", "/mnt", "/media"];
  const hours = Number(s["backup.config_schedule_hours"] ?? 24);
  const run = async (kind: "test" | "export" | "all") => {
    setBusy(kind); setResult(null);
    try {
      if (kind === "test") setResult(await api<{ ok: boolean; message: string }>("/api/backup-folder/test", { method: "POST" }));
      else {
        const r = await api<{ exported: number; folder: string }>(`/api/backup-folder/export-configs${kind === "all" ? "?all=true" : ""}`, { method: "POST" });
        setResult({ ok: true, message: kind === "all" ? `All ${r.exported} stored device backup(s) written to ${r.folder} again.` : `${r.exported} new device backup(s) written to ${r.folder}.` });
      }
    } catch (e) { setResult({ ok: false, message: (e as Error).message }); } finally { setBusy(""); refetch(); }
  };
  return (
    <Card title="Folder on the server" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />} onClick={async () => { await save(FOLDER_KEYS); qc.invalidateQueries({ queryKey: ["backup-folder"] }); }}>Save</Button>}>
      <p className="mb-3 text-sm text-slate-500">
        Writes every switch, router and firewall configuration backup into a folder on the InfraPilot server, about a minute after it is taken.
        {" "}{hours > 0 ? <>Scheduled backups run every <b>{hours} h</b> (General tab).</> : <span className="text-amber-700 dark:text-amber-400">Scheduled backups are off — set the interval on the General tab.</span>}
      </p>
      {chk("devexport.enabled", "Copy device backups to a folder")}
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {txt("devexport.path", "Folder", { placeholder: "/srv/infrapilot-exports/device-backups" })}
        {txt("devexport.keep_days", "Delete dated copies after (days, 0 = keep all)", { type: "number", min: 0, max: 3650 })}
      </div>
      <p className="mt-1.5 text-xs text-slate-500">
        Must be inside {roots.map((r, i) => <span key={r}>{i > 0 && (i === roots.length - 1 ? " or " : ", ")}<code>{r}</code></span>)}.
        For a NAS or Windows share, mount it on the server under <code>/mnt</code> (e.g. <code>/mnt/nas</code>, CIFS option <code>uid=10001,gid=10001</code>) — or use the Network share (SMB) section below.
        The folder must be writable by uid 10001: <code>sudo chown -R 10001:10001 &lt;folder&gt;</code>.
      </p>
      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
        {chk("devexport.write_latest", "Also keep latest_<kind>.cfg per device (always the newest config)")}
      </div>
      <div className="mt-4">
        <p className="label">Files in the folder</p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="radiogroup" aria-label="Device backup copies in folder">
          {([["full", "Full copy (restorable)", "Exactly as taken from the device, including passwords, keys and SNMP communities. Restrict the folder to administrators."],
             ["masked", "Masked copy (for reading only)", "Secrets replaced — safe to share more widely, but cannot be used to restore a device."]] as const).map(([v, title, hint]) => {
            const on = (s["devexport.mode"] || "full") === v;
            return (
              <button key={v} type="button" role="radio" aria-checked={on} onClick={() => set("devexport.mode", v)}
                className={`rounded-md border p-2.5 text-left text-sm ${on ? "border-brand-500 bg-brand-50 ring-1 ring-brand-500 dark:bg-brand-900/30" : "border-slate-200 hover:border-slate-300 dark:border-slate-700"}`}>
                <span className="font-medium">{title}</span><span className="mt-0.5 block text-xs text-slate-500">{hint}</span>
              </button>
            );
          })}
        </div>
        <p className="mt-1.5 text-xs text-slate-500">Layout: <code>&lt;folder&gt;/&lt;hostname&gt;/&lt;date-time&gt;_&lt;kind&gt;.cfg</code>. A dated file is written only when the configuration changed since the previous backup.</p>
      </div>
      <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-100 pt-4 dark:border-slate-800">
        <Button size="sm" variant="outline" loading={busy === "test"} disabled={!data?.enabled} onClick={() => run("test")}>Test folder</Button>
        <Button size="sm" variant="outline" loading={busy === "export"} disabled={!data?.enabled} onClick={() => run("export")}>Copy new backups now</Button>
        <Button size="sm" variant="ghost" loading={busy === "all"} disabled={!data?.enabled} onClick={() => run("all")}>Copy all again</Button>
        {!data?.enabled && <span className="self-center text-xs text-slate-500">Enable, enter the folder and Save first.</span>}
      </div>
      {result && <div className="mt-3"><Callout tone={result.ok ? "success" : "danger"} title={result.ok ? "Success" : "Failed"}>{result.message}</Callout></div>}
      <div className="mt-4">
        <KeyValue items={[
          ["Last copy", st.last_export_at ? `${fmtDate(String(st.last_export_at))}${st.last_export_count != null ? ` — ${st.last_export_count} file(s)` : ""}${st.folder ? ` to ${st.folder}` : ""}` : "never"],
          ["Last error", st.last_error ? <span key="e" className="text-red-600">{String(st.last_error)}{st.last_error_at ? ` (${fmtDate(String(st.last_error_at))})` : ""}</span> : "none"],
        ]} />
      </div>
    </Card>
  );
}

const OFFSITE_KEYS = ["offsite.enabled", "offsite.share", "offsite.username", "offsite.domain", "offsite.password", "offsite.passphrase", "offsite.keep_days",
  "offsite.include_database", "offsite.include_config", "offsite.include_device_configs", "offsite.require_encryption", "offsite.device_configs_mode"];
type OffsiteStatus = { status: Record<string, string | number | boolean | null>; enabled: boolean };

function BackupStorageCard({ s, set, save, saving, txt, chk }: {
  s: S; set: (k: string, v: unknown) => void; save: (keys: string[]) => Promise<void>; saving: boolean;
  txt: (k: string, label: string, props?: Record<string, unknown>) => JSX.Element; chk: (k: string, label: string) => JSX.Element;
}) {
  const qc = useQueryClient();
  const { data, refetch } = useQuery({ queryKey: ["backup-storage"], queryFn: () => api<OffsiteStatus>("/api/backup-storage"), refetchInterval: 30000 });
  const [busy, setBusy] = useState<"" | "test" | "export" | "all">("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const st = data?.status || {};
  const run = async (kind: "test" | "export" | "all") => {
    setBusy(kind); setResult(null);
    try {
      if (kind === "test") setResult(await api<{ ok: boolean; message: string }>("/api/backup-storage/test", { method: "POST" }));
      else {
        const r = await api<{ exported: number }>(`/api/backup-storage/export-configs${kind === "all" ? "?all=true" : ""}`, { method: "POST" });
        setResult({ ok: true, message: kind === "all" ? `All ${r.exported} stored device configuration backup(s) copied to the share again.` : `${r.exported} new device configuration backup(s) copied to the share.` });
      }
    } catch (e) { setResult({ ok: false, message: (e as Error).message }); } finally { setBusy(""); refetch(); }
  };
  const passSet = !!s["offsite.passphrase_set"];
  return (
    <div className="space-y-4">
      <Card title="Network share (SMB)" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />} onClick={async () => { await save(OFFSITE_KEYS); qc.invalidateQueries({ queryKey: ["backup-storage"] }); }}>Save</Button>}>
        <p className="mb-3 text-sm text-slate-500">Copies backups to a Windows file server or NAS share: every switch/firewall/server configuration backup (within about a minute of it being taken), the nightly database backup and the encrypted InfraPilot configuration archive.</p>
        {chk("offsite.enabled", "Copy backups to a network share")}
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {txt("offsite.share", "Share path", { placeholder: "\\\\fileserver\\backups\\infrapilot" })}
          {txt("offsite.keep_days", "Keep files on the share for (days)", { type: "number", min: 1, max: 3650 })}
          {txt("offsite.username", "User name", { placeholder: "svc_infrapilot_backup", autoComplete: "off" })}
          {txt("offsite.domain", "Domain (optional)", { placeholder: "CORP" })}
          {txt("offsite.password", s["offsite.password_set"] ? "Password (saved — leave blank to keep)" : "Password", { type: "password", autoComplete: "new-password" })}
          {txt("offsite.passphrase", passSet ? "Backup encryption passphrase (saved — leave blank to keep)" : "Backup encryption passphrase (min. 12 characters)", { type: "password", autoComplete: "new-password" })}
        </div>
        {!passSet && <div className="mt-3"><Callout tone="warning" title="Set an encryption passphrase">The configuration archive contains the master key and database passwords, so it is only copied to the share encrypted with this passphrase. Store the passphrase in your password manager — without it the archive cannot be restored.</Callout></div>}
        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {chk("offsite.include_database", "Database backup (.bak)")}
          {chk("offsite.include_config", "Configuration and secrets archive (encrypted)")}
          {chk("offsite.include_device_configs", "Device configuration backups (copied ~1 minute after each backup)")}
          {chk("offsite.require_encryption", "Require SMB 3 encryption in transit")}
        </div>
        {!!s["offsite.include_device_configs"] && (
          <div className="mt-4">
            <p className="label">Device configuration files on the share</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="radiogroup" aria-label="Device configuration copies">
              {([["full", "Full copy (restorable)", "Exactly as taken from the device, including passwords, keys and SNMP communities — usable to restore the device. Restrict the share to administrators."],
                 ["masked", "Masked copy (for reading only)", "Passwords, keys and communities replaced by ***** — safe to share more widely, but cannot be used to restore a device."]] as const).map(([v, title, hint]) => {
                const on = (s["offsite.device_configs_mode"] || "full") === v;
                return (
                  <button key={v} type="button" role="radio" aria-checked={on} onClick={() => set("offsite.device_configs_mode", v)}
                    className={`rounded-md border p-2.5 text-left text-sm ${on ? "border-brand-500 bg-brand-50 ring-1 ring-brand-500 dark:bg-brand-900/30" : "border-slate-200 hover:border-slate-300 dark:border-slate-700"}`}>
                    <span className="font-medium">{title}</span><span className="mt-0.5 block text-xs text-slate-500">{hint}</span>
                  </button>
                );
              })}
            </div>
            <p className="mt-1.5 text-xs text-slate-500">Files: <code>devices\&lt;hostname&gt;\&lt;date-time&gt;_&lt;kind&gt;.cfg</code>. After changing this, Save and use “Copy all again” to rewrite existing files.</p>
          </div>
        )}
        {!s["offsite.require_encryption"] && <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">Without SMB encryption the database backup crosses the network readable. Only untick this for old NAS devices on a trusted network.</p>}
        <div className="mt-4 flex flex-wrap gap-2 border-t border-slate-100 pt-4 dark:border-slate-800">
          <Button size="sm" variant="outline" loading={busy === "test"} disabled={!data?.enabled} onClick={() => run("test")}>Test connection</Button>
          <Button size="sm" variant="outline" loading={busy === "export"} disabled={!data?.enabled} onClick={() => run("export")}>Copy new device configs now</Button>
          <Button size="sm" variant="ghost" loading={busy === "all"} disabled={!data?.enabled} onClick={() => run("all")}>Copy all again</Button>
          {!data?.enabled && <span className="self-center text-xs text-slate-500">Enable, fill in the share and Save first.</span>}
        </div>
        {result && <div className="mt-3"><Callout tone={result.ok ? "success" : "danger"} title={result.ok ? "Success" : "Failed"}>{result.message}</Callout></div>}
      </Card>
      <Card title="Status">
        <KeyValue items={[
          ["Last nightly upload", st.last_backup_upload_at ? `${fmtDate(String(st.last_backup_upload_at))} — ${st.last_backup_message ?? ""}` : "never"],
          ["Last device config copy", st.last_config_export_at ? `${fmtDate(String(st.last_config_export_at))}${st.last_config_export_count != null ? ` — ${st.last_config_export_count} file(s)` : ""}` : "never"],
          ["Last error", st.last_error ? <span key="e" className="text-red-600">{String(st.last_error)}{st.last_error_at ? ` (${fmtDate(String(st.last_error_at))})` : ""}</span> : "none"],
        ]} />
        <p className="mt-3 text-xs text-slate-500">The nightly backup (01:30, <code>infrapilot-backup</code>) uploads the database and configuration archive right after it finishes; run <code>sudo infrapilot-backup</code> on the server to back up and upload now. Restore: copy the files back to the server, then <code>sudo infrapilot-restore --db FILE.bak --config FILE.tar.gz.enc --passphrase-file PASSFILE</code>.</p>
      </Card>
    </div>
  );
}

export default function SettingsPage() {
  const { can } = useAuth();
  const admin = can("settings.manage");
  const [tab, setTab] = useState<"profile" | "general" | "branding" | "backup" | "security" | "email" | "ldap" | "diagnostics">(
    () => (new URLSearchParams(window.location.search).get("tab") as "profile") || "profile");
  const { data, isLoading } = useQuery({ queryKey: ["settings"], enabled: admin, queryFn: () => api<S>("/api/settings") });
  const { data: roles } = useQuery({ queryKey: ["roles"], enabled: admin, queryFn: () => api<Role[]>("/api/roles") });
  const [s, setS] = useState<S>({});
  const [mapText, setMapText] = useState("");
  const [err, setErr] = useState<unknown>(null); const [saving, setSaving] = useState(false);
  const [testTo, setTestTo] = useState("");
  const qc = useQueryClient(); const toast = useToast();
  useEffect(() => {
    if (data) { setS(data); setMapText(Object.entries((data["ldap.group_role_map"] as Record<string, string>) || {}).map(([k, v]) => `${k} = ${v}`).join("\n")); }
  }, [data]);
  const set = (k: string, v: unknown) => setS((prev) => ({ ...prev, [k]: v }));
  const save = async (keys: string[]) => {
    setSaving(true); setErr(null);
    const values: S = Object.fromEntries(keys.map((k) => [k, s[k]]));
    if (keys.includes("ldap.group_role_map")) values["ldap.group_role_map"] = Object.fromEntries(mapText.split("\n").filter((l) => l.includes("=")).map((l) => { const i = l.lastIndexOf("="); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));
    try { await api("/api/settings", { method: "PUT", body: { values } }); qc.invalidateQueries({ queryKey: ["settings"] }); toast({ tone: "success", title: "Settings saved" }); }
    catch (e) { setErr(e); } finally { setSaving(false); }
  };
  const test = async (path: string, body?: unknown) => {
    try { const r = await api<{ message: string }>(path, { method: "POST", body }); toast({ tone: "success", title: r.message }); } catch (e) { toast({ tone: "error", title: "Test failed", body: (e as Error).message }); }
  };
  const txt = (k: string, label: string, props: Record<string, unknown> = {}) => (
    <Field label={label} htmlFor={k}><input id={k} className="input" value={String(s[k] ?? "")} onChange={(e) => set(k, e.target.value)} {...props} /></Field>
  );
  const chk = (k: string, label: string) => <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={!!s[k]} onChange={(e) => set(k, e.target.checked)} />{label}</label>;
  const tabs = [{ id: "profile" as const, label: "My account" }, ...(admin ? [{ id: "general" as const, label: "General & approvals" }, { id: "branding" as const, label: "Branding" }, { id: "backup" as const, label: "Backup storage" }, { id: "security" as const, label: "Security" },
    { id: "email" as const, label: "E-mail" }, { id: "ldap" as const, label: "Active Directory" }, { id: "diagnostics" as const, label: "Diagnostics" }] : [])];
  return (
    <div>
      <PageHeader title="Settings" />
      <Tabs value={tab} onChange={setTab} tabs={tabs} />
      {tab === "profile" && <Profile />}
      {tab === "diagnostics" && <Diagnostics />}
      {tab !== "profile" && tab !== "diagnostics" && (isLoading ? <Skeleton /> : (
        <div className={tab === "branding" ? "max-w-5xl space-y-4" : tab === "backup" ? "max-w-4xl space-y-4" : "max-w-3xl space-y-4"}><ErrorBox error={err} />
          {tab === "branding" && <BrandingCard s={s} set={set} save={save} saving={saving} />}
          {tab === "backup" && <div className="space-y-4"><BackupFolderCard s={s} set={set} save={save} saving={saving} txt={txt} chk={chk} /><BackupStorageCard s={s} set={set} save={save} saving={saving} txt={txt} chk={chk} /></div>}
          {tab === "general" && <Card title="General & change control" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />}
            onClick={() => save(["ui.organization_name", "approval.medium_in_production", "approval.expiry_hours", "monitoring.interval_seconds", "monitoring.metrics_retention_days", "backup.config_schedule_hours"])}>Save</Button>}>
            <div className="space-y-3">
              {txt("ui.organization_name", "Organization name")}
              {chk("approval.medium_in_production", "Require approval for medium-risk changes on production devices")}
              <p className="text-xs text-slate-500">Critical changes (firewall policies, GPO links, feature removal, VM power actions) always require approval in every environment. Production firewall changes additionally wait for a maintenance window. Fine-grained policies are listed under Approvals.</p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {txt("approval.expiry_hours", "Approval request expiry (hours)", { type: "number", min: 1, max: 720 })}
                {txt("monitoring.interval_seconds", "Monitoring interval (seconds)", { type: "number", min: 30, max: 3600 })}
                {txt("monitoring.metrics_retention_days", "Metric retention (days)", { type: "number", min: 1, max: 730 })}
                {txt("backup.config_schedule_hours", "Scheduled config backups every (hours, 0 = off)", { type: "number", min: 0, max: 720 })}
              </div>
            </div>
          </Card>}
          {tab === "security" && <Card title="Security policy" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />} onClick={() => save(["security.mfa_required"])}>Save</Button>}>
            {chk("security.mfa_required", "Require two-factor authentication for all local users")}
            <p className="mt-2 text-xs text-slate-500">Users without MFA will be asked to enrol at their next sign-in before they can use the platform. Account lockout, session idle timeout and rate limits are configured in the server environment file (see Administrator Manual).</p>
          </Card>}
          {tab === "email" && <Card title="SMTP" actions={<Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />} onClick={() => save(["smtp.host", "smtp.port", "smtp.username", "smtp.password", "smtp.from", "smtp.starttls"])}>Save</Button>}>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {txt("smtp.host", "SMTP server")}{txt("smtp.port", "Port", { type: "number" })}{txt("smtp.username", "Username")}
              {txt("smtp.password", "Password", { type: "password", autoComplete: "new-password" })}{txt("smtp.from", "From address")}
              <div className="pt-6">{chk("smtp.starttls", "Use STARTTLS (port 587); port 465 uses implicit TLS")}</div>
            </div>
            <div className="mt-4 flex items-end gap-2"><Field label="Send test e-mail to"><input className="input" type="email" value={testTo} onChange={(e) => setTestTo(e.target.value)} /></Field>
              <Button variant="outline" disabled={!testTo} onClick={() => test("/api/settings/test-email", { to: testTo })}>Send test</Button></div>
          </Card>}
          {tab === "ldap" && <Card title="Active Directory (LDAPS)" actions={<><Button size="sm" variant="outline" onClick={() => test("/api/settings/test-ldap")}>Test bind</Button>
            <Button size="sm" loading={saving} icon={<Save className="h-4 w-4" />} onClick={() => save(["ldap.enabled", "ldap.url", "ldap.bind_dn", "ldap.bind_password", "ldap.base_dn", "ldap.user_filter", "ldap.start_tls", "ldap.group_role_map", "ldap.default_role"])}>Save</Button></>}>
            <div className="space-y-3">
              {chk("ldap.enabled", "Enable Active Directory sign-in")}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {txt("ldap.url", "Server URL", { placeholder: "ldaps://dc01.corp.local:636" })}{txt("ldap.base_dn", "Base DN", { placeholder: "DC=corp,DC=local" })}
                {txt("ldap.bind_dn", "Service account DN", { placeholder: "CN=svc-infrapilot,OU=Service,DC=corp,DC=local" })}
                {txt("ldap.bind_password", "Service account password", { type: "password", autoComplete: "new-password" })}
              </div>
              {txt("ldap.user_filter", "User filter ({username} is escaped and substituted)")}
              {chk("ldap.start_tls", "Use StartTLS on port 389 instead of LDAPS")}
              <Field label="AD group → role mapping" hint="One per line: full group DN = role name. Users get the roles of all mapped groups they belong to.">
                <textarea className="input font-mono text-xs" rows={5} value={mapText} onChange={(e) => setMapText(e.target.value)}
                  placeholder={"CN=IT-Network,OU=Groups,DC=corp,DC=local = Network Administrator\nCN=IT-Auditors,OU=Groups,DC=corp,DC=local = Auditor / Read Only"} /></Field>
              <Field label="Default role for directory users not in a mapped group" hint="Leave empty to deny sign-in to unmapped users (recommended).">
                <select className="input" value={String(s["ldap.default_role"] || "")} onChange={(e) => set("ldap.default_role", e.target.value)}>
                  <option value="">— deny —</option>{(roles || []).map((r) => <option key={r.id}>{r.name}</option>)}</select></Field>
              <Callout>The CA certificate of your domain controllers must be trusted: place it at <span className="font-mono">/opt/infrapilot/certs/ldap-ca.pem</span> on the server (the installer can do this).</Callout>
            </div>
          </Card>}
        </div>
      ))}
    </div>
  );
}

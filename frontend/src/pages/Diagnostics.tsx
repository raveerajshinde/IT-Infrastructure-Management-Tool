import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ClipboardCopy, Play, Trash2, XCircle } from "lucide-react";
import { useState } from "react";
import { Badge, Button, Card, EmptyState, ErrorBox, KeyValue, Skeleton, useToast } from "../components/ui";
import { ApiError, api } from "../lib/api";
import { fmtDate } from "../lib/format";

type Diag = {
  version: string; mode: string; database: string; database_version: string; schema_revision: string; worker_last_seen: string | null;
  errors: { ref: string; at: string; method: string; path: string; error: string; trace: string }[];
};
const CHECKS: [string, string][] = [
  ["Dashboard", "/api/dashboard"], ["Devices", "/api/devices?page_size=5"], ["Operations catalogue", "/api/operations"],
  ["Job templates", "/api/templates"], ["Playbooks", "/api/playbooks"], ["Approved commands", "/api/approved-commands"],
  ["Jobs", "/api/jobs?page_size=5"], ["Schedules", "/api/schedules"], ["Reports", "/api/reports"], ["Approvals", "/api/approvals"],
  ["Approval policies", "/api/approval-policies"], ["Maintenance windows", "/api/maintenance-windows"], ["Alerts", "/api/alerts?page_size=5"],
  ["Alert rules", "/api/alert-rules"], ["Credentials", "/api/credentials"], ["Users", "/api/users"], ["Roles", "/api/roles"],
  ["Sites", "/api/sites"], ["Groups", "/api/groups"], ["Integrations", "/api/integrations"], ["Audit log", "/api/audit?page_size=5"],
  ["Settings", "/api/settings"], ["Branding", "/api/branding"],
];
type Result = { name: string; path: string; ok: boolean; status: number; ms: number; message: string };

export function Diagnostics() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["diagnostics"], queryFn: () => api<Diag>("/api/system/diagnostics") });
  const [results, setResults] = useState<Result[] | null>(null);
  const [running, setRunning] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const qc = useQueryClient(); const toast = useToast();

  const selfCheck = async () => {
    setRunning(true); const out: Result[] = [];
    for (const [name, path] of CHECKS) {
      const t0 = performance.now();
      try { await api(path); out.push({ name, path, ok: true, status: 200, ms: Math.round(performance.now() - t0), message: "" }); }
      catch (e) {
        const a = e instanceof ApiError ? e : null;
        out.push({ name, path, ok: a?.status === 403, status: a?.status || 0, ms: Math.round(performance.now() - t0), message: a?.status === 403 ? "not permitted for your role" : (e as Error).message });
      }
      setResults([...out]);
    }
    setRunning(false); refetch();
  };
  const report = () => {
    const d = data;
    const lines = [`InfraPilot diagnostics ${new Date().toISOString()}`, `version ${d?.version} (${d?.mode}) db ${d?.database} ${d?.database_version} schema ${d?.schema_revision} worker ${d?.worker_last_seen}`,
      "", "Self-check:", ...(results || []).map((r) => `${r.ok ? "OK  " : "FAIL"} ${r.status} ${r.path} ${r.message}`), "", "Recent errors:",
      ...(d?.errors || []).slice(0, 10).map((e) => `[${e.ref}] ${e.at} ${e.method} ${e.path}\n${e.error}\n${e.trace}\n`)];
    navigator.clipboard.writeText(lines.join("\n")).then(() => toast({ tone: "success", title: "Report copied — paste it to support" }),
      () => toast({ tone: "error", title: "Clipboard not available" }));
  };

  if (isLoading) return <Card><Skeleton /></Card>;
  if (error) return <ErrorBox error={error} />;
  const d = data!;
  const fails = (results || []).filter((r) => !r.ok);
  return (
    <div className="space-y-4">
      <Card title="System" actions={<Button size="sm" variant="outline" icon={<ClipboardCopy className="h-4 w-4" />} onClick={report}>Copy report</Button>}>
        <KeyValue items={[["Version", <span key="v" className="font-mono">{d.version}</span>], ["Mode", d.mode], ["Database", `${d.database} — ${d.database_version}`],
          ["Schema revision", d.schema_revision], ["Worker last seen", d.worker_last_seen ? fmtDate(d.worker_last_seen) : "never — the worker is not running"],
          ["Recent server errors", String(d.errors.length)]]} />
      </Card>
      <Card title="Self-check" actions={<Button size="sm" loading={running} icon={<Play className="h-4 w-4" />} onClick={selfCheck}>Run self-check</Button>} padded={!results}>
        {!results ? <p className="text-sm text-slate-500">Calls every main API endpoint as you and reports which ones fail. Use it after an upgrade or when a page shows an error.</p> : (
          <>
            {!running && <p className={`border-b px-4 py-2 text-sm dark:border-slate-800 ${fails.length ? "text-red-600" : "text-emerald-600"}`}>{fails.length ? `${fails.length} endpoint(s) failed — details below and under Recent server errors.` : "All endpoints responded."}</p>}
            <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">{results.map((r) => (
              <li key={r.path} className="flex items-start gap-2 px-4 py-1.5">
                {r.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />}
                <span className="w-44 shrink-0">{r.name}</span><span className="w-12 shrink-0 font-mono text-xs text-slate-500">{r.status || "—"}</span>
                <span className="w-16 shrink-0 text-xs text-slate-500">{r.ms} ms</span><span className="min-w-0 break-words text-xs text-red-600">{r.message}</span>
              </li>))}</ul>
          </>
        )}
      </Card>
      <Card title="Recent server errors" padded={false} actions={d.errors.length > 0 && <Button size="sm" variant="ghost" icon={<Trash2 className="h-4 w-4" />} onClick={async () => {
        await api("/api/system/diagnostics/errors", { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["diagnostics"] });
      }}>Clear</Button>}>
        {!d.errors.length ? <EmptyState title="No server errors recorded" /> : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">{d.errors.map((e) => (
            <li key={e.ref} className="px-4 py-2 text-sm">
              <button className="flex w-full items-start gap-2 text-left" onClick={() => setOpen(open === e.ref ? null : e.ref)}>
                <Badge tone="red">{e.ref}</Badge><span className="font-mono text-xs text-slate-500">{e.method} {e.path}</span>
                <span className="ml-auto shrink-0 text-xs text-slate-500">{fmtDate(e.at)}</span>
              </button>
              <p className="mt-1 break-words text-red-700 dark:text-red-300">{e.error}</p>
              {open === e.ref && <pre className="code mt-2 max-h-80 overflow-auto">{e.trace}</pre>}
            </li>))}</ul>
        )}
      </Card>
    </div>
  );
}

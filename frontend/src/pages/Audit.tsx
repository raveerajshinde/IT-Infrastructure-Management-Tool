import { useQuery } from "@tanstack/react-query";
import { Download, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Modal, PageHeader, Pagination, Skeleton } from "../components/ui";
import { api, download, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";
import type { AuditRow, Paged } from "../lib/types";

export default function Audit() {
  const { can } = useAuth();
  const [f, setF] = useState({ action: "", actor: "", target_type: "", result: "", since: "", until: "" });
  const [page, setPage] = useState(1);
  const [verify, setVerify] = useState<{ valid: boolean; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [row, setRow] = useState<AuditRow | null>(null);
  const params = { ...f, since: f.since ? new Date(f.since).toISOString() : "", until: f.until ? new Date(f.until).toISOString() : "" };
  const { data, isLoading, error } = useQuery({ queryKey: ["audit", params, page], placeholderData: (p) => p,
    queryFn: () => api<Paged<AuditRow>>(`/api/audit${qs({ ...params, page, page_size: 50 })}`) });
  const set = (k: keyof typeof f, v: string) => { setF({ ...f, [k]: v }); setPage(1); };
  const runVerify = async () => { setBusy(true); try { setVerify(await api("/api/audit/verify")); } finally { setBusy(false); } };
  return (
    <div>
      <PageHeader title="Audit log" subtitle="Append-only, hash-chained record of every sign-in, change request, approval, execution and configuration change."
        actions={<>
          <Button variant="outline" loading={busy} icon={<ShieldCheck className="h-4 w-4" />} onClick={runVerify}>Verify integrity</Button>
          {can("audit.export") && <Button variant="outline" icon={<Download className="h-4 w-4" />} onClick={() => download(`/api/audit/export${qs(params)}`, "audit.csv")}>Export CSV</Button>}
        </>} />
      {verify && <div className="mb-4"><Callout tone={verify.valid ? "success" : "danger"} title={verify.valid ? "Audit chain intact" : "TAMPERING DETECTED"}>{verify.message}</Callout></div>}
      <Card padded={false}>
        <div className="grid grid-cols-2 gap-2 border-b border-slate-200 p-3 dark:border-slate-800 md:grid-cols-6">
          <input className="input" placeholder="Action prefix (e.g. job.)" aria-label="Action" value={f.action} onChange={(e) => set("action", e.target.value)} />
          <input className="input" placeholder="Actor username" aria-label="Actor" value={f.actor} onChange={(e) => set("actor", e.target.value)} />
          <select className="input" aria-label="Target type" value={f.target_type} onChange={(e) => set("target_type", e.target.value)}>
            <option value="">Any target</option>{["device", "job", "user", "credential", "role", "settings", "alert", "integration", "group", "site", "template"].map((t) => <option key={t}>{t}</option>)}</select>
          <select className="input" aria-label="Result" value={f.result} onChange={(e) => set("result", e.target.value)}>
            <option value="">Any result</option>{["success", "failure", "approved", "rejected", "succeeded", "failed", "partial", "locked"].map((t) => <option key={t}>{t}</option>)}</select>
          <input type="datetime-local" className="input" aria-label="From" value={f.since} onChange={(e) => set("since", e.target.value)} />
          <input type="datetime-local" className="input" aria-label="Until" value={f.until} onChange={(e) => set("until", e.target.value)} />
        </div>
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading ? <Skeleton rows={10} /> : !data?.items.length ? <EmptyState title="No audit records match" /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th><th className="th">Target</th><th className="th">Result</th><th className="th">Source IP</th><th className="th" /></tr></thead>
              <tbody className="divide-y divide-slate-100 font-[450] dark:divide-slate-800">
                {data.items.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="td whitespace-nowrap text-xs">{fmtDate(r.ts)}</td><td className="td">{r.actor}</td><td className="td font-mono text-xs">{r.action}</td>
                    <td className="td text-xs">{r.target_type}{r.target_id && ` #${r.target_id}`}</td>
                    <td className="td"><Badge tone={["failure", "failed", "rejected", "locked"].includes(r.result) ? "red" : r.result === "success" || r.result === "succeeded" || r.result === "approved" ? "green" : "gray"}>{r.result}</Badge></td>
                    <td className="td font-mono text-xs">{r.ip || "—"}</td>
                    <td className="td text-right"><Button size="sm" variant="ghost" onClick={() => setRow(r)}>Details</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <Pagination page={page} pageSize={50} total={data.total} onPage={setPage} />}
      </Card>
      {row && <Modal open size="lg" onClose={() => setRow(null)} title={`Audit record #${row.id}`}>
        <p className="mb-2 text-sm">{fmtDate(row.ts)} · <b>{row.actor}</b> · <span className="font-mono">{row.action}</span></p>
        <pre className="code max-h-96 overflow-auto">{JSON.stringify(row.details, null, 2)}</pre>
        <p className="mt-2 break-all font-mono text-[11px] text-slate-500">hash {row.row_hash}</p>
      </Modal>}
    </div>
  );
}

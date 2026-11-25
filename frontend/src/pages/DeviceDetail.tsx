import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, FlaskConical, GitCompare, Pencil, Play, PlugZap, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DeviceForm } from "../components/DeviceForm";
import { ManageConsole } from "../components/ManageConsole";
import { OperationRunner } from "../components/OperationRunner";
import {
  Badge, Button, Callout, Card, DiffView, EmptyState, ErrorBox, KeyValue, Modal, RiskBadge, Skeleton, StatusBadge, Tabs, useConfirm, useToast,
} from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { DEVICE_TYPE_LABEL, FAMILY_LABEL, ago, fmtDate } from "../lib/format";
import type { Alert, Device, Job, Operation, Paged } from "../lib/types";

type TestResult = { ok: boolean; latency_ms: number | null; message: string; facts: Record<string, unknown>; tested_at: string };
type Backup = { id: number; kind: string; sha256: string; size: number; created_at: string; job_id: number | null };

function MetricChart({ id, metric, label }: { id: number; metric: string; label: string }) {
  const [hours, setHours] = useState(24);
  const { data } = useQuery({ queryKey: ["metrics", id, metric, hours], queryFn: () => api<{ points: { ts: string; value: number }[] }>(`/api/devices/${id}/metrics?metric=${metric}&hours=${hours}`) });
  return (
    <Card title={label} actions={<select className="input w-auto py-1 text-xs" aria-label="Range" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
      <option value={6}>6h</option><option value={24}>24h</option><option value={168}>7d</option></select>}>
      {data?.points.length ? (
        <div className="h-44"><ResponsiveContainer width="100%" height="100%">
          <LineChart data={data.points} margin={{ left: -20, right: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#94a3b833" />
            <XAxis dataKey="ts" tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} fontSize={10} stroke="#94a3b8" />
            <YAxis domain={metric === "latency_ms" ? ["auto", "auto"] : [0, 100]} fontSize={10} stroke="#94a3b8" />
            <Tooltip labelFormatter={(v) => new Date(v as string).toLocaleString()} />
            <Line type="monotone" dataKey="value" stroke="#2148e0" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer></div>
      ) : <p className="py-8 text-center text-sm text-slate-500">No samples in this range.</p>}
    </Card>
  );
}

function Backups({ id }: { id: number }) {
  const { data, isLoading } = useQuery({ queryKey: ["backups", id], queryFn: () => api<Backup[]>(`/api/devices/${id}/backups`) });
  const [pick, setPick] = useState<number[]>([]);
  const [view, setView] = useState<{ title: string; content?: string; diff?: string } | null>(null);
  const open = async (b: Backup) => { const r = await api<Backup & { content: string }>(`/api/backups/${b.id}`); setView({ title: `Backup #${b.id} — ${fmtDate(b.created_at)}`, content: r.content }); };
  const compare = async () => {
    const [a, b] = [...pick].sort((x, y) => x - y);
    const r = await api<{ diff: string; added: number; removed: number }>(`/api/backups-diff?a=${a}&b=${b}`);
    setView({ title: `Compare #${a} → #${b} (+${r.added} / −${r.removed})`, diff: r.diff });
  };
  if (isLoading) return <Skeleton />;
  return (
    <Card title="Configuration backups" padded={false} actions={<Button size="sm" variant="outline" disabled={pick.length !== 2} icon={<GitCompare className="h-4 w-4" />} onClick={compare}>Compare selected</Button>}>
      {!data?.length ? <EmptyState title="No backups yet" hint="Run the “Back up configuration” operation. Scheduled backups run daily for switches, routers and firewalls." /> : (
        <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th w-8" /><th className="th">Taken</th><th className="th">Kind</th><th className="th">Size</th><th className="th">SHA-256</th><th className="th" /></tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{data.map((b) => (
            <tr key={b.id}><td className="td"><input type="checkbox" aria-label={`Select backup ${b.id}`} checked={pick.includes(b.id)} onChange={() => setPick((p) => p.includes(b.id) ? p.filter((x) => x !== b.id) : [...p.slice(-1), b.id])} /></td>
              <td className="td">{fmtDate(b.created_at)}</td><td className="td">{b.kind}</td><td className="td">{(b.size / 1024).toFixed(1)} KB</td>
              <td className="td font-mono text-xs">{b.sha256.slice(0, 16)}…</td><td className="td text-right"><Button size="sm" variant="ghost" onClick={() => open(b)}>View</Button></td></tr>
          ))}</tbody></table>
      )}
      {view && <Modal open size="xl" onClose={() => setView(null)} title={view.title}>{view.diff !== undefined ? <DiffView diff={view.diff} /> : <pre className="code max-h-[65vh] overflow-auto">{view.content}</pre>}</Modal>}
    </Card>
  );
}

export default function DeviceDetail() {
  const { id } = useParams();
  const did = Number(id);
  const { can } = useAuth();
  const nav = useNavigate(); const qc = useQueryClient(); const toast = useToast(); const confirm = useConfirm();
  const [tab, setTab] = useState<"overview" | "manage" | "operations" | "jobs" | "backups" | "alerts">(
    () => (new URLSearchParams(window.location.search).get("tab") as "manage") || "overview");
  const [edit, setEdit] = useState(false);
  const [op, setOp] = useState<Operation | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const { data: d, isLoading, error } = useQuery({ queryKey: ["device", did], queryFn: () => api<Device>(`/api/devices/${did}`) });
  const { data: latest } = useQuery({ queryKey: ["latest", did], queryFn: () => api<Record<string, { value: number; ts: string }>>(`/api/devices/${did}/metrics/latest`), refetchInterval: 60000 });
  const { data: jobs } = useQuery({ queryKey: ["jobs", "device", did], enabled: tab === "jobs", queryFn: () => api<Paged<Job>>(`/api/jobs?device_id=${did}&page_size=50`) });
  const { data: alerts } = useQuery({ queryKey: ["alerts", "device", did], enabled: tab === "alerts", queryFn: () => api<Paged<Alert>>(`/api/alerts?device_id=${did}&status=&page_size=50`) });
  const testM = useMutation({
    mutationFn: () => api<TestResult>(`/api/devices/${did}/test`, { method: "POST" }),
    onSuccess: (r) => { setTest(r); qc.invalidateQueries({ queryKey: ["device", did] }); },
    onError: (e: Error) => toast({ tone: "error", title: "Test failed", body: e.message }),
  });

  if (isLoading) return <Card><Skeleton rows={10} /></Card>;
  if (error || !d) return <ErrorBox error={error || "Device not found"} />;
  const fams = [...new Set((d.operations || []).map((o) => o.family))];
  const m = (k: string) => (latest?.[k] ? `${latest[k].value.toFixed(1)}${k.endsWith("pct") ? "%" : k === "latency_ms" ? " ms" : ""}` : "—");

  return (
    <div className="space-y-4">
      <Link to="/devices" className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800"><ArrowLeft className="h-4 w-4" />Devices</Link>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold">{d.hostname} <StatusBadge status={d.status} />
            {d.is_simulated && <Badge tone="violet"><FlaskConical className="h-3 w-3" />Simulated</Badge>}</h1>
          <p className="text-sm text-slate-500"><span className="font-mono">{d.ip_address}</span> · {DEVICE_TYPE_LABEL[d.device_type]} · {d.environment} · last successful connection {ago(d.last_success_at)}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {can("devices.test") && <Button variant="outline" icon={<PlugZap className="h-4 w-4" />} loading={testM.isPending} onClick={() => testM.mutate()}>Test connectivity</Button>}
          {can("devices.write") && <Button variant="outline" icon={<Pencil className="h-4 w-4" />} onClick={() => setEdit(true)}>Edit</Button>}
          {can("devices.delete") && <Button variant="danger" icon={<Trash2 className="h-4 w-4" />} onClick={async () => {
            if (await confirm({ title: `Remove ${d.hostname}?`, message: "The device is removed from the inventory. Job history, backups and audit records are retained. Nothing is changed on the device itself.", danger: true, confirmLabel: "Remove" })) {
              await api(`/api/devices/${did}`, { method: "DELETE" }); toast({ tone: "success", title: "Device removed" }); nav("/devices");
            }
          }}>Remove</Button>}
        </div>
      </div>
      {test && !test.ok && /CERTIFICATE_VERIFY_FAILED|self[- ]signed|certificate verify failed/i.test(test.message) && d.options?.verify_tls !== false && can("devices.write") && (
        <Callout tone="warning" title="The device uses a certificate this server does not trust">
          <p>This is normal for firewalls and hypervisors with their factory self-signed certificate. You can skip certificate verification for <b>this device only</b>
            (the connection stays encrypted but the device's identity is not checked), or install the device's CA certificate on the InfraPilot host.</p>
          <Button size="sm" variant="outline" className="mt-2" onClick={async () => {
            if (!(await confirm({ title: `Skip certificate verification for ${d.hostname}?`, message: "Only do this on a trusted management network. The change is recorded in the audit log and can be reverted in Edit.", confirmLabel: "Skip verification and retest" }))) return;
            await api(`/api/devices/${did}/tls`, { body: { verify_tls: false } }); qc.invalidateQueries({ queryKey: ["device", did] }); testM.mutate();
          }}>Skip certificate verification and retest</Button>
        </Callout>
      )}
      {test && <Callout tone={test.ok ? "success" : "danger"} title={test.ok ? `Connected${test.latency_ms ? ` in ${test.latency_ms} ms` : ""}` : "Connectivity test failed"}>
        <p>{test.message}</p>{test.ok && Object.keys(test.facts || {}).length > 0 && <p className="mt-1 text-xs">Facts: {Object.entries(test.facts).filter(([k]) => k !== "host_key_sha256").map(([k, v]) => `${k}=${v}`).join(" · ")}</p>}</Callout>}
      {d.last_error && !test && d.status !== "up" && <Callout tone="warning" title="Last error">{d.last_error}</Callout>}

      <Tabs value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "manage", label: "Manage" }, { id: "operations", label: `All operations (${d.operations?.length || 0})` },
        { id: "jobs", label: "Job history" }, { id: "backups", label: "Config backups" }, { id: "alerts", label: "Alerts" }]} />

      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card title="Details" className="xl:col-span-2">
            <KeyValue items={[["Vendor", d.vendor], ["Model", d.model], ["Operating system", [d.os_name, d.os_version].filter(Boolean).join(" ")], ["Firmware", d.firmware],
              ["Serial number", d.serial_number], ["Driver", d.driver], ["Site", d.site?.name], ["Department", d.department], ["Owner", d.owner],
              ["Tags", d.tags.join(", ")], ["TLS certificate check", d.options?.verify_tls === false ? <Badge tone="amber">skipped</Badge> : "verified"], ["Last seen", fmtDate(d.last_seen_at)], ["Last successful connection", fmtDate(d.last_success_at)]]} />
            {d.notes && <p className="mt-4 whitespace-pre-wrap rounded bg-slate-50 p-3 text-sm dark:bg-slate-800">{d.notes}</p>}
          </Card>
          <Card title="Current health">
            <KeyValue items={[["Availability", latest?.availability ? (latest.availability.value ? "Reachable" : "Unreachable") : "—"], ["Latency", m("latency_ms")], ["CPU", m("cpu_pct")], ["Memory", m("mem_pct")], ["Disk", m("disk_pct")],
              ["Sampled", ago(latest?.availability?.ts)]]} />
          </Card>
          <MetricChart id={did} metric="cpu_pct" label="CPU %" />
          <MetricChart id={did} metric="mem_pct" label="Memory %" />
          <MetricChart id={did} metric="latency_ms" label="Latency (ms)" />
        </div>
      )}

      {tab === "manage" && (
        <>
          {!d.credential_id && !d.is_simulated && <Callout tone="warning" title="No credential assigned">Management needs a credential. Edit the device to assign one.</Callout>}
          <ManageConsole device={d} />
        </>
      )}

      {tab === "operations" && (
        <div className="space-y-4">
          {!d.credential_id && !d.is_simulated && <Callout tone="warning" title="No credential assigned">Operations need a management credential. Edit the device to assign one.</Callout>}
          {fams.map((f) => (
            <Card key={f} title={FAMILY_LABEL[f] || f} padded={false}>
              <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                {d.operations!.filter((o) => o.family === f).map((o) => (
                  <li key={o.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
                    <div className="min-w-0"><p className="text-sm font-medium">{o.name}</p><p className="truncate text-xs text-slate-500">{o.summary.replace(/\{[^}]+\}/g, "…")}</p></div>
                    <div className="flex items-center gap-2">{o.mutating ? <RiskBadge risk={o.risk} /> : <Badge>read-only</Badge>}
                      <Button size="sm" variant={o.mutating ? "outline" : "secondary"} disabled={!o.allowed} title={o.allowed ? "" : `Requires ${o.permission}`} icon={<Play className="h-3.5 w-3.5" />} onClick={() => setOp(o)}>Run</Button></div>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      )}

      {tab === "jobs" && (
        <Card padded={false}>{!jobs?.items.length ? <EmptyState title="No jobs for this device yet" /> : (
          <table className="w-full"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">#</th><th className="th">Job</th><th className="th">Status</th><th className="th">By</th><th className="th">Created</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{jobs.items.map((j) => (
              <tr key={j.id}><td className="td"><Link to={`/jobs/${j.id}`} className="text-brand-600 hover:underline">#{j.id}</Link></td><td className="td">{j.title}{j.check_mode && <Badge className="ml-2" tone="blue">dry-run</Badge>}</td>
                <td className="td"><StatusBadge status={j.status} /></td><td className="td">{j.requested_by}</td><td className="td text-xs text-slate-500">{fmtDate(j.created_at)}</td></tr>
            ))}</tbody></table>)}
        </Card>
      )}
      {tab === "backups" && <Backups id={did} />}
      {tab === "alerts" && (
        <Card padded={false}>{!alerts?.items.length ? <EmptyState title="No alerts recorded for this device" /> : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">{alerts.items.map((a) => (
            <li key={a.id} className="flex items-center justify-between px-4 py-2.5 text-sm"><span>{a.title}<span className="block text-xs text-slate-500">{a.detail}</span></span>
              <span className="flex items-center gap-2"><StatusBadge status={a.severity} /><StatusBadge status={a.status} /><span className="text-xs text-slate-500">{fmtDate(a.opened_at)}</span></span></li>
          ))}</ul>)}
        </Card>
      )}
      {edit && <DeviceForm device={d} onClose={() => setEdit(false)} />}
      {op && <OperationRunner op={op} deviceIds={[did]} onClose={() => setOp(null)} />}
    </div>
  );
}

import { SecurityPosture } from "../components/SecurityPosture";
import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, AlertOctagon, ArrowRight, CalendarClock, CheckCircle2, ClipboardCheck, Cpu, DatabaseBackup, FileBarChart, HardDrive,
  MemoryStick, Plus, RefreshCw, Server, Sparkles, TimerOff, Workflow,
} from "lucide-react";
import { ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Area, AreaChart, Bar, CartesianGrid, Cell, ComposedChart, Legend, Line, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Skeleton, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useBranding } from "../lib/branding";
import { DEVICE_TYPE_LABEL, ago, fmtDate } from "../lib/format";
import type { Alert, Job } from "../lib/types";

type Dash = {
  devices: { total: number; by_type: Record<string, number>; by_status: Record<string, number>; by_environment: Record<string, number> };
  availability_24h_pct: number | null;
  resources: Record<string, { avg: number | null; max: number | null; samples: number }>;
  availability_trend: { hour: string; availability_pct: number }[];
  alerts: { counts: Record<string, number>; recent: Alert[] };
  jobs_24h: Record<string, number>; pending_approvals: number;
  top_cpu: { device_id: number; hostname: string; cpu_pct: number }[]; has_simulated: boolean;
  activity_7d: { day: string; alerts: number; jobs_succeeded: number; jobs_failed: number; jobs_other: number }[];
  sites: { site: string; total: number; up: number; down: number; degraded: number; unknown: number }[];
  by_vendor: Record<string, number>;
  backup_coverage: { eligible: number; fresh_7d: number; never: number; never_devices: string[] };
  stale_devices: { id: number; hostname: string; last_seen_at: string | null; status: string }[];
  recent_jobs: Job[]; upcoming_schedules: { id: number; name: string; next_run_at: string | null }[];
};

const BASE = { up: "#10b981", degraded: "#f59e0b", down: "#ef4444", unknown: "#94a3b8", brand: "#3563f5", brandDark: "#2148e0", violet: "#8b5cf6" };
let C = BASE;
const pct = (v: number | null | undefined, d = 1) => (v === null || v === undefined ? "—" : `${v.toFixed(d)}%`);
const axis = { fontSize: 11, stroke: "#94a3b8", tickLine: false, axisLine: false } as const;
const tip = { contentStyle: { borderRadius: 8, border: "1px solid #e2e8f0", fontSize: 12 } };

function Kpi({ label, value, sub, icon, tone, to, children }: {
  label: string; value: ReactNode; sub?: ReactNode; icon: ReactNode; tone: "green" | "amber" | "red" | "blue" | "gray"; to?: string; children?: ReactNode;
}) {
  const accent = { green: "bg-emerald-500", amber: "bg-amber-500", red: "bg-red-500", blue: "bg-brand-500", gray: "bg-slate-300 dark:bg-slate-700" }[tone];
  const ic = { green: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40", amber: "text-amber-600 bg-amber-50 dark:bg-amber-950/40",
    red: "text-red-600 bg-red-50 dark:bg-red-950/40", blue: "text-brand-600 bg-brand-50 dark:bg-brand-900/40", gray: "text-slate-500 bg-slate-100 dark:bg-slate-800" }[tone];
  const body = (
    <div className="relative h-full overflow-hidden rounded-xl border border-slate-200 bg-white p-4 shadow-card transition hover:shadow-md dark:border-slate-800 dark:bg-slate-900">
      <span className={clsx("absolute inset-x-0 top-0 h-0.5", accent)} aria-hidden />
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
        <span className={clsx("rounded-lg p-1.5", ic)}>{icon}</span>
      </div>
      <p className="mt-2 text-3xl font-semibold tabular-nums tracking-tight">{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
      {children}
    </div>
  );
  return to ? <Link to={to} className="block focus-visible:rounded-xl">{body}</Link> : body;
}

function StackBar({ parts }: { parts: { value: number; color: string; label: string }[] }) {
  const total = parts.reduce((a, b) => a + b.value, 0) || 1;
  return (
    <div className="mt-3 flex h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" role="img"
      aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
      {parts.map((p) => p.value > 0 && <span key={p.label} style={{ width: `${(100 * p.value) / total}%`, background: p.color }} />)}
    </div>
  );
}

function Gauge({ label, icon, avg, max, samples }: { label: string; icon: ReactNode; avg: number | null | undefined; max: number | null | undefined; samples: number }) {
  const tone = !samples ? "bg-slate-300" : (max || 0) > 90 ? "bg-red-500" : (max || 0) > 75 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="flex items-center gap-2 font-medium text-slate-700 dark:text-slate-200">{icon}{label}</span>
        <span className="tabular-nums text-slate-500">{samples ? <>avg <b className="text-slate-800 dark:text-slate-100">{pct(avg)}</b> · peak {pct(max)}</> : "no samples"}</span>
      </div>
      <div className="relative mt-1.5 h-2 rounded-full bg-slate-100 dark:bg-slate-800">
        <div className={clsx("h-2 rounded-full", tone)} style={{ width: `${Math.min(100, avg || 0)}%` }} />
        {!!samples && <span className="absolute top-[-3px] h-3.5 w-0.5 rounded bg-slate-700 dark:bg-slate-200" style={{ left: `${Math.min(99.5, max || 0)}%` }} title={`Peak ${pct(max)}`} />}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { user, can } = useAuth();
  const brand = useBranding();
  C = { ...BASE, brand: brand.primary_color, brandDark: brand.primary_color };
  const { data, isLoading, error, refetch, isFetching, dataUpdatedAt } = useQuery({
    queryKey: ["dashboard"], queryFn: () => api<Dash>("/api/dashboard"), refetchInterval: 60000,
  });
  if (isLoading) return <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">{[0, 1, 2, 3].map((i) => <Card key={i}><Skeleton rows={3} /></Card>)}</div>;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;
  // Tolerate partial responses (an older API or a failed section) instead of crashing the page.
  const raw = data as Partial<Dash>;
  const d: Dash = {
    ...(data as Dash),
    devices: { ...{ total: 0, by_type: {}, by_status: {}, by_environment: {} }, ...(raw.devices || {}) },
    resources: data.resources || {}, availability_trend: data.availability_trend || [],
    alerts: { counts: data.alerts?.counts || {}, recent: data.alerts?.recent || [] },
    jobs_24h: data.jobs_24h || {}, pending_approvals: data.pending_approvals || 0, top_cpu: data.top_cpu || [],
    activity_7d: data.activity_7d || [], sites: data.sites || [], by_vendor: data.by_vendor || {},
    backup_coverage: { ...{ eligible: 0, fresh_7d: 0, never: 0, never_devices: [] as string[] }, ...(raw.backup_coverage || {}) },
    stale_devices: data.stale_devices || [], recent_jobs: data.recent_jobs || [], upcoming_schedules: data.upcoming_schedules || [],
  };

  if (d.devices.total === 0) {
    return (
      <Card>
        <EmptyState icon={<Sparkles className="h-6 w-6" />} title={`Welcome${user?.display_name ? `, ${user.display_name}` : ""} — no devices yet`}
          hint="Start with the onboarding wizard: store a credential, register your first device and test connectivity."
          action={<Link to="/onboarding"><Button>Start onboarding</Button></Link>} />
      </Card>
    );
  }

  const st = d.devices.by_status;
  const statusData = (["up", "degraded", "down", "unknown"] as const).map((k) => ({ name: k, value: st[k] || 0 })).filter((x) => x.value);
  const crit = d.alerts.counts.critical || 0, warn = d.alerts.counts.warning || 0;
  const openAlerts = Object.values(d.alerts.counts).reduce((a, b) => a + b, 0);
  const jobsTotal = Object.values(d.jobs_24h).reduce((a, b) => a + b, 0);
  const jobsFailed = (d.jobs_24h.failed || 0) + (d.jobs_24h.partial || 0);
  const bc = d.backup_coverage;
  const coverage = bc.eligible ? (100 * bc.fresh_7d) / bc.eligible : null;
  const health = (st.down || 0) > 0 || crit > 0 ? "red" : (st.degraded || 0) > 0 || warn > 0 ? "amber" : "green";
  const healthText = { red: "Action needed", amber: "Degraded", green: "All systems operational" }[health];
  const typeData = Object.entries(d.devices.by_type).sort((a, b) => b[1] - a[1]);
  const activity = d.activity_7d.map((x) => ({ ...x, label: new Date(`${x.day}T00:00:00Z`).toLocaleDateString(undefined, { weekday: "short" }) }));
  const attention = d.stale_devices.length + bc.never + (d.pending_approvals ? 1 : 0);

  return (
    <div className="space-y-5">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{brand.dashboard_title}</h1>
            <span className={clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
              health === "green" && "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-900",
              health === "amber" && "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-900",
              health === "red" && "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-900")}>
              <span className={clsx("h-2 w-2 rounded-full", { green: "bg-emerald-500", amber: "bg-amber-500", red: "animate-pulse bg-red-500" }[health])} />{healthText}
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-500">
            {brand.organization ? `${brand.organization} · ` : ""}{d.devices.total} managed devices across {d.sites.length} site{d.sites.length === 1 ? "" : "s"} · updated {new Date(dataUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" icon={<RefreshCw className={clsx("h-4 w-4", isFetching && "animate-spin")} />} onClick={() => refetch()}>Refresh</Button>
          <Link to="/reports/center"><Button variant="outline" size="sm" icon={<FileBarChart className="h-4 w-4" />}>Reports</Button></Link>
          <Link to="/schedules"><Button variant="outline" size="sm" icon={<CalendarClock className="h-4 w-4" />}>Schedules</Button></Link>
          {can("devices.write") && <Link to="/devices?new=1"><Button size="sm" icon={<Plus className="h-4 w-4" />}>Add device</Button></Link>}
        </div>
      </div>
      {d.has_simulated && <Callout tone="warning" title="Simulated devices present">Some devices are simulated demo devices. Their metrics and command output are generated, not real.</Callout>}

      {/* KPIs */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi label="Devices" value={d.devices.total} icon={<Server className="h-4 w-4" />} tone={(st.down || 0) ? "red" : "blue"} to="/devices"
          sub={<><b className="text-emerald-600">{st.up || 0}</b> up · <b className="text-red-600">{st.down || 0}</b> down · {st.degraded || 0} degraded</>}>
          <StackBar parts={(["up", "degraded", "down", "unknown"] as const).map((k) => ({ label: k, value: st[k] || 0, color: C[k] }))} />
        </Kpi>
        <Kpi label="Availability 24h" value={pct(d.availability_24h_pct, 2)} icon={<Activity className="h-4 w-4" />}
          tone={d.availability_24h_pct === null ? "gray" : d.availability_24h_pct >= 99.5 ? "green" : d.availability_24h_pct >= 97 ? "amber" : "red"}
          sub="reachability samples, all devices" />
        <Kpi label="Open alerts" value={openAlerts} icon={<AlertOctagon className="h-4 w-4" />} tone={crit ? "red" : warn ? "amber" : "green"} to="/alerts"
          sub={<><b className={crit ? "text-red-600" : ""}>{crit}</b> critical · {warn} warning · {d.alerts.counts.info || 0} info</>} />
        <Kpi label="Changes 24h" value={jobsTotal} icon={<Workflow className="h-4 w-4" />} tone={jobsFailed ? "amber" : "blue"} to="/jobs"
          sub={<>{d.jobs_24h.succeeded || 0} succeeded · <span className={jobsFailed ? "text-red-600" : ""}>{jobsFailed} failed</span> · <Link to="/approvals" className="text-brand-600 hover:underline">{d.pending_approvals} awaiting approval</Link></>} />
        <Kpi label="Config backup coverage" value={coverage === null ? "—" : pct(coverage, 0)} icon={<DatabaseBackup className="h-4 w-4" />}
          tone={coverage === null ? "gray" : coverage >= 95 ? "green" : coverage >= 70 ? "amber" : "red"} to="/reports/operational?r=backup-coverage"
          sub={bc.eligible ? `${bc.fresh_7d}/${bc.eligible} backed up in 7 days · ${bc.never} never` : "no switches/firewalls yet"} />
      </div>

      <SecurityPosture />

      {/* trends */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Availability — last 24 hours" className="xl:col-span-2">
          {d.availability_trend.length ? (
            <div className="h-64" aria-label="Availability chart">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={d.availability_trend} margin={{ left: -12, right: 8, top: 4 }}>
                  <defs><linearGradient id="av" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={C.brand} stopOpacity={0.3} /><stop offset="95%" stopColor={C.brand} stopOpacity={0} /></linearGradient></defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#94a3b822" vertical={false} />
                  <XAxis dataKey="hour" tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: "2-digit" })} {...axis} minTickGap={24} />
                  <YAxis domain={[(min: number) => Math.max(0, Math.floor(min - 2)), 100]} {...axis} unit="%" width={48} />
                  <Tooltip {...tip} labelFormatter={(v) => new Date(v as string).toLocaleString()} formatter={(v: number) => [`${v}%`, "Availability"]} />
                  <Area type="monotone" dataKey="availability_pct" stroke={C.brandDark} fill="url(#av)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : <EmptyState title="No availability samples yet" hint="The monitoring worker polls devices every few minutes." />}
        </Card>
        <Card title="Fleet health">
          <div className="relative h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={statusData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={80} paddingAngle={2} stroke="none">
                  {statusData.map((s) => <Cell key={s.name} fill={C[s.name]} />)}
                </Pie>
                <Tooltip {...tip} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold tabular-nums">{d.devices.total ? Math.round((100 * (st.up || 0)) / d.devices.total) : 0}%</span>
              <span className="text-[11px] uppercase tracking-wide text-slate-500">up</span>
            </div>
          </div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
            {(["up", "degraded", "down", "unknown"] as const).map((k) => (
              <Link key={k} to={`/devices?status=${k}`} className="flex items-center justify-between rounded-md bg-slate-50 px-2 py-1.5 hover:bg-slate-100 dark:bg-slate-800/60 dark:hover:bg-slate-800">
                <span className="flex items-center gap-1.5 capitalize"><span className="h-2 w-2 rounded-full" style={{ background: C[k] }} />{k}</span>
                <b className="tabular-nums">{st[k] || 0}</b>
              </Link>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Activity — last 7 days" className="xl:col-span-2">
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={activity} margin={{ left: -16, right: 8, top: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#94a3b822" vertical={false} />
                <XAxis dataKey="label" {...axis} />
                <YAxis allowDecimals={false} {...axis} width={40} />
                <Tooltip {...tip} labelFormatter={(_, p) => String(p?.[0]?.payload?.day ?? "")} />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="jobs_succeeded" name="Jobs succeeded" stackId="j" fill={C.up} radius={[0, 0, 0, 0]} maxBarSize={36} />
                <Bar dataKey="jobs_failed" name="Jobs failed" stackId="j" fill={C.down} maxBarSize={36} />
                <Bar dataKey="jobs_other" name="Jobs other" stackId="j" fill="#cbd5e1" radius={[4, 4, 0, 0]} maxBarSize={36} />
                <Line type="monotone" dataKey="alerts" name="Alerts raised" stroke={C.violet} strokeWidth={2} dot={{ r: 3 }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Resource utilisation (last hour)">
          <div className="space-y-5 pt-1">
            <Gauge label="CPU" icon={<Cpu className="h-4 w-4 text-slate-400" />} {...(d.resources.cpu_pct || { avg: null, max: null, samples: 0 })} />
            <Gauge label="Memory" icon={<MemoryStick className="h-4 w-4 text-slate-400" />} {...(d.resources.mem_pct || { avg: null, max: null, samples: 0 })} />
            <Gauge label="Disk (fullest volume)" icon={<HardDrive className="h-4 w-4 text-slate-400" />} {...(d.resources.disk_pct || { avg: null, max: null, samples: 0 })} />
          </div>
          {d.top_cpu.length > 0 && (
            <div className="mt-5 border-t border-slate-100 pt-3 dark:border-slate-800">
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Busiest devices</p>
              <ul className="space-y-1.5">
                {d.top_cpu.map((t) => (
                  <li key={t.device_id} className="flex items-center gap-2 text-sm">
                    <Link className="w-32 truncate text-brand-600 hover:underline" to={`/devices/${t.device_id}`}>{t.hostname}</Link>
                    <div className="h-1.5 flex-1 rounded-full bg-slate-100 dark:bg-slate-800"><div className={clsx("h-1.5 rounded-full", t.cpu_pct > 90 ? "bg-red-500" : t.cpu_pct > 75 ? "bg-amber-500" : "bg-brand-500")} style={{ width: `${Math.min(100, t.cpu_pct)}%` }} /></div>
                    <span className="w-12 text-right text-xs tabular-nums">{t.cpu_pct.toFixed(0)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </div>

      {/* sites, alerts */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Card title="Sites" className="xl:col-span-2" padded={false} actions={<Link to="/inventory" className="text-xs text-brand-600 hover:underline">Manage</Link>}>
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Site</th><th className="th w-1/2">Health</th><th className="th text-right">Devices</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {d.sites.slice(0, 8).map((s) => (
                <tr key={s.site}>
                  <td className="td font-medium">{s.site}</td>
                  <td className="td"><StackBar parts={[{ label: "up", value: s.up, color: C.up }, { label: "degraded", value: s.degraded, color: C.degraded }, { label: "down", value: s.down, color: C.down }, { label: "unknown", value: s.unknown, color: C.unknown }]} /></td>
                  <td className="td text-right tabular-nums">{s.total}{s.down > 0 && <Badge tone="red" className="ml-2">{s.down} down</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex flex-wrap gap-1.5 border-t border-slate-100 p-3 dark:border-slate-800">
            {typeData.map(([k, v]) => <Link key={k} to={`/devices?device_type=${k}`}><Badge tone="gray">{DEVICE_TYPE_LABEL[k] || k} · {v}</Badge></Link>)}
          </div>
        </Card>
        <Card title="Active alerts" className="xl:col-span-3" padded={false} actions={<Link to="/alerts" className="text-xs text-brand-600 hover:underline">View all</Link>}>
          {d.alerts.recent.length ? (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {d.alerts.recent.map((a) => (
                <li key={a.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                  <span className={clsx("h-8 w-1 shrink-0 rounded-full", a.severity === "critical" ? "bg-red-500" : a.severity === "warning" ? "bg-amber-500" : "bg-brand-500")} aria-hidden />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium">{a.title}</p>
                    <p className="truncate text-xs text-slate-500">{a.hostname && <Link to={`/devices/${a.device_id}`} className="text-brand-600 hover:underline">{a.hostname}</Link>}{a.hostname && " · "}{a.detail}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2"><StatusBadge status={a.status} /><span className="w-14 text-right text-xs text-slate-500">{ago(a.opened_at)}</span></div>
                </li>
              ))}
            </ul>
          ) : <EmptyState icon={<CheckCircle2 className="h-6 w-6 text-emerald-500" />} title="No open alerts" hint="All monitored thresholds are within limits." />}
        </Card>
      </div>

      {/* jobs, attention */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Card title="Recent jobs" className="xl:col-span-3" padded={false} actions={<Link to="/jobs" className="text-xs text-brand-600 hover:underline">All jobs</Link>}>
          {d.recent_jobs.length ? (
            <table className="w-full">
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {d.recent_jobs.map((j) => (
                  <tr key={j.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="td w-14 text-xs text-slate-500"><Link to={`/jobs/${j.id}`} className="text-brand-600 hover:underline">#{j.id}</Link></td>
                    <td className="td max-w-0"><p className="truncate">{j.title}</p><p className="truncate text-xs text-slate-500">{j.requested_by} · {j.device_count} device(s){j.check_mode ? " · dry-run" : ""}</p></td>
                    <td className="td w-36"><StatusBadge status={j.status} /></td>
                    <td className="td w-20 text-right text-xs text-slate-500">{ago(j.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <EmptyState title="No jobs yet" hint="Open a device and use the Manage tab to run your first operation." />}
        </Card>
        <Card title={<span className="flex items-center gap-2">Needs attention {attention > 0 && <Badge tone="amber">{attention}</Badge>}</span>} className="xl:col-span-2">
          <div className="space-y-4 text-sm">
            {d.pending_approvals > 0 && (
              <Link to="/approvals" className="flex items-center justify-between rounded-lg bg-amber-50 px-3 py-2 text-amber-900 hover:bg-amber-100 dark:bg-amber-950/40 dark:text-amber-200">
                <span className="flex items-center gap-2"><ClipboardCheck className="h-4 w-4" />{d.pending_approvals} change(s) awaiting approval</span><ArrowRight className="h-4 w-4" />
              </Link>
            )}
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><TimerOff className="h-3.5 w-3.5" />Not polled in 24h</p>
              {d.stale_devices.length ? d.stale_devices.map((s) => (
                <Link key={s.id} to={`/devices/${s.id}`} className="flex items-center justify-between py-0.5 hover:underline"><span className="truncate">{s.hostname}</span><span className="text-xs text-slate-500">{ago(s.last_seen_at)}</span></Link>
              )) : <p className="text-slate-500">Every monitored device was polled recently.</p>}
            </div>
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><DatabaseBackup className="h-3.5 w-3.5" />Never backed up</p>
              {bc.never_devices.length ? <div className="flex flex-wrap gap-1">{bc.never_devices.map((h) => <Badge key={h} tone="amber">{h}</Badge>)}{bc.never > bc.never_devices.length && <Badge>+{bc.never - bc.never_devices.length}</Badge>}</div>
                : <p className="text-slate-500">All switches and firewalls have a configuration backup.</p>}
            </div>
            <div>
              <p className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><CalendarClock className="h-3.5 w-3.5" />Next scheduled runs</p>
              {d.upcoming_schedules.length ? d.upcoming_schedules.map((s) => (
                <Link key={s.id} to="/schedules" className="flex items-center justify-between py-0.5 hover:underline"><span className="truncate">{s.name}</span><span className="text-xs text-slate-500">{fmtDate(s.next_run_at)}</span></Link>
              )) : <p className="text-slate-500">No schedules. <Link to="/schedules" className="text-brand-600 hover:underline">Create one</Link></p>}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

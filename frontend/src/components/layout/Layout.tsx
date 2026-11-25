import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, AlertTriangle, Archive, ArchiveRestore, Bell, Boxes, Bug, CalendarClock, ChevronDown, ChevronRight, ClipboardList, Code2, FileBarChart, FileCheck2, FileSpreadsheet,
  CheckCheck, ClipboardCheck, FileClock, FlaskConical, FolderTree, Gauge, GitCompare, History, KeyRound, Landmark, LayoutDashboard, LogOut, Menu, Monitor, Moon, Network,
  PackageCheck, PlayCircle, Plug, Router, ScrollText, Search, Server, Settings, Shield, ShieldAlert, ShieldCheck, Sun, UserRound, Users, UsersRound, Wifi, Workflow, X,
} from "lucide-react";
import { ReactNode, useEffect, useRef, useState } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../../lib/api";
import { ErrorBoundary } from "../ErrorBoundary";
import { BrandMark, useBranding } from "../../lib/branding";
import { useAuth } from "../../lib/auth";
import { ago } from "../../lib/format";
import type { Notification } from "../../lib/types";

type NavItem = { to: string; label: string; icon: ReactNode; perm?: string; match?: string };
type NavSection = { section: string; icon: ReactNode; items: NavItem[] };
const I = (C: typeof Server) => <C className="h-4 w-4" />;
// Navigation follows the platform's functional areas. Infrastructure entries are filtered views of the device inventory.
export const NAV: NavSection[] = [
  { section: "Overview", icon: I(LayoutDashboard), items: [
    { to: "/", label: "Dashboard", icon: I(LayoutDashboard), perm: "dashboard.read" },
    { to: "/alerts", label: "Alerts", icon: I(ShieldAlert), perm: "alerts.read" },
  ] },
  { section: "Infrastructure", icon: I(Server), items: [
    { to: "/devices", label: "All devices", icon: I(Server), perm: "devices.read", match: "/devices?" },
    { to: "/devices?device_type=windows_server", label: "Windows servers", icon: I(Server), perm: "devices.read" },
    { to: "/devices?device_type=linux_server", label: "Linux servers", icon: I(Server), perm: "devices.read" },
    { to: "/devices?device_type=firewall", label: "Firewalls", icon: I(Shield), perm: "devices.read" },
    { to: "/devices?device_type=switch", label: "Switches", icon: I(Network), perm: "devices.read" },
    { to: "/devices?device_type=router", label: "Routers", icon: I(Router), perm: "devices.read" },
    { to: "/devices?device_type=access_point", label: "Access points", icon: I(Wifi), perm: "devices.read" },
    { to: "/inventory", label: "Sites & groups", icon: I(Boxes), perm: "devices.read" },
  ] },
  { section: "Active Directory", icon: I(UsersRound), items: [
    { to: "/ad/overview", label: "Overview", icon: I(UsersRound), perm: "ad.read" },
    { to: "/ad/users", label: "Users", icon: I(UserRound), perm: "ad.read" },
    { to: "/ad/groups", label: "Groups", icon: I(UsersRound), perm: "ad.read" },
    { to: "/ad/computers", label: "Computers", icon: I(Monitor), perm: "ad.read" },
    { to: "/ad/ous", label: "Organizational units", icon: I(FolderTree), perm: "ad.read" },
    { to: "/ad/dcs", label: "Domain controllers", icon: I(Server), perm: "ad.read" },
    { to: "/ad/reports", label: "AD reports", icon: I(FileBarChart), perm: "ad.read" },
  ] },
  { section: "Group Policy", icon: I(ScrollText), items: [
    { to: "/gpo/inventory", label: "GPO inventory", icon: I(ScrollText), perm: "gpo.read", match: "/gpo/object" },
    { to: "/gpo/reports", label: "GPO reports", icon: I(FileBarChart), perm: "gpo.read" },
    { to: "/gpo/compare", label: "GPO comparison", icon: I(GitCompare), perm: "gpo.read" },
    { to: "/gpo/baseline", label: "GPO compliance", icon: I(ShieldCheck), perm: "gpo.read" },
    { to: "/gpo/backup", label: "Backup & restore", icon: I(ArchiveRestore), perm: "gpo.read" },
  ] },
  { section: "Security Operations", icon: I(ShieldAlert), items: [
    { to: "/alerts", label: "Security alerts", icon: I(ShieldAlert), perm: "alerts.read" },
    { to: "/reports/center?r=vulnerability-risk", label: "Vulnerabilities & risk", icon: I(Bug), perm: "reports.read" },
    { to: "/reports/center?r=patch-compliance", label: "Patch management", icon: I(PackageCheck), perm: "reports.read" },
    { to: "/reports/center?r=config-changes", label: "Configuration changes", icon: I(History), perm: "reports.read" },
    { to: "/approvals", label: "Approvals", icon: I(ClipboardCheck), perm: "approvals.read" },
  ] },
  { section: "Operations", icon: I(PlayCircle), items: [
    { to: "/jobs", label: "Jobs", icon: I(PlayCircle) },
    { to: "/automation", label: "Automation", icon: I(Workflow) },
    { to: "/scripts", label: "Scripts", icon: I(Code2), perm: "scripts.read" },
    { to: "/schedules", label: "Schedules", icon: I(CalendarClock), perm: "automation.read" },
  ] },
  { section: "IT Audit", icon: I(ClipboardList), items: [
    { to: "/compliance/dashboard", label: "Audit dashboard", icon: I(Gauge), perm: "compliance.read" },
    { to: "/compliance/assessments", label: "Assessments", icon: I(ClipboardList), perm: "compliance.read" },
    { to: "/compliance/findings", label: "Findings", icon: I(AlertTriangle), perm: "compliance.read" },
    { to: "/compliance/evidence", label: "Evidence repository", icon: I(FileCheck2), perm: "compliance.read" },
    { to: "/compliance/frameworks", label: "Compliance frameworks", icon: I(Landmark), perm: "compliance.read" },
  ] },
  { section: "Reports", icon: I(FileBarChart), items: [
    { to: "/reports/center", label: "Report center", icon: I(FileBarChart), perm: "reports.read" },
    { to: "/reports/schedules", label: "Scheduled reports", icon: I(CalendarClock), perm: "reports.read" },
    { to: "/reports/history", label: "Historical reports", icon: I(Archive), perm: "reports.read" },
    { to: "/reports/operational", label: "Operational reports", icon: I(FileSpreadsheet), perm: "dashboard.read" },
  ] },
  { section: "Administration", icon: I(Settings), items: [
    { to: "/users", label: "Users & roles", icon: I(Users), perm: "users.manage" },
    { to: "/credentials", label: "Credentials", icon: I(KeyRound), perm: "credentials.read" },
    { to: "/integrations", label: "Integrations", icon: I(Plug), perm: "integrations.manage" },
    { to: "/ad/domains", label: "AD domains", icon: I(Network), perm: "ad.read" },
    { to: "/settings", label: "Settings", icon: I(Settings) },
    { to: "/audit", label: "Audit log", icon: I(FileClock), perm: "audit.read" },
  ] },
];

function isActive(item: NavItem, path: string, search: string): boolean {
  const [p, q] = item.to.split("?");
  if (p === "/") return path === "/";
  if (q) {
    const want = new URLSearchParams(q);
    const have = new URLSearchParams(search);
    return path === p && [...want.entries()].every(([k, v]) => k === "r" ? true : have.get(k) === v) && (p !== "/reports/center" || have.get("r") === want.get("r"));
  }
  if (p === "/devices") return path.startsWith("/devices") && !new URLSearchParams(search).get("device_type");
  return path === p || path.startsWith(p + "/") || (!!item.match && path.startsWith(item.match));
}

export function Breadcrumbs() {
  const loc = useLocation();
  let section: NavSection | undefined, item: NavItem | undefined;
  for (const s of NAV) {
    const hit = s.items.find((i) => isActive(i, loc.pathname, loc.search));
    if (hit) { section = s; item = hit; break; }
  }
  if (!section || !item || loc.pathname === "/") return null;
  const detail = /\/(object|assessments|findings)\/[^/]+$/.test(loc.pathname) || /^\/(devices|jobs)\/\d+/.test(loc.pathname);
  return (
    <nav aria-label="Breadcrumb" className="mb-3 flex flex-wrap items-center gap-1 text-xs text-slate-500">
      <Link to="/" className="hover:text-slate-700 dark:hover:text-slate-300">Home</Link><ChevronRight className="h-3 w-3" />
      <span>{section.section}</span><ChevronRight className="h-3 w-3" />
      {detail ? <><Link to={item.to} className="hover:text-slate-700 dark:hover:text-slate-300">{item.label}</Link><ChevronRight className="h-3 w-3" /><span className="text-slate-700 dark:text-slate-300">Details</span></>
        : <span className="text-slate-700 dark:text-slate-300">{item.label}</span>}
    </nav>
  );
}

export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => (document.documentElement.classList.contains("dark") ? "dark" : "light"));
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.classList.toggle("dark", next === "dark");
    try { localStorage.setItem("ip-theme", next); } catch { /* storage unavailable */ }
    setTheme(next);
  };
  return [theme, toggle];
}

function GlobalSearch() {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const box = useRef<HTMLDivElement>(null);
  const { data } = useQuery({
    queryKey: ["search", q], enabled: q.trim().length >= 2,
    queryFn: () => api<{ devices: { id: number; hostname: string; ip_address: string; status: string }[]; jobs: { id: number; title: string; status: string }[];
      alerts: { id: number; title: string; severity: string }[] }>(`/api/search?q=${encodeURIComponent(q.trim())}`),
  });
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const k = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); box.current?.querySelector("input")?.focus(); } };
    document.addEventListener("mousedown", h); document.addEventListener("keydown", k);
    return () => { document.removeEventListener("mousedown", h); document.removeEventListener("keydown", k); };
  }, []);
  const go = (path: string) => { setOpen(false); setQ(""); nav(path); };
  const empty = data && !data.devices.length && !data.jobs.length && !data.alerts.length;
  return (
    <div ref={box} className="relative w-full max-w-md">
      <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" aria-hidden />
      <input className="input pl-9" placeholder="Search devices, jobs, alerts…  (Ctrl+K)" value={q} aria-label="Global search"
        onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} />
      {open && q.trim().length >= 2 && data && (
        <div className="absolute z-40 mt-1 w-full overflow-hidden rounded-md border border-slate-200 bg-white text-sm shadow-lg dark:border-slate-700 dark:bg-slate-900">
          {empty && <p className="px-3 py-3 text-slate-500">No matches for “{q}”.</p>}
          {data.devices.map((d) => (
            <button key={`d${d.id}`} onClick={() => go(`/devices/${d.id}`)} className="flex w-full items-center justify-between px-3 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800">
              <span><Server className="mr-2 inline h-3.5 w-3.5 text-slate-400" />{d.hostname}</span><span className="font-mono text-xs text-slate-500">{d.ip_address}</span>
            </button>
          ))}
          {data.jobs.map((j) => (
            <button key={`j${j.id}`} onClick={() => go(`/jobs/${j.id}`)} className="flex w-full items-center px-3 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800">
              <PlayCircle className="mr-2 h-3.5 w-3.5 text-slate-400" />#{j.id} {j.title}
            </button>
          ))}
          {data.alerts.map((a) => (
            <button key={`a${a.id}`} onClick={() => go(`/alerts`)} className="flex w-full items-center px-3 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800">
              <ShieldAlert className="mr-2 h-3.5 w-3.5 text-slate-400" />{a.title}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const nav = useNavigate();
  const { data } = useQuery({ queryKey: ["notifications"], queryFn: () => api<{ unread: number; items: Notification[] }>("/api/notifications"),
    refetchInterval: 30000 });
  const markAll = async () => { await api("/api/notifications/read", { method: "POST" }); qc.invalidateQueries({ queryKey: ["notifications"] }); };
  const dot = { error: "bg-red-500", warning: "bg-amber-500", success: "bg-emerald-500", info: "bg-brand-500" } as Record<string, string>;
  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} className="relative rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
        aria-label={`Notifications (${data?.unread || 0} unread)`}>
        <Bell className="h-5 w-5" />
        {!!data?.unread && <span className="absolute right-1 top-1 min-w-[1.1rem] rounded-full bg-red-600 px-1 text-[10px] font-semibold leading-4 text-white">{data.unread > 99 ? "99+" : data.unread}</span>}
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-md border border-slate-200 bg-white shadow-xl dark:border-slate-700 dark:bg-slate-900 sm:w-96">
          <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2 dark:border-slate-800">
            <span className="text-sm font-semibold">Notifications</span>
            <button onClick={markAll} className="flex items-center gap-1 text-xs text-brand-600 hover:underline"><CheckCheck className="h-3.5 w-3.5" />Mark all read</button>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {!data?.items.length && <p className="px-3 py-6 text-center text-sm text-slate-500">You're all caught up.</p>}
            {data?.items.map((n) => (
              <button key={n.id} onClick={() => { setOpen(false); if (n.link) nav(n.link); }}
                className={clsx("flex w-full gap-2 border-b border-slate-100 px-3 py-2 text-left text-sm last:border-0 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800", !n.read && "bg-brand-50/50 dark:bg-brand-900/10")}>
                <span className={clsx("mt-1.5 h-2 w-2 shrink-0 rounded-full", dot[n.level] || "bg-slate-400")} />
                <span className="min-w-0"><span className="block font-medium">{n.title}</span>
                  {n.body && <span className="line-clamp-2 block text-xs text-slate-500">{n.body}</span>}
                  <span className="text-[11px] text-slate-400">{ago(n.created_at)}</span></span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function Layout() {
  const { user, logout, can } = useAuth();
  const brand = useBranding();
  const [theme, toggleTheme] = useTheme();
  const [mobile, setMobile] = useState(false);
  const loc = useLocation();
  useEffect(() => setMobile(false), [loc.pathname]);
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    const all = NAV.map((x) => x.section).filter((x) => x !== "Overview"); // collapsed by default; the active section always opens
    try { const v = localStorage.getItem("ip-nav-collapsed"); return new Set(v ? JSON.parse(v) : all); } catch { return new Set(all); }
  });
  const toggle = (sec: string) => setCollapsed((c) => {
    const n = new Set(c); if (n.has(sec)) n.delete(sec); else n.add(sec);
    try { localStorage.setItem("ip-nav-collapsed", JSON.stringify([...n])); } catch { /* storage unavailable */ }
    return n;
  });
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: () => api<{ mode: string; version?: string }>("/api/meta"), staleTime: 300000 });

  const sidebar = (
    <nav className="flex h-full flex-col gap-2 overflow-y-auto px-3 py-4" aria-label="Main">
      <Link to="/" className="flex items-center gap-2 px-2">
        <BrandMark className="h-8 w-8 shrink-0 bg-white p-0.5" fallback={<span className="rounded-md bg-brand-600 p-1.5 text-white"><Network className="h-5 w-5" /></span>} />
        <span className="min-w-0">
          <span className="block truncate text-lg font-semibold leading-tight tracking-tight text-white">{brand.product_name}</span>
          {brand.organization && <span className="block truncate text-[11px] text-slate-400">{brand.organization}</span>}
        </span>
      </Link>
      {NAV.map((s) => {
        const items = s.items.filter((i) => !i.perm || can(i.perm));
        if (!items.length) return null;
        const active = items.some((i) => isActive(i, loc.pathname, loc.search));
        const open = active || !collapsed.has(s.section);
        return (
          <div key={s.section}>
            <button onClick={() => toggle(s.section)} aria-expanded={open}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 hover:text-slate-300">
              <span className="flex-1 text-left">{s.section}</span>{open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            </button>
            {open && items.map((i) => (
              <Link key={i.to + i.label} to={i.to} aria-current={isActive(i, loc.pathname, loc.search) ? "page" : undefined}
                className={clsx("flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm",
                  isActive(i, loc.pathname, loc.search) ? "bg-slate-800 text-white" : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100")}>
                {i.icon}{i.label}
              </Link>
            ))}
          </div>
        );
      })}
      <div className="mt-auto rounded-md border border-slate-800 p-2 text-xs text-slate-500">
        <Activity className="mr-1 inline h-3 w-3" /> {meta?.mode === "demo" ? "Demo mode" : "Production"} · {brand.product_name === "InfraPilot" ? `v${meta?.version || "?"}` : `InfraPilot ${meta?.version || ""}`}
      </div>
    </nav>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 hidden w-60 bg-slate-900 lg:block dark:bg-slate-950 dark:border-r dark:border-slate-800">{sidebar}</aside>
      {mobile && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-slate-900/60" onClick={() => setMobile(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 bg-slate-900">{sidebar}
            <button className="absolute right-2 top-3 p-1 text-slate-400" onClick={() => setMobile(false)} aria-label="Close menu"><X className="h-5 w-5" /></button>
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        {meta?.mode === "demo" && (
          <div className="flex items-center justify-center gap-2 bg-violet-600 px-3 py-1 text-xs font-medium text-white">
            <FlaskConical className="h-3.5 w-3.5" /> DEMO MODE — devices marked “Simulated” are not real; their output is generated.
          </div>
        )}
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-slate-200 bg-white/90 px-4 py-2.5 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
          <button className="rounded p-1.5 text-slate-500 lg:hidden" onClick={() => setMobile(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
          <GlobalSearch />
          <div className="ml-auto flex items-center gap-1">
            <button onClick={toggleTheme} className="rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Toggle dark mode">
              {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>
            <NotificationCenter />
            <div className="ml-2 hidden text-right text-xs sm:block">
              <p className="font-medium text-slate-700 dark:text-slate-200">{user?.display_name || user?.username}</p>
              <p className="text-slate-500">{user?.roles.map((r) => r.role).join(", ") || "No role"}</p>
            </div>
            <button onClick={logout} className="ml-1 rounded-md p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Sign out" title="Sign out"><LogOut className="h-5 w-5" /></button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6"><Breadcrumbs /><ErrorBoundary key={loc.pathname}><Outlet /></ErrorBoundary></main>
      </div>
    </div>
  );
}

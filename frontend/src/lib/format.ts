export function fmtDate(v: string | null | undefined): string {
  if (!v) return "—";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function ago(v: string | null | undefined): string {
  if (!v) return "never";
  const s = Math.round((Date.now() - new Date(v).getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const label = (s: string) => s.replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

export const DEVICE_TYPE_LABEL: Record<string, string> = {
  windows_server: "Windows Server", linux_server: "Linux Server", switch: "Switch", router: "Router", firewall: "Firewall",
  access_point: "Access Point", hypervisor: "Hypervisor", storage: "Storage", workstation: "Workstation",
};

export const FAMILY_LABEL: Record<string, string> = {
  common: "General", windows: "Windows", ad: "Active Directory / DNS / DHCP / GPO", linux: "Linux", network: "Network",
  firewall: "Firewall", virtualization: "Virtualization", automation: "Automation",
};

export function duration(a: string | null, b: string | null): string {
  if (!a) return "—";
  const ms = (b ? new Date(b) : new Date()).getTime() - new Date(a).getTime();
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

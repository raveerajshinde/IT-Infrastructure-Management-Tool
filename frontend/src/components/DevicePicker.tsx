import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, qs } from "../lib/api";
import { DEVICE_TYPE_LABEL } from "../lib/format";
import type { Device, Paged } from "../lib/types";
import { Badge } from "./ui";

const CATEGORY_TYPES: Record<string, string[]> = {
  windows: ["windows_server", "workstation"], linux: ["linux_server"], network: ["switch", "router", "access_point"],
  firewall: ["firewall"], virtualization: ["hypervisor", "storage"],
};

export function DevicePicker({ value, onChange, deviceType, category, platforms }: {
  value: number[]; onChange: (ids: number[]) => void; deviceType?: string; category?: string; platforms?: string[];
}) {
  const [q, setQ] = useState("");
  const { data } = useQuery({ queryKey: ["devices", "picker", q, deviceType], queryFn: () => api<Paged<Device>>(`/api/devices${qs({ q, device_type: deviceType, page_size: 50 })}`) });
  const toggle = (id: number) => onChange(value.includes(id) ? value.filter((x) => x !== id) : [...value, id]);
  return (
    <div className="rounded-md border border-slate-200 dark:border-slate-700">
      <div className="flex items-center gap-2 border-b border-slate-200 p-2 dark:border-slate-700">
        <input className="input" placeholder="Filter devices…" aria-label="Filter devices" value={q} onChange={(e) => setQ(e.target.value)} />
        <Badge tone="blue">{value.length} selected</Badge>
      </div>
      <ul className="max-h-56 overflow-y-auto text-sm">
        {(data?.items || []).filter((d) => (!category || !CATEGORY_TYPES[category] || CATEGORY_TYPES[category].includes(d.device_type)) && (!platforms || platforms.includes(d.driver))).map((d) => (
          <li key={d.id}><label className="flex cursor-pointer items-center gap-2 px-3 py-1.5 hover:bg-slate-50 dark:hover:bg-slate-800">
            <input type="checkbox" checked={value.includes(d.id)} onChange={() => toggle(d.id)} />
            <span className="font-medium">{d.hostname}</span><span className="font-mono text-xs text-slate-500">{d.ip_address}</span>
            <span className="ml-auto text-xs text-slate-500">{DEVICE_TYPE_LABEL[d.device_type]} · {d.environment}</span></label></li>
        ))}
        {data && !data.items.length && <li className="px-3 py-4 text-center text-slate-500">No devices found.</li>}
      </ul>
    </div>
  );
}

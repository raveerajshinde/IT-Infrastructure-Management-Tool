import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowDownUp, Bookmark, Download, FileUp, FlaskConical, Play, Plus, Server, Trash2, X } from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { DeviceForm } from "../components/DeviceForm";
import { OperationRunner } from "../components/OperationRunner";
import {
  Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, Pagination, Skeleton, StatusBadge, useConfirm, useToast,
} from "../components/ui";
import { api, download, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { DEVICE_TYPE_LABEL, FAMILY_LABEL, ago } from "../lib/format";
import type { Device, Group, Meta, Operation, Paged, Site } from "../lib/types";

const FILTER_KEYS = ["q", "device_type", "environment", "status", "site_id", "group_id", "tag"] as const;

function ImportModal({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [update, setUpdate] = useState(false);
  const [result, setResult] = useState<{ rows: number; create: number; update: number; errors: { row: number; hostname: string; error: string }[]; applied: boolean } | null>(null);
  const [busy, setBusy] = useState(false); const [err, setErr] = useState<unknown>(null);
  const qc = useQueryClient(); const toast = useToast();
  const send = async (dry: boolean) => {
    if (!file) return;
    setBusy(true); setErr(null);
    const fd = new FormData(); fd.append("file", file); fd.append("dry_run", String(dry)); fd.append("update_existing", String(update));
    try {
      const r = await api<typeof result>("/api/devices-import", { form: fd });
      setResult(r);
      if (r?.applied) { qc.invalidateQueries({ queryKey: ["devices"] }); toast({ tone: "success", title: "Import complete", body: `${r.create} created, ${r.update} updated` }); onClose(); }
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return (
    <Modal open onClose={onClose} title="Import devices (CSV or Excel)" size="lg"
      footer={<><Button variant="outline" onClick={onClose}>Close</Button>
        <Button variant="secondary" disabled={!file} loading={busy} onClick={() => send(true)}>Validate (dry-run)</Button>
        <Button disabled={!file || !result || result.errors.length > 0} loading={busy} onClick={() => send(false)}>Import {result ? result.create + result.update : ""} device(s)</Button></>}>
      <div className="space-y-3 text-sm">
        <p>Columns: <span className="font-mono text-xs">hostname, ip_address, device_type, driver, vendor, model, os_name, os_version, firmware, serial_number, owner, department, environment, site, credential, port, tags, notes</span>.
          Sites and credentials are matched by name; tags are separated by semicolons.</p>
        <Button variant="outline" size="sm" icon={<Download className="h-4 w-4" />} onClick={() => download("/api/devices-import/template", "device-import-template.csv")}>Download template</Button>
        <input type="file" accept=".csv,.xlsx" aria-label="Import file" onChange={(e) => { setFile(e.target.files?.[0] || null); setResult(null); }}
          className="block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-brand-50 file:px-3 file:py-2 file:text-brand-700" />
        <label className="flex items-center gap-2"><input type="checkbox" checked={update} onChange={(e) => { setUpdate(e.target.checked); setResult(null); }} /> Update devices that already exist (matched by hostname + IP)</label>
        <ErrorBox error={err} />
        {result && (result.errors.length ? (
          <Callout tone="danger" title={`${result.errors.length} row(s) have problems — nothing was imported`}>
            <ul className="mt-1 max-h-48 list-disc overflow-y-auto pl-5">{result.errors.map((e) => <li key={e.row}>Row {e.row} {e.hostname && `(${e.hostname})`}: {e.error}</li>)}</ul>
          </Callout>
        ) : <Callout tone="success" title="Validation passed">{result.create} device(s) will be created and {result.update} updated.</Callout>)}
      </div>
    </Modal>
  );
}

function BulkOperation({ ids, devices, onClose }: { ids: number[]; devices: Device[]; onClose: () => void }) {
  const { data: ops } = useQuery({ queryKey: ["operations"], queryFn: () => api<Operation[]>("/api/operations") });
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: () => api<Meta>("/api/meta") });
  const [op, setOp] = useState<Operation | null>(null);
  const selected = devices.filter((d) => ids.includes(d.id));
  const common = useMemo(() => {
    if (!ops || !meta) return [];
    const sets = selected.map((d) => new Set(d.is_simulated ? ops.map((o) => o.id) : [...(meta.drivers.find((x) => x.name === d.driver)?.operations || []), "automation.ansible"]));
    return ops.filter((o) => o.allowed && sets.every((s) => s.has(o.id)));
  }, [ops, meta, selected]);
  if (op) return <OperationRunner op={op} deviceIds={ids} onClose={onClose} />;
  const fams = [...new Set(common.map((o) => o.family))];
  return (
    <Modal open onClose={onClose} title={`Run operation on ${ids.length} device(s)`} size="lg">
      {!common.length ? <EmptyState title="No common operation" hint="The selected devices use different drivers or you lack permissions. Narrow the selection to one device type." /> :
        fams.map((f) => (
          <div key={f} className="mb-3">
            <p className="label">{FAMILY_LABEL[f] || f}</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {common.filter((o) => o.family === f).map((o) => (
                <button key={o.id} onClick={() => setOp(o)} className="flex items-center justify-between rounded-md border border-slate-200 px-3 py-2 text-left text-sm hover:border-brand-400 hover:bg-brand-50 dark:border-slate-700 dark:hover:bg-slate-800">
                  <span>{o.name}</span><Badge tone={o.mutating ? "amber" : "gray"}>{o.mutating ? o.risk : "read"}</Badge>
                </button>
              ))}
            </div>
          </div>
        ))}
    </Modal>
  );
}

function GroupAssign({ ids, onClose }: { ids: number[]; onClose: () => void }) {
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const [gid, setGid] = useState(""); const qc = useQueryClient(); const toast = useToast();
  const save = async () => {
    await api(`/api/groups/${gid}/members`, { body: { device_ids: ids, action: "add" } });
    qc.invalidateQueries({ queryKey: ["groups"] }); toast({ tone: "success", title: `Added ${ids.length} device(s) to group` }); onClose();
  };
  return (
    <Modal open onClose={onClose} size="sm" title="Add to group" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button disabled={!gid} onClick={save}>Add</Button></>}>
      <Field label="Group" htmlFor="grp"><select id="grp" className="input" value={gid} onChange={(e) => setGid(e.target.value)}>
        <option value="">Select…</option>{(groups || []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}</select></Field>
    </Modal>
  );
}

export default function Devices() {
  const [sp, setSp] = useSearchParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const confirm = useConfirm(); const toast = useToast();
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState<{ k: string; o: "asc" | "desc" }>({ k: "hostname", o: "asc" });
  const [selected, setSelected] = useState<number[]>([]);
  const [modal, setModal] = useState<"" | "add" | "import" | "bulk" | "group" | "save">(() => (sp.get("new") ? "add" : ""));
  const [qInput, setQInput] = useState(sp.get("q") || "");
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, sp.get(k) || ""]));
  useEffect(() => setPage(1), [sp]);
  useEffect(() => { const t = setTimeout(() => { if ((sp.get("q") || "") !== qInput) setFilter("q", qInput); }, 350); return () => clearTimeout(t); }, [qInput]); // eslint-disable-line

  const { data, isLoading, error } = useQuery({
    queryKey: ["devices", filters, page, sort],
    queryFn: () => api<Paged<Device>>(`/api/devices${qs({ ...filters, page, page_size: 25, sort: sort.k, order: sort.o })}`),
    placeholderData: (p) => p, refetchInterval: 60000,
  });
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: () => api<Meta>("/api/meta") });
  const { data: sites } = useQuery({ queryKey: ["sites"], queryFn: () => api<Site[]>("/api/sites") });
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const { data: saved } = useQuery({ queryKey: ["saved-filters"], queryFn: () => api<{ id: number; name: string; filters: Record<string, string> }[]>("/api/saved-filters") });

  const setFilter = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n); };
  const toggleSort = (k: string) => setSort((s) => ({ k, o: s.k === k && s.o === "asc" ? "desc" : "asc" }));
  const del = useMutation({
    mutationFn: async (ids: number[]) => { for (const id of ids) await api(`/api/devices/${id}`, { method: "DELETE" }); },
    onSuccess: (_, ids) => { setSelected([]); qc.invalidateQueries({ queryKey: ["devices"] }); toast({ tone: "success", title: `Removed ${ids.length} device(s)` }); },
    onError: (e: Error) => toast({ tone: "error", title: "Delete failed", body: e.message }),
  });
  const [filterName, setFilterName] = useState("");
  const saveFilter = async (e: FormEvent) => {
    e.preventDefault();
    await api("/api/saved-filters", { body: { name: filterName, filters: Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) } });
    qc.invalidateQueries({ queryKey: ["saved-filters"] }); setModal(""); setFilterName("");
  };
  const items = data?.items || [];
  const allChecked = items.length > 0 && items.every((d) => selected.includes(d.id));
  const activeFilters = Object.values(filters).filter(Boolean).length;
  const SortTh = ({ k, children, className }: { k: string; children: string; className?: string }) => (
    <th className={clsx("th", className)}><button className="inline-flex items-center gap-1 uppercase" onClick={() => toggleSort(k)}>{children}
      <ArrowDownUp className={clsx("h-3 w-3", sort.k === k ? "text-brand-600" : "text-slate-300")} /></button></th>
  );

  return (
    <div>
      <PageHeader title="Devices" subtitle="Inventory of managed servers, network devices, firewalls, hypervisors and storage."
        actions={<>
          {can("devices.import") && <Button variant="outline" icon={<Download className="h-4 w-4" />} onClick={() => download(`/api/devices-export${qs({ fmt: "xlsx", ...filters })}`, "devices.xlsx")}>Export Excel</Button>}
          {can("devices.import") && <Button variant="outline" icon={<Download className="h-4 w-4" />} onClick={() => download(`/api/devices-export${qs({ fmt: "csv", ...filters })}`, "devices.csv")}>CSV</Button>}
          {can("devices.import") && can("devices.write") && <Button variant="outline" icon={<FileUp className="h-4 w-4" />} onClick={() => setModal("import")}>Import</Button>}
          {can("devices.write") && <Button icon={<Plus className="h-4 w-4" />} onClick={() => setModal("add")}>Add device</Button>}
        </>} />

      <Card padded={false}>
        <div className="flex flex-wrap items-end gap-2 border-b border-slate-200 p-3 dark:border-slate-800">
          <input className="input w-full sm:w-64" placeholder="Search hostname, IP, serial, owner…" aria-label="Search devices" value={qInput} onChange={(e) => setQInput(e.target.value)} />
          <select className="input w-auto" aria-label="Device type" value={filters.device_type} onChange={(e) => setFilter("device_type", e.target.value)}>
            <option value="">All types</option>{(meta?.device_types || []).map((t) => <option key={t} value={t}>{DEVICE_TYPE_LABEL[t]}</option>)}</select>
          <select className="input w-auto" aria-label="Status" value={filters.status} onChange={(e) => setFilter("status", e.target.value)}>
            <option value="">Any status</option>{["up", "degraded", "down", "unknown"].map((s) => <option key={s}>{s}</option>)}</select>
          <select className="input w-auto" aria-label="Environment" value={filters.environment} onChange={(e) => setFilter("environment", e.target.value)}>
            <option value="">All environments</option>{(meta?.environments || []).map((s) => <option key={s}>{s}</option>)}</select>
          <select className="input w-auto" aria-label="Site" value={filters.site_id} onChange={(e) => setFilter("site_id", e.target.value)}>
            <option value="">All sites</option>{(sites || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          <select className="input w-auto" aria-label="Group" value={filters.group_id} onChange={(e) => setFilter("group_id", e.target.value)}>
            <option value="">All groups</option>{(groups || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          {activeFilters > 0 && <Button variant="ghost" size="sm" icon={<X className="h-3.5 w-3.5" />} onClick={() => { setQInput(""); setSp(new URLSearchParams()); }}>Clear</Button>}
          <div className="ml-auto flex items-center gap-2">
            {saved && saved.length > 0 && (
              <select className="input w-auto" aria-label="Saved filters" value="" onChange={(e) => { const f = saved.find((s) => String(s.id) === e.target.value); if (f) { setQInput(f.filters.q || ""); setSp(new URLSearchParams(f.filters)); } }}>
                <option value="">Saved filters…</option>{saved.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
            )}
            {activeFilters > 0 && <Button variant="outline" size="sm" icon={<Bookmark className="h-3.5 w-3.5" />} onClick={() => setModal("save")}>Save filter</Button>}
          </div>
        </div>
        {selected.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 bg-brand-50 px-3 py-2 text-sm dark:border-slate-800 dark:bg-brand-900/20">
            <span className="font-medium">{selected.length} selected</span>
            <Button size="sm" icon={<Play className="h-3.5 w-3.5" />} onClick={() => setModal("bulk")}>Run operation</Button>
            {can("devices.write") && <Button size="sm" variant="outline" onClick={() => setModal("group")}>Add to group</Button>}
            {can("devices.delete") && <Button size="sm" variant="danger" icon={<Trash2 className="h-3.5 w-3.5" />} onClick={async () => {
              if (await confirm({ title: "Remove devices?", message: `Remove ${selected.length} device(s) from the inventory? History and audit records are kept. Nothing is changed on the devices.`, danger: true, confirmLabel: "Remove" })) del.mutate(selected);
            }}>Remove</Button>}
            <Button size="sm" variant="ghost" onClick={() => setSelected([])}>Clear selection</Button>
          </div>
        )}
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isLoading ? <Skeleton rows={8} /> : !items.length ? (
          <EmptyState icon={<Server className="h-6 w-6" />} title={activeFilters ? "No devices match these filters" : "No devices registered yet"}
            hint={activeFilters ? "Adjust or clear the filters." : "Register devices one by one or import a CSV/Excel inventory."}
            action={!activeFilters && can("devices.write") ? <Button icon={<Plus className="h-4 w-4" />} onClick={() => setModal("add")}>Add device</Button> : undefined} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead className="bg-slate-50 dark:bg-slate-900/60"><tr>
                <th className="th w-8"><input type="checkbox" aria-label="Select all" checked={allChecked} onChange={() => setSelected(allChecked ? [] : items.map((d) => d.id))} /></th>
                <SortTh k="hostname">Hostname</SortTh><SortTh k="ip_address">Address</SortTh><SortTh k="device_type">Type</SortTh>
                <th className="th">Vendor / OS</th><th className="th">Site</th><SortTh k="environment">Env</SortTh><SortTh k="status">Status</SortTh><SortTh k="last_seen_at">Last seen</SortTh><th className="th" />
              </tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {items.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="td"><input type="checkbox" aria-label={`Select ${d.hostname}`} checked={selected.includes(d.id)} onChange={() => setSelected((s) => s.includes(d.id) ? s.filter((x) => x !== d.id) : [...s, d.id])} /></td>
                    <td className="td"><Link to={`/devices/${d.id}`} className="font-medium text-brand-700 hover:underline dark:text-brand-300">{d.hostname}</Link>
                      {d.is_simulated && <Badge tone="violet" className="ml-2"><FlaskConical className="h-3 w-3" />Simulated</Badge>}
                      {d.tags.length > 0 && <div className="mt-0.5 flex flex-wrap gap-1">{d.tags.map((t) => <button key={t} onClick={() => setFilter("tag", t)} className="rounded bg-slate-100 px-1.5 text-[11px] text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300">{t}</button>)}</div>}</td>
                    <td className="td font-mono text-xs">{d.ip_address}</td>
                    <td className="td">{DEVICE_TYPE_LABEL[d.device_type] || d.device_type}</td>
                    <td className="td text-slate-600 dark:text-slate-300"><div>{d.vendor || "—"}</div><div className="text-xs text-slate-500">{[d.os_name, d.os_version].filter(Boolean).join(" ")}</div></td>
                    <td className="td">{d.site?.name || "—"}</td>
                    <td className="td"><Badge tone={d.environment === "production" ? "amber" : "gray"}>{d.environment}</Badge></td>
                    <td className="td"><StatusBadge status={d.status} /></td>
                    <td className="td text-xs text-slate-500" title={d.last_seen_at || ""}>{ago(d.last_seen_at)}</td>
                    <td className="td text-right"><Link to={`/devices/${d.id}?tab=manage`} className="rounded-md px-2 py-1 text-xs font-medium text-brand-600 hover:bg-brand-50 dark:hover:bg-brand-900/30">Manage</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && <Pagination page={page} pageSize={25} total={data.total} onPage={setPage} />}
      </Card>

      {modal === "add" && <DeviceForm onClose={() => setModal("")} />}
      {modal === "import" && <ImportModal onClose={() => setModal("")} />}
      {modal === "bulk" && <BulkOperation ids={selected} devices={items} onClose={() => setModal("")} />}
      {modal === "group" && <GroupAssign ids={selected} onClose={() => setModal("")} />}
      {modal === "save" && (
        <Modal open size="sm" onClose={() => setModal("")} title="Save current filter" footer={<><Button variant="outline" onClick={() => setModal("")}>Cancel</Button><Button form="sf" type="submit">Save</Button></>}>
          <form id="sf" onSubmit={saveFilter}><Field label="Name" htmlFor="sfn"><input id="sfn" className="input" required value={filterName} onChange={(e) => setFilterName(e.target.value)} /></Field></form>
        </Modal>
      )}
    </div>
  );
}

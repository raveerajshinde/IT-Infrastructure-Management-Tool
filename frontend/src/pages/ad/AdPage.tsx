import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileSpreadsheet, FileText, Network, Plus, RefreshCw, ShieldAlert, Users as UsersIcon, XCircle } from "lucide-react";
import { ReactNode, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { DataTable } from "../../components/DataTable";
import { DevicePicker } from "../../components/DevicePicker";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, KeyValue, Modal, PageHeader, Skeleton, Stat, Tabs, useConfirm, useToast } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { download, openInline, qs } from "../../lib/download";
import { ago, fmtDate } from "../../lib/format";

type Domain = { id: number; name: string; ldap_url: string; base_dn: string; credential_id: number | null; credential_name: string | null; verify_tls: boolean;
  start_tls: boolean; enabled: boolean; sync_interval_hours: number; stale_days: number; dc_device_id: number | null; ca_file: string | null;
  last_sync_at: string | null; last_sync_ok: boolean | null; last_sync_message: string | null; last_success_at: string | null; stats: Record<string, number | Record<string, unknown>> };
type AdObj = { id: number; domain_id: number; kind: string; dn: string; sam: string; name: string; display_name: string; enabled: boolean | null; privileged: boolean;
  locked: boolean; pwd_never_expires: boolean; last_logon: string | null; pwd_last_set: string | null; account_expires: string | null; when_created: string | null;
  when_changed: string | null; os: string; attrs: Record<string, unknown> };
type Change = { ts: string; domain_id: number; kind: string; name: string; change: string; details: Record<string, unknown> };
type TabId = "overview" | "users" | "groups" | "computers" | "ous" | "dcs" | "reports" | "changes" | "domains";
const TABS: { id: TabId; label: ReactNode }[] = [{ id: "overview", label: "Overview" }, { id: "users", label: "Users" }, { id: "groups", label: "Groups" },
  { id: "computers", label: "Computers" }, { id: "ous", label: "Organizational Units" }, { id: "dcs", label: "Domain Controllers" }, { id: "reports", label: "Reports" },
  { id: "changes", label: "Changes" }, { id: "domains", label: "Domains" }];

export default function AdPage() {
  const { tab = "overview" } = useParams();
  const nav = useNavigate();
  const { data: domains, isLoading } = useQuery({ queryKey: ["ad-domains"], queryFn: () => api<Domain[]>("/api/ad/domains") });
  const [domainId, setDomainId] = useState<number | null>(null);
  const did = domainId ?? domains?.[0]?.id ?? null;
  return (
    <div>
      <PageHeader title="Active Directory" subtitle="Read-only LDAPS inventory, account hygiene reports and approved account actions."
        actions={domains && domains.length > 1 ? (
          <select className="input w-auto py-1.5" value={did ?? ""} onChange={(e) => setDomainId(Number(e.target.value))} aria-label="Domain">{domains.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}</select>
        ) : undefined} />
      <Tabs tabs={TABS} value={tab as TabId} onChange={(t) => nav(`/ad/${t}`)} />
      {isLoading ? <Card><Skeleton /></Card> : !domains?.length && tab !== "domains" ? (
        <Card><EmptyState icon={<Network className="h-6 w-6" />} title="No domain configured" hint="Add a domain with an LDAPS URL and a read-only service account. No administrative rights are needed to read the inventory."
          action={<Button onClick={() => nav("/ad/domains")}>Configure a domain</Button>} /></Card>
      ) : (
        <>
          {tab === "overview" && <Overview domains={domains || []} />}
          {tab === "users" && did && <Objects kind="user" domain={domains!.find((d) => d.id === did)!} />}
          {tab === "groups" && did && <Objects kind="group" domain={domains!.find((d) => d.id === did)!} />}
          {tab === "computers" && did && <Objects kind="computer" domain={domains!.find((d) => d.id === did)!} />}
          {tab === "dcs" && did && <Objects kind="dc" domain={domains!.find((d) => d.id === did)!} />}
          {tab === "ous" && did && <Objects kind="ou" domain={domains!.find((d) => d.id === did)!} />}
          {tab === "reports" && did && <Reports domainId={did} />}
          {tab === "changes" && did && <Changes domainId={did} />}
          {tab === "domains" && <Domains domains={domains || []} />}
        </>
      )}
    </div>
  );
}

function SyncButton({ d }: { d: Domain }) {
  const qc = useQueryClient();
  const toast = useToast();
  const { can } = useAuth();
  const m = useMutation({ mutationFn: () => api(`/api/ad/domains/${d.id}/sync`, { method: "POST" }),
    onSuccess: () => { qc.invalidateQueries(); toast({ tone: "success", title: `${d.name} synchronised` }); },
    onError: (e) => { qc.invalidateQueries({ queryKey: ["ad-domains"] }); toast({ tone: "error", title: "Synchronisation failed", body: (e as Error).message }); } });
  if (!can("ad.manage")) return null;
  return <Button size="sm" variant="outline" loading={m.isPending} icon={<RefreshCw className="h-4 w-4" />} onClick={() => m.mutate()}>Sync now</Button>;
}

function Overview({ domains }: { domains: Domain[] }) {
  const { data } = useQuery({ queryKey: ["ad-summary"], queryFn: () => api<{ totals: Record<string, number>; recent_changes: Change[] }>("/api/ad/summary") });
  const t = data?.totals || {};
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="Users" value={t.users ?? 0} sub={`${t.enabled_users ?? 0} enabled`} icon={<UsersIcon className="h-5 w-5" />} tone="blue" />
        <Stat label="Privileged users" value={t.privileged_users ?? 0} tone="red" icon={<ShieldAlert className="h-5 w-5" />} />
        <Stat label="Dormant users" value={t.inactive_users ?? 0} sub="enabled, no recent logon" tone="amber" />
        <Stat label="Computers" value={t.computers ?? 0} sub={`${t.stale_computers ?? 0} stale`} />
        <Stat label="Groups" value={t.groups ?? 0} sub={`${t.ous ?? 0} OUs`} />
        <Stat label="Domain controllers" value={t.dcs ?? 0} tone="green" />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {domains.map((d) => (
          <Card key={d.id} title={<span className="flex items-center gap-2">{d.name}{d.last_sync_ok === false ? <Badge tone="red">Sync failed</Badge> : d.last_success_at ? <Badge tone="green">Synchronised</Badge> : <Badge>Never synchronised</Badge>}</span>}
            actions={<SyncButton d={d} />}>
            <KeyValue items={[["Last success", d.last_success_at ? `${fmtDate(d.last_success_at)} (${ago(d.last_success_at)})` : "never"], ["Source", d.ldap_url],
              ["Min. password length", String((d.stats.policy as Record<string, unknown>)?.min_pwd_length ?? "—")], ["Lockout threshold", String((d.stats.policy as Record<string, unknown>)?.lockout_threshold ?? "—")],
              ["Pwd never expires (enabled)", String(d.stats.pwd_never_expires ?? "—")], ["Next sync", d.sync_interval_hours ? `every ${d.sync_interval_hours} h` : "manual only"]]} />
            {d.last_sync_message && <p className={`mt-3 text-xs ${d.last_sync_ok === false ? "text-red-600" : "text-slate-500"}`}>{d.last_sync_message}</p>}
          </Card>
        ))}
      </div>
      <Card padded={false} title="Recent directory changes (detected between synchronisations)">
        {data?.recent_changes.length ? <ChangeTable rows={data.recent_changes} /> : <EmptyState title="No changes detected yet" hint="Changes appear after the second synchronisation." />}
      </Card>
    </div>
  );
}

const yes = (v: boolean | null) => v == null ? "—" : v ? <CheckCircle2 className="h-4 w-4 text-emerald-600" aria-label="yes" /> : <XCircle className="h-4 w-4 text-slate-300" aria-label="no" />;

function Objects({ kind, domain }: { kind: string; domain: Domain }) {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("name");
  const [desc, setDesc] = useState(false);
  const [enabled, setEnabled] = useState("");
  const [priv, setPriv] = useState("");
  const [sel, setSel] = useState<string[]>([]);
  const [detail, setDetail] = useState<number | null>(null);
  const [bulk, setBulk] = useState(false);
  const { can } = useAuth();
  const { data, isLoading, error } = useQuery({ queryKey: ["ad-objects", domain.id, kind, page, q, sort, desc, enabled, priv], placeholderData: (p) => p,
    queryFn: () => api<{ items: AdObj[]; total: number; page: number; page_size: number }>(`/api/ad/objects${qs({ domain_id: domain.id, kind, page, page_size: 50, q, sort, desc, enabled, privileged: priv })}`) });
  if (error) return <ErrorBox error={error} />;
  const user = kind === "user";
  const cols = [
    ...(user && can("ad.manage") ? [{ key: "sel", label: "", sortable: false, render: (r: AdObj) => <input type="checkbox" aria-label={`Select ${r.sam}`} checked={sel.includes(r.sam)} onClick={(e) => e.stopPropagation()}
      onChange={() => setSel((s) => s.includes(r.sam) ? s.filter((x) => x !== r.sam) : [...s, r.sam])} /> }] : []),
    { key: kind === "ou" ? "name" : "sam", label: kind === "ou" ? "OU" : kind === "group" ? "Group" : "Account", render: (r: AdObj) => <div><p className="font-medium">{kind === "ou" ? r.display_name : r.sam || r.name}</p>
      {kind !== "ou" && r.display_name && <p className="text-xs text-slate-500">{r.display_name}</p>}</div> },
    ...(kind === "user" || kind === "computer" ? [{ key: "enabled", label: "Enabled", render: (r: AdObj) => yes(r.enabled) }] : []),
    ...(kind === "user" ? [{ key: "privileged", label: "Privileged", render: (r: AdObj) => r.privileged ? <Badge tone="red">{((r.attrs.privileged_groups as string[]) || []).join(", ") || "yes"}</Badge> : "" },
      { key: "flags", label: "Flags", sortable: false, render: (r: AdObj) => <div className="flex flex-wrap gap-1">{r.locked && <Badge tone="red">Locked</Badge>}{r.pwd_never_expires && <Badge tone="amber">Pwd never expires</Badge>}
        {((r.attrs.flags as string[]) || []).map((f) => <Badge key={f} tone="amber">{f.replace(/_/g, " ")}</Badge>)}{!!(r.attrs.spn as string[] | undefined)?.length && <Badge tone="violet">SPN</Badge>}</div> }] : []),
    ...(kind === "computer" || kind === "dc" ? [{ key: "os", label: "Operating system", sortable: false }] : []),
    ...(kind === "group" ? [{ key: "type", label: "Type / scope", sortable: false, render: (r: AdObj) => `${r.attrs.type} · ${r.attrs.scope}` },
      { key: "members", label: "Members", sortable: false, render: (r: AdObj) => String(r.attrs.member_count ?? 0) },
      { key: "privileged", label: "Privileged", render: (r: AdObj) => r.privileged ? <Badge tone="red">{String(r.attrs.privileged_label || "nested")}</Badge> : "" }] : []),
    ...(kind === "ou" ? [{ key: "block", label: "Block inheritance", sortable: false, render: (r: AdObj) => r.attrs.block_inheritance ? <Badge tone="amber">Yes</Badge> : "No" },
      { key: "links", label: "GPO links", sortable: false, render: (r: AdObj) => String(((r.attrs.gp_link as string) || "").split("LDAP://").length - 1) }] : []),
    ...(kind !== "ou" && kind !== "group" ? [{ key: "last_logon", label: "Last logon", render: (r: AdObj) => <span className="whitespace-nowrap text-xs">{r.last_logon ? `${fmtDate(r.last_logon)}` : "never"}</span> }] : []),
    ...(user ? [{ key: "pwd_last_set", label: "Password set", render: (r: AdObj) => <span className="whitespace-nowrap text-xs">{fmtDate(r.pwd_last_set)}</span> }] : []),
    { key: "ou", label: "OU", sortable: false, hidden: kind === "ou", render: (r: AdObj) => <span className="text-xs">{String(r.attrs.ou || "")}</span> },
    { key: "when_created", label: "Created", hidden: true, render: (r: AdObj) => fmtDate(r.when_created) },
  ];
  return (
    <Card padded={false}>
      <DataTable id={`ad-${kind}`} rows={data?.items} loading={isLoading} rowKey={(r) => r.id} onRowClick={(r) => setDetail(r.id)} columns={cols} empty={`No ${kind}s synchronised`}
        server={{ total: data?.total || 0, page, pageSize: 50, onPage: setPage, sort, desc, onSort: (k) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } }, search: q, onSearch: (v) => { setQ(v); setPage(1); } }}
        toolbar={<>
          {(kind === "user" || kind === "computer") && <select className="input w-auto py-1.5 text-sm" value={enabled} onChange={(e) => { setEnabled(e.target.value); setPage(1); }} aria-label="Enabled"><option value="">Enabled + disabled</option><option value="true">Enabled</option><option value="false">Disabled</option></select>}
          {(kind === "user" || kind === "group") && <select className="input w-auto py-1.5 text-sm" value={priv} onChange={(e) => { setPriv(e.target.value); setPage(1); }} aria-label="Privileged"><option value="">All</option><option value="true">Privileged only</option></select>}
          {user && can("ad.manage") && <Button size="sm" variant="outline" disabled={!sel.length} onClick={() => setBulk(true)}>Bulk action ({sel.length})</Button>}
        </>} />
      {detail && <ObjectModal id={detail} onClose={() => setDetail(null)} />}
      {bulk && <BulkModal domain={domain} accounts={sel} onClose={() => setBulk(false)} onDone={() => setSel([])} />}
    </Card>
  );
}

function ObjectModal({ id, onClose }: { id: number; onClose: () => void }) {
  const { data } = useQuery({ queryKey: ["ad-object", id], queryFn: () => api<AdObj>(`/api/ad/objects/${id}`) });
  const resolved = (data?.attrs.members_resolved || data?.attrs.member_of_resolved || []) as { dn: string; name: string }[];
  return (
    <Modal open onClose={onClose} size="lg" title={data ? `${data.kind.toUpperCase()}: ${data.sam || data.display_name || data.name}` : "Loading…"}>
      {!data ? <Skeleton /> : (
        <div className="space-y-4">
          <KeyValue items={[["Distinguished name", <span key="dn" className="break-all text-xs">{data.dn}</span>], ["Display name", data.display_name], ["Enabled", data.enabled == null ? "—" : data.enabled ? "Yes" : "No"],
            ["Privileged", data.privileged ? "Yes" : "No"], ["Last logon", fmtDate(data.last_logon)], ["Password last set", fmtDate(data.pwd_last_set)],
            ["Password expires", data.pwd_never_expires ? "Never" : fmtDate(data.attrs.pwd_expires as string)], ["Account expires", fmtDate(data.account_expires)],
            ["Created", fmtDate(data.when_created)], ["Changed", fmtDate(data.when_changed)], ["Operating system", data.os], ["UPN / mail", [data.attrs.upn, data.attrs.mail].filter(Boolean).join(" · ") as string]]} />
          {data.attrs.description != null && <p className="text-sm"><b>Description:</b> {String(data.attrs.description)}</p>}
          {!!resolved.length && <div><p className="mb-1 text-sm font-medium">{data.kind === "group" ? `Members (${resolved.length})` : `Member of (${resolved.length})`}</p>
            <div className="flex max-h-48 flex-wrap gap-1 overflow-y-auto">{resolved.map((m) => <Badge key={m.dn}>{m.name}</Badge>)}</div></div>}
          <p className="text-xs text-slate-400">Synchronised {fmtDate(data.attrs && (data as unknown as { synced_at: string }).synced_at)}. Data is read-only; account changes run as approved jobs on a domain controller.</p>
        </div>
      )}
    </Modal>
  );
}

type BulkPreview = { action: string; operation: string; dc_device_id: number | null; note: string; items: { account: string; display_name: string; warnings: string[]; will_run: boolean }[] };
function BulkModal({ domain, accounts, onClose, onDone }: { domain: Domain; accounts: string[]; onClose: () => void; onDone: () => void }) {
  const [action, setAction] = useState("disable");
  const [group, setGroup] = useState("");
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<BulkPreview | null>(null);
  const nav = useNavigate();
  const toast = useToast();
  const body = (execute: boolean) => ({ domain_id: domain.id, action, accounts, group: group || null, reason, execute });
  const pv = useMutation({ mutationFn: () => api<BulkPreview>("/api/ad/bulk", { body: body(false) }), onSuccess: setPreview });
  const ex = useMutation({ mutationFn: () => api<{ jobs: { job_id: number }[] }>("/api/ad/bulk", { body: body(true) }),
    onSuccess: (r) => { toast({ tone: "success", title: `${r.jobs.length} job(s) created`, body: "Approval policies apply; see Jobs and Approvals." }); onDone(); onClose(); nav("/jobs"); } });
  return (
    <Modal open onClose={onClose} size="lg" title={`Bulk action on ${accounts.length} account(s)`}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button>{!preview ? <Button loading={pv.isPending} onClick={() => pv.mutate()} disabled={(action.includes("group") && !group)}>Preview</Button>
        : <Button variant="danger" loading={ex.isPending} disabled={!preview.dc_device_id || reason.trim().length < 3} onClick={() => ex.mutate()}>Create jobs</Button>}</>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Action"><select className="input" value={action} onChange={(e) => { setAction(e.target.value); setPreview(null); }}>
          <option value="disable">Disable accounts</option><option value="enable">Enable accounts</option><option value="unlock">Unlock accounts</option>
          <option value="add_to_group">Add to group</option><option value="remove_from_group">Remove from group</option></select></Field>
        {action.includes("group") && <Field label="Group (sAMAccountName)"><input className="input" value={group} onChange={(e) => { setGroup(e.target.value); setPreview(null); }} /></Field>}
      </div>
      <Field label="Reason / ticket (recorded on every job)"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Leavers October, ticket INC-1234" /></Field>
      {pv.error && <ErrorBox error={pv.error} />}{ex.error && <ErrorBox error={ex.error} />}
      {preview && (
        <div className="mt-3 space-y-2">
          <Callout tone={preview.dc_device_id ? "info" : "warning"}>{preview.note} Operation: <code>{preview.operation}</code>.</Callout>
          <table className="w-full text-sm"><thead><tr><th className="th">Account</th><th className="th">Will run</th><th className="th">Warnings</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{preview.items.map((i) => <tr key={i.account}><td className="td">{i.account} <span className="text-xs text-slate-500">{i.display_name}</span></td>
              <td className="td">{i.will_run ? "Yes" : "No"}</td><td className="td text-xs text-amber-700 dark:text-amber-300">{i.warnings.join("; ")}</td></tr>)}</tbody></table>
        </div>
      )}
    </Modal>
  );
}

function Reports({ domainId }: { domainId: number }) {
  const { data: list } = useQuery({ queryKey: ["ad-reports"], queryFn: () => api<{ key: string; title: string }[]>("/api/ad/reports") });
  const [key, setKey] = useState("inactive-users");
  const [days, setDays] = useState(30);
  const { data, isFetching, error } = useQuery({ queryKey: ["ad-report", domainId, key, days], queryFn: () => api<{ title: string; columns: string[]; rows: unknown[][]; note: string }>(`/api/ad/reports/${key}?domain_id=${domainId}&days=${days}`) });
  const url = (fmt: string) => `/api/ad/reports/${key}?domain_id=${domainId}&days=${days}&format=${fmt}`;
  return (
    <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
      <Card padded={false}><nav className="p-2">{list?.map((r) => (
        <button key={r.key} onClick={() => setKey(r.key)} className={`block w-full rounded-md px-3 py-2 text-left text-sm ${r.key === key ? "bg-brand-50 font-medium text-brand-700 dark:bg-brand-900/30 dark:text-brand-200" : "hover:bg-slate-50 dark:hover:bg-slate-800"}`}>{r.title}</button>))}</nav></Card>
      <Card padded={false} title={data?.title || "Report"} actions={<>
        {["password-expiry", "account-expiry", "recent"].includes(key) && <select className="input w-auto py-1 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Days">{[7, 30, 60, 90, 180].map((d) => <option key={d} value={d}>{d} days</option>)}</select>}
        <Button size="sm" variant="outline" icon={<FileText className="h-4 w-4" />} onClick={() => download(url("pdf"))}>PDF</Button>
        <Button size="sm" variant="outline" icon={<FileSpreadsheet className="h-4 w-4" />} onClick={() => download(url("xlsx"))}>Excel</Button>
        <Button size="sm" variant="ghost" onClick={() => download(url("csv"))}>CSV</Button><Button size="sm" variant="ghost" onClick={() => openInline(url("html"))}>HTML</Button></>}>
        {data?.note && <p className="border-b border-slate-200 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">{data.note}</p>}
        {error ? <div className="p-4"><ErrorBox error={error} /></div> : isFetching && !data ? <Skeleton /> : (
          <DataTable id={`adr-${key}`} rows={data?.rows.map((r, i) => ({ i, r }))} rowKey={(x) => x.i} empty="Nothing to report"
            columns={(data?.columns || []).map((c, j) => ({ key: String(j), label: c, value: (x: { r: unknown[] }) => x.r[j] as string,
              render: (x: { r: unknown[] }) => { const v = x.r[j]; return typeof v === "boolean" ? (v ? "Yes" : "No") : typeof v === "string" && /^\d{4}-\d\d-\d\dT/.test(v) ? fmtDate(v) : String(v ?? ""); } }))} />
        )}
      </Card>
    </div>
  );
}

function ChangeTable({ rows }: { rows: Change[] }) {
  const tone: Record<string, "red" | "green" | "amber" | "violet" | "gray"> = { created: "green", deleted: "red", disabled: "amber", enabled: "green", privileged_added: "red", privileged_removed: "violet", members_changed: "violet" };
  return (
    <DataTable id="ad-changes" rows={rows} rowKey={(r) => `${r.ts}${r.name}${r.change}`} columns={[
      { key: "ts", label: "Detected", render: (r) => <span className="whitespace-nowrap text-xs">{fmtDate(r.ts)}</span> }, { key: "name", label: "Object" }, { key: "kind", label: "Kind" },
      { key: "change", label: "Change", render: (r) => <Badge tone={tone[r.change] || "gray"}>{r.change.replace(/_/g, " ")}</Badge> },
      { key: "details", label: "Details", value: (r) => JSON.stringify(r.details), render: (r) => <span className="text-xs text-slate-500">{Object.entries(r.details).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`).join(" · ")}</span> },
    ]} />
  );
}

function Changes({ domainId }: { domainId: number }) {
  const [days, setDays] = useState(30);
  const { data } = useQuery({ queryKey: ["ad-changes", domainId, days], queryFn: () => api<Change[]>(`/api/ad/changes?domain_id=${domainId}&days=${days}`) });
  return (
    <Card padded={false} title="Directory changes" actions={<select className="input w-auto py-1 text-xs" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Days">{[7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} days</option>)}</select>}>
      <ChangeTable rows={data || []} />
    </Card>
  );
}

function Domains({ domains }: { domains: Domain[] }) {
  const [edit, setEdit] = useState<Partial<Domain> | null>(null);
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const test = useMutation({ mutationFn: (id: number) => api<{ ok: boolean; message: string }>(`/api/ad/domains/${id}/test`, { method: "POST" }),
    onSuccess: (r) => toast({ tone: r.ok ? "success" : "error", title: r.ok ? "Connection OK" : "Connection failed", body: r.message }) });
  const del = useMutation({ mutationFn: (id: number) => api(`/api/ad/domains/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries() });
  const confirm = useConfirm();
  return (
    <div className="space-y-4">
      {can("ad.manage") && <div><Button icon={<Plus className="h-4 w-4" />} onClick={() => setEdit({ verify_tls: true, enabled: true, sync_interval_hours: 6, stale_days: 90 })}>Add domain</Button></div>}
      {domains.map((d) => (
        <Card key={d.id} title={d.name} actions={can("ad.manage") ? <>
          <Button size="sm" variant="outline" loading={test.isPending && test.variables === d.id} onClick={() => test.mutate(d.id)}>Test connection</Button><SyncButton d={d} />
          <Button size="sm" variant="ghost" onClick={() => setEdit(d)}>Edit</Button>
          <Button size="sm" variant="ghost" onClick={async () => { if (await confirm({ title: `Remove ${d.name}`, message: "Remove this domain and its synchronised inventory from InfraPilot? The directory itself is not changed.", danger: true })) del.mutate(d.id); }}>Remove</Button></> : undefined}>
          <KeyValue items={[["LDAP URL", d.ldap_url], ["Base DN", d.base_dn], ["Credential", d.credential_name || "—"], ["Certificate validation", d.verify_tls ? "On" : "Off"],
            ["Sync interval", d.sync_interval_hours ? `${d.sync_interval_hours} h` : "manual"], ["Inactive after", `${d.stale_days} days`],
            ["Account-action DC", d.dc_device_id ? `device #${d.dc_device_id}` : "not set (bulk actions disabled)"], ["Last sync", d.last_sync_message || "never"]]} />
        </Card>
      ))}
      {edit && <DomainForm d={edit} onClose={() => setEdit(null)} />}
    </div>
  );
}

function DomainForm({ d, onClose }: { d: Partial<Domain>; onClose: () => void }) {
  const [v, setV] = useState({ name: d.name || "", ldap_url: d.ldap_url || "ldaps://", base_dn: d.base_dn || "", credential_id: d.credential_id ?? null, verify_tls: d.verify_tls ?? true,
    start_tls: d.start_tls ?? false, enabled: d.enabled ?? true, sync_interval_hours: d.sync_interval_hours ?? 6, stale_days: d.stale_days ?? 90, dc_device_id: d.dc_device_id ?? null, ca_file: d.ca_file || "" });
  const { data: creds } = useQuery({ queryKey: ["credentials"], queryFn: () => api<{ id: number; name: string; kind: string; username: string }[]>("/api/credentials") });
  const qc = useQueryClient();
  const save = useMutation({ mutationFn: () => api(d.id ? `/api/ad/domains/${d.id}` : "/api/ad/domains", { method: d.id ? "PUT" : "POST", body: { ...v, ca_file: v.ca_file || null } }),
    onSuccess: () => { qc.invalidateQueries(); onClose(); } });
  const set = (k: string, x: unknown) => setV((o) => ({ ...o, [k]: x }));
  return (
    <Modal open onClose={onClose} size="lg" title={d.id ? `Edit ${d.name}` : "Add Active Directory domain"}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={save.isPending} onClick={() => save.mutate()}>Save</Button></>}>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Domain DNS name" required><input className="input" value={v.name} onChange={(e) => set("name", e.target.value)} placeholder="corp.example.com" /></Field>
        <Field label="Base DN" required><input className="input" value={v.base_dn} onChange={(e) => set("base_dn", e.target.value)} placeholder="DC=corp,DC=example,DC=com" /></Field>
        <Field label="LDAP URL" required hint="ldaps://dc01.corp.example.com:636 (plain ldap:// only with StartTLS)"><input className="input" value={v.ldap_url} onChange={(e) => set("ldap_url", e.target.value)} /></Field>
        <Field label="Read-only service account" hint="Credential of kind user name + password (any domain user can read the inventory)">
          <select className="input" value={v.credential_id ?? ""} onChange={(e) => set("credential_id", e.target.value ? Number(e.target.value) : null)}><option value="">Choose…</option>
            {creds?.filter((c) => ["password", "winrm"].includes(c.kind)).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.username})</option>)}</select></Field>
        <Field label="Sync every (hours, 0 = manual)"><input className="input" type="number" min={0} max={168} value={v.sync_interval_hours} onChange={(e) => set("sync_interval_hours", Number(e.target.value))} /></Field>
        <Field label="Inactive after (days)"><input className="input" type="number" min={14} max={3650} value={v.stale_days} onChange={(e) => set("stale_days", Number(e.target.value))} /></Field>
        <Field label="CA certificate file (optional)" hint="Path inside the container, e.g. /opt/infrapilot/certs/ldap-ca.pem"><input className="input" value={v.ca_file} onChange={(e) => set("ca_file", e.target.value)} /></Field>
        <div className="space-y-2 pt-6 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.verify_tls} onChange={(e) => set("verify_tls", e.target.checked)} />Validate the DC certificate</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.start_tls} onChange={(e) => set("start_tls", e.target.checked)} />Use StartTLS on ldap://</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Enabled</label>
        </div>
      </div>
      <Field label="Domain controller for account actions (optional)" hint="Bulk disable/enable/unlock/group changes run as approved Windows jobs on this device.">
        <DevicePicker value={v.dc_device_id ? [v.dc_device_id] : []} onChange={(ids) => set("dc_device_id", ids.slice(-1)[0] ?? null)} category="windows" /></Field>
      {!v.verify_tls && <Callout tone="warning">Without certificate validation a network attacker could impersonate the domain controller and capture the service account password.</Callout>}
      {save.error && <ErrorBox error={save.error} />}
    </Modal>
  );
}

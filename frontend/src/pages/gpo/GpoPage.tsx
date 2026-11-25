import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ArchiveRestore, Download, FileCode2, FileSpreadsheet, FileText, GitCompare, Globe, History, RefreshCw, ShieldCheck, Upload } from "lucide-react";
import { ReactNode, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ComplianceBadge, Risk, ScoreRing, StackBar } from "../../components/badges";
import { DataTable } from "../../components/DataTable";
import { DevicePicker } from "../../components/DevicePicker";
import { OperationRunner } from "../../components/OperationRunner";
import { Badge, Button, Callout, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, Skeleton, Stat, Tabs, useToast } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { download, openInline, qs } from "../../lib/download";
import { fmtDate } from "../../lib/format";
import type { Operation } from "../../lib/types";

export type GpoLink = { som_name: string; som_path: string; enabled: boolean; enforced: boolean; site: boolean };
export type GpoRow = {
  guid: string; name: string; status: string; created: string | null; modified: string | null; owner: string; wmi_filter: string; links: GpoLink[];
  linked: boolean; linked_at_root: boolean; flags: string[]; unused: boolean; computer_settings: number; user_settings: number;
  non_compliant: number; worst_risk: string | null; security_filtering: string[]; computer_version: string; user_version: string;
};
export type Collection = { id: number; domain: string; source: string; collected_at: string; collected_by: string; gpo_count: number; changed_count: number;
  warnings: string[]; note: string; domain_info: Record<string, string> };
type Summary = { gpo_count: number; enabled: number; partially_disabled: number; disabled: number; unlinked: number; empty: number; orphaned: number; unused: number;
  settings: number; baseline_counts: Record<string, number>; baseline_score: number | null; non_compliant_by_risk: Record<string, number>; conflicts: number;
  duplicates: number; ou_differences: number; exact_precedence: boolean };
type Overview = { collection: Collection; summary: Summary; executive_summary: string; inventory: GpoRow[]; categories: string[] };
type TabId = "inventory" | "baseline" | "conflicts" | "compare" | "history" | "backup" | "reports";
const TABS: { id: TabId; label: ReactNode }[] = [
  { id: "inventory", label: "GPO Inventory" }, { id: "baseline", label: "GPO Compliance" }, { id: "conflicts", label: "Conflicts & Precedence" },
  { id: "compare", label: "GPO Comparison" }, { id: "history", label: "History" }, { id: "backup", label: "Backup & Restore" }, { id: "reports", label: "GPO Reports" },
];

export function useGpoScope() {
  const [sp, setSp] = useSearchParams();
  const collection = sp.get("collection") ? Number(sp.get("collection")) : undefined;
  const domain = sp.get("domain") || undefined;
  const set = (k: string, v?: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); if (k === "domain") n.delete("collection"); setSp(n); };
  return { collection, domain, set, query: qs({ collection, domain }) };
}

export default function GpoPage() {
  const { tab = "inventory" } = useParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const scope = useGpoScope();
  const [modal, setModal] = useState<"" | "upload" | "collect">("");
  const { data: domains } = useQuery({ queryKey: ["gpo-domains"], queryFn: () => api<{ domain: string; collection_id: number; collected_at: string }[]>("/api/gpo/domains") });
  const { data, isLoading, error } = useQuery({ queryKey: ["gpo-overview", scope.collection, scope.domain], retry: false,
    queryFn: () => api<Overview>(`/api/gpo/overview${scope.query}`) });
  const noData = !isLoading && (!domains || domains.length === 0);
  const manage = can("gpo.manage");
  return (
    <div>
      <PageHeader title="Group Policy" subtitle="Readable GPO settings, security baseline, conflicts, history and reports for management and administrators."
        actions={<>
          {!!domains?.length && (
            <select className="input w-auto py-1.5" aria-label="Domain" value={scope.domain || data?.collection.domain || ""} onChange={(e) => scope.set("domain", e.target.value)}>
              {domains.map((d) => <option key={d.domain} value={d.domain}>{d.domain}</option>)}
            </select>
          )}
          {manage && <Button variant="outline" icon={<Upload className="h-4 w-4" />} onClick={() => setModal("upload")}>Upload report</Button>}
          {manage && <Button icon={<RefreshCw className="h-4 w-4" />} onClick={() => setModal("collect")}>Collect from DC</Button>}
        </>} />
      {data?.collection && <CollectionBar c={data.collection} />}
      <Tabs tabs={TABS} value={tab as TabId} onChange={(t) => nav(`/gpo/${t}${scope.query}`)} />
      {noData ? (
        <Card><EmptyState icon={<ShieldCheck className="h-6 w-6" />} title="No Group Policy data yet"
          hint={<>Collect directly from a domain controller over WinRM (read-only job; needs GPMC/RSAT on the target), or upload the XML produced by
            <code className="mx-1 rounded bg-slate-100 px-1 dark:bg-slate-800">Get-GPOReport -All -ReportType Xml -Path gpos.xml</code>.</>}
          action={manage ? <div className="flex gap-2"><Button variant="outline" onClick={() => setModal("upload")}>Upload report</Button><Button onClick={() => setModal("collect")}>Collect from DC</Button></div> : undefined} /></Card>
      ) : error ? <ErrorBox error={error} /> : isLoading || !data ? <Card><Skeleton rows={10} /></Card> : (
        <>
          {tab === "inventory" && <Inventory data={data} />}
          {tab === "baseline" && <Baseline />}
          {tab === "conflicts" && <Conflicts />}
          {tab === "compare" && <Compare inventory={data.inventory} />}
          {tab === "history" && <HistoryTab inventory={data.inventory} domain={data.collection.domain} />}
          {tab === "backup" && <BackupRestore inventory={data.inventory} />}
          {tab === "reports" && <Reports inventory={data.inventory} c={data.collection} />}
        </>
      )}
      {modal === "upload" && <UploadModal onClose={() => setModal("")} />}
      {modal === "collect" && <CollectModal onClose={() => setModal("")} />}
    </div>
  );
}

export function CollectionBar({ c }: { c: Collection }) {
  const scope = useGpoScope();
  const { data: cols } = useQuery({ queryKey: ["gpo-collections", c.domain], queryFn: () => api<Collection[]>(`/api/gpo/collections?domain=${encodeURIComponent(c.domain)}`) });
  return (
    <div className="mb-4 space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-900">
        <span><Globe className="mr-1 inline h-3.5 w-3.5" /><b className="text-slate-700 dark:text-slate-200">{c.domain}</b></span>
        <span>Collection #{c.id} · {fmtDate(c.collected_at)} · {c.source === "upload" ? "uploaded report" : "collected from a domain controller"} · {c.collected_by}</span>
        {cols && cols.length > 1 && (
          <label className="ml-auto flex items-center gap-1">View collection
            <select className="input w-auto py-0.5 text-xs" value={c.id} onChange={(e) => scope.set("collection", e.target.value)}>
              {cols.map((x) => <option key={x.id} value={x.id}>#{x.id} — {fmtDate(x.collected_at)}{x.changed_count ? ` (${x.changed_count} changed)` : ""}</option>)}
            </select>
          </label>
        )}
      </div>
      {c.warnings.map((w) => <Callout key={w} tone="info">{w}</Callout>)}
    </div>
  );
}

// ------------------------------------------------------------------ inventory
const FLAG_FILTERS = ["All", "Non-compliant", "Unlinked", "Empty (no settings)", "All settings disabled", "Version mismatch AD/SYSVOL", "Orphaned"] as const;

function Inventory({ data }: { data: Overview }) {
  const s = data.summary;
  const scope = useGpoScope();
  const nav = useNavigate();
  const [flag, setFlag] = useState<(typeof FLAG_FILTERS)[number]>("All");
  const rows = data.inventory.filter((r) => flag === "All" || (flag === "Non-compliant" ? r.non_compliant > 0 : r.flags.some((f) => f.startsWith(flag))));
  const bc = s.baseline_counts;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="GPOs" value={s.gpo_count} sub={`${s.settings} settings`} tone="blue" />
        <Stat label="Enabled" value={s.enabled} sub={`${s.partially_disabled} partly, ${s.disabled} fully disabled`} tone="green" />
        <Stat label="Unlinked / empty" value={`${s.unlinked} / ${s.empty}`} sub={`${s.orphaned} orphaned`} tone={s.unlinked + s.empty ? "amber" : "gray"} />
        <Stat label="Critical + high" value={s.non_compliant_by_risk.critical + s.non_compliant_by_risk.high} sub="non-compliant settings" tone="red" />
        <Stat label="Conflicts" value={s.conflicts} sub={`${s.duplicates} duplicates`} tone={s.conflicts ? "amber" : "gray"} />
        <Card className="flex items-center"><ScoreRing score={s.baseline_score} label="Baseline score" /></Card>
      </div>
      <Card title="Executive summary">
        <p className="text-sm leading-relaxed">{data.executive_summary}</p>
        <div className="mt-4"><StackBar parts={[{ label: "Compliant", value: bc.compliant, color: "#059669" }, { label: "Non-compliant", value: bc.non_compliant, color: "#dc2626" },
          { label: "Unknown", value: bc.unknown, color: "#7c3aed" }, { label: "Not configured", value: bc.not_configured, color: "#cbd5e1" },
          { label: "Not applicable", value: bc.not_applicable, color: "#94a3b8" }]} /></div>
      </Card>
      <Card padded={false} title="GPO inventory">
        <DataTable id="gpo-inventory" rows={rows} rowKey={(r) => r.guid} onRowClick={(r) => nav(`/gpo/object/${r.guid}${scope.query}`)}
          toolbar={<div className="flex flex-wrap gap-1">{FLAG_FILTERS.map((f) => (
            <button key={f} onClick={() => setFlag(f)} className={clsx("rounded-full border px-2.5 py-0.5 text-xs", flag === f ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-200" : "border-slate-200 text-slate-500 dark:border-slate-700")}>{f}</button>))}</div>}
          columns={[
            { key: "name", label: "GPO", render: (r) => <Link to={`/gpo/object/${r.guid}${scope.query}`} className="font-medium text-brand-700 hover:underline dark:text-brand-300" onClick={(e) => e.stopPropagation()}>{r.name}</Link> },
            { key: "status", label: "Status", render: (r) => <Badge tone={r.status === "Enabled" ? "green" : r.status === "Orphaned" ? "red" : "amber"}>{r.status}</Badge> },
            { key: "links", label: "Linked to", value: (r) => r.links.map((l) => l.som_path).join(", "), render: (r) => r.links.length ? (
              <div className="space-y-0.5">{r.links.map((l) => <div key={l.som_path} className="text-xs">{l.som_path}{l.enforced && <Badge tone="violet" className="ml-1">Enforced</Badge>}{!l.enabled && <Badge className="ml-1">Disabled</Badge>}{l.site && <Badge tone="blue" className="ml-1">Site</Badge>}</div>)}</div>
            ) : <span className="text-xs text-slate-400">Not linked</span> },
            { key: "settings", label: "Settings C/U", value: (r) => r.computer_settings + r.user_settings, render: (r) => `${r.computer_settings} / ${r.user_settings}` },
            { key: "non_compliant", label: "Non-compliant", render: (r) => r.non_compliant ? <span className="flex items-center gap-1.5">{r.non_compliant}<Risk risk={r.worst_risk} /></span> : <span className="text-slate-400">0</span> },
            { key: "flags", label: "Flags", value: (r) => r.flags.join(", "), render: (r) => <div className="flex flex-wrap gap-1">{r.flags.map((f) => <Badge key={f} tone="amber">{f}</Badge>)}</div> },
            { key: "modified", label: "Modified", render: (r) => <span className="whitespace-nowrap text-xs">{fmtDate(r.modified)}</span> },
            { key: "owner", label: "Owner", hidden: true }, { key: "wmi_filter", label: "WMI filter", hidden: true },
            { key: "guid", label: "GUID", hidden: true, render: (r) => <code className="text-xs">{r.guid}</code> },
            { key: "created", label: "Created", hidden: true, render: (r) => fmtDate(r.created) },
          ]} />
      </Card>
    </div>
  );
}

// ------------------------------------------------------------------ baseline
type Rule = { rule_id: string; title: string; category: string; expected: string; risk: string; status: string; explanation: string; recommendation: string;
  reference: string; note?: string; gpos: { guid: string; name: string; value: string; status: string }[]; effective_values: { ou: string; gpo: string; value: string; status: string }[];
  not_configured_in: string[] };

function Baseline() {
  const scope = useGpoScope();
  const { can } = useAuth();
  const toast = useToast();
  const qc = useQueryClient();
  const [cat, setCat] = useState("");
  const [st, setSt] = useState("");
  const [excl, setExcl] = useState<Rule | null>(null);
  const [reason, setReason] = useState("");
  const { data, isLoading, error } = useQuery({ queryKey: ["gpo-baseline", scope.collection, scope.domain], queryFn: () => api<{ rules: Rule[]; exclusions: Record<string, string>; summary: Summary }>(`/api/gpo/baseline${scope.query}`) });
  const save = useMutation({
    mutationFn: (v: { id: string; reason: string | null }) => api(`/api/gpo/baseline/${v.id}/exclusion`, { method: "PUT", body: { reason: v.reason } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["gpo-baseline"] }); qc.invalidateQueries({ queryKey: ["gpo-overview"] }); setExcl(null); toast({ tone: "success", title: "Baseline updated" }); },
    onError: (e) => toast({ tone: "error", title: (e as Error).message }),
  });
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Card><Skeleton rows={10} /></Card>;
  const cats = [...new Set(data.rules.map((r) => r.category))].sort();
  const rows = data.rules.filter((r) => (!cat || r.category === cat) && (!st || r.status === st));
  const c = data.summary.baseline_counts;
  return (
    <div className="space-y-4">
      <Callout tone="info" title="How to read this">A baseline setting that no GPO configures is shown as <b>Not configured</b> — it may be set locally or by other tools and is not
        automatically insecure. <b>Not applicable</b> means the setting cannot take effect where it is linked (e.g. password policy outside the domain root) or was excluded.
        The baseline is aligned with the CIS Windows Server Benchmark Level 1 and the Microsoft Security Baseline; it is not a certification.</Callout>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {(["compliant", "non_compliant", "unknown", "not_configured", "not_applicable"] as const).map((k) => (
          <button key={k} onClick={() => setSt(st === k ? "" : k)} className={clsx("rounded-lg border bg-white p-3 text-left dark:bg-slate-900", st === k ? "border-brand-500 ring-1 ring-brand-500" : "border-slate-200 dark:border-slate-800")}>
            <p className="text-2xl font-semibold tabular-nums">{c[k]}</p><ComplianceBadge status={k} />
          </button>
        ))}
      </div>
      <Card padded={false} title="Security baseline assessment">
        <DataTable id="gpo-baseline" rows={rows} rowKey={(r) => r.rule_id}
          toolbar={<select className="input w-auto py-1.5 text-sm" value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Category"><option value="">All categories</option>{cats.map((x) => <option key={x}>{x}</option>)}</select>}
          columns={[
            { key: "title", label: "Policy", render: (r) => <div><p className="font-medium">{r.title}</p><p className="text-xs text-slate-500">{r.explanation}</p></div> },
            { key: "category", label: "Category" },
            { key: "effective", label: "Configured value (effective per OU)", value: (r) => r.effective_values.map((v) => v.value).join(" "), render: (r) => r.effective_values.length ? (
              <div className="space-y-0.5 text-xs">{r.effective_values.slice(0, 6).map((v, i) => <div key={i}><span className={clsx("font-medium", v.status === "non_compliant" && "text-red-600")}>{v.value}</span> <span className="text-slate-400">— {v.ou} ({v.gpo})</span></div>)}</div>
            ) : <span className="text-xs text-slate-400">Not set by any GPO</span> },
            { key: "expected", label: "Expected" },
            { key: "status", label: "Status", render: (r) => <div className="space-y-1"><ComplianceBadge status={r.status} />{r.note && <p className="max-w-xs text-xs text-slate-500">{r.note}</p>}</div> },
            { key: "risk", label: "Risk", render: (r) => r.status === "non_compliant" ? <Risk risk={r.risk} /> : <span className="text-xs text-slate-400">—</span> },
            { key: "recommendation", label: "Recommendation", render: (r) => <span className="text-xs">{r.recommendation || "—"}</span> },
            { key: "reference", label: "Reference", hidden: true },
            { key: "act", label: "", sortable: false, render: (r) => can("gpo.manage") ? (
              data.exclusions[r.rule_id]
                ? <Button size="sm" variant="ghost" onClick={() => save.mutate({ id: r.rule_id, reason: null })}>Include</Button>
                : <Button size="sm" variant="ghost" onClick={() => { setExcl(r); setReason(""); }}>Exclude…</Button>
            ) : null },
          ]} />
      </Card>
      <Modal open={!!excl} onClose={() => setExcl(null)} title={`Exclude “${excl?.title}” from the baseline`}
        footer={<><Button variant="outline" onClick={() => setExcl(null)}>Cancel</Button><Button loading={save.isPending} disabled={reason.trim().length < 5} onClick={() => excl && save.mutate({ id: excl.rule_id, reason })}>Exclude</Button></>}>
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">Excluded rules show as Not applicable in all reports. The exclusion and its reason are recorded in the audit trail.</p>
        <Field label="Reason (required)"><textarea className="input" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Chrome is not deployed in this organisation" /></Field>
      </Modal>
    </div>
  );
}

// ------------------------------------------------------------------ conflicts & precedence
type Overlap = { setting_key: string; scope: string; name: string; category: string; ous: string[]; gpos: { guid: string; name: string; value: string; wins: boolean }[]; winner?: string; value?: string; explanation: string };
function Conflicts() {
  const scope = useGpoScope();
  const { data, error } = useQuery({ queryKey: ["gpo-overlaps", scope.collection, scope.domain], queryFn: () => api<{ conflicts: Overlap[]; duplicates: Overlap[];
    ou_differences: { name: string; category: string; values: { ou: string; gpo: string; value: string }[] }[]; exact_precedence: boolean }>(`/api/gpo/overlaps${scope.query}`) });
  const { data: prec } = useQuery({ queryKey: ["gpo-precedence", scope.collection, scope.domain], queryFn: () => api<{ ou: string; blocked: boolean | null;
    gpos: { guid: string; name: string; precedence: number; enforced: boolean; source: string }[] }[]>(`/api/gpo/precedence${scope.query}`) });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Card><Skeleton /></Card>;
  const ov = (o: Overlap, conflict: boolean) => (
    <tr key={o.setting_key + o.ous.join()} className="align-top">
      <td className="td"><p className="font-medium">{o.name}</p><p className="text-xs text-slate-500">{o.category} · {o.scope}</p></td>
      <td className="td text-xs">{o.ous.join(", ")}</td>
      <td className="td"><div className="space-y-1">{o.gpos.map((g) => <div key={g.guid} className="text-xs"><span className={clsx(g.wins && "font-semibold")}>{g.name}</span>: {g.value}{g.wins && conflict && <Badge tone="green" className="ml-1">wins</Badge>}</div>)}</div></td>
      <td className="td text-xs text-slate-500">{o.explanation}</td>
    </tr>
  );
  return (
    <div className="space-y-4">
      {!data.exact_precedence && <Callout tone="warning">Precedence below is derived from the links in an uploaded report — link order and block inheritance were not available. Collect from a domain controller for exact precedence.</Callout>}
      {[["Conflicting settings (same OU, different values)", data.conflicts, true], ["Duplicate settings (same OU, same value)", data.duplicates, false]].map(([title, list, conflict]) => (
        <Card key={title as string} padded={false} title={<span>{title as string} <Badge>{(list as Overlap[]).length}</Badge></span>}>
          {(list as Overlap[]).length ? <div className="overflow-x-auto"><table className="w-full text-sm"><thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Setting</th><th className="th">OU(s)</th><th className="th">GPOs and values</th><th className="th">Explanation</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{(list as Overlap[]).map((o) => ov(o, conflict as boolean))}</tbody></table></div>
            : <EmptyState title="None found" />}
        </Card>
      ))}
      <Card padded={false} title={<span>Settings configured differently across OUs <Badge>{data.ou_differences.length}</Badge></span>}>
        {data.ou_differences.length ? <div className="divide-y divide-slate-100 dark:divide-slate-800">{data.ou_differences.map((d) => (
          <div key={d.name + d.category} className="px-4 py-2.5 text-sm"><p className="font-medium">{d.name} <span className="text-xs font-normal text-slate-500">· {d.category}</span></p>
            <div className="mt-1 grid gap-0.5 text-xs sm:grid-cols-2">{d.values.map((v) => <div key={v.ou}><span className="text-slate-500">{v.ou}:</span> <b>{v.value}</b> <span className="text-slate-400">({v.gpo})</span></div>)}</div></div>))}</div>
          : <EmptyState title="Every setting has the same effective value in all OUs" />}
      </Card>
      <Card title="Precedence per OU (1 wins)">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {(prec || []).map((o) => (
            <div key={o.ou} className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
              <p className="text-sm font-medium">{o.ou}{o.blocked && <Badge tone="amber" className="ml-1">Blocks inheritance</Badge>}</p>
              <ol className="mt-2 space-y-1 text-xs">{o.gpos.map((g) => <li key={g.guid} className="flex items-center gap-2"><span className="w-4 text-right font-semibold text-slate-400">{g.precedence}</span>{g.name}{g.enforced && <Badge tone="violet">Enforced</Badge>}</li>)}
                {!o.gpos.length && <li className="text-slate-400">No GPOs apply</li>}</ol>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------------ compare
type CompareResult = { gpos: { guid: string; name: string; status: string }[]; rows: { name: string; category: string; scope: string; expected: string; values: (string | null)[]; state: string }[]; counts: Record<string, number> };
function Compare({ inventory }: { inventory: GpoRow[] }) {
  const scope = useGpoScope();
  const [sel, setSel] = useState<string[]>([]);
  const [onlyDiff, setOnlyDiff] = useState(true);
  const cmp = useMutation({ mutationFn: () => api<CompareResult>("/api/gpo/compare", { body: { guids: sel, collection: scope.collection } }) });
  const rows = (cmp.data?.rows || []).filter((r) => !onlyDiff || r.state !== "same");
  return (
    <div className="space-y-4">
      <Card title="Choose two or more GPOs" actions={<Button icon={<GitCompare className="h-4 w-4" />} disabled={sel.length < 2} loading={cmp.isPending} onClick={() => cmp.mutate()}>Compare</Button>}>
        <div className="grid max-h-64 gap-1 overflow-y-auto sm:grid-cols-2 lg:grid-cols-3">
          {inventory.filter((g) => g.computer_settings + g.user_settings > 0).map((g) => (
            <label key={g.guid} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-slate-50 dark:hover:bg-slate-800">
              <input type="checkbox" checked={sel.includes(g.guid)} onChange={() => setSel((s) => s.includes(g.guid) ? s.filter((x) => x !== g.guid) : [...s, g.guid].slice(0, 10))} />
              <span className="truncate">{g.name}</span><span className="ml-auto text-xs text-slate-400">{g.computer_settings + g.user_settings}</span>
            </label>
          ))}
        </div>
      </Card>
      {cmp.error && <ErrorBox error={cmp.error} />}
      {cmp.data && (
        <Card padded={false} title={<span className="flex flex-wrap items-center gap-2">Comparison <Badge tone="red">{cmp.data.counts.different} different</Badge><Badge tone="amber">{cmp.data.counts.only_in_some} only in some</Badge><Badge tone="green">{cmp.data.counts.same} same</Badge></span>}
          actions={<label className="flex items-center gap-1.5 text-xs"><input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} />Only differences</label>}>
          <div className="max-h-[70vh] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-slate-50 dark:bg-slate-900"><tr><th className="th">Setting</th>{cmp.data.gpos.map((g) => <th key={g.guid} className="th">{g.name}</th>)}</tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {rows.map((r, i) => (
                  <tr key={i} className={clsx(r.state === "different" && "bg-red-50/50 dark:bg-red-950/20", r.state === "only_in_some" && "bg-amber-50/40 dark:bg-amber-950/10")}>
                    <td className="td"><p className="font-medium">{r.name}</p><p className="text-xs text-slate-500">{r.category} · {r.scope}{r.expected && ` · expected ${r.expected}`}</p></td>
                    {r.values.map((v, j) => <td key={j} className="td text-xs">{v ?? <span className="text-slate-400">Not configured</span>}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
            {!rows.length && <EmptyState title="No differences" />}
          </div>
        </Card>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ history
type Version = { snapshot_id: number; first_seen: string; name: string; modified: string | null; sha256: string; collections: number; settings: number };
export type VersionDiff = { gpo: string; before: { first_seen: string; modified: string | null }; after: { first_seen: string; modified: string | null };
  settings: { change: string; scope: string; name: string; category: string; before: string | null; after: string | null }[]; metadata: { field: string; before: string; after: string }[];
  counts: Record<string, number> };

function HistoryTab({ inventory, domain }: { inventory: GpoRow[]; domain: string }) {
  const { data: cols } = useQuery({ queryKey: ["gpo-collections", domain], queryFn: () => api<(Collection & { changed: { guid: string; name: string; new: boolean }[]; deleted: { guid: string; name: string }[] })[]>(`/api/gpo/collections?domain=${encodeURIComponent(domain)}`) });
  const [guid, setGuid] = useState("");
  return (
    <div className="space-y-4">
      <Card padded={false} title="Collections and detected changes">
        <DataTable id="gpo-collections" rows={cols} rowKey={(c) => c.id} columns={[
          { key: "collected_at", label: "Collected", render: (c) => fmtDate(c.collected_at) }, { key: "id", label: "#" },
          { key: "source", label: "Source", render: (c) => c.source === "upload" ? "Uploaded" : "Domain controller" }, { key: "gpo_count", label: "GPOs" },
          { key: "changes", label: "Changes", value: (c) => c.changed_count, render: (c) => c.changed.length + c.deleted.length ? (
            <div className="flex flex-wrap gap-1">{c.changed.map((x) => <button key={x.guid} onClick={() => setGuid(x.guid)}><Badge tone={x.new ? "green" : "amber"}>{x.new ? "New" : "Changed"}: {x.name}</Badge></button>)}
              {c.deleted.map((x) => <Badge key={x.guid} tone="red">Deleted: {x.name}</Badge>)}</div>) : <span className="text-xs text-slate-400">No changes</span> },
          { key: "collected_by", label: "By", hidden: true }, { key: "note", label: "Note", hidden: true },
        ]} />
      </Card>
      <Card title="Before / after comparison of a GPO">
        <select className="input max-w-md" value={guid} onChange={(e) => setGuid(e.target.value)} aria-label="GPO"><option value="">Choose a GPO…</option>{inventory.map((g) => <option key={g.guid} value={g.guid}>{g.name}</option>)}</select>
        {guid && <VersionHistory domain={domain} guid={guid} />}
      </Card>
    </div>
  );
}

export function VersionHistory({ domain, guid }: { domain: string; guid: string }) {
  const { data: versions } = useQuery({ queryKey: ["gpo-history", domain, guid], queryFn: () => api<Version[]>(`/api/gpo/history/${guid}?domain=${encodeURIComponent(domain)}`) });
  const [pair, setPair] = useState<[number, number] | null>(null);
  const a = pair?.[0], b = pair?.[1];
  const { data: diff } = useQuery({ queryKey: ["gpo-diff", a, b], enabled: !!pair, queryFn: () => api<VersionDiff>(`/api/gpo/diff?a=${a}&b=${b}`) });
  if (!versions) return <Skeleton rows={3} />;
  if (versions.length < 2) return <p className="mt-3 text-sm text-slate-500">Only one version of this GPO has been collected so far. Changes appear here after the next collection that finds a difference.</p>;
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap gap-2">
        {versions.map((v, i) => i > 0 && (
          <Button key={v.snapshot_id} size="sm" variant={pair?.[1] === v.snapshot_id ? "primary" : "outline"} onClick={() => setPair([versions[i - 1].snapshot_id, v.snapshot_id])}>
            <History className="h-3.5 w-3.5" />{fmtDate(versions[i - 1].first_seen)} → {fmtDate(v.first_seen)}
          </Button>
        ))}
      </div>
      {diff && <DiffTable diff={diff} />}
    </div>
  );
}

export function DiffTable({ diff }: { diff: VersionDiff }) {
  const tone = { added: "green", removed: "red", modified: "amber" } as const;
  return (
    <div className="space-y-2">
      <div className="flex gap-2 text-xs"><Badge tone="green">{diff.counts.added || 0} added</Badge><Badge tone="red">{diff.counts.removed || 0} removed</Badge><Badge tone="amber">{diff.counts.modified || 0} modified</Badge></div>
      {!!diff.metadata.length && <table className="w-full text-sm"><tbody>{diff.metadata.map((m) => <tr key={m.field}><td className="td w-40 text-slate-500">{m.field}</td><td className="td text-red-700 line-through dark:text-red-300">{m.before}</td><td className="td text-emerald-700 dark:text-emerald-300">{m.after}</td></tr>)}</tbody></table>}
      <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Change</th><th className="th">Setting</th><th className="th">Before</th><th className="th">After</th></tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {diff.settings.map((c, i) => <tr key={i}><td className="td"><Badge tone={tone[c.change as keyof typeof tone]}>{c.change}</Badge></td>
              <td className="td"><p className="font-medium">{c.name}</p><p className="text-xs text-slate-500">{c.category} · {c.scope}</p></td>
              <td className="td text-xs">{c.before ?? "—"}</td><td className="td text-xs">{c.after ?? "—"}</td></tr>)}
          </tbody>
        </table>
        {!diff.settings.length && <p className="p-3 text-sm text-slate-500">No setting changes (only metadata such as links or version numbers changed).</p>}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ backup & restore
function BackupRestore({ inventory }: { inventory: GpoRow[] }) {
  const { data: ops } = useQuery({ queryKey: ["operations"], queryFn: () => api<Operation[]>("/api/operations") });
  const [dev, setDev] = useState<number[]>([]);
  const [run, setRun] = useState<{ op: Operation; defaults: Record<string, unknown> } | null>(null);
  const [gpo, setGpo] = useState("");
  const [path, setPath] = useState("");
  const op = (id: string) => ops?.find((o) => o.id === id);
  const start = (id: string, defaults: Record<string, unknown>) => { const o = op(id); if (o) setRun({ op: o, defaults }); };
  return (
    <div className="space-y-4">
      <Callout tone="info" title="How backup and restore work">Backups are made with <code>Backup-GPO</code> on the domain controller you choose, into a folder on that server.
        A restore replaces all settings of the GPO, so it is a <b>critical</b> operation: run it as a dry-run first to see a setting-by-setting comparison, then submit it —
        approval policies apply. The GPO is captured before and after, and both versions are kept in the history.</Callout>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="1. Domain controller">
          <p className="mb-2 text-xs text-slate-500">A Windows device with the GroupPolicy module (a DC or a server with GPMC).</p>
          <DevicePicker value={dev} onChange={(v) => setDev(v.slice(-1))} category="windows" />
        </Card>
        <Card title="2. GPO and backup folder">
          <div className="space-y-3">
            <Field label="GPO"><select className="input" value={gpo} onChange={(e) => setGpo(e.target.value)}><option value="">Choose…</option>{inventory.filter((g) => g.status !== "Orphaned").map((g) => <option key={g.guid} value={g.name}>{g.name}</option>)}</select></Field>
            <Field label="Backup folder on the server" hint="e.g. D:\GPOBackups"><input className="input" value={path} onChange={(e) => setPath(e.target.value)} placeholder="D:\GPOBackups" /></Field>
            <div className="flex flex-wrap gap-2">
              <Button disabled={!dev.length || !gpo || !path || !op("windows.gpo.backup")} icon={<Download className="h-4 w-4" />} onClick={() => start("windows.gpo.backup", { name: gpo, path })}>Back up GPO</Button>
              <Button variant="outline" disabled={!dev.length || !path || !op("windows.gpo.backups.list")} onClick={() => start("windows.gpo.backups.list", { path })}>List backups in folder</Button>
              <Button variant="danger" disabled={!dev.length || !gpo || !path || !op("windows.gpo.restore")} icon={<ArchiveRestore className="h-4 w-4" />} onClick={() => start("windows.gpo.restore", { name: gpo, path })}>Restore… (dry-run first)</Button>
            </div>
            {ops && !op("windows.gpo.restore") && <p className="text-xs text-amber-600">Your role does not include the Windows operations needed for backup/restore.</p>}
          </div>
        </Card>
      </div>
      {run && <OperationRunner op={run.op} deviceIds={dev} defaults={run.defaults} onClose={() => setRun(null)} />}
    </div>
  );
}

// ------------------------------------------------------------------ reports
const SECTIONS = ["Executive Summary", "Domain Information", "GPO Inventory", "GPO Configuration Details", "Password and Account Security Policies", "Windows Security Policies",
  "Browser Security Policies", "User and Computer Configuration", "OU Links and Inheritance", "Conflicting and Duplicate Settings", "Missing or Weak Security Configurations",
  "Risk Classification", "Recommendations and Remediation", "Historical Changes", "Audit Trail"];

function Reports({ inventory, c }: { inventory: GpoRow[]; c: Collection }) {
  const [sel, setSel] = useState<string[]>([]);
  const url = (fmt: string, guids?: string[]) => `/api/gpo/report${qs({ format: fmt, collection: c.id, guids: guids?.join(",") })}`;
  const buttons = (guids?: string[]) => (
    <div className="flex flex-wrap gap-2">
      <Button icon={<FileText className="h-4 w-4" />} disabled={guids && !guids.length} onClick={() => download(url("pdf", guids))}>PDF</Button>
      <Button variant="outline" icon={<FileSpreadsheet className="h-4 w-4" />} disabled={guids && !guids.length} onClick={() => download(url("xlsx", guids))}>Excel</Button>
      <Button variant="outline" icon={<FileCode2 className="h-4 w-4" />} disabled={guids && !guids.length} onClick={() => openInline(url("html", guids))}>HTML (open)</Button>
      <Button variant="ghost" disabled={guids && !guids.length} onClick={() => download(url("csv", guids))}>CSV</Button>
    </div>
  );
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Complete GPO report">
        <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">All {inventory.length} GPOs of {c.domain}. Written for administrators and management; every setting shows its value, the expected baseline value, status, risk, explanation and recommendation.</p>
        {buttons()}
        <ol className="mt-4 grid list-inside list-decimal gap-x-4 text-xs text-slate-500 sm:grid-cols-2">{SECTIONS.map((s) => <li key={s}>{s}</li>)}</ol>
      </Card>
      <Card title="Report for selected GPOs">
        <div className="mb-3 max-h-56 space-y-0.5 overflow-y-auto">{inventory.map((g) => (
          <label key={g.guid} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={sel.includes(g.guid)} onChange={() => setSel((s) => s.includes(g.guid) ? s.filter((x) => x !== g.guid) : [...s, g.guid])} />{g.name}</label>))}</div>
        {buttons(sel)}
        <p className="mt-3 text-xs text-slate-500">Every export is kept under Reports → Historical reports with its SHA-256 and recorded in the audit log.</p>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------------ modals
function UploadModal({ onClose }: { onClose: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [note, setNote] = useState("");
  const qc = useQueryClient();
  const nav = useNavigate();
  const toast = useToast();
  const up = useMutation({
    mutationFn: () => { const f = new FormData(); f.append("file", file as File); f.append("note", note); return api<Collection>("/api/gpo/upload", { form: f }); },
    onSuccess: (c) => { qc.invalidateQueries(); toast({ tone: "success", title: `Imported ${c.gpo_count} GPOs from ${c.domain}` }); onClose(); nav(`/gpo/inventory?domain=${encodeURIComponent(c.domain)}`); },
  });
  return (
    <Modal open onClose={onClose} title="Upload a Group Policy report" footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={up.isPending} disabled={!file} onClick={() => up.mutate()}>Import</Button></>}>
      <ol className="mb-3 list-inside list-decimal space-y-1 text-sm text-slate-600 dark:text-slate-300">
        <li>On a domain controller or a workstation with GPMC, run in PowerShell:<pre className="mt-1 overflow-x-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">Get-GPOReport -All -ReportType Xml -Path C:\Temp\gpos.xml</pre></li>
        <li>Upload the file here (UTF-16 as produced by PowerShell is fine, up to 64 MB).</li>
      </ol>
      <Field label="XML file"><input type="file" accept=".xml" onChange={(e) => setFile(e.target.files?.[0] || null)} /></Field>
      <Field label="Note (optional)"><input className="input" value={note} onChange={(e) => setNote(e.target.value)} maxLength={400} /></Field>
      <p className="text-xs text-slate-500">Uploaded reports do not contain link order or block inheritance; collecting from a DC gives exact precedence and SYSVOL checks.</p>
      {up.error && <div className="mt-3"><ErrorBox error={up.error} /></div>}
    </Modal>
  );
}

function CollectModal({ onClose }: { onClose: () => void }) {
  const [dev, setDev] = useState<number[]>([]);
  const [domain, setDomain] = useState("");
  const nav = useNavigate();
  const run = useMutation({ mutationFn: () => api<{ id: number }>("/api/gpo/collect", { body: { device_id: dev[0], domain: domain || null } }),
    onSuccess: (j) => { onClose(); nav(`/jobs/${j.id}`); } });
  const hint = useMemo(() => "A read-only job runs Get-GPOReport, Get-GPInheritance and SYSVOL checks over WinRM. The result is stored as a new collection; changes since the previous collection raise alerts.", []);
  return (
    <Modal open onClose={onClose} title="Collect Group Policy from a domain controller" size="lg"
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button loading={run.isPending} disabled={!dev.length} onClick={() => run.mutate()}>Start collection</Button></>}>
      <p className="mb-3 text-sm text-slate-600 dark:text-slate-300">{hint} Schedule it daily under Automation → Schedules (operation “Collect all GPOs for reporting”).</p>
      <Field label="Domain controller (Windows device with WinRM credentials)"><DevicePicker value={dev} onChange={(v) => setDev(v.slice(-1))} category="windows" /></Field>
      <Field label="Domain (optional)" hint="Leave empty for the DC's own domain"><input className="input" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="corp.example.com" /></Field>
      {run.error && <ErrorBox error={run.error} />}
    </Modal>
  );
}

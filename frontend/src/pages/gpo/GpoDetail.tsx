import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowLeft, ChevronDown, ChevronRight, FileText } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ComplianceBadge, Risk } from "../../components/badges";
import { Badge, Button, Callout, Card, ErrorBox, KeyValue, PageHeader, Skeleton, Tabs } from "../../components/ui";
import { api } from "../../lib/api";
import { download, qs } from "../../lib/download";
import { fmtDate } from "../../lib/format";
import { Collection, CollectionBar, GpoRow, VersionHistory, useGpoScope } from "./GpoPage";

export type EvalSetting = { key: string; scope: string; name: string; report_name: string; category: string; configured_value: string; expected_value: string;
  status: string; risk: string; explanation: string; recommendation: string; rule_id: string | null; reference: string; effective: boolean; note: string; path: string; extension: string };
type Detail = { collection: Collection; gpo: GpoRow; settings: EvalSetting[]; history: unknown[]; precedence: { ou: string; position: number }[] };

export default function GpoDetail() {
  const { guid = "" } = useParams();
  const scope = useGpoScope();
  const [tab, setTab] = useState<"computer" | "user" | "links" | "history">("computer");
  const [status, setStatus] = useState("");
  const { data, error, isLoading } = useQuery({ queryKey: ["gpo-detail", guid, scope.collection, scope.domain], queryFn: () => api<Detail>(`/api/gpo/gpos/${guid}${scope.query}`) });
  if (error) return <ErrorBox error={error} />;
  if (isLoading || !data) return <Card><Skeleton rows={12} /></Card>;
  const g = data.gpo;
  const comp = data.settings.filter((s) => s.scope === "computer");
  const user = data.settings.filter((s) => s.scope === "user");
  const nc = data.settings.filter((s) => s.status === "non_compliant");
  return (
    <div>
      <Link to={`/gpo/inventory${scope.query}`} className="mb-2 inline-flex items-center gap-1 text-sm text-brand-700 hover:underline dark:text-brand-300"><ArrowLeft className="h-4 w-4" />GPO inventory</Link>
      <PageHeader title={g.name} subtitle={<span className="flex flex-wrap items-center gap-2"><Badge tone={g.status === "Enabled" ? "green" : "amber"}>{g.status}</Badge>
        {g.flags.map((f) => <Badge key={f} tone="amber">{f}</Badge>)}{nc.length > 0 && <Badge tone="red">{nc.length} non-compliant</Badge>}</span>}
        actions={<Button variant="outline" icon={<FileText className="h-4 w-4" />} onClick={() => download(`/api/gpo/report${qs({ format: "pdf", collection: data.collection.id, guids: g.guid })}`)}>PDF report</Button>} />
      <CollectionBar c={data.collection} />
      <Card className="mb-4">
        <KeyValue items={[["GUID", <code key="g" className="text-xs">{g.guid}</code>], ["Owner", g.owner], ["Created", fmtDate(g.created)], ["Modified", fmtDate(g.modified)],
          ["WMI filter", g.wmi_filter || "None"], ["Security filtering (Apply)", g.security_filtering.join(", ") || "—"],
          ["Computer version (AD/SYSVOL)", g.computer_version], ["User version (AD/SYSVOL)", g.user_version]]} />
      </Card>
      {!g.linked && <div className="mb-4"><Callout tone="warning" title="Not applied anywhere">This GPO is not linked (or all links are disabled), so none of its settings take effect.</Callout></div>}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "computer", label: `Computer Configuration (${comp.length})` }, { id: "user", label: `User Configuration (${user.length})` },
        { id: "links", label: `Links & precedence (${g.links.length})` }, { id: "history", label: "History" }]} />
      {(tab === "computer" || tab === "user") && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
            <span className="text-slate-500">Show:</span>
            {["", "non_compliant", "compliant", "no_baseline", "not_applicable", "unknown"].map((s) => (
              <button key={s} onClick={() => setStatus(s)} className={clsx("rounded-full border px-2.5 py-0.5 text-xs", status === s ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-200" : "border-slate-200 text-slate-500 dark:border-slate-700")}>
                {s ? s.replace(/_/g, " ") : "All"}
              </button>
            ))}
          </div>
          <SettingsByCategory settings={(tab === "computer" ? comp : user).filter((s) => !status || s.status === status)}
            disabledHalf={tab === "computer" ? g.status.startsWith("Computer settings disabled") || g.status === "All settings disabled" : g.status.startsWith("User settings disabled") || g.status === "All settings disabled"} />
        </>
      )}
      {tab === "links" && (
        <Card padded={false}>
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">Linked to</th><th className="th">Link enabled</th><th className="th">Enforced</th><th className="th">Precedence in that OU</th></tr></thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {g.links.map((l) => <tr key={l.som_path}><td className="td">{l.som_path}{l.site && <Badge tone="blue" className="ml-1">Site</Badge>}</td><td className="td">{l.enabled ? "Yes" : "No"}</td>
                <td className="td">{l.enforced ? <Badge tone="violet">Enforced</Badge> : "No"}</td><td className="td">{data.precedence.find((p) => p.ou.toLowerCase().startsWith(l.som_path.toLowerCase()))?.position ?? "—"}</td></tr>)}
            </tbody>
          </table>
          {!!data.precedence.length && <div className="border-t border-slate-200 p-4 text-sm dark:border-slate-800"><p className="mb-1 font-medium">Applies to these OUs (incl. inheritance)</p>
            <ul className="grid gap-1 text-xs sm:grid-cols-2">{data.precedence.map((p) => <li key={p.ou}>{p.ou} — position <b>{p.position}</b></li>)}</ul></div>}
        </Card>
      )}
      {tab === "history" && <Card title="Versions"><VersionHistory domain={data.collection.domain} guid={g.guid} /></Card>}
    </div>
  );
}

export function SettingsByCategory({ settings, disabledHalf }: { settings: EvalSetting[]; disabledHalf?: boolean }) {
  const groups = useMemo(() => {
    const m = new Map<string, EvalSetting[]>();
    settings.forEach((s) => m.set(s.category, [...(m.get(s.category) || []), s]));
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [settings]);
  const [closed, setClosed] = useState<Set<string>>(new Set());
  if (!settings.length) return <Card><p className="text-sm text-slate-500">No settings{disabledHalf ? " (this half of the GPO is disabled)" : ""}.</p></Card>;
  return (
    <div className="space-y-3">
      {disabledHalf && <Callout tone="warning">This half of the GPO is disabled, so these settings are not applied.</Callout>}
      {groups.map(([cat, list]) => {
        const open = !closed.has(cat);
        const bad = list.filter((s) => s.status === "non_compliant").length;
        return (
          <Card key={cat} padded={false}>
            <button className="flex w-full items-center gap-2 px-4 py-3 text-left" onClick={() => setClosed((c) => { const n = new Set(c); if (n.has(cat)) n.delete(cat); else n.add(cat); return n; })} aria-expanded={open}>
              {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}<span className="font-semibold">{cat}</span>
              <Badge>{list.length}</Badge>{bad > 0 && <Badge tone="red">{bad} non-compliant</Badge>}
            </button>
            {open && (
              <div className="divide-y divide-slate-100 border-t border-slate-200 dark:divide-slate-800 dark:border-slate-800">
                {list.map((s) => (
                  <div key={s.key} className={clsx("grid gap-3 px-4 py-3 text-sm lg:grid-cols-12", s.status === "non_compliant" && "bg-red-50/40 dark:bg-red-950/10")}>
                    <div className="lg:col-span-4">
                      <p className="font-medium">{s.name}</p>
                      {s.report_name !== s.name && <p className="text-xs text-slate-500">{s.report_name}</p>}
                      {s.path && s.extension === "Registry" && <p className="truncate text-xs text-slate-400" title={s.path}>{s.path}</p>}
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">{s.explanation}</p>
                    </div>
                    <div className="lg:col-span-3">
                      <p className="text-xs uppercase text-slate-400">Configured</p><p className="break-words">{s.configured_value || "—"}</p>
                      {s.expected_value && <><p className="mt-1 text-xs uppercase text-slate-400">Expected</p><p className="text-slate-600 dark:text-slate-300">{s.expected_value}</p></>}
                    </div>
                    <div className="space-y-1 lg:col-span-2"><ComplianceBadge status={s.status} />{s.status === "non_compliant" && <div><Risk risk={s.risk} /></div>}</div>
                    <div className="text-xs lg:col-span-3">
                      {s.recommendation && <p><b>Recommendation:</b> {s.recommendation}</p>}
                      {s.note && <p className="mt-1 text-slate-500">{s.note}</p>}
                      {s.reference && <p className="mt-1 text-slate-400">{s.rule_id} · {s.reference}</p>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

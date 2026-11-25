import clsx from "clsx";
import { ArrowDownUp, Download, Loader2, Play, Plus, RefreshCw, Search, TerminalSquare, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { FAMILY_LABEL, label } from "../lib/format";
import type { Device, Operation, ReadResult, RowAction } from "../lib/types";
import { OperationRunner } from "./OperationRunner";
import { SchemaForm, cleanValues, initialValues } from "./SchemaForm";
import { Badge, Button, Callout, EmptyState, ErrorBox, RiskBadge } from "./ui";

type Row = Record<string, unknown>;

/** Turn arbitrary read-operation data into one or more tables. */
export function toTables(data: unknown): { name: string; rows: Row[] }[] {
  const isRows = (v: unknown): v is Row[] => Array.isArray(v) && v.length > 0 && v.every((r) => r && typeof r === "object" && !Array.isArray(r));
  if (isRows(data)) return [{ name: "", rows: data }];
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;
    const tables = Object.entries(obj).filter(([, v]) => isRows(v)).map(([k, v]) => ({ name: label(k), rows: v as Row[] }));
    const scalars = Object.entries(obj).filter(([, v]) => v === null || ["string", "number", "boolean"].includes(typeof v));
    if (scalars.length) tables.unshift({ name: tables.length ? "Summary" : "", rows: scalars.map(([k, v]) => ({ Property: label(k), Value: v })) });
    return tables;
  }
  return [];
}

const fmt = (v: unknown): string => {
  if (v === null || v === undefined) return "";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.map(fmt).join(", ");
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.DateTime === "string") return o.DateTime;  // PowerShell date objects
    return JSON.stringify(v);
  }
  return String(v);
};

const matches = (a: RowAction, row: Row) =>
  Object.entries(a.when || {}).every(([col, vals]) => col in row && vals.some((x) => String(x).toLowerCase() === String(row[col]).toLowerCase()));

function csvDownload(name: string, rows: Row[]) {
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  const esc = (s: string) => {
    const safe = /^[=+\-@]/.test(s) ? `'${s}` : s;
    return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  const body = [cols.join(","), ...rows.map((r) => cols.map((c) => esc(fmt(r[c]))).join(","))].join("\n");
  const url = URL.createObjectURL(new Blob(["﻿" + body], { type: "text/csv" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: `${name}.csv` });
  a.click();
  URL.revokeObjectURL(url);
}

function ResultTable({ rows, actions, ops, onAction, name }: {
  rows: Row[]; actions: RowAction[]; ops: Record<string, Operation>; onAction: (a: RowAction, row: Row) => void; name: string;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ col: string; dir: 1 | -1 } | null>(null);
  const cols = useMemo(() => [...new Set(rows.flatMap((r) => Object.keys(r)))].slice(0, 12), [rows]);
  const shown = useMemo(() => {
    let r = q ? rows.filter((x) => cols.some((c) => fmt(x[c]).toLowerCase().includes(q.toLowerCase()))) : rows;
    if (sort) {
      r = [...r].sort((a, b) => {
        const x = a[sort.col], y = b[sort.col];
        if (typeof x === "number" && typeof y === "number") return (x - y) * sort.dir;
        return fmt(x).localeCompare(fmt(y), undefined, { numeric: true }) * sort.dir;
      });
    }
    return r;
  }, [rows, q, sort, cols]);
  const usable = actions.filter((a) => ops[a.op]);
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-3 py-2 dark:border-slate-800">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" aria-hidden />
          <input className="input w-56 py-1.5 pl-8 text-xs" placeholder="Filter rows…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter rows" />
        </div>
        <span className="text-xs text-slate-500">{shown.length} of {rows.length} row(s)</span>
        <Button size="sm" variant="ghost" className="ml-auto" icon={<Download className="h-3.5 w-3.5" />} onClick={() => csvDownload(name, shown)}>CSV</Button>
      </div>
      <div className="max-h-[60vh] overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 dark:bg-slate-900">
            <tr>
              {cols.map((c) => (
                <th key={c} className="th cursor-pointer select-none whitespace-nowrap" onClick={() => setSort((s) => (s?.col === c ? { col: c, dir: (s.dir * -1) as 1 | -1 } : { col: c, dir: 1 }))}>
                  {label(c)} {sort?.col === c && <ArrowDownUp className="inline h-3 w-3" />}
                </th>
              ))}
              {usable.length > 0 && <th className="th sticky right-0 bg-slate-50 text-right shadow-[-8px_0_8px_-8px_rgba(15,23,42,0.15)] dark:bg-slate-900">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {shown.slice(0, 1000).map((r, i) => (
              <tr key={i} className="group hover:bg-slate-50 dark:hover:bg-slate-800/40">
                {cols.map((c) => {
                  const v = r[c];
                  const s = fmt(v);
                  const status = /^(status|state|active|sub|enabled|lockedout|installed)$/i.test(c);
                  return (
                    <td key={c} className="td max-w-xs truncate" title={s}>
                      {status && s ? <Badge tone={/^(running|active|yes|ready|connected|up|online|enabled|true)$/i.test(s) ? "green"
                        : /^(stopped|failed|no|disabled|down|err-disabled|inactive|dead)$/i.test(s) ? "red" : "gray"}>{s}</Badge> : s}
                    </td>
                  );
                })}
                {usable.length > 0 && (
                  <td className="td sticky right-0 whitespace-nowrap bg-white text-right shadow-[-8px_0_8px_-8px_rgba(15,23,42,0.15)] group-hover:bg-slate-50 dark:bg-slate-900 dark:group-hover:bg-slate-800">
                    <div className="flex justify-end gap-1">
                      {usable.filter((a) => matches(a, r)).map((a, j) => {
                        const target = ops[a.op];
                        return (
                          <Button key={j} size="sm" variant={a.tone === "danger" ? "outline" : "secondary"} disabled={!target.allowed}
                            title={target.allowed ? target.name : `Requires ${target.permission}`}
                            className={clsx(a.tone === "danger" && "text-red-600 dark:text-red-400")} onClick={() => onAction(a, r)}>{a.label}</Button>
                        );
                      })}
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length > 1000 && <p className="p-3 text-center text-xs text-slate-500">Showing the first 1000 rows — use the filter or export to CSV.</p>}
      </div>
    </div>
  );
}

/**
 * Point-and-click device management: run any read operation, see the result as a table and act on
 * individual rows (restart a service, kill a process, disable a rule…). Every change still goes
 * through OperationRunner, i.e. server-side preview, approval policy and audit.
 */
export function ManageConsole({ device }: { device: Device }) {
  const ops = useMemo(() => Object.fromEntries((device.operations || []).map((o) => [o.id, o])), [device.operations]);
  const reads = (device.operations || []).filter((o) => !o.mutating);
  const changes = (device.operations || []).filter((o) => o.mutating);
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<Operation | null>(null);
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<ReadResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [runner, setRunner] = useState<{ op: Operation; defaults: Record<string, unknown> } | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const needsInput = (o: Operation) => (o.schema.required || []).length > 0;

  const execute = async (o: Operation, p: Record<string, unknown>) => {
    setBusy(true); setErr(null); setResult(null); setShowRaw(false);
    try {
      setResult(await api<ReadResult>(`/api/devices/${device.id}/operations/${o.id}/read`, { body: cleanValues(o.schema, p) }));
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };

  const select = (o: Operation, p?: Record<string, unknown>) => {
    const init = initialValues(o.schema, p || {});
    setSel(o); setParams(init); setResult(null); setErr(null);
    if (o.allowed && (!needsInput(o) || p)) execute(o, init);
  };

  const onAction = (a: RowAction, row: Row) => {
    const target = ops[a.op];
    const fields = Object.keys(target.schema.properties || {});
    const carried = Object.fromEntries(Object.entries(params).filter(([k]) => fields.includes(k)));  // e.g. node/vmid for snapshot actions
    const defaults = { ...carried, ...Object.fromEntries(Object.entries(a.map).map(([p, col]) => [p, row[col]])), ...a.fixed };
    if (!target.mutating) select(target, defaults);
    else setRunner({ op: target, defaults });
  };

  const groups = useMemo(() => {
    const f = filter.toLowerCase();
    const out: Record<string, Operation[]> = {};
    reads.filter((o) => !f || o.name.toLowerCase().includes(f) || o.id.includes(f)).forEach((o) => { (out[o.family] ||= []).push(o); });
    return out;
  }, [reads, filter]);

  const tables = result ? toTables(result.data) : [];
  if (!reads.length && !changes.length) return <EmptyState title="No operations available for this platform" />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[18rem_1fr]">
      <aside className="rounded-lg border border-slate-200 bg-white shadow-card dark:border-slate-800 dark:bg-slate-900">
        <div className="border-b border-slate-200 p-2 dark:border-slate-800">
          <input className="input py-1.5 text-xs" placeholder="Find a view…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Find a view" />
        </div>
        <nav className="max-h-[70vh] overflow-y-auto p-2" aria-label="Views">
          {Object.entries(groups).map(([fam, list]) => (
            <div key={fam} className="mb-2">
              <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{FAMILY_LABEL[fam] || fam}</p>
              {list.map((o) => (
                <button key={o.id} onClick={() => select(o)} disabled={!o.allowed} title={o.allowed ? o.id : `Requires ${o.permission}`}
                  className={clsx("flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-sm disabled:opacity-40",
                    sel?.id === o.id ? "bg-brand-50 font-medium text-brand-700 dark:bg-brand-900/30 dark:text-brand-200" : "hover:bg-slate-100 dark:hover:bg-slate-800")}>
                  <span className="truncate">{o.name}</span>
                  {(o.row_actions?.length || 0) > 0 && <Wrench className="h-3 w-3 shrink-0 text-slate-400" aria-label="has actions" />}
                </button>
              ))}
            </div>
          ))}
        </nav>
        {changes.length > 0 && (
          <div className="border-t border-slate-200 p-2 dark:border-slate-800">
            <p className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Changes ({changes.length})</p>
            <select className="input py-1.5 text-xs" aria-label="Start a change" value="" onChange={(e) => { const o = ops[e.target.value]; if (o) setRunner({ op: o, defaults: {} }); }}>
              <option value="">Start a change…</option>
              {changes.filter((o) => o.allowed).map((o) => <option key={o.id} value={o.id}>{o.name} ({o.risk})</option>)}
            </select>
          </div>
        )}
      </aside>

      <section className="min-w-0 rounded-lg border border-slate-200 bg-white shadow-card dark:border-slate-800 dark:bg-slate-900">
        {!sel ? (
          <EmptyState icon={<TerminalSquare className="h-6 w-6" />} title="Pick a view on the left"
            hint={<>Results appear here as a table. Rows offer actions such as <b>Restart</b>, <b>Stop</b>, <b>Disable</b> or <b>Snapshot</b>; every change is previewed, approved where policy requires, and audited.</>} />
        ) : (
          <>
            <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
              <div className="min-w-0">
                <h2 className="text-sm font-semibold">{sel.name}</h2>
                <p className="font-mono text-[11px] text-slate-500">{sel.id}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {(sel.view_actions || []).filter((va) => ops[va.op]?.allowed).map((va) => (
                  <Button key={va.op} size="sm" icon={<Plus className="h-3.5 w-3.5" />} onClick={() => {
                    const target = ops[va.op]; const fields = Object.keys(target.schema.properties || {});
                    setRunner({ op: target, defaults: Object.fromEntries(Object.entries(params).filter(([k]) => fields.includes(k))) });
                  }}>{va.label}</Button>
                ))}
                {result && <Badge tone={result.status === "succeeded" ? "green" : result.status === "unsupported" ? "violet" : "red"}>{result.status}</Badge>}
                <Button size="sm" variant="outline" icon={busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  disabled={busy || !sel.allowed} onClick={() => execute(sel, params)}>{result ? "Refresh" : "Run"}</Button>
              </div>
            </header>
            {Object.keys(sel.schema.properties || {}).length > 0 && (
              <form className="border-b border-slate-200 p-4 dark:border-slate-800" onSubmit={(e) => { e.preventDefault(); execute(sel, params); }}>
                <SchemaForm schema={sel.schema} values={params} onChange={setParams} errors={{}} />
                <Button type="submit" size="sm" className="mt-3" icon={<Play className="h-3.5 w-3.5" />} loading={busy}>Run</Button>
              </form>
            )}
            <div className="p-0">
              {err ? <div className="p-4"><ErrorBox error={err} /></div> : null}
              {busy && !result && <div className="flex items-center gap-2 p-6 text-sm text-slate-500"><Loader2 className="h-4 w-4 animate-spin" />Contacting {device.hostname}…</div>}
              {result && result.status !== "succeeded" && <div className="p-4"><Callout tone={result.status === "unsupported" ? "info" : "danger"} title={result.status === "unsupported" ? "Not supported" : "Operation failed"}>
                <pre className="whitespace-pre-wrap text-xs">{result.output}</pre></Callout></div>}
              {result?.backups?.length ? <div className="p-4"><Callout tone="success" title="Configuration captured">{result.backups.map((b) => `${b.kind}${b.changed ? " (changed since last backup)" : " (unchanged)"}`).join(", ")} — see the Config backups tab.</Callout></div> : null}
              {result && result.status === "succeeded" && tables.map((t, i) => (
                <div key={i} className={clsx(i > 0 && "border-t border-slate-200 dark:border-slate-800")}>
                  {t.name && <h3 className="px-4 pt-3 text-xs font-semibold uppercase tracking-wide text-slate-500">{t.name}</h3>}
                  <ResultTable rows={t.rows} actions={i === tables.length - 1 || tables.length === 1 ? sel.row_actions || [] : []} ops={ops} onAction={onAction}
                    name={`${device.hostname}-${sel.id}`} />
                </div>
              ))}
              {result && result.status === "succeeded" && result.output && (tables.length === 0 || showRaw) && (
                <pre className="code m-4 max-h-[60vh] overflow-auto">{result.output}</pre>
              )}
              {result && result.status === "succeeded" && tables.length > 0 && result.output && (
                <button className="px-4 pb-3 text-xs text-brand-600 hover:underline" onClick={() => setShowRaw(!showRaw)}>{showRaw ? "Hide" : "Show"} raw output</button>
              )}
              {result && result.status === "succeeded" && !tables.length && !result.output && <EmptyState title="No data returned" />}
            </div>
          </>
        )}
        {sel && (sel.row_actions?.length || 0) > 0 && result?.status === "succeeded" && (
          <p className="border-t border-slate-200 px-4 py-2 text-[11px] text-slate-500 dark:border-slate-800">
            Row actions: {[...new Set(sel.row_actions!.filter((a) => ops[a.op]).map((a) => a.label))].join(" · ")} — changes open a preview first.
            {sel.row_actions!.some((a) => ops[a.op] && ops[a.op].risk === "critical") && <> Critical actions require typing CONFIRM <RiskBadge risk="critical" />.</>}
          </p>
        )}
      </section>
      {runner && <OperationRunner op={runner.op} deviceIds={[device.id]} defaults={runner.defaults} onClose={() => setRunner(null)} />}
    </div>
  );
}

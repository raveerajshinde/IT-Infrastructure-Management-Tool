import clsx from "clsx";
import { ArrowDown, ArrowUp, Columns3, Search } from "lucide-react";
import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { EmptyState, Pagination, Skeleton } from "./ui";

export type Column<T> = {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  value?: (row: T) => string | number | boolean | null | undefined; // used for sorting, searching and as default text
  sortable?: boolean;
  hidden?: boolean; // hidden by default (can be shown with the column picker)
  className?: string;
};

type ServerMode = { total: number; page: number; pageSize: number; onPage: (p: number) => void; sort?: string; desc?: boolean;
  onSort?: (key: string) => void; search?: string; onSearch?: (q: string) => void };

/** Table with sorting, searching, pagination and column selection. Client-side by default; pass `server` for server paging. */
export function DataTable<T>({ id, columns, rows, rowKey, loading, empty = "Nothing to show", emptyHint, onRowClick, server, toolbar, pageSize = 25,
  searchPlaceholder = "Search…", dense }: {
  id: string; columns: Column<T>[]; rows: T[] | undefined; rowKey: (r: T) => string | number; loading?: boolean; empty?: string; emptyHint?: ReactNode;
  onRowClick?: (r: T) => void; server?: ServerMode; toolbar?: ReactNode; pageSize?: number; searchPlaceholder?: string; dense?: boolean;
}) {
  const storageKey = `ip-cols-${id}`;
  const [hidden, setHidden] = useState<Set<string>>(() => {
    try { const v = localStorage.getItem(storageKey); if (v) return new Set(JSON.parse(v)); } catch { /* storage unavailable */ }
    return new Set(columns.filter((c) => c.hidden).map((c) => c.key));
  });
  const [q, setQ] = useState(server?.search || "");
  const [sort, setSort] = useState<{ k: string; desc: boolean } | null>(null);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(pageSize);
  const [picker, setPicker] = useState(false);
  const pick = useRef<HTMLDivElement>(null);
  useEffect(() => { try { localStorage.setItem(storageKey, JSON.stringify([...hidden])); } catch { /* ignore */ } }, [hidden, storageKey]);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!pick.current?.contains(e.target as Node)) setPicker(false); };
    document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h);
  }, []);
  useEffect(() => { if (!server) setPage(1); }, [q, rows, server]);
  useEffect(() => { if (!server?.onSearch) return; const t = setTimeout(() => { if ((server.search || "") !== q) server.onSearch?.(q); }, 350); return () => clearTimeout(t); }, [q]); // eslint-disable-line

  const val = (c: Column<T>, r: T) => (c.value ? c.value(r) : (r as Record<string, unknown>)[c.key] as string | number | null | undefined);
  const visible = columns.filter((c) => !hidden.has(c.key));
  const filtered = useMemo(() => {
    if (server || !rows) return rows || [];
    let out = rows;
    const s = q.trim().toLowerCase();
    if (s) out = out.filter((r) => columns.some((c) => String(val(c, r) ?? "").toLowerCase().includes(s)));
    if (sort) {
      const c = columns.find((x) => x.key === sort.k);
      if (c) out = [...out].sort((a, b) => {
        const x = val(c, a), y = val(c, b);
        const r = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true });
        return sort.desc ? -r : r;
      });
    }
    return out;
  }, [rows, q, sort, server, columns]); // eslint-disable-line
  const pageRows = server ? filtered : filtered.slice((page - 1) * size, page * size);
  const onSort = (k: string) => {
    if (server?.onSort) return server.onSort(k);
    setSort((s) => (s?.k === k ? { k, desc: !s.desc } : { k, desc: false }));
  };
  const sortKey = server ? server.sort : sort?.k;
  const sortDesc = server ? server.desc : sort?.desc;
  const showSearch = !server || !!server.onSearch;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-3 py-2 dark:border-slate-800">
        {showSearch && (
          <div className="relative w-full max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-slate-400" aria-hidden />
            <input className="input py-1.5 pl-8 text-sm" placeholder={searchPlaceholder} value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search table" />
          </div>
        )}
        <div className="flex flex-1 flex-wrap items-center gap-2">{toolbar}</div>
        <div className="relative" ref={pick}>
          <button className="flex items-center gap-1 rounded-md px-2 py-1.5 text-xs text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => setPicker(!picker)}
            aria-haspopup="true" aria-expanded={picker}><Columns3 className="h-4 w-4" />Columns</button>
          {picker && (
            <div className="absolute right-0 z-30 mt-1 w-56 rounded-md border border-slate-200 bg-white p-2 text-sm shadow-lg dark:border-slate-700 dark:bg-slate-900">
              {columns.map((c) => (
                <label key={c.key} className="flex items-center gap-2 rounded px-1 py-1 hover:bg-slate-50 dark:hover:bg-slate-800">
                  <input type="checkbox" checked={!hidden.has(c.key)} onChange={() => setHidden((h) => { const n = new Set(h); if (n.has(c.key)) n.delete(c.key); else n.add(c.key); return n; })} />
                  {c.label}
                </label>
              ))}
            </div>
          )}
        </div>
      </div>
      {loading && !rows ? <Skeleton rows={8} /> : !pageRows.length ? <EmptyState title={q ? `No matches for “${q}”` : empty} hint={q ? undefined : emptyHint} /> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60">
              <tr>
                {visible.map((c) => {
                  const sortable = c.sortable !== false;
                  return (
                    <th key={c.key} className={clsx("th whitespace-nowrap", c.className)} aria-sort={sortKey === c.key ? (sortDesc ? "descending" : "ascending") : undefined}>
                      {sortable ? (
                        <button className="inline-flex items-center gap-1 hover:text-slate-800 dark:hover:text-slate-200" onClick={() => onSort(c.key)}>
                          {c.label}{sortKey === c.key && (sortDesc ? <ArrowDown className="h-3 w-3" /> : <ArrowUp className="h-3 w-3" />)}
                        </button>
                      ) : c.label}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {pageRows.map((r) => (
                <tr key={rowKey(r)} className={clsx("hover:bg-slate-50 dark:hover:bg-slate-800/40", onRowClick && "cursor-pointer")}
                  onClick={onRowClick ? () => onRowClick(r) : undefined} tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={onRowClick ? (e) => { if (e.key === "Enter") onRowClick(r); } : undefined}>
                  {visible.map((c) => <td key={c.key} className={clsx(dense ? "px-3 py-1.5 text-sm" : "td", "align-top", c.className)}>{c.render ? c.render(r) : String(val(c, r) ?? "")}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {server ? <Pagination page={server.page} pageSize={server.pageSize} total={server.total} onPage={server.onPage} /> : (
        <div className="flex items-center justify-between">
          <Pagination page={page} pageSize={size} total={filtered.length} onPage={setPage} />
          <select className="input mr-3 w-auto py-1 text-xs" value={size} onChange={(e) => { setSize(Number(e.target.value)); setPage(1); }} aria-label="Rows per page">
            {[25, 50, 100, 250].map((n) => <option key={n} value={n}>{n} / page</option>)}
          </select>
        </div>
      )}
    </div>
  );
}

import clsx from "clsx";
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Info, Inbox, Loader2, X, XCircle } from "lucide-react";
import {
  ButtonHTMLAttributes, ReactNode, createContext, forwardRef, useCallback, useContext, useEffect, useId, useRef, useState,
} from "react";
import { ApiError } from "../../lib/api";

// ── Button ──
type Variant = "primary" | "secondary" | "danger" | "ghost" | "outline";
const variants: Record<Variant, string> = {
  primary: "bg-brand-600 text-white hover:bg-brand-700 disabled:bg-brand-600/50",
  secondary: "bg-slate-100 text-slate-800 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700",
  danger: "bg-red-600 text-white hover:bg-red-700 disabled:bg-red-600/50",
  ghost: "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
  outline: "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800",
};

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant; size?: "sm" | "md"; loading?: boolean; icon?: ReactNode;
}>(function Button({ variant = "primary", size = "md", loading, icon, className, children, disabled, ...rest }, ref) {
  return (
    <button ref={ref} disabled={disabled || loading}
      className={clsx("inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium transition-colors disabled:cursor-not-allowed",
        size === "sm" ? "px-2.5 py-1.5 text-xs" : "px-3.5 py-2 text-sm", variants[variant], className)} {...rest}>
      {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
});

// ── Card ──
export function Card({ title, actions, children, className, padded = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean }) {
  return (
    <section className={clsx("rounded-lg border border-slate-200 bg-white shadow-card dark:border-slate-800 dark:bg-slate-900", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={padded ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-900 dark:text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

// ── Badge & status ──
const tones = {
  gray: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700",
  green: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-300 dark:ring-emerald-900",
  red: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/50 dark:text-red-300 dark:ring-red-900",
  amber: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:ring-amber-900",
  blue: "bg-brand-50 text-brand-700 ring-brand-200 dark:bg-brand-900/40 dark:text-brand-200 dark:ring-brand-800",
  violet: "bg-violet-50 text-violet-700 ring-violet-200 dark:bg-violet-950/50 dark:text-violet-300 dark:ring-violet-900",
};
export type Tone = keyof typeof tones;
export function Badge({ tone = "gray", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return <span className={clsx("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", tones[tone], className)}>{children}</span>;
}

const STATUS_TONE: Record<string, Tone> = {
  up: "green", succeeded: "green", approved: "green", resolved: "green", success: "green", check_ok: "blue", no_change: "gray",
  down: "red", failed: "red", rejected: "red", critical: "red", failure: "red", timed_out: "red",
  degraded: "amber", partial: "amber", warning: "amber", pending_approval: "amber", pending: "amber", post_review: "violet", acknowledged: "blue",
  running: "blue", queued: "gray", unknown: "gray", cancelled: "gray", expired: "gray", unsupported: "violet", info: "blue", open: "red",
  high: "red", medium: "amber", low: "gray", locked: "red",
};
const STATUS_LABEL: Record<string, string> = { pending_approval: "Awaiting approval", check_ok: "Check OK", no_change: "No change", post_review: "Post-review", timed_out: "Timed out" };
export function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONE[status] || "gray";
  const dot = { green: "bg-emerald-500", red: "bg-red-500", amber: "bg-amber-500", blue: "bg-brand-500", gray: "bg-slate-400", violet: "bg-violet-500" }[tone];
  return (
    <Badge tone={tone}>
      <span className={clsx("h-1.5 w-1.5 rounded-full", dot, status === "running" && "animate-pulse")} aria-hidden />
      {STATUS_LABEL[status] || status.replace(/_/g, " ")}
    </Badge>
  );
}
export function RiskBadge({ risk }: { risk: string }) {
  return <Badge tone={STATUS_TONE[risk] || "gray"} className="uppercase tracking-wide">{risk}</Badge>;
}

// ── Feedback ──
export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
      <Loader2 className="h-5 w-5 animate-spin" aria-hidden /> {label}
    </div>
  );
}

export function Skeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="animate-pulse space-y-2 p-4" aria-hidden>
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="h-4 rounded bg-slate-200 dark:bg-slate-800" style={{ width: `${90 - (i % 3) * 15}%` }} />)}
    </div>
  );
}

export function EmptyState({ title, hint, action, icon }: { title: string; hint?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-12 text-center">
      <div className="mb-3 rounded-full bg-slate-100 p-3 text-slate-400 dark:bg-slate-800">{icon || <Inbox className="h-6 w-6" />}</div>
      <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{title}</p>
      {hint && <p className="mt-1 max-w-md text-sm text-slate-500">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorBox({ error, title = "Something went wrong" }: { error: unknown; title?: string }) {
  if (!error) return null;
  const e = error instanceof ApiError ? error : null;
  const msg = e?.message || (error as Error)?.message || String(error);
  return (
    <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
      <div className="flex gap-2">
        <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
        <div>
          <p className="font-medium">{e?.status === 403 ? "Not permitted" : title}</p>
          <p>{msg}</p>
          {e?.fieldErrors.length ? (
            <ul className="mt-1 list-disc pl-5">{e.fieldErrors.map((f, i) => <li key={i}><span className="font-mono">{f.field || "input"}</span>: {f.message}</li>)}</ul>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function Callout({ tone = "info", title, children }: { tone?: "info" | "warning" | "success" | "danger"; title?: ReactNode; children: ReactNode }) {
  const map = {
    info: ["border-brand-200 bg-brand-50 text-brand-900 dark:border-brand-800 dark:bg-brand-900/30 dark:text-brand-100", Info],
    warning: ["border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100", AlertTriangle],
    success: ["border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-100", CheckCircle2],
    danger: ["border-red-200 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100", XCircle],
  } as const;
  const [cls, Icon] = map[tone];
  return (
    <div className={clsx("flex gap-2 rounded-md border p-3 text-sm", cls)}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div>{title && <p className="font-semibold">{title}</p>}{children}</div>
    </div>
  );
}

// ── Modal & confirm ──
export function Modal({ open, onClose, title, children, footer, size = "md" }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; size?: "sm" | "md" | "lg" | "xl";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const id = useId();
  // Only run on open/close — re-running on every parent render would steal focus while typing.
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") closeRef.current(); };
    document.addEventListener("keydown", onKey);
    const t = setTimeout(() => (bodyRef.current?.querySelector<HTMLElement>("input,select,textarea") || ref.current?.querySelector<HTMLElement>("button"))?.focus(), 10);
    return () => { clearTimeout(t); document.removeEventListener("keydown", onKey); prev?.focus(); };
  }, [open]);
  if (!open) return null;
  const w = { sm: "max-w-md", md: "max-w-xl", lg: "max-w-3xl", xl: "max-w-5xl" }[size];
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/50 p-4 backdrop-blur-sm sm:items-center"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={id} className={clsx("w-full rounded-lg bg-white shadow-xl dark:bg-slate-900", w)}>
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3 dark:border-slate-800">
          <h2 id={id} className="text-base font-semibold">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800" aria-label="Close"><X className="h-5 w-5" /></button>
        </div>
        <div ref={bodyRef} className="max-h-[75vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800">{footer}</div>}
      </div>
    </div>
  );
}

type ConfirmOpts = { title: string; message: ReactNode; confirmLabel?: string; danger?: boolean; requireText?: string };
const ConfirmCtx = createContext<(o: ConfirmOpts) => Promise<boolean>>(async () => false);
export const useConfirm = () => useContext(ConfirmCtx);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null);
  const [typed, setTyped] = useState("");
  const confirm = useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => { setTyped(""); setState({ ...o, resolve }); }), []);
  const close = (v: boolean) => { state?.resolve(v); setState(null); };
  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      <Modal open={!!state} onClose={() => close(false)} title={state?.title} size="sm"
        footer={<>
          <Button variant="outline" onClick={() => close(false)}>Cancel</Button>
          <Button variant={state?.danger ? "danger" : "primary"} disabled={!!state?.requireText && typed !== state.requireText}
            onClick={() => close(true)}>{state?.confirmLabel || "Confirm"}</Button>
        </>}>
        <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300">
          <div>{state?.message}</div>
          {state?.requireText && (
            <div>
              <label className="label" htmlFor="confirm-text">Type <span className="font-mono normal-case">{state.requireText}</span> to confirm</label>
              <input id="confirm-text" className="input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </div>
          )}
        </div>
      </Modal>
    </ConfirmCtx.Provider>
  );
}

// ── Toasts ──
type Toast = { id: number; tone: "success" | "error" | "info"; title: string; body?: string };
const ToastCtx = createContext<(t: Omit<Toast, "id">) => void>(() => {});
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = Date.now() + Math.random();
    setToasts((x) => [...x, { ...t, id }]);
    setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), t.tone === "error" ? 9000 : 5000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={clsx("pointer-events-auto rounded-md border p-3 text-sm shadow-lg",
            t.tone === "success" && "border-emerald-200 bg-white dark:border-emerald-900 dark:bg-slate-900",
            t.tone === "error" && "border-red-200 bg-white dark:border-red-900 dark:bg-slate-900",
            t.tone === "info" && "border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-900")}>
            <div className="flex items-start gap-2">
              {t.tone === "success" ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : t.tone === "error" ? <XCircle className="h-4 w-4 text-red-600" /> : <Info className="h-4 w-4 text-brand-600" />}
              <div><p className="font-medium">{t.title}</p>{t.body && <p className="mt-0.5 text-slate-600 dark:text-slate-400">{t.body}</p>}</div>
            </div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

// ── Form helpers ──
export function Field({ label, hint, error, children, required, htmlFor }: { label: string; hint?: ReactNode; error?: string; children: ReactNode; required?: boolean; htmlFor?: string }) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>{label}{required && <span className="text-red-500"> *</span>}</label>
      {children}
      {error ? <p className="mt-1 text-xs text-red-600">{error}</p> : hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={clsx("-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium",
            value === t.id ? "border-brand-600 text-brand-700 dark:text-brand-300" : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="flex items-center justify-between gap-2 border-t border-slate-200 px-3 py-2 text-xs text-slate-500 dark:border-slate-800">
      <span>{total === 0 ? "No results" : `${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}`}</span>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></Button>
        <span>Page {page} / {pages}</span>
        <Button variant="ghost" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight className="h-4 w-4" /></Button>
      </div>
    </div>
  );
}

export function Stat({ label, value, sub, icon, tone = "gray" }: { label: string; value: ReactNode; sub?: ReactNode; icon?: ReactNode; tone?: Tone }) {
  const ring = { gray: "text-slate-500 bg-slate-100 dark:bg-slate-800", green: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/50",
    red: "text-red-600 bg-red-50 dark:bg-red-950/50", amber: "text-amber-600 bg-amber-50 dark:bg-amber-950/50",
    blue: "text-brand-600 bg-brand-50 dark:bg-brand-900/40", violet: "text-violet-600 bg-violet-50 dark:bg-violet-950/50" }[tone];
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-card dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
          {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
        </div>
        {icon && <div className={clsx("rounded-md p-2", ring)}>{icon}</div>}
      </div>
    </div>
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{k}</dt>
          <dd className="mt-0.5 truncate text-sm">{v || <span className="text-slate-400">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DiffView({ diff }: { diff: string }) {
  if (!diff.trim()) return <p className="text-sm text-slate-500">No differences.</p>;
  return (
    <pre className="max-h-[60vh] overflow-auto rounded-md border border-slate-200 bg-white font-mono text-xs dark:border-slate-800 dark:bg-slate-950">
      {diff.split("\n").map((l, i) => (
        <div key={i} className={clsx("px-3",
          l.startsWith("+") && !l.startsWith("+++") && "bg-emerald-50 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300",
          l.startsWith("-") && !l.startsWith("---") && "bg-red-50 text-red-800 dark:bg-red-950/40 dark:text-red-300",
          l.startsWith("@@") && "bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300")}>{l || " "}</div>
      ))}
    </pre>
  );
}

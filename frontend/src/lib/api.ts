// Typed API client. Authentication is an httpOnly, SameSite=Strict session cookie set by the
// server (JavaScript never sees it). Every state-changing request carries the anti-CSRF header
// X-Requested-With: InfraPilot, which a cross-site page cannot set without a CORS preflight.

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;
  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
  get fieldErrors(): { field: string; message: string }[] {
    return (this.details?.errors as { field: string; message: string }[]) || [];
  }
}

const listeners = new Set<() => void>();
export const session = {
  /** Called when the server reports the session has expired (401 on a non-auth endpoint). */
  onExpired(fn: () => void) { listeners.add(fn); return () => listeners.delete(fn); },
};

async function parse(res: Response): Promise<unknown> {
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

function toError(status: number, body: unknown): ApiError {
  const d = (body as { detail?: unknown })?.detail;
  if (d && typeof d === "object" && !Array.isArray(d)) {
    const o = d as { code?: string; message?: string; errors?: unknown };
    return new ApiError(status, o.code || "error", o.message || "Request failed", o as Record<string, unknown>);
  }
  const fallback: Record<number, string> = { 0: "Cannot reach the server. Check your network connection.", 429: "Too many requests - wait a moment and retry.",
    502: "The API is not responding (bad gateway).", 503: "Service temporarily unavailable.", 504: "The request timed out at the gateway." };
  return new ApiError(status, "error", typeof d === "string" ? d : fallback[status] || `Request failed (${status})`);
}

type Opts = { method?: string; body?: unknown; form?: FormData; raw?: boolean };

export async function api<T = unknown>(path: string, opts: Opts = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "InfraPilot", Accept: "application/json" };
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.body); }
  let res: Response;
  try {
    res = await fetch(path, { method: opts.method || (body ? "POST" : "GET"), headers, body, credentials: "same-origin" });
  } catch {
    throw toError(0, null);
  }
  if (res.status === 401 && !path.startsWith("/api/auth/")) listeners.forEach((fn) => fn());
  if (opts.raw && res.ok) return res as unknown as T;
  const data = await parse(res);
  if (!res.ok) throw toError(res.status, data);
  return data as T;
}

export async function download(path: string, fallbackName: string) {
  const res = await api<Response>(path, { raw: true });
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const name = /filename="?([^";]+)"?/.exec(cd)?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function qs(params: Record<string, unknown>): string {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") p.set(k, String(v)); });
  const s = p.toString();
  return s ? `?${s}` : "";
}

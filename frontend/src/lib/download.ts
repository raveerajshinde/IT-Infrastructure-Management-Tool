// Report/evidence downloads use the session cookie; a plain navigation keeps memory use flat for large files.
export function download(url: string) {
  window.location.href = url;
}

export function openInline(url: string) {
  const sep = url.includes("?") ? "&" : "?";
  window.open(`${url}${sep}inline=true`, "_blank", "noopener");
}

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") p.set(k, String(v)); });
  const s = p.toString();
  return s ? `?${s}` : "";
}

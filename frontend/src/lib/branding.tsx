import { useQuery } from "@tanstack/react-query";
import { ReactNode, createContext, useContext, useEffect } from "react";
import { api } from "./api";

export type Branding = {
  product_name: string; tagline: string; organization: string; primary_color: string; logo: string; login_message: string; dashboard_title: string;
};
export const DEFAULT_BRANDING: Branding = {
  product_name: "InfraPilot", tagline: "", organization: "", primary_color: "#2148e0", logo: "", login_message: "", dashboard_title: "Operations overview",
};

const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900] as const;

function hexToRgb(hex: string): [number, number, number] | null {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/** Build a 50-900 palette from one colour: the chosen colour is shade 600 (buttons, links). */
export function palette(hex: string): Record<number, [number, number, number]> | null {
  const base = hexToRgb(hex);
  if (!base) return null;
  const mix = (c: number[], t: number[], w: number) => c.map((v, i) => Math.round(v + (t[i] - v) * w)) as [number, number, number];
  const white = [255, 255, 255], black = [0, 0, 0];
  const w: Record<number, [number[], number]> = {
    50: [white, 0.93], 100: [white, 0.86], 200: [white, 0.72], 300: [white, 0.52], 400: [white, 0.3], 500: [white, 0.12],
    600: [white, 0], 700: [black, 0.18], 800: [black, 0.34], 900: [black, 0.48],
  };
  return Object.fromEntries(SHADES.map((s) => [s, mix(base, w[s][0], w[s][1])])) as Record<number, [number, number, number]>;
}

export function applyBrandColor(hex: string) {
  const p = palette(hex);
  if (!p) return;
  SHADES.forEach((s) => document.documentElement.style.setProperty(`--brand-${s}`, p[s].join(" ")));
}

const Ctx = createContext<Branding>(DEFAULT_BRANDING);
export const useBranding = () => useContext(Ctx);

/** Loads branding from the public /api/branding endpoint (works before sign-in) and applies it. */
export function BrandingProvider({ children }: { children: ReactNode }) {
  const { data } = useQuery({ queryKey: ["branding"], queryFn: () => api<Branding>("/api/branding"), staleTime: 300000, retry: 1 });
  const b = { ...DEFAULT_BRANDING, ...(data || {}) };
  useEffect(() => {
    applyBrandColor(b.primary_color);
    document.title = b.organization ? `${b.product_name} · ${b.organization}` : b.product_name;
  }, [b.primary_color, b.product_name, b.organization]);
  return <Ctx.Provider value={b}>{children}</Ctx.Provider>;
}

/** Logo mark: uploaded image, or the default icon tinted with the brand colour. */
export function BrandMark({ className = "h-8 w-8", fallback }: { className?: string; fallback: ReactNode }) {
  const b = useBranding();
  return b.logo ? <img src={b.logo} alt="" className={`${className} rounded-md object-contain`} /> : <>{fallback}</>;
}

import { useQueryClient } from "@tanstack/react-query";
import { ReactNode, createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { ApiError, api, session } from "./api";
import type { Me } from "./types";

type LoginResult = { mfa_required?: boolean } & Partial<Me>;
type Ctx = {
  user: Me | null; loading: boolean; restricted: boolean;
  login: (u: string, p: string) => Promise<LoginResult>; verifyMfa: (code: string) => Promise<void>;
  logout: () => Promise<void>; reload: () => Promise<void>; can: (perm: string) => boolean;
};
const AuthCtx = createContext<Ctx>(null as unknown as Ctx);
export const useAuth = () => useContext(AuthCtx);

/** UI permission names ("devices.write") map onto server permission codes ("devices:write"). */
const PERM_ALIASES: Record<string, string> = {
  "alerts.ack": "alerts:manage", "devices.import": "devices:write", "devices.test": "devices:read", "credentials.manage": "credentials:write",
  "emergency.execute": "changes:emergency", "jobs.cancel": "automation:run", "maintenance.manage": "approvals:manage",
  "templates.manage": "automation:manage", "commands.manage": "settings:manage",
};
export const toServerPerm = (p: string) => PERM_ALIASES[p] || p.replace(".", ":");

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const pending = useRef<{ u: string; p: string } | null>(null);
  const qc = useQueryClient();

  const loadMe = useCallback(async () => { setUser(await api<Me>("/api/auth/me")); }, []);
  const reload = useCallback(async () => { try { await loadMe(); } catch { setUser(null); } }, [loadMe]);

  useEffect(() => {
    (async () => { try { await loadMe(); } catch { /* not signed in */ } finally { setLoading(false); } })();
    return session.onExpired(() => { setUser(null); qc.clear(); }) as () => void;
  }, [loadMe, qc]);

  const login = async (username: string, password: string) => {
    const r = await api<LoginResult>("/api/auth/login", { body: { username, password } });
    if (r.mfa_required) { pending.current = { u: username, p: password }; return r; }
    pending.current = null;
    await loadMe();
    return r;
  };
  const verifyMfa = async (code: string) => {
    if (!pending.current) throw new ApiError(400, "mfa", "Sign in again");
    await api("/api/auth/login", { body: { username: pending.current.u, password: pending.current.p, totp: code } });
    pending.current = null;
    await loadMe();
  };
  const logout = async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch { /* ignore */ }
    setUser(null); qc.clear();
  };
  const can = (perm: string) => !!user?.permissions.includes(toServerPerm(perm));
  const restricted = !!user && (user.must_change_password || (!!user.mfa_required_by_policy && !user.mfa_enabled));

  return <AuthCtx.Provider value={{ user, loading, restricted, login, verifyMfa, logout, reload, can }}>{children}</AuthCtx.Provider>;
}

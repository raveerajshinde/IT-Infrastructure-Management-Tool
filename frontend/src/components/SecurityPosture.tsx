import { useQuery } from "@tanstack/react-query";
import { ClipboardList, ScrollText, UsersRound } from "lucide-react";
import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago } from "../lib/format";
import { ScoreRing } from "./badges";
import { Card } from "./ui";

type GpoSum = { collection: { domain: string; collected_at: string }; summary: { gpo_count: number; baseline_score: number | null; non_compliant_by_risk: Record<string, number>;
  unlinked: number; empty: number; conflicts: number } };
type AdSum = { domains: { name: string; last_success_at: string | null }[]; totals: Record<string, number> };
type AuditSum = { frameworks: { framework: string; score: number | null; status: string; assessment_id: number }[]; open_findings: number; overdue: number; by_severity: Record<string, number> };

function Tile({ title, icon, to, children, empty }: { title: string; icon: ReactNode; to: string; children?: ReactNode; empty?: ReactNode }) {
  return (
    <Card title={<span className="flex items-center gap-2">{icon}{title}</span>} actions={<Link to={to} className="text-xs text-brand-700 hover:underline dark:text-brand-300">Open</Link>}>
      {children ?? <p className="text-sm text-slate-500">{empty}</p>}
    </Card>
  );
}

const Num = ({ v, label, tone }: { v: number | string; label: string; tone?: string }) => (
  <div><p className={`text-xl font-semibold tabular-nums ${tone || ""}`}>{v}</p><p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p></div>
);

/** Dashboard row for Group Policy, Active Directory and IT audit. Shows real data or a "not set up" hint - never sample numbers. */
export function SecurityPosture() {
  const { can } = useAuth();
  const gpo = useQuery({ queryKey: ["gpo-overview", undefined, undefined], enabled: can("gpo.read"), retry: false, queryFn: () => api<GpoSum>("/api/gpo/overview") });
  const ad = useQuery({ queryKey: ["ad-summary"], enabled: can("ad.read"), queryFn: () => api<AdSum>("/api/ad/summary") });
  const audit = useQuery({ queryKey: ["compliance-dashboard"], enabled: can("compliance.read"), queryFn: () => api<AuditSum>("/api/compliance/dashboard") });
  if (!can("gpo.read") && !can("ad.read") && !can("compliance.read")) return null;
  const adOk = ad.data && ad.data.domains.some((d) => d.last_success_at);
  const t = ad.data?.totals || {};
  const latest = audit.data?.frameworks[0];
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      {can("gpo.read") && (
        <Tile title="Group Policy baseline" icon={<ScrollText className="h-4 w-4" />} to="/gpo/baseline"
          empty={gpo.isLoading ? "Loading…" : "No GPO data yet - collect from a domain controller or upload a GPO report."}>
          {gpo.data && (
            <div className="flex flex-wrap items-center gap-5">
              <ScoreRing score={gpo.data.summary.baseline_score} label={`${gpo.data.collection.domain} · ${ago(gpo.data.collection.collected_at)}`} />
              <div className="grid grid-cols-2 gap-3">
                <Num v={gpo.data.summary.non_compliant_by_risk.critical + gpo.data.summary.non_compliant_by_risk.high} label="Critical/high" tone="text-red-600" />
                <Num v={gpo.data.summary.gpo_count} label="GPOs" />
                <Num v={gpo.data.summary.unlinked + gpo.data.summary.empty} label="Unlinked/empty" />
                <Num v={gpo.data.summary.conflicts} label="Conflicts" />
              </div>
            </div>
          )}
        </Tile>
      )}
      {can("ad.read") && (
        <Tile title="Active Directory" icon={<UsersRound className="h-4 w-4" />} to="/ad/overview"
          empty={ad.isLoading ? "Loading…" : "No synchronised domain - configure one under Active Directory → Domains."}>
          {adOk ? (
            <div className="grid grid-cols-3 gap-3">
              <Num v={t.users ?? 0} label="Users" /><Num v={t.privileged_users ?? 0} label="Privileged" tone="text-red-600" /><Num v={t.inactive_users ?? 0} label="Dormant" tone="text-amber-600" />
              <Num v={t.computers ?? 0} label="Computers" /><Num v={t.stale_computers ?? 0} label="Stale" tone="text-amber-600" /><Num v={t.dcs ?? 0} label="DCs" />
            </div>
          ) : undefined}
        </Tile>
      )}
      {can("compliance.read") && (
        <Tile title="IT audit" icon={<ClipboardList className="h-4 w-4" />} to="/compliance/dashboard"
          empty={audit.isLoading ? "Loading…" : "No assessments yet."}>
          {audit.data && (latest || audit.data.open_findings) ? (
            <div className="flex flex-wrap items-center gap-5">
              {latest && <ScoreRing score={latest.score} label={latest.framework.split(" - ")[0].split("(")[0]} />}
              <div className="grid grid-cols-2 gap-3">
                <Num v={audit.data.open_findings} label="Open findings" /><Num v={audit.data.overdue} label="Overdue" tone={audit.data.overdue ? "text-red-600" : ""} />
                <Num v={(audit.data.by_severity.critical || 0) + (audit.data.by_severity.high || 0)} label="Critical/high" tone="text-red-600" />
              </div>
            </div>
          ) : undefined}
        </Tile>
      )}
    </div>
  );
}

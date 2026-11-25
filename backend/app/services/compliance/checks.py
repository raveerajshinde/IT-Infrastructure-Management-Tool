"""Automated technical checks used as evidence for compliance controls.

Each check reads data InfraPilot already holds (inventory, job results, GPO collections, AD synchronisation,
configuration backups, monitoring, audit trail). A check returns "not_assessed" when the data it needs does
not exist or is too old - it never guesses. Results are evidence for an auditor, not a verdict on the control:
process and policy aspects are assessed manually.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy import false, func, select, true
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.drivers.registry import driver_class
from app.models import (
    AdDomain, AdObject, ApprovalPolicy, ConfigBackup, Device, DeviceGroupMember, Job, JobExecution, Metric, Role, RolePermission,
    Permission, SystemSetting, User, UserRole, Approval,
)

FRESH_DAYS = 30


@dataclass
class CheckResult:
    status: str                       # compliant | partial | non_compliant | not_assessed
    summary: str
    evidence: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)  # {title, severity, asset, description, recommendation, root_cause, impact}


@dataclass
class Ctx:
    db: Session
    scope: dict
    as_of: datetime


CHECKS: dict[str, tuple[str, Callable[[Ctx], CheckResult]]] = {}


def check(key: str, title: str):
    def deco(fn):
        CHECKS[key] = (title, fn)
        return fn
    return deco


def _devices(ctx: Ctx) -> list[Device]:
    q = select(Device).where(Device.deleted_at.is_(None), Device.is_simulated == false())
    devs = ctx.db.execute(q).scalars().all()
    sites = set(ctx.scope.get("site_ids") or [])
    groups = set(ctx.scope.get("group_ids") or [])
    if sites:
        devs = [d for d in devs if d.site_id in sites]
    if groups:
        ids = set(ctx.db.execute(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id.in_(groups))).scalars().all())
        devs = [d for d in devs if d.id in ids]
    return devs


def _cat(d: Device) -> str:
    try:
        return driver_class(d.platform).category
    except Exception:  # noqa: BLE001
        return "other"


def _latest_results(ctx: Ctx, ops: tuple[str, ...], device_ids: list[int], days: int = FRESH_DAYS) -> dict[int, JobExecution]:
    if not device_ids:
        return {}
    since = ctx.as_of - timedelta(days=days)
    rows = ctx.db.execute(select(JobExecution).join(Job, Job.id == JobExecution.job_id)
                          .where(Job.operation_id.in_(ops), JobExecution.status == "succeeded", JobExecution.finished_at >= since,
                                 JobExecution.device_id.in_(device_ids)).order_by(JobExecution.id.desc())).scalars().all()
    out: dict[int, JobExecution] = {}
    for r in rows:
        out.setdefault(r.device_id, r)
    return out


def _ratio_status(ok: int, total: int, good: float = 0.95) -> str:
    if total == 0:
        return "not_assessed"
    r = ok / total
    return "compliant" if r >= good else ("partial" if r >= 0.5 else "non_compliant")


# ------------------------------------------------------------------ inventory
@check("asset_inventory", "Asset inventory is complete and current")
def asset_inventory(ctx: Ctx) -> CheckResult:
    devs = _devices(ctx)
    if not devs:
        return CheckResult("not_assessed", "No devices in the inventory for this scope.")
    week = ctx.as_of - timedelta(days=7)
    seen = [d for d in devs if d.last_checked_at and d.last_checked_at >= week]
    owned = [d for d in devs if (d.owner or "").strip() and d.site_id]
    st = _ratio_status(min(len(seen), len(owned)), len(devs), 0.9)
    f = [{"title": f"Asset without owner or site: {d.hostname}", "severity": "low", "asset": d.hostname,
          "description": "The inventory record has no owner and/or site.", "recommendation": "Assign an owner and site in Devices."}
         for d in devs if d not in owned][:50]
    f += [{"title": f"Asset not seen for 7+ days: {d.hostname}", "severity": "medium", "asset": d.hostname,
           "description": f"Last successful check: {d.last_checked_at or 'never'}.", "recommendation": "Verify the device still exists, its credentials and monitoring."}
          for d in devs if d not in seen][:50]
    by = {}
    for d in devs:
        by[_cat(d)] = by.get(_cat(d), 0) + 1
    return CheckResult(st, f"{len(devs)} assets; {len(seen)} checked in the last 7 days; {len(owned)} with owner and site.",
                       {"assets": len(devs), "by_category": by, "seen_7d": len(seen), "with_owner_and_site": len(owned)}, f)


@check("software_inventory", "Software inventory collected on servers")
def software_inventory(ctx: Ctx) -> CheckResult:
    servers = [d for d in _devices(ctx) if _cat(d) in ("windows", "linux")]
    if not servers:
        return CheckResult("not_assessed", "No Windows/Linux servers in scope.")
    res = _latest_results(ctx, ("windows.software.list", "linux.package.query", "linux.updates.pending"), [d.id for d in servers])
    st = _ratio_status(len(res), len(servers))
    missing = [d.hostname for d in servers if d.id not in res]
    return CheckResult(st, f"Software inventory collected in the last {FRESH_DAYS} days for {len(res)} of {len(servers)} servers.",
                       {"servers": len(servers), "with_inventory": len(res), "missing": missing[:200]},
                       [{"title": "Software inventory not collected", "severity": "low", "asset": ", ".join(missing[:20]) + (" …" if len(missing) > 20 else ""),
                         "description": f"{len(missing)} server(s) have no software inventory from the last {FRESH_DAYS} days.",
                         "recommendation": "Schedule 'Installed software' (Windows) / package queries (Linux) monthly in Automation -> Schedules."}] if missing else [])


@check("patch_status", "Operating system patches are applied")
def patch_status(ctx: Ctx) -> CheckResult:
    servers = [d for d in _devices(ctx) if _cat(d) in ("windows", "linux")]
    res = _latest_results(ctx, ("windows.updates.pending", "linux.updates.pending"), [d.id for d in servers])
    if not res:
        return CheckResult("not_assessed", f"No pending-update scans in the last {FRESH_DAYS} days. Schedule 'Pending Windows updates' / "
                                           "'Pending package updates' to assess patch compliance.")
    names = {d.id: d.hostname for d in servers}
    findings, ok, rows = [], 0, []
    for did, ex in res.items():
        items = ex.result if isinstance(ex.result, list) else (ex.result or {}).get("items", []) if isinstance(ex.result, dict) else []
        crit = [u for u in items if isinstance(u, dict) and (str(u.get("Severity", "")).lower() in ("critical", "important") or u.get("security"))]
        rows.append({"device": names.get(did), "pending": len(items), "security": len(crit), "scanned": ex.finished_at.isoformat()})
        if crit:
            findings.append({"title": f"Security updates pending on {names.get(did)}", "severity": "high" if len(crit) >= 5 else "medium",
                             "asset": names.get(did), "description": f"{len(crit)} security/critical update(s) pending of {len(items)} total "
                                                                     f"(scan {ex.finished_at:%Y-%m-%d}).",
                             "recommendation": "Install pending security updates in the next maintenance window."})
        else:
            ok += 1
    st = _ratio_status(ok, len(res))
    unscanned = len(servers) - len(res)
    if unscanned and st == "compliant":
        st = "partial"
    return CheckResult(st, f"{len(res)} server(s) scanned in the last {FRESH_DAYS} days; {ok} without pending security updates; {unscanned} not scanned.",
                       {"servers": len(servers), "scanned": len(res), "rows": rows}, findings)


@check("config_backup", "Network and firewall configurations are backed up")
def config_backup(ctx: Ctx) -> CheckResult:
    net = [d for d in _devices(ctx) if _cat(d) in ("network", "firewall")]
    if not net:
        return CheckResult("not_assessed", "No switches, routers or firewalls in scope.")
    latest = dict(ctx.db.execute(select(ConfigBackup.device_id, func.max(ConfigBackup.created_at)).where(ConfigBackup.device_id.in_([d.id for d in net]))
                                 .group_by(ConfigBackup.device_id)).all())
    week = ctx.as_of - timedelta(days=7)
    ok = [d for d in net if latest.get(d.id) and latest[d.id] >= week]
    f = [{"title": f"No recent configuration backup: {d.hostname}", "severity": "medium" if latest.get(d.id) else "high", "asset": d.hostname,
          "description": f"Latest backup: {latest[d.id]:%Y-%m-%d}" if latest.get(d.id) else "No configuration backup has ever been taken.",
          "recommendation": "Check the device credentials; scheduled backups run every N hours (Settings -> General)."} for d in net if d not in ok]
    return CheckResult(_ratio_status(len(ok), len(net)), f"{len(ok)} of {len(net)} network/firewall devices backed up in the last 7 days.",
                       {"devices": len(net), "backed_up_7d": len(ok), "latest": {d.hostname: latest.get(d.id).isoformat() if latest.get(d.id) else None for d in net}}, f)


@check("backup_offsite", "Backups are copied off the server")
def backup_offsite(ctx: Ctx) -> CheckResult:
    st = {}
    for key in ("offsite.state", "devexport.state"):
        row = ctx.db.get(SystemSetting, key)
        st[key] = dict(row.value or {}) if row else {}
    from app.services import settings_store
    v = settings_store.all_values(ctx.db)
    enabled = bool(v.get("offsite.enabled") and v.get("offsite.share")) or bool(v.get("devexport.enabled") and v.get("devexport.path"))
    if not enabled:
        return CheckResult("non_compliant", "No backup copy destination (network share or folder) is configured.", {"configured": False},
                           [{"title": "Backups are not copied off the InfraPilot server", "severity": "medium", "asset": "InfraPilot",
                             "description": "Database, configuration and device backups exist only on the InfraPilot host.",
                             "recommendation": "Configure Settings -> Backup -> Network share or Folder on the server."}])
    stamps = [x for s in st.values() for x in (s.get("last_backup_upload_at"), s.get("last_config_export_at"), s.get("last_export_at")) if x]
    last = max(stamps) if stamps else None
    errors = [s.get("last_error") for s in st.values() if s.get("last_error")]
    recent = last and datetime.fromisoformat(last.rstrip("Z")) >= ctx.as_of - timedelta(days=2)
    status = "compliant" if recent and not errors else ("partial" if last else "non_compliant")
    return CheckResult(status, f"Backup copy configured; last copy {last or 'never'}{'; errors: ' + '; '.join(errors) if errors else ''}.",
                       {"configured": True, "last_copy": last, "errors": errors},
                       [] if status == "compliant" else [{"title": "Backup copy is failing or stale", "severity": "medium", "asset": "InfraPilot",
                                                          "description": "; ".join(errors) or f"Last copy {last or 'never'}.",
                                                          "recommendation": "Fix the destination on Settings -> Backup and run 'Copy now'."}])


# ------------------------------------------------------------------ Group Policy
def _gpo(ctx: Ctx):
    from app.services.gpo import store
    from app.models import GpoCollection
    doms = ctx.scope.get("gpo_domains") or None
    q = select(GpoCollection).order_by(GpoCollection.id.desc())
    cols = ctx.db.execute(q.limit(200)).scalars().all()
    latest: dict[str, GpoCollection] = {}
    for c in cols:
        if (not doms or c.domain in doms) and c.domain not in latest:
            latest[c.domain] = c
    return [(c, store.analyse(ctx.db, c).baseline()) for c in latest.values()], latest


def _gpo_check(ctx: Ctx, rule_prefixes: tuple[str, ...], label: str) -> CheckResult:
    data, latest = _gpo(ctx)
    if not data:
        return CheckResult("not_assessed", "No Group Policy data. Collect GPOs from a domain controller or upload a GPO report (Group Policy).")
    stale = [c.domain for c in latest.values() if c.collected_at < ctx.as_of - timedelta(days=FRESH_DAYS)]
    rows, findings = [], []
    worst = "compliant"
    for c, rules in data:
        for r in rules:
            if not r["rule_id"].startswith(rule_prefixes):
                continue
            rows.append({"domain": c.domain, "rule": r["rule_id"], "title": r["title"], "status": r["status"], "risk": r["risk"],
                         "values": [v["value"] for v in r["effective_values"]][:5]})
            if r["status"] == "non_compliant":
                worst = "non_compliant" if r["risk"] in ("critical", "high") or worst == "non_compliant" else "partial"
                vals = "; ".join(f"{v['ou']}: {v['value']} ({v['gpo']})" for v in r["effective_values"] if v["status"] == "non_compliant")
                findings.append({"title": f"GPO: {r['title']} not as expected", "severity": r["risk"], "asset": f"{c.domain} - {vals[:200]}",
                                 "description": f"Expected {r['expected']}. Effective: {vals}.", "recommendation": r["recommendation"],
                                 "root_cause": "Group Policy configuration differs from the security baseline.", "impact": r["explanation"]})
    assessed = [x for x in rows if x["status"] in ("compliant", "non_compliant")]
    if not assessed:
        return CheckResult("not_assessed", f"None of the {label} baseline settings are configured by Group Policy (they may be set locally - verify separately).",
                           {"rules": rows})
    summary = f"{sum(1 for x in assessed if x['status'] == 'compliant')} of {len(assessed)} configured {label} settings meet the baseline; " \
              f"{sum(1 for x in rows if x['status'] == 'not_configured')} not configured by GPO."
    if stale:
        summary += f" GPO data older than {FRESH_DAYS} days for: {', '.join(stale)}."
    return CheckResult(worst, summary, {"collections": {d: c.id for d, c in latest.items()}, "rules": rows}, findings)


@check("gpo_baseline", "Windows security baseline (Group Policy)")
def gpo_baseline(ctx): return _gpo_check(ctx, ("",), "security")  # noqa: E704


@check("gpo_password", "Password and lockout policy (Group Policy)")
def gpo_password(ctx): return _gpo_check(ctx, ("PWD-", "LOCK-", "KRB-"), "password/lockout")  # noqa: E704


@check("gpo_audit", "Audit policy (Group Policy)")
def gpo_audit(ctx): return _gpo_check(ctx, ("AUD-", "AAUD-", "EVT-", "SO-AUDITSUB"), "audit/logging")  # noqa: E704


@check("gpo_malware", "Microsoft Defender / anti-malware policy (Group Policy)")
def gpo_malware(ctx): return _gpo_check(ctx, ("AT-DEFENDER",), "anti-malware")  # noqa: E704


@check("gpo_host_firewall", "Host firewall policy (Group Policy)")
def gpo_host_firewall(ctx): return _gpo_check(ctx, ("FW-",), "host firewall")  # noqa: E704


@check("gpo_remote_access", "Remote access and protocol security (Group Policy)")
def gpo_remote_access(ctx): return _gpo_check(ctx, ("AT-RDP", "UR-RDP", "AT-WINRM", "AT-SMB1", "SO-LMCOMPAT", "SO-SMB", "AT-WDIGEST", "AT-LLMNR"), "remote access")  # noqa: E704,E501


@check("gpo_updates", "Windows Update policy (Group Policy)")
def gpo_updates(ctx): return _gpo_check(ctx, ("AT-WU",), "Windows Update")  # noqa: E704


@check("gpo_removable_media", "Removable media / AutoRun policy (Group Policy)")
def gpo_removable_media(ctx): return _gpo_check(ctx, ("AT-AUTORUN", "AT-AUTOPLAY"), "removable media")  # noqa: E704


# ------------------------------------------------------------------ Active Directory
def _ad(ctx: Ctx) -> list[AdDomain]:
    ids = set(ctx.scope.get("ad_domain_ids") or [])
    doms = ctx.db.execute(select(AdDomain).where(AdDomain.last_success_at.is_not(None))).scalars().all()
    return [d for d in doms if not ids or d.id in ids]


def _ad_fresh(ctx: Ctx) -> tuple[list[AdDomain], str]:
    doms = _ad(ctx)
    if not doms:
        return [], "No synchronised Active Directory domain. Configure one under Active Directory -> Domains."
    stale = [d.name for d in doms if d.last_success_at < ctx.as_of - timedelta(days=7)]
    return doms, (f" Directory data older than 7 days for: {', '.join(stale)}." if stale else "")


@check("ad_inactive_users", "Dormant user accounts are disabled")
def ad_inactive_users(ctx: Ctx) -> CheckResult:
    from app.services import ad
    doms, note = _ad_fresh(ctx)
    if not doms:
        return CheckResult("not_assessed", note)
    rows, f, enabled = [], [], 0
    for d in doms:
        head, data, _ = ad.report(ctx.db, d, "inactive-users")
        enabled += (d.stats or {}).get("enabled_users", 0)
        for r in data:
            rows.append({"domain": d.name, "account": r[0], "last_logon": r[2], "privileged": r[4]})
        if data:
            f.append({"title": f"{len(data)} dormant enabled account(s) in {d.name}", "severity": "high" if any(r[4] for r in data) else "medium",
                      "asset": d.name, "description": f"Enabled accounts with no logon for {d.stale_days}+ days: " + ", ".join(r[0] for r in data[:30]) + (" …" if len(data) > 30 else ""),
                      "recommendation": "Disable dormant accounts after confirming with their owners; automate leaver processing.",
                      "root_cause": "Accounts are not disabled when staff leave or roles end.", "impact": "Unused accounts are easy targets for password attacks."})
    pct = len(rows) / enabled if enabled else 0
    st = "compliant" if not rows else ("partial" if pct <= 0.02 else "non_compliant")
    return CheckResult(st, f"{len(rows)} dormant enabled user account(s) of {enabled} enabled.{note}", {"dormant": rows[:500], "enabled_users": enabled}, f)


@check("ad_stale_computers", "Stale computer accounts are removed")
def ad_stale_computers(ctx: Ctx) -> CheckResult:
    from app.services import ad
    doms, note = _ad_fresh(ctx)
    if not doms:
        return CheckResult("not_assessed", note)
    rows = [(d, r) for d in doms for r in ad.report(ctx.db, d, "stale-computers")[1]]
    total = sum((d.stats or {}).get("computers", 0) for d in doms)
    st = "compliant" if not rows else ("partial" if total and len(rows) / total <= 0.05 else "non_compliant")
    return CheckResult(st, f"{len(rows)} stale computer account(s) of {total}.{note}", {"stale": [{"domain": d.name, "computer": r[0], "last_logon": r[3]} for d, r in rows][:500]},
                       [{"title": f"{len(rows)} stale computer account(s)", "severity": "low", "asset": ", ".join(sorted({d.name for d, _ in rows})),
                         "description": ", ".join(r[0] for _, r in rows[:40]), "recommendation": "Disable, then delete stale computer accounts after a grace period."}] if rows else [])


@check("ad_privileged", "Privileged accounts are minimal and controlled")
def ad_privileged(ctx: Ctx) -> CheckResult:
    from app.services import ad
    doms, note = _ad_fresh(ctx)
    if not doms:
        return CheckResult("not_assessed", note)
    rows, f, st = [], [], "compliant"
    for d in doms:
        priv = ad.report(ctx.db, d, "privileged")[1]
        da = {r[1] for r in ad.report(ctx.db, d, "domain-admins")[1] if r[0] == "Domain Admins" and r[2] == "user"}
        risky = [r for r in priv if r[8] in ("High", "Medium")]
        rows += [{"domain": d.name, "account": r[0], "groups": r[3], "last_logon": r[4], "never_expires": r[6], "spn": r[7], "risk": r[8]} for r in priv]
        if len(da) > 5:
            st = "partial" if st == "compliant" else st
            f.append({"title": f"{len(da)} members of Domain Admins in {d.name}", "severity": "medium", "asset": d.name,
                      "description": "Domain Admins: " + ", ".join(sorted(da)), "recommendation": "Keep Domain Admins to a few named break-glass/admin accounts; delegate the rest.",
                      "root_cause": "Administrative rights granted broadly instead of delegated.", "impact": "Each additional Domain Admin increases the chance of full domain compromise."})
        for r in risky:
            st = "non_compliant" if r[8] == "High" else ("partial" if st == "compliant" else st)
            f.append({"title": f"Risky privileged account {r[0]}", "severity": "high" if r[8] == "High" else "medium", "asset": f"{d.name}\\{r[0]}",
                      "description": f"Groups: {r[3]}; last logon {r[4]}; password never expires: {r[6]}; SPN: {r[7]}.",
                      "recommendation": "Remove SPNs from admin accounts, rotate passwords regularly, disable unused admin accounts."})
    return CheckResult(st, f"{len(rows)} privileged account(s) across {len(doms)} domain(s); {len(f)} issue(s).{note}", {"privileged": rows}, f)


@check("ad_risky_accounts", "No accounts with insecure authentication settings")
def ad_risky_accounts(ctx: Ctx) -> CheckResult:
    from app.services import ad
    doms, note = _ad_fresh(ctx)
    if not doms:
        return CheckResult("not_assessed", note)
    rows = [(d, r) for d in doms for r in ad.report(ctx.db, d, "risky-accounts")[1]]
    sev = {"Critical": "critical", "High": "high", "Medium": "medium"}
    st = "compliant" if not rows else ("non_compliant" if any(r[4] in ("Critical", "High") for _, r in rows) else "partial")
    return CheckResult(st, f"{len(rows)} account setting issue(s).{note}", {"issues": [{"domain": d.name, "account": r[0], "issue": r[3], "risk": r[4]} for d, r in rows]},
                       [{"title": f"{r[3]}: {r[0]}", "severity": sev.get(r[4], "medium"), "asset": f"{d.name}\\{r[0]}", "description": r[3], "recommendation": r[5]}
                        for d, r in rows[:100]])


@check("ad_password_policy", "Domain password and lockout policy")
def ad_password_policy(ctx: Ctx) -> CheckResult:
    doms, note = _ad_fresh(ctx)
    if not doms:
        return CheckResult("not_assessed", note)
    f, rows = [], []
    for d in doms:
        p = (d.stats or {}).get("policy") or {}
        issues = []
        if p.get("min_pwd_length") is not None and p["min_pwd_length"] < 14:
            issues.append(f"minimum length {p['min_pwd_length']} (< 14)")
        if p.get("lockout_threshold") is not None and not 1 <= p["lockout_threshold"] <= 10:
            issues.append(f"lockout threshold {p['lockout_threshold']} ({'no lockout' if p['lockout_threshold'] == 0 else '> 10'})")
        if p.get("pwd_history") is not None and p["pwd_history"] < 24:
            issues.append(f"password history {p['pwd_history']} (< 24)")
        rows.append({"domain": d.name, **p, "issues": issues})
        if issues:
            f.append({"title": f"Weak domain password policy in {d.name}", "severity": "high", "asset": d.name, "description": "; ".join(issues),
                      "recommendation": "Raise minimum length to 14+, set lockout to 5-10 attempts (or use fine-grained policies)."})
    return CheckResult("non_compliant" if f else "compliant", f"Domain policy checked for {len(doms)} domain(s); {len(f)} with issues.{note}", {"domains": rows}, f)


# ------------------------------------------------------------------ servers / network
@check("linux_ssh", "SSH server hardening on Linux")
def linux_ssh(ctx: Ctx) -> CheckResult:
    lx = [d for d in _devices(ctx) if _cat(d) == "linux"]
    res = _latest_results(ctx, ("linux.ssh.config",), [d.id for d in lx])
    if not res:
        return CheckResult("not_assessed", "No sshd configuration collected in the last 30 days (run 'Effective sshd configuration').")
    names = {d.id: d.hostname for d in lx}
    f, ok = [], 0
    for did, ex in res.items():
        c = {k.lower(): str(v).lower() for k, v in (ex.result or {}).items()} if isinstance(ex.result, dict) else {}
        issues = []
        if c.get("permitrootlogin") not in ("no", "prohibit-password", "without-password", "forced-commands-only", None):
            issues.append(f"PermitRootLogin {c.get('permitrootlogin')}")
        if c.get("passwordauthentication") == "yes":
            issues.append("PasswordAuthentication yes")
        if c.get("permitemptypasswords") == "yes":
            issues.append("PermitEmptyPasswords yes")
        if c.get("x11forwarding") == "yes":
            issues.append("X11Forwarding yes")
        try:
            if int(c.get("maxauthtries", "6")) > 4:
                issues.append(f"MaxAuthTries {c.get('maxauthtries')}")
        except ValueError:
            pass
        if issues:
            f.append({"title": f"SSH hardening gaps on {names.get(did)}", "severity": "high" if any("Root" in i or "Empty" in i for i in issues) else "medium",
                      "asset": names.get(did), "description": "; ".join(issues), "recommendation": "Disable root and password logins, X11 forwarding; MaxAuthTries 4."})
        else:
            ok += 1
    return CheckResult(_ratio_status(ok, len(res)), f"{ok} of {len(res)} Linux servers meet the SSH baseline ({len(lx) - len(res)} not checked).",
                       {"checked": len(res), "servers": len(lx)}, f)


@check("firewall_rules", "Firewall rules are restrictive")
def firewall_rules(ctx: Ctx) -> CheckResult:
    fws = [d for d in _devices(ctx) if _cat(d) == "firewall"]
    res = _latest_results(ctx, ("firewall.rules.analyse",), [d.id for d in fws], days=90)
    if not res:
        return CheckResult("not_assessed", "No firewall rule analysis in the last 90 days (run 'Analyse policies' on each firewall).")
    names = {d.id: d.hostname for d in fws}
    f, ok = [], 0
    for did, ex in res.items():
        fs = (ex.result or {}).get("findings") or [] if isinstance(ex.result, dict) else []
        hi = [x for x in fs if str(x.get("severity", "")).lower() in ("high", "critical")]
        for x in fs[:50]:
            f.append({"title": f"Broad firewall rule on {names.get(did)}: {x.get('rule_name') or x.get('rule_id')}", "severity": str(x.get("severity") or "medium").lower(),
                      "asset": names.get(did), "description": "; ".join(x.get("issues") or []), "recommendation": "Restrict source, destination and service; remove unused rules."})
        if not hi:
            ok += 1
    st = _ratio_status(ok, len(res))
    return CheckResult(st if not f or st != "compliant" else "partial", f"{len(res)} firewall(s) analysed; {len(f)} broad rule(s).",
                       {"analysed": len(res), "firewalls": len(fws)}, f)


@check("monitoring_coverage", "Infrastructure is monitored with alerting")
def monitoring_coverage(ctx: Ctx) -> CheckResult:
    devs = _devices(ctx)
    if not devs:
        return CheckResult("not_assessed", "No devices in scope.")
    since = ctx.as_of - timedelta(days=1)
    mon = set(ctx.db.execute(select(Metric.device_id).where(Metric.ts >= since, Metric.device_id.in_([d.id for d in devs])).distinct()).scalars().all())
    from app.models import AlertRule
    rules = ctx.db.execute(select(func.count()).select_from(AlertRule).where(AlertRule.enabled == true())).scalar()
    st = _ratio_status(len(mon), len(devs), 0.9)
    if not rules:
        st = "non_compliant"
    return CheckResult(st, f"{len(mon)} of {len(devs)} devices reported metrics in the last 24 hours; {rules} alert rule(s) enabled.",
                       {"monitored_24h": len(mon), "devices": len(devs), "alert_rules": rules},
                       [{"title": "Devices without monitoring data", "severity": "medium", "asset": ", ".join(d.hostname for d in devs if d.id not in mon)[:250],
                         "description": f"{len(devs) - len(mon)} device(s) sent no metrics in the last 24 hours.",
                         "recommendation": "Check credentials/SNMP and that the worker can reach the devices."}] if len(mon) < len(devs) else [])


# ------------------------------------------------------------------ platform
@check("audit_trail", "Administrative actions are logged in a tamper-evident trail")
def audit_trail(ctx: Ctx) -> CheckResult:
    from app.services import audit
    r = audit.verify_chain(ctx.db)
    ok = bool(r.get("valid", r.get("ok")))
    return CheckResult("compliant" if ok else "non_compliant", f"Audit hash chain verified over {r.get('checked', '?')} record(s): {'intact' if ok else 'BROKEN'}.",
                       {k: v for k, v in r.items() if k != "records"},
                       [] if ok else [{"title": "Audit trail integrity check failed", "severity": "critical", "asset": "InfraPilot",
                                       "description": str(r)[:500], "recommendation": "Investigate database access; restore the audit table from backup."}])


@check("change_control", "Changes go through approval")
def change_control(ctx: Ctx) -> CheckResult:
    pols = ctx.db.execute(select(ApprovalPolicy).where(ApprovalPolicy.enabled == true(), ApprovalPolicy.require_approval == true())).scalars().all()
    crit = any(p.risk in ("critical", None) for p in pols)
    since = ctx.as_of - timedelta(days=90)
    em = ctx.db.execute(select(Job).where(Job.is_emergency == true(), Job.created_at >= since)).scalars().all()
    pending = ctx.db.execute(select(func.count()).select_from(Approval).where(Approval.kind == "emergency_review", Approval.status == "pending")).scalar()
    changes = ctx.db.execute(select(func.count()).select_from(Job).where(Job.risk != "read", Job.created_at >= since)).scalar()
    st = "compliant" if crit and not pending else ("partial" if pols else "non_compliant")
    f = []
    if not crit:
        f.append({"title": "Critical changes do not require approval", "severity": "high", "asset": "InfraPilot", "description": "No enabled approval policy covers critical-risk operations.",
                  "recommendation": "Enable 'Critical changes always need approval' (Approvals -> Policies)."})
    if pending:
        f.append({"title": f"{pending} emergency change(s) awaiting post-implementation review", "severity": "medium", "asset": "InfraPilot",
                  "description": "Emergency changes were executed without pre-approval and have not been reviewed.", "recommendation": "Review them in Approvals."})
    return CheckResult(st, f"{len(pols)} approval polic(ies) enabled; {changes} change job(s) and {len(em)} emergency change(s) in 90 days; {pending} review(s) pending.",
                       {"policies": [p.name for p in pols], "change_jobs_90d": changes, "emergency_90d": len(em), "pending_reviews": pending}, f)


@check("platform_mfa", "Administrators of InfraPilot use MFA")
def platform_mfa(ctx: Ctx) -> CheckResult:
    admin_perm = ctx.db.execute(select(Permission.id).where(Permission.code.in_(["settings:manage", "users:manage", "windows:change", "network:change",
                                                                                 "firewall:change", "linux:change"]))).scalars().all()
    role_ids = set(ctx.db.execute(select(RolePermission.role_id).where(RolePermission.permission_id.in_(admin_perm or [-1]))).scalars().all())
    uids = set(ctx.db.execute(select(UserRole.user_id).where(UserRole.role_id.in_(role_ids or {-1}))).scalars().all())
    users = [u for u in ctx.db.execute(select(User).where(User.is_active == true())).scalars().all() if u.id in uids]
    if not users:
        return CheckResult("not_assessed", "No active administrative users.")
    from app.services import settings_store
    required = bool(settings_store.value(ctx.db, "security.mfa_required"))
    without = [u.username for u in users if not u.mfa_enabled and getattr(u, "auth_source", "local") == "local"]
    st = "compliant" if not without else ("partial" if len(without) < len(users) else "non_compliant")
    return CheckResult(st, f"{len(users) - len(without)} of {len(users)} administrative users have MFA; MFA required for all: {required}.",
                       {"admins": len(users), "without_mfa": without, "mfa_required_setting": required},
                       [{"title": "Administrators without MFA", "severity": "high", "asset": "InfraPilot", "description": ", ".join(without),
                         "recommendation": "Enable 'Require MFA' (Settings -> Security) and have each administrator enrol."}] if without else [])


def run(db: Session, keys: list[str], scope: dict | None = None, as_of: datetime | None = None) -> dict[str, CheckResult]:
    ctx = Ctx(db, scope or {}, as_of or utcnow())
    out = {}
    for k in dict.fromkeys(keys):
        if k not in CHECKS:
            continue
        try:
            out[k] = CHECKS[k][1](ctx)
        except Exception as exc:  # noqa: BLE001 - one broken data source must not stop the assessment
            out[k] = CheckResult("not_assessed", f"Check could not run: {exc.__class__.__name__}: {str(exc)[:300]}")
    return out

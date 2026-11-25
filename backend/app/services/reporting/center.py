"""Report Center: report templates built from live data, scheduled generation and e-mail delivery.

Every number comes from InfraPilot's database (inventory, monitoring metrics, alerts, jobs, configuration backups,
GPO collections, AD synchronisation, assessments). Where a data source has never been populated the report says so
instead of showing zeros that look like good news.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from sqlalchemy import func, select, true
from sqlalchemy.orm import Session

from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.drivers.registry import driver_class
from app.models import (
    AdDomain, Alert, Assessment, AuditLog, ComplianceFramework, ConfigBackup, ConfigChange, Device, DeviceGroupMember, Finding, Job,
    JobExecution, Metric, ReportRun, ReportSchedule, Site, User,
)
from app.services import auth, settings_store
from app.services.reporting.render import Doc, Section, Table


@dataclass
class Template:
    key: str
    title: str
    description: str
    permission: str
    build: Callable
    filters: tuple[str, ...] = ("site_id", "department", "device_type", "asset")
    default_days: int = 30


TEMPLATES: dict[str, Template] = {}


def template(key: str, title: str, description: str, permission: str, filters=("site_id", "department", "device_type", "asset"), days: int = 30):
    def deco(fn):
        TEMPLATES[key] = Template(key, title, description, permission, fn, tuple(filters), days)
        return fn
    return deco


# ------------------------------------------------------------------ helpers
def _cat(d: Device) -> str:
    try:
        return driver_class(d.platform).category
    except Exception:  # noqa: BLE001
        return "other"


def devices(db: Session, user: User | None, p: dict) -> list[Device]:
    devs = db.execute(select(Device).where(Device.deleted_at.is_(None)).order_by(Device.hostname)).scalars().all()
    if user is not None:
        groups = auth.visible_device_filter(db, user)
        if groups is not None:
            ids = set(db.execute(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id.in_(groups or {-1}))).scalars().all())
            devs = [d for d in devs if d.id in ids]
    if p.get("site_id"):
        devs = [d for d in devs if d.site_id == int(p["site_id"])]
    if p.get("department"):
        devs = [d for d in devs if (d.department or "").lower() == str(p["department"]).lower()]
    if p.get("device_type"):
        devs = [d for d in devs if d.device_type == p["device_type"] or _cat(d) == p["device_type"]]
    if p.get("asset"):
        q = str(p["asset"]).lower()
        devs = [d for d in devs if q in d.hostname.lower() or q in (d.ip_address or "")]
    return devs


def _filters_text(db: Session, p: dict) -> str:
    parts = []
    if p.get("site_id"):
        s = db.get(Site, int(p["site_id"]))
        parts.append(f"site {s.name if s else p['site_id']}")
    for k in ("department", "device_type", "asset", "severity"):
        if p.get(k):
            parts.append(f"{k.replace('_', ' ')} {p[k]}")
    return ", ".join(parts) or "none"


def _metric_stats(db: Session, ids: list[int], since) -> dict[int, dict[str, tuple[float, float]]]:
    out: dict[int, dict[str, tuple[float, float]]] = {}
    if not ids:
        return out
    rows = db.execute(select(Metric.device_id, Metric.metric, func.avg(Metric.value), func.max(Metric.value))
                      .where(Metric.device_id.in_(ids), Metric.ts >= since, Metric.metric.in_(["cpu_pct", "mem_pct", "disk_pct", "availability"]))
                      .group_by(Metric.device_id, Metric.metric)).all()
    for did, m, avg, mx in rows:
        out.setdefault(did, {})[m] = (round(float(avg or 0), 1), round(float(mx or 0), 1))
    return out


def _sev_ok(p: dict, sev: str) -> bool:
    return not p.get("severity") or sev.lower() in [s.strip().lower() for s in str(p["severity"]).split(",")]


def _backups(db: Session, ids: list[int]) -> dict[int, object]:
    if not ids:
        return {}
    return dict(db.execute(select(ConfigBackup.device_id, func.max(ConfigBackup.created_at)).where(ConfigBackup.device_id.in_(ids))
                           .group_by(ConfigBackup.device_id)).all())


def _doc(db: Session, t: Template, p: dict, subtitle: str = "") -> Doc:
    days = int(p.get("days") or t.default_days)
    return Doc(title=t.title, subtitle=subtitle or t.description, organisation=settings_store.value(db, "ui.organization_name") or "",
               meta=[("Period", f"last {days} day(s)" if "days" in p or t.default_days else "current state"), ("Filters", _filters_text(db, p))])


# ------------------------------------------------------------------ templates
@template("daily-health", "Daily IT Infrastructure Health Report", "Availability, open alerts, resource pressure, failed jobs and backup status for the last 24 hours.",
          "dashboard:read", days=1)
def daily_health(db: Session, user, p: dict) -> Doc:
    t = TEMPLATES["daily-health"]
    since = utcnow() - timedelta(days=int(p.get("days") or 1))
    devs = devices(db, user, p)
    ids = [d.id for d in devs]
    stats = _metric_stats(db, ids, since)
    down = [d for d in devs if d.status in ("down", "unreachable")]
    alerts = [a for a in db.execute(select(Alert).where(Alert.status != "resolved").order_by(Alert.id.desc()).limit(2000)).scalars().all()
              if (a.device_id is None or a.device_id in ids) and _sev_ok(p, a.severity)]
    failed = db.execute(select(Job).where(Job.created_at >= since, Job.status.in_(["failed", "partial"])).order_by(Job.id.desc()).limit(500)).scalars().all()
    pressure = [(d, stats.get(d.id, {})) for d in devs if any(stats.get(d.id, {}).get(m, (0, 0))[1] >= 85 for m in ("cpu_pct", "mem_pct", "disk_pct"))]
    last = _backups(db, [d.id for d in devs if _cat(d) in ("network", "firewall")])
    stale = [d for d in devs if _cat(d) in ("network", "firewall") and (not last.get(d.id) or last[d.id] < utcnow() - timedelta(days=2))]
    doc = _doc(db, t, p)
    doc.kpis = [("Devices", len(devs), ""), ("Down / unreachable", len(down), "critical" if down else "compliant"),
                ("Open alerts", len(alerts), "high" if alerts else "compliant"), ("Critical alerts", sum(1 for a in alerts if a.severity == "critical"), "critical"),
                ("Failed jobs", len(failed), "medium" if failed else "compliant"), ("Backups older than 48 h", len(stale), "medium" if stale else "compliant")]
    doc.sections = [
        Section("Availability", paragraphs=[f"{len(devs) - len(down)} of {len(devs)} devices are up." if devs else "No devices match the filters."],
                tables=[Table(["Device", "IP", "Type", "Site", "Status", "Last seen", "Last error"],
                              [[d.hostname, d.ip_address, d.device_type, d.site.name if d.site else "", d.status, d.last_checked_at, d.last_error or ""] for d in down],
                              title="Devices down or unreachable")]),
        Section("Open alerts", tables=[Table(["Opened", "Severity", "Title", "Occurrences", "Status"],
                                             [[a.first_seen_at, a.severity.title(), a.title, a.count, a.status] for a in alerts[:500]])]),
        Section("Resource pressure (peak ≥ 85% in the period)", paragraphs=[] if stats else ["No monitoring metrics in the period."],
                tables=[Table(["Device", "CPU avg/max %", "Memory avg/max %", "Disk avg/max %"],
                              [[d.hostname, "/".join(map(str, s.get("cpu_pct", ("-", "-")))), "/".join(map(str, s.get("mem_pct", ("-", "-")))),
                                "/".join(map(str, s.get("disk_pct", ("-", "-"))))] for d, s in pressure])]),
        Section("Failed jobs", tables=[Table(["Job", "Operation", "Status", "Summary", "Created"], [[f"#{j.id} {j.title}", j.operation_id or j.playbook, j.status, j.summary, j.created_at] for j in failed])]),
        Section("Configuration backups older than 48 hours", tables=[Table(["Device", "Type", "Latest backup", "Status"],
                                                                         [[d.hostname, d.device_type, last.get(d.id) or "never", "Stale" if last.get(d.id) else "Missing"] for d in stale])]),
    ]
    return doc


@template("weekly-server-health", "Weekly Server Health Report", "Windows and Linux servers: availability, CPU, memory and disk over the week, alerts and pending updates.",
          "monitoring:read", days=7)
def weekly_server(db: Session, user, p: dict) -> Doc:
    t = TEMPLATES["weekly-server-health"]
    days = int(p.get("days") or 7)
    since = utcnow() - timedelta(days=days)
    servers = [d for d in devices(db, user, p) if _cat(d) in ("windows", "linux", "virtualization")]
    stats = _metric_stats(db, [d.id for d in servers], since)
    acount = dict(db.execute(select(Alert.device_id, func.count()).where(Alert.first_seen_at >= since).group_by(Alert.device_id)).all())
    upd = {}
    for e, j in db.execute(select(JobExecution, Job).join(Job, Job.id == JobExecution.job_id).where(
            Job.operation_id.in_(["windows.updates.pending", "linux.updates.pending"]), JobExecution.status == "succeeded",
            JobExecution.device_id.in_([d.id for d in servers] or [-1])).order_by(JobExecution.id.desc())).all():
        upd.setdefault(e.device_id, (len(e.result) if isinstance(e.result, list) else None, e.finished_at))
    rows = []
    for d in servers:
        s = stats.get(d.id, {})
        av = s.get("availability")
        rows.append([d.hostname, d.os_name or d.platform, d.status, f"{av[0] * 100:.1f}%" if av else "no data", s.get("cpu_pct", ("-",))[0], s.get("cpu_pct", ("-", "-"))[1],
                     s.get("mem_pct", ("-",))[0], s.get("disk_pct", ("-", "-"))[1], acount.get(d.id, 0),
                     f"{upd[d.id][0]} (scan {upd[d.id][1]:%Y-%m-%d})" if d.id in upd and upd[d.id][0] is not None else "not scanned"])
    doc = _doc(db, t, p)
    doc.kpis = [("Servers", len(servers), ""), ("Up", sum(1 for d in servers if d.status == "up"), "compliant"),
                ("With metrics", sum(1 for d in servers if stats.get(d.id)), ""), ("Alerts in period", sum(acount.get(d.id, 0) for d in servers), "medium")]
    doc.sections = [Section("Server health", paragraphs=["Availability is the share of successful checks; CPU/memory are averages, disk is the peak usage."],
                            tables=[Table(["Server", "OS", "Status", "Availability", "CPU avg %", "CPU max %", "Memory avg %", "Disk max %", "Alerts", "Pending updates"], rows)])]
    return doc


@template("monthly-infra-audit", "Monthly Infrastructure Audit Report", "Inventory, backups, changes, alerts and the results of all automated audit checks.",
          "dashboard:read")
def monthly_audit(db: Session, user, p: dict) -> Doc:
    from app.services.compliance import checks as ck
    t = TEMPLATES["monthly-infra-audit"]
    days = int(p.get("days") or 30)
    since = utcnow() - timedelta(days=days)
    devs = devices(db, user, p)
    by: dict[str, int] = {}
    for d in devs:
        by[_cat(d)] = by.get(_cat(d), 0) + 1
    res = ck.run(db, list(ck.CHECKS), {"site_ids": [int(p["site_id"])] if p.get("site_id") else []})
    changes = db.execute(select(func.count()).select_from(Job).where(Job.created_at >= since, Job.risk != "read")).scalar()
    alerts = db.execute(select(Alert.severity, func.count()).where(Alert.first_seen_at >= since).group_by(Alert.severity)).all()
    doc = _doc(db, t, p)
    label = {"compliant": "Compliant", "partial": "Partially compliant", "non_compliant": "Non-compliant", "not_assessed": "Not assessed"}
    doc.kpis = [("Assets", len(devs), ""), ("Checks compliant", sum(1 for r in res.values() if r.status == "compliant"), "compliant"),
                ("Checks non-compliant", sum(1 for r in res.values() if r.status == "non_compliant"), "non_compliant"),
                ("Not assessed", sum(1 for r in res.values() if r.status == "not_assessed"), "not_assessed"), ("Changes", changes, ""),
                ("Alerts", sum(n for _, n in alerts), "medium")]
    doc.sections = [
        Section("Inventory", kv=[("Assets", len(devs)), *[(k.title(), v) for k, v in sorted(by.items())]]),
        Section("Automated audit checks", paragraphs=["Technical evidence from InfraPilot data. 'Not assessed' means the data source has not been set up or is stale."],
                tables=[Table(["Check", "Status", "Summary", "Issues"], [[ck.CHECKS[k][0], label[r.status], r.summary, len(r.findings)] for k, r in res.items()],
                              widths=[2, 1, 5, 0.6])]),
        Section("Issues found by the checks", tables=[Table(["Severity", "Issue", "Asset", "Recommendation"],
                                                             sorted([[f["severity"].title(), f["title"], f.get("asset", ""), f.get("recommendation", "")]
                                                                     for r in res.values() for f in r.findings if _sev_ok(p, f["severity"])],
                                                                    key=lambda x: ["Critical", "High", "Medium", "Low", "Informational"].index(x[0]) if x[0] in
                                                                    ["Critical", "High", "Medium", "Low", "Informational"] else 9))]),
        Section("Alerts in the period", tables=[Table(["Severity", "Alerts"], [[s.title(), n] for s, n in alerts])]),
    ]
    return doc


@template("ad-security", "Active Directory Security Report", "Domain policy, privileged accounts, dormant and risky accounts and recent directory changes.", "ad:read",
          filters=("domain_id",))
def ad_security(db: Session, user, p: dict) -> Doc:
    from app.services import ad
    t = TEMPLATES["ad-security"]
    doms = [d for d in db.execute(select(AdDomain).order_by(AdDomain.name)).scalars().all() if not p.get("domain_id") or d.id == int(p["domain_id"])]
    doc = _doc(db, t, p)
    if not doms:
        doc.sections = [Section("No data", paragraphs=["No Active Directory domain is configured. Add one under Active Directory -> Domains."])]
        return doc
    tot = lambda k: sum((d.stats or {}).get(k, 0) for d in doms)  # noqa: E731
    doc.kpis = [("Users", tot("users"), ""), ("Privileged", tot("privileged_users"), "high"), ("Dormant", tot("inactive_users"), "medium"),
                ("Stale computers", tot("stale_computers"), "medium"), ("Pwd never expires", tot("pwd_never_expires"), "low"), ("DCs", tot("dcs"), "")]
    for d in doms:
        pol = (d.stats or {}).get("policy") or {}
        sec = Section(f"Domain {d.name}", kv=[("Last synchronised", d.last_success_at or "never"), ("Minimum password length", pol.get("min_pwd_length")),
                                                ("Lockout threshold", pol.get("lockout_threshold")), ("Maximum password age (days)", pol.get("max_pwd_age_days")),
                                                ("Machine account quota", pol.get("machine_account_quota"))])
        for key in ("privileged", "domain-admins", "risky-accounts", "inactive-users", "stale-computers", "recent"):
            head, rows, note = ad.report(db, d, key, int(p.get("days") or 30))
            sec.children.append(Section(ad.REPORTS[key], paragraphs=[note] if note else [], tables=[Table(head, rows, sheet=f"{d.name[:10]} {key}"[:28])]))
        doc.sections.append(sec)
    return doc


@template("gpo-complete", "Complete GPO Report", "All Group Policy Objects with readable settings, baseline assessment, conflicts and history (15 sections).", "gpo:read",
          filters=("gpo_domain",))
def gpo_complete(db: Session, user, p: dict) -> Doc:
    from app.services.gpo import report as gr, store
    c = store.get_collection(db, None, p.get("gpo_domain") or None)
    return gr.build(db, c, None, organisation=settings_store.value(db, "ui.organization_name") or "")


@template("firewall-security", "Firewall Security Report", "Firewall inventory, firmware, configuration backups, rule analysis findings and configuration changes.",
          "firewall:read")
def firewall_security(db: Session, user, p: dict) -> Doc:
    t = TEMPLATES["firewall-security"]
    days = int(p.get("days") or 30)
    since = utcnow() - timedelta(days=days)
    fws = [d for d in devices(db, user, p) if _cat(d) == "firewall"]
    ids = [d.id for d in fws]
    last = _backups(db, ids)
    analysis = {}
    for e, _j in db.execute(select(JobExecution, Job).join(Job, Job.id == JobExecution.job_id).where(
            Job.operation_id == "firewall.rules.analyse", JobExecution.status == "succeeded", JobExecution.device_id.in_(ids or [-1])).order_by(JobExecution.id.desc())).all():
        analysis.setdefault(e.device_id, e)
    changes = db.execute(select(ConfigChange).where(ConfigChange.device_id.in_(ids or [-1]), ConfigChange.created_at >= since).order_by(ConfigChange.id.desc())).scalars().all()
    names = {d.id: d.hostname for d in fws}
    frows = []
    for did, e in analysis.items():
        for f in (e.result or {}).get("findings") or [] if isinstance(e.result, dict) else []:
            sev = str(f.get("severity") or "medium")
            if _sev_ok(p, sev):
                frows.append([names[did], e.finished_at, f"{f.get('rule_id')} {f.get('rule_name') or ''}".strip(), sev.title(), "; ".join(f.get("issues") or [])])
    doc = _doc(db, t, p)
    doc.kpis = [("Firewalls", len(fws), ""), ("Up", sum(1 for d in fws if d.status == "up"), "compliant"), ("Analysed", len(analysis), ""),
                ("Broad rules", len(frows), "high" if frows else "compliant"), ("Config changes", len(changes), ""),
                ("Backup > 7 days", sum(1 for d in fws if not last.get(d.id) or last[d.id] < utcnow() - timedelta(days=7)), "medium")]
    doc.sections = [
        Section("Inventory and health", tables=[Table(["Firewall", "Vendor", "Model", "Firmware", "Serial", "Management IP", "Status", "Last seen", "Latest backup"],
                                                      [[d.hostname, d.vendor, d.model, d.firmware, d.serial_number, d.ip_address, d.status, d.last_checked_at,
                                                        last.get(d.id) or "never"] for d in fws])]),
        Section("Rule analysis (overly permissive rules)", paragraphs=[] if analysis else ["No rule analysis has been run. Run 'Analyse policies' on each firewall."],
                tables=[Table(["Firewall", "Analysed", "Rule", "Severity", "Issues"], frows)]),
        Section("Configuration changes", tables=[Table(["When", "Firewall", "Lines changed"], [[c.created_at, names.get(c.device_id), sum(1 for ln in (c.diff or "").splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))] for c in changes])]),
        Section("Capabilities", paragraphs=["Interface, VPN tunnel, IPS/web-filter status and traffic reports depend on the vendor API. "
                                            "Operations a vendor does not expose are shown as unsupported on the device page; this report never assumes them."]),
    ]
    return doc


@template("network-audit", "Switch and Network Audit Report", "Switches, routers and access points: firmware, backups, configuration changes and reachability.",
          "network:read")
def network_audit(db: Session, user, p: dict) -> Doc:
    t = TEMPLATES["network-audit"]
    since = utcnow() - timedelta(days=int(p.get("days") or 30))
    net = [d for d in devices(db, user, p) if _cat(d) == "network"]
    ids = [d.id for d in net]
    last = _backups(db, ids)
    changes = db.execute(select(ConfigChange).where(ConfigChange.device_id.in_(ids or [-1]), ConfigChange.created_at >= since).order_by(ConfigChange.id.desc())).scalars().all()
    fw_versions: dict[tuple, int] = {}
    for d in net:
        fw_versions[(d.vendor or d.platform, d.model, d.firmware or d.os_version)] = fw_versions.get((d.vendor or d.platform, d.model, d.firmware or d.os_version), 0) + 1
    names = {d.id: d.hostname for d in net}
    doc = _doc(db, t, p)
    doc.kpis = [("Network devices", len(net), ""), ("Up", sum(1 for d in net if d.status == "up"), "compliant"),
                ("Backed up ≤ 7 days", sum(1 for d in net if last.get(d.id) and last[d.id] >= utcnow() - timedelta(days=7)), "compliant"),
                ("Never backed up", sum(1 for d in net if not last.get(d.id)), "high"), ("Firmware versions", len(fw_versions), ""), ("Config changes", len(changes), "")]
    doc.sections = [
        Section("Inventory", tables=[Table(["Device", "Type", "Vendor", "Model", "Firmware/OS", "Serial", "IP", "Site", "Status", "Latest backup"],
                                           [[d.hostname, d.device_type, d.vendor, d.model, d.firmware or d.os_version, d.serial_number, d.ip_address,
                                             d.site.name if d.site else "", d.status, last.get(d.id) or "never"] for d in net])]),
        Section("Firmware consistency", paragraphs=["Different firmware on the same model makes behaviour and vulnerability exposure inconsistent."],
                tables=[Table(["Vendor", "Model", "Firmware/OS", "Devices"], [[*k, n] for k, n in sorted(fw_versions.items(), key=lambda x: (str(x[0][0]), str(x[0][1])))])]),
        Section("Configuration changes in the period", tables=[Table(["When", "Device", "Lines changed"], [[c.created_at, names.get(c.device_id),
                                                                    sum(1 for ln in (c.diff or "").splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---"))] for c in changes])]),
    ]
    return doc


@template("patch-compliance", "Patch Compliance Report", "Pending operating system updates per server from the latest scans.", "monitoring:read")
def patch_compliance(db: Session, user, p: dict) -> Doc:
    from app.services.compliance import checks as ck
    t = TEMPLATES["patch-compliance"]
    servers = [d for d in devices(db, user, p) if _cat(d) in ("windows", "linux")]
    ctx = ck.Ctx(db, {}, utcnow())
    res = ck._latest_results(ctx, ("windows.updates.pending", "linux.updates.pending"), [d.id for d in servers], days=int(p.get("days") or 30))
    rows, detail = [], []
    for d in servers:
        e = res.get(d.id)
        if not e:
            rows.append([d.hostname, d.os_name or d.platform, "not scanned", "", "", "Not assessed"])
            continue
        items = e.result if isinstance(e.result, list) else []
        sec = [u for u in items if isinstance(u, dict) and (str(u.get("Severity", "")).lower() in ("critical", "important") or u.get("security"))]
        rows.append([d.hostname, d.os_name or d.platform, e.finished_at, len(items), len(sec), "Compliant" if not sec else "Non-compliant"])
        for u in items[:200]:
            detail.append([d.hostname, u.get("Title") or u.get("package"), u.get("KB") or u.get("new_version") or "", u.get("Severity") or ("Security" if u.get("security") else "")])
    scanned = sum(1 for r in rows if r[5] != "Not assessed")
    doc = _doc(db, t, p)
    doc.kpis = [("Servers", len(servers), ""), ("Scanned", scanned, ""), ("Compliant", sum(1 for r in rows if r[5] == "Compliant"), "compliant"),
                ("Non-compliant", sum(1 for r in rows if r[5] == "Non-compliant"), "non_compliant"), ("Not scanned", len(servers) - scanned, "not_assessed")]
    doc.sections = [Section("Servers", paragraphs=["Schedule 'Pending Windows updates' / 'Pending package updates' weekly to keep this report current."],
                            tables=[Table(["Server", "OS", "Last scan", "Pending", "Security/critical", "Status"], rows)]),
                    Section("Pending updates", tables=[Table(["Server", "Update / package", "KB / version", "Severity"], detail)])]
    return doc


@template("privileged-accounts", "Privileged Account Report", "Privileged directory accounts across domains and InfraPilot administrators with MFA status.", "ad:read",
          filters=("domain_id",))
def privileged_accounts(db: Session, user, p: dict) -> Doc:
    from app.services import ad
    from app.services.compliance import checks as ck
    t = TEMPLATES["privileged-accounts"]
    doc = _doc(db, t, p)
    rows = []
    for d in db.execute(select(AdDomain).order_by(AdDomain.name)).scalars().all():
        if p.get("domain_id") and d.id != int(p["domain_id"]):
            continue
        for r in ad.report(db, d, "privileged")[1]:
            rows.append([d.name, *r])
    mfa = ck.platform_mfa(ck.Ctx(db, {}, utcnow()))
    doc.kpis = [("Privileged AD accounts", len(rows), "high"), ("High risk", sum(1 for r in rows if r[-1] == "High"), "critical"),
                ("InfraPilot admins without MFA", len(mfa.evidence.get("without_mfa", [])), "high")]
    doc.sections = [Section("Active Directory", paragraphs=[] if rows else ["No synchronised AD domain."],
                            tables=[Table(["Domain", "Account", "Display name", "Enabled", "Privileged groups", "Last logon", "Password last set", "Never expires", "SPN", "Risk"], rows)]),
                    Section("InfraPilot administrators", paragraphs=[mfa.summary], kv=[("Without MFA", ", ".join(mfa.evidence.get("without_mfa", [])) or "none")])]
    return doc


@template("config-changes", "Configuration Change Report", "Configuration changes and change jobs with requester, approval and result.", "audit:read")
def config_changes(db: Session, user, p: dict) -> Doc:
    t = TEMPLATES["config-changes"]
    since = utcnow() - timedelta(days=int(p.get("days") or 30))
    devs = devices(db, user, p)
    vis = {d.id: d.hostname for d in devs}
    users = {u.id: u.username for u in db.execute(select(User)).scalars().all()}
    jobs = db.execute(select(Job).where(Job.created_at >= since, Job.risk != "read").order_by(Job.id.desc()).limit(5000)).scalars().all()
    from app.models import Approval
    appr = {a.job_id: a for a in db.execute(select(Approval).where(Approval.job_id.in_([j.id for j in jobs] or [-1]))).scalars().all()}
    jrows = []
    for j in jobs:
        targets = [vis[e.device_id] for e in j.executions if e.device_id in vis]
        if not targets:
            continue
        a = appr.get(j.id)
        jrows.append([j.created_at, f"#{j.id}", j.title, j.operation_id or j.playbook, j.risk.title(), users.get(j.requested_by, "scheduler"),
                      ", ".join(targets[:10]), f"{a.status} by {users.get(a.decided_by, '-')}" if a else ("emergency" if j.is_emergency else "not required"), j.status])
    changes = db.execute(select(ConfigChange).where(ConfigChange.created_at >= since, ConfigChange.device_id.in_(list(vis) or [-1])).order_by(ConfigChange.id.desc())).scalars().all()
    gpo = db.execute(select(AuditLog).where(AuditLog.ts >= since, AuditLog.action.in_(["gpo.collect"])).order_by(AuditLog.id.desc())).scalars().all()
    doc = _doc(db, t, p)
    doc.kpis = [("Change jobs", len(jrows), ""), ("Critical", sum(1 for r in jrows if r[4] == "Critical"), "high"),
                ("Emergency", sum(1 for r in jrows if r[7] == "emergency"), "medium"), ("Device config diffs", len(changes), ""),
                ("GPO changes detected", sum((x.details or {}).get("changed", 0) + (x.details or {}).get("deleted", 0) for x in gpo), "")]
    doc.sections = [
        Section("Change jobs", tables=[Table(["Created", "Job", "Title", "Operation", "Risk", "Requested by", "Targets", "Approval", "Result"], jrows,
                                             widths=[1.1, 0.5, 2.2, 1.6, 0.6, 1, 1.6, 1.3, 0.8])]),
        Section("Device configuration changes (before/after diffs)", tables=[Table(["When", "Device", "Job execution", "Diff excerpt"],
                                                                                    [[c.created_at, vis.get(c.device_id), c.job_execution_id or "", (c.diff or "")[:600]] for c in changes])]),
        Section("Group Policy changes", tables=[Table(["When", "Domain", "Changed", "Deleted", "Source"], [[x.ts, x.target_name, (x.details or {}).get("changed"),
                                                                                                      (x.details or {}).get("deleted"), (x.details or {}).get("source")] for x in gpo])]),
    ]
    return doc


@template("vulnerability-risk", "Vulnerability and Risk Report", "Open audit findings, GPO baseline gaps, risky accounts, broad firewall rules and pending security updates.",
          "dashboard:read", filters=("severity", "site_id"))
def vulnerability_risk(db: Session, user, p: dict) -> Doc:
    from app.services.compliance import checks as ck
    t = TEMPLATES["vulnerability-risk"]
    res = ck.run(db, ["gpo_baseline", "ad_risky_accounts", "ad_privileged", "firewall_rules", "patch_status", "linux_ssh"],
                 {"site_ids": [int(p["site_id"])] if p.get("site_id") else []})
    items = [[f["severity"].title(), ck.CHECKS[k][0], f["title"], f.get("asset", ""), f.get("recommendation", "")]
             for k, r in res.items() for f in r.findings if _sev_ok(p, f["severity"])]
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    items.sort(key=lambda x: order.index(x[0]) if x[0] in order else 9)
    can_f = user is None or auth.has_any_scope(db, user, "compliance:read")
    open_f = [f for f in db.execute(select(Finding).where(Finding.status.not_in(["closed", "accepted_risk"])).order_by(Finding.id.desc())).scalars().all()
              if _sev_ok(p, f.severity)] if can_f else []
    doc = _doc(db, t, p, "Current exposure from technical checks and open audit findings. Third-party CVE feeds are not integrated; "
                         "firmware/OS vulnerability status relies on vendor update scans.")
    doc.kpis = [(s, sum(1 for x in items if x[0] == s) + sum(1 for f in open_f if f.severity.title() == s), s.lower()) for s in order[:4]] + \
               [("Checks not assessed", sum(1 for r in res.values() if r.status == "not_assessed"), "not_assessed")]
    doc.sections = [Section("Technical exposure", tables=[Table(["Risk", "Source", "Issue", "Asset", "Recommendation"], items, widths=[0.7, 1.6, 2.4, 1.6, 3])]),
                    Section("Open audit findings", paragraphs=[] if can_f else ["Requires the compliance:read permission."],
                            tables=[Table(["ID", "Severity", "Finding", "Asset", "Status", "Owner", "Due"], [[f"F-{f.id}", f.severity.title(), f.title, f.asset,
                                                                                                             f.status.replace("_", " ").title(), f.owner_department, f.due_date] for f in open_f])]),
                    Section("Checks without data", bullets=[f"{ck.CHECKS[k][0]}: {r.summary}" for k, r in res.items() if r.status == "not_assessed"])]
    return doc


@template("executive-summary", "Management Executive Summary", "One-page view for management: availability, security posture, compliance and key risks.",
          "dashboard:read", filters=())
def executive(db: Session, user, p: dict) -> Doc:
    from app.services.compliance import checks as ck
    t = TEMPLATES["executive-summary"]
    since = utcnow() - timedelta(days=int(p.get("days") or 30))
    devs = devices(db, user, p)
    up = sum(1 for d in devs if d.status == "up")
    crit_alerts = db.execute(select(func.count()).select_from(Alert).where(Alert.status != "resolved", Alert.severity == "critical")).scalar()
    res = ck.run(db, list(ck.CHECKS))
    assess = []
    for a in db.execute(select(Assessment).order_by(Assessment.id.desc()).limit(50)).scalars().all():
        if a.framework_id not in {x[0] for x in assess}:
            fw = db.get(ComplianceFramework, a.framework_id)
            assess.append((a.framework_id, fw.name if fw else "", a))
    open_f = db.execute(select(Finding).where(Finding.status.not_in(["closed", "accepted_risk"]))).scalars().all()
    overdue = [f for f in open_f if f.due_date and f.due_date < utcnow()]
    risks = sorted([(f["severity"], f["title"], f.get("recommendation", "")) for r in res.values() for f in r.findings if f["severity"] in ("critical", "high")],
                   key=lambda x: 0 if x[0] == "critical" else 1)[:10]
    doc = _doc(db, t, p)
    doc.kpis = [("Assets", len(devs), ""), ("Availability now", f"{round(100 * up / len(devs))}%" if devs else "n/a", "compliant"),
                ("Critical alerts open", crit_alerts, "critical" if crit_alerts else "compliant"),
                ("Checks passing", f"{sum(1 for r in res.values() if r.status == 'compliant')}/{sum(1 for r in res.values() if r.status != 'not_assessed')}", ""),
                ("Open findings", len(open_f), "medium"), ("Overdue findings", len(overdue), "high" if overdue else "compliant")]
    summary = (f"{up} of {len(devs)} managed assets are currently up. {crit_alerts} critical alert(s) are open. "
               f"Of {sum(1 for r in res.values() if r.status != 'not_assessed')} automated security checks with data, "
               f"{sum(1 for r in res.values() if r.status == 'compliant')} pass. {len(open_f)} audit finding(s) are open, {len(overdue)} overdue. "
               f"{sum(1 for r in res.values() if r.status == 'not_assessed')} check(s) have no data yet and are not counted.")
    doc.sections = [Section("Summary", paragraphs=[summary]),
                    Section("Key risks", tables=[Table(["Risk", "Issue", "Action"], [[s.title(), ti, rec] for s, ti, rec in risks], widths=[0.7, 3, 4])]),
                    Section("Compliance status (latest assessment per framework)", paragraphs=[] if assess else ["No assessments yet."],
                            tables=[Table(["Framework", "Assessment", "Date", "Status", "Score", "Non-compliant controls"],
                                          [[n, a.title, a.created_at, a.status.title(), f"{(a.summary or {}).get('score')}%" if (a.summary or {}).get("score") is not None else "n/a",
                                            ((a.summary or {}).get("counts") or {}).get("non_compliant", "")] for _, n, a in assess])]),
                    Section("Security posture by area", tables=[Table(["Area", "Status", "Summary"], [[ck.CHECKS[k][0], r.status.replace("_", " ").title(), r.summary]
                                                                                                  for k, r in res.items()], widths=[2, 1, 5])])]
    return doc


# ------------------------------------------------------------------ public API
def get_template(key: str) -> Template:
    t = TEMPLATES.get(key)
    if t is None:
        raise NotFound("Unknown report")
    return t


def build(db: Session, user: User | None, key: str, params: dict) -> Doc:
    t = get_template(key)
    if user is not None and not auth.has_any_scope(db, user, t.permission):
        raise Forbidden(f"This report needs the '{t.permission}' permission")
    clean = {k: v for k, v in (params or {}).items() if v not in (None, "") and k in (*t.filters, "days", "severity")}
    if "days" in clean:
        try:
            clean["days"] = max(1, min(3660, int(clean["days"])))
        except (TypeError, ValueError):
            raise ValidationFailed("days must be a number")
    return t.build(db, user, clean)


RUN_PERMS = {"gpo": "gpo:read", "audit": "compliance:read"}


def run_permission(key: str) -> str:
    if key in RUN_PERMS:
        return RUN_PERMS[key]
    if key.startswith("ad-"):
        return "ad:read"
    t = TEMPLATES.get(key)
    return t.permission if t else "reports:read"


# ------------------------------------------------------------------ schedules
def schedule_due(db: Session) -> int:
    from app.core.cron import Cron
    from app.services import notify, reporting
    from app.services.reporting.render import MEDIA, render
    now = utcnow()
    due = db.execute(select(ReportSchedule).where(ReportSchedule.enabled == true(), ReportSchedule.next_run_at.is_not(None),
                                                  ReportSchedule.next_run_at <= now)).scalars().all()
    n = 0
    for s in due:
        nxt = Cron(s.cron).next_after(now)
        claimed = db.execute(ReportSchedule.__table__.update().where(ReportSchedule.id == s.id, ReportSchedule.next_run_at == s.next_run_at)
                             .values(next_run_at=nxt)).rowcount
        db.commit()
        if not claimed:
            continue
        run_schedule(db, s)
        n += 1
    return n


def run_schedule(db: Session, s: ReportSchedule) -> ReportRun | None:
    from app.services import audit, notify, reporting
    from app.services.reporting.render import MEDIA, render
    owner = db.get(User, s.created_by)
    try:
        if owner is None or not owner.is_active:
            raise Forbidden("The schedule owner is no longer active; reassign the schedule")
        doc = build(db, owner, s.report_key, s.params or {})
        content = render(doc, s.format)
        sent, msg = (False, "no recipients")
        name = reporting.filename(doc.title, s.format)
        if s.recipients.strip():
            sent, msg = notify.send_email(db, s.recipients, f"[InfraPilot] {doc.title}",
                                          f"{doc.title}\n{doc.subtitle}\n\nGenerated {doc.generated_at:%Y-%m-%d %H:%M} UTC by schedule '{s.name}'.\n"
                                          "The report is attached. It is also available under Reports -> Historical reports.",
                                          attachments=[(name, content, MEDIA[s.format].split(";")[0])])
        run = reporting.save_run(db, key=s.report_key, doc=doc, fmt=s.format, params=s.params or {}, content=content, actor_name=f"schedule:{s.name}",
                                 schedule_id=s.id, emailed_to=s.recipients if sent else "")
        s.last_run_at, s.last_status = utcnow(), "succeeded" if sent or not s.recipients.strip() else "partial"
        s.last_message = f"Generated {len(content) // 1024} KB" + (f"; e-mailed to {s.recipients}" if sent else f"; e-mail not sent: {msg}" if s.recipients.strip() else "")
        audit.record(db, "report.scheduled", actor_name=f"schedule:{s.name}", target_type="report_schedule", target_id=s.id, target_name=s.name,
                     result="success" if s.last_status == "succeeded" else "failure", details={"run_id": run.id, "emailed": sent, "message": s.last_message})
        db.commit()
        return run
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        s = db.get(ReportSchedule, s.id)
        s.last_run_at, s.last_status, s.last_message = utcnow(), "failed", str(getattr(exc, "message", None) or exc)[:1000]
        audit.record(db, "report.scheduled", actor_name=f"schedule:{s.name}", target_type="report_schedule", target_id=s.id, target_name=s.name,
                     result="failure", details={"error": s.last_message})
        db.commit()
        return None

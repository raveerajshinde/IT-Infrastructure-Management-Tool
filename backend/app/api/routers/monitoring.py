"""Dashboard, metrics, alerts and rules, notifications, global search, integrations, settings and setup."""
from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, true
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, current_user, need, need_global, paging
from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.models import Alert, AlertRule, Approval, ConfigBackup, Credential, Device, DeviceGroupMember, Integration, Job, JobSchedule, Metric, Notification, User
from app.drivers.registry import driver_class
from app.services import audit, auth, integrations, ldap_auth, notify, settings_store

router = APIRouter(prefix="/api", tags=["monitoring"])
log = logging.getLogger("infrapilot.dashboard")
RES_METRICS = ("cpu_pct", "mem_pct", "disk_pct")


def _visible_ids(db: Session, user: User) -> set[int] | None:
    groups = auth.visible_device_filter(db, user)
    if groups is None:
        return None
    return set(db.execute(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id.in_(groups or {-1}))).scalars())


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(user: User = Depends(need("dashboard:read")), db: Session = Depends(get_db)):
    vis = _visible_ids(db, user)
    devs = [d for d in db.execute(select(Device).where(Device.deleted_at.is_(None))).scalars() if vis is None or d.id in vis]
    ids = [d.id for d in devs] or [-1]
    names = {d.id: d.hostname for d in devs}
    by_type: dict[str, int] = {}
    by_env: dict[str, int] = {}
    by_status = {"up": 0, "down": 0, "degraded": 0, "unknown": 0}
    for d in devs:
        by_type[d.device_type] = by_type.get(d.device_type, 0) + 1
        by_env[d.environment] = by_env.get(d.environment, 0) + 1
        by_status[d.status] = by_status.get(d.status, 0) + 1
    t24 = utcnow() - timedelta(hours=24)
    avail = db.execute(select(func.avg(Metric.value), func.count()).where(Metric.metric == "availability", Metric.ts >= t24, Metric.device_id.in_(ids))).one()
    resources = {}
    for m in RES_METRICS:
        r = db.execute(select(func.avg(Metric.value), func.max(Metric.value), func.count()).where(Metric.metric == m, Metric.ts >= utcnow() - timedelta(hours=1),
                                                                                                 Metric.device_id.in_(ids))).one()
        resources[m] = {"avg": round(r[0], 1) if r[0] is not None else None, "max": round(r[1], 1) if r[1] is not None else None, "samples": r[2]}
    buckets: dict[str, list[float]] = {}
    for ts, val in db.execute(select(Metric.ts, Metric.value).where(Metric.metric == "availability", Metric.ts >= t24, Metric.device_id.in_(ids))).all():
        buckets.setdefault(ts.strftime("%Y-%m-%dT%H:00:00Z"), []).append(val)
    trend = [{"hour": h, "availability_pct": round(100 * sum(v) / len(v), 2)} for h, v in sorted(buckets.items())]
    # latest CPU sample per device in the last 30 minutes
    sub = (select(Metric.device_id, func.max(Metric.ts).label("ts")).where(Metric.metric == "cpu_pct", Metric.ts >= utcnow() - timedelta(minutes=30),
           Metric.device_id.in_(ids)).group_by(Metric.device_id).subquery())
    cpu_rows = db.execute(select(Metric).join(sub, (Metric.device_id == sub.c.device_id) & (Metric.ts == sub.c.ts)).where(Metric.metric == "cpu_pct")).scalars().all()
    top_cpu = sorted(({"device_id": m.device_id, "hostname": names.get(m.device_id), "cpu_pct": round(m.value, 1)} for m in cpu_rows), key=lambda x: -x["cpu_pct"])[:5]
    open_alerts = [a for a in db.execute(select(Alert).where(Alert.status != "resolved").order_by(Alert.last_seen_at.desc()).limit(500)).scalars()
                   if vis is None or a.device_id is None or a.device_id in vis]
    counts = {"critical": 0, "warning": 0, "info": 0}
    for a in open_alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    jobs24 = dict(db.execute(select(Job.status, func.count()).where(Job.created_at >= t24).group_by(Job.status)).all())

    # Enrichment sections are isolated: if one fails (e.g. a database-specific error) the rest of the
    # dashboard still renders and the failure is logged with a traceback.
    extra = {"activity_7d": [], "sites": [], "by_vendor": {}, "backup_coverage": {"eligible": 0, "fresh_7d": 0, "never": 0, "never_devices": []},
             "stale_devices": [], "recent_jobs": [], "upcoming_schedules": []}
    try:
        # 7-day activity (alerts raised, jobs by outcome) for trend charts
        t7 = (utcnow() - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        days = [(t7 + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        act = {d: {"day": d, "alerts": 0, "jobs_succeeded": 0, "jobs_failed": 0, "jobs_other": 0} for d in days}
        for ts, dev in db.execute(select(Alert.first_seen_at, Alert.device_id).where(Alert.first_seen_at >= t7)).all():
            if (vis is None or dev is None or dev in vis) and ts.strftime("%Y-%m-%d") in act:
                act[ts.strftime("%Y-%m-%d")]["alerts"] += 1
        for ts, st in db.execute(select(Job.created_at, Job.status).where(Job.created_at >= t7)).all():
            k = {"succeeded": "jobs_succeeded", "failed": "jobs_failed", "partial": "jobs_failed"}.get(st, "jobs_other")
            if ts.strftime("%Y-%m-%d") in act:
                act[ts.strftime("%Y-%m-%d")][k] += 1

        sites: dict[str, dict] = {}
        for d in devs:
            k = d.site.name if d.site else "Unassigned"
            e = sites.setdefault(k, {"site": k, "total": 0, "up": 0, "down": 0, "degraded": 0, "unknown": 0})
            e["total"] += 1
            e[d.status if d.status in e else "unknown"] += 1

        # configuration backup coverage for devices that support config export
        latest = dict(db.execute(select(ConfigBackup.device_id, func.max(ConfigBackup.created_at)).where(ConfigBackup.device_id.in_(ids))
                                 .group_by(ConfigBackup.device_id)).all())
        eligible = [d for d in devs if driver_class(d.platform).category in ("network", "firewall")]
        week = utcnow() - timedelta(days=7)
        fresh = sum(1 for d in eligible if latest.get(d.id) and latest[d.id] >= week)
        never = [d for d in eligible if d.id not in latest]
        stale_cut = utcnow() - timedelta(hours=24)
        stale = [{"id": d.id, "hostname": d.hostname, "last_seen_at": ser.iso(d.last_checked_at), "status": d.status} for d in devs
                 if d.monitoring_enabled and (d.last_checked_at is None or d.last_checked_at < stale_cut)][:8]
        recent_jobs = [ser.job(db, j, detail=False) for j in db.execute(select(Job).order_by(Job.id.desc()).limit(8)).scalars().all()]
        sched = db.execute(select(JobSchedule).where(JobSchedule.enabled == true(), JobSchedule.next_run_at.is_not(None))
                           .order_by(JobSchedule.next_run_at).limit(5)).scalars().all()
        by_vendor: dict[str, int] = {}
        for d in devs:
            by_vendor[d.vendor or "Unknown"] = by_vendor.get(d.vendor or "Unknown", 0) + 1
        extra.update({
            "activity_7d": list(act.values()), "sites": sorted(sites.values(), key=lambda x: -x["total"]), "by_vendor": by_vendor,
            "backup_coverage": {"eligible": len(eligible), "fresh_7d": fresh, "never": len(never), "never_devices": [d.hostname for d in never][:8]},
            "stale_devices": stale, "recent_jobs": recent_jobs,
            "upcoming_schedules": [{"id": x.id, "name": x.name, "next_run_at": ser.iso(x.next_run_at)} for x in sched],
        })
    except Exception:  # noqa: BLE001
        log.exception("dashboard enrichment failed")
        db.rollback()
    return {
        **extra,
        "devices": {"total": len(devs), "by_type": by_type, "by_status": by_status, "by_environment": by_env},
        "availability_24h_pct": round(100 * avail[0], 2) if avail[1] else None, "resources": resources, "availability_trend": trend,
        "alerts": {"counts": counts, "recent": [ser.alert(db, a) for a in sorted(open_alerts, key=lambda a: (a.severity != "critical", a.severity != "warning"))[:8]]},
        "jobs_24h": jobs24, "pending_approvals": db.execute(select(func.count()).select_from(Approval).where(Approval.status == "pending")).scalar(),
        "top_cpu": top_cpu, "has_simulated": any(d.is_simulated for d in devs), "mode": get_settings().app_mode,
    }


@router.get("/devices/{device_id}/metrics")
def device_metrics(device_id: int, metric: str | None = None, hours: int = 24, user: User = Depends(current_user), db: Session = Depends(get_db)):
    auth.require(db, user, "monitoring:read", device_id)
    hours = min(max(hours, 1), 24 * 30)
    q = select(Metric).where(Metric.device_id == device_id, Metric.ts >= utcnow() - timedelta(hours=hours))
    if metric:
        q = q.where(Metric.metric == metric)
    rows = list(db.execute(q.order_by(Metric.ts)).scalars())
    step = max(1, len(rows) // 720)  # down-sample for charts
    if metric:
        return {"metric": metric, "points": [{"ts": ser.iso(m.ts), "value": round(m.value, 2)} for m in rows[::step]]}
    series: dict[str, list] = {}
    for m in rows:
        series.setdefault(m.metric, []).append({"ts": ser.iso(m.ts), "value": round(m.value, 2)})
    return series


@router.get("/devices/{device_id}/metrics/latest")
def latest_metrics(device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    auth.require(db, user, "monitoring:read", device_id)
    sub = select(Metric.metric, func.max(Metric.ts).label("ts")).where(Metric.device_id == device_id).group_by(Metric.metric).subquery()
    rows = db.execute(select(Metric).join(sub, (Metric.metric == sub.c.metric) & (Metric.ts == sub.c.ts)).where(Metric.device_id == device_id)).scalars().all()
    return {m.metric: {"value": round(m.value, 2), "ts": ser.iso(m.ts)} for m in rows}


# ---------------------------------------------------------------- alerts
@router.get("/alerts")
def list_alerts(status: str | None = "open,acknowledged", severity: str | None = None, device_id: int | None = None,
                user: User = Depends(need("alerts:read")), db: Session = Depends(get_db), pg=Depends(paging)):
    q = select(Alert)
    if status:
        q = q.where(Alert.status.in_(status.split(",")))
    if severity:
        q = q.where(Alert.severity == severity)
    if device_id:
        q = q.where(Alert.device_id == device_id)
    vis = _visible_ids(db, user)
    if vis is not None:
        q = q.where(or_(Alert.device_id.in_(vis or {-1}), Alert.device_id.is_(None)))
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    page, size = pg
    rows = db.execute(q.order_by(Alert.last_seen_at.desc()).offset((page - 1) * size).limit(size)).scalars().all()
    return {"items": [ser.alert(db, a) for a in rows], "total": total, "page": page, "page_size": size}


class AlertActionIn(BaseModel):
    note: str = Field("", max_length=1000)


@router.post("/alerts/{aid}/{action}")
def alert_action(aid: int, action: str, request: Request, body: AlertActionIn | None = None, user: User = Depends(need("alerts:manage")),
                 db: Session = Depends(get_db)):
    a = db.get(Alert, aid)
    if not a:
        raise NotFound("Alert not found")
    if a.device_id:
        auth.require(db, user, "alerts:manage", a.device_id)
    if action == "acknowledge":
        if a.status != "open":
            raise ValidationFailed(f"Alert is already {a.status}")
        a.status, a.acknowledged_by, a.acknowledged_at = "acknowledged", user.id, utcnow()
    elif action == "resolve":
        if a.status == "resolved":
            raise ValidationFailed("Alert is already resolved")
        a.status, a.resolved_at = "resolved", utcnow()
    else:
        raise NotFound("Unknown action")
    audit.record(db, f"alert.{action}", actor=user, target_type="alert", target_id=a.id, target_name=a.title, device_id=a.device_id,
                 ip=client_ip(request), details={"note": body.note if body else ""})
    db.commit()
    return ser.alert(db, a)


class RuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    metric: str = Field(pattern=r"^(cpu_pct|mem_pct|disk_pct|availability|latency_ms|uptime_hours|load1)$")
    operator: str = Field(">", pattern=r"^(>|>=|<|<=)$")
    threshold: float
    severity: str = Field("warning", pattern=r"^(info|warning|critical)$")
    device_type: str | None = None
    device_group_id: int | None = None
    notify_emails: str = Field("", max_length=1000)
    escalate_after_s: int = Field(0, ge=0, le=604800)
    escalation_emails: str = Field("", max_length=1000)
    enabled: bool = True


def _rule(r: AlertRule) -> dict:
    return {"id": r.id, "name": r.name, "metric": r.metric, "operator": r.operator, "threshold": r.threshold, "severity": r.severity,
            "device_type": r.device_type, "device_group_id": r.device_group_id, "enabled": r.enabled, "notify_emails": r.notify_email or "",
            "escalate_after_s": (r.escalate_after_minutes or 0) * 60, "escalation_emails": r.escalation_email or ""}


def _apply_rule(r: AlertRule, b: RuleIn) -> None:
    import re
    for field in (b.notify_emails, b.escalation_emails):
        for e in [x.strip() for x in field.split(",") if x.strip()]:
            if not re.fullmatch(r"[^@\s,]+@[^@\s,]+\.[^@\s,]+", e):
                raise ValidationFailed(f"Invalid e-mail address: {e}")
    r.name, r.metric, r.operator, r.threshold, r.severity = b.name, b.metric, b.operator, b.threshold, b.severity
    r.device_type, r.device_group_id, r.enabled = b.device_type or None, b.device_group_id, b.enabled
    r.notify_email, r.escalation_email = b.notify_emails or None, b.escalation_emails or None
    r.escalate_after_minutes = (b.escalate_after_s // 60) or None


@router.get("/alert-rules")
def list_rules(user: User = Depends(need("alerts:read")), db: Session = Depends(get_db)):
    return [_rule(r) for r in db.execute(select(AlertRule).order_by(AlertRule.name)).scalars()]


@router.post("/alert-rules", status_code=201)
def create_rule(body: RuleIn, request: Request, user: User = Depends(need_global("alerts:manage")), db: Session = Depends(get_db)):
    if db.execute(select(AlertRule).where(AlertRule.name == body.name)).first():
        raise Conflict("A rule with this name already exists")
    r = AlertRule(name=body.name, metric=body.metric, threshold=body.threshold)
    _apply_rule(r, body)
    db.add(r)
    db.flush()
    audit.record(db, "alert_rule.create", actor=user, target_type="alert_rule", target_id=r.id, target_name=r.name, ip=client_ip(request), details=body.model_dump())
    db.commit()
    return _rule(r)


@router.put("/alert-rules/{rid}")
def update_rule(rid: int, body: RuleIn, request: Request, user: User = Depends(need_global("alerts:manage")), db: Session = Depends(get_db)):
    r = db.get(AlertRule, rid)
    if not r:
        raise NotFound("Rule not found")
    _apply_rule(r, body)
    audit.record(db, "alert_rule.update", actor=user, target_type="alert_rule", target_id=r.id, target_name=r.name, ip=client_ip(request), details=body.model_dump())
    db.commit()
    return _rule(r)


@router.delete("/alert-rules/{rid}")
def delete_rule(rid: int, request: Request, user: User = Depends(need_global("alerts:manage")), db: Session = Depends(get_db)):
    r = db.get(AlertRule, rid)
    if not r:
        raise NotFound("Rule not found")
    r.enabled = False  # alerts keep their rule reference; the rule is disabled and renamed
    r.name = f"{r.name} (deleted {utcnow():%Y%m%d%H%M%S})"[:150]
    audit.record(db, "alert_rule.delete", actor=user, target_type="alert_rule", target_id=r.id, target_name=r.name, ip=client_ip(request))
    db.commit()
    return {"message": "Rule deleted"}


# ---------------------------------------------------------------- notifications & search
@router.get("/notifications")
def list_notifications(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(Notification).where(Notification.user_id == user.id).order_by(Notification.id.desc()).limit(50)).scalars().all()
    unread = db.execute(select(func.count()).select_from(Notification).where(Notification.user_id == user.id, Notification.read_at.is_(None))).scalar()
    return {"unread": unread, "items": [{"id": n.id, "title": n.title, "body": n.body, "level": n.severity, "link": n.link,
                                         "created_at": ser.iso(n.created_at), "read": n.read_at is not None} for n in rows]}


@router.post("/notifications/read")
@router.post("/notifications/read-all")
def read_all(user: User = Depends(current_user), db: Session = Depends(get_db)):
    for n in db.execute(select(Notification).where(Notification.user_id == user.id, Notification.read_at.is_(None))).scalars().all():
        n.read_at = utcnow()
    db.commit()
    return {"ok": True}


@router.get("/search")
def search(q: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = q.strip()[:100]
    if len(q) < 2:
        return {"devices": [], "jobs": [], "alerts": []}
    like = f"%{q}%"
    vis = _visible_ids(db, user)
    out: dict = {"devices": [], "jobs": [], "alerts": []}
    if auth.has_any_scope(db, user, "devices:read"):
        for d in db.execute(select(Device).where(Device.deleted_at.is_(None), or_(Device.hostname.ilike(like), Device.ip_address.ilike(like),
                                                  Device.serial_number.ilike(like))).limit(20)).scalars().all():
            if vis is None or d.id in vis:
                out["devices"].append({"id": d.id, "hostname": d.hostname, "ip_address": d.ip_address, "status": d.status, "device_type": d.device_type})
    if auth.has_permission(db, user, "automation:read"):
        out["jobs"] = [{"id": j.id, "title": j.title, "status": j.status} for j in db.execute(select(Job).where(Job.title.ilike(like)).order_by(Job.id.desc()).limit(10)).scalars()]
    if auth.has_any_scope(db, user, "alerts:read"):
        out["alerts"] = [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status}
                         for a in db.execute(select(Alert).where(Alert.title.ilike(like)).order_by(Alert.id.desc()).limit(10)).scalars()]
    return out


# ---------------------------------------------------------------- integrations
class IntegrationIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    kind: str = Field(pattern=r"^(zabbix|librenms)$")
    base_url: str = Field(pattern=r"^https?://[A-Za-z0-9.\-:\[\]/_]+$", max_length=500)
    credential_id: int | None = None
    settings: dict = Field(default_factory=dict)
    enabled: bool = True


@router.get("/integrations")
def list_integrations(user: User = Depends(need("monitoring:read")), db: Session = Depends(get_db)):
    return [ser.integration(i) for i in db.execute(select(Integration).order_by(Integration.name)).scalars()]


@router.post("/integrations", status_code=201)
def create_integration(body: IntegrationIn, request: Request, user: User = Depends(need_global("integrations:manage")), db: Session = Depends(get_db)):
    if db.execute(select(Integration).where(Integration.name == body.name)).first():
        raise Conflict("An integration with this name already exists")
    if body.credential_id:
        c = db.get(Credential, body.credential_id)
        if not c or c.kind not in ("api_token", "password"):
            raise ValidationFailed("Select an API token credential")
    it = Integration(name=body.name, kind=body.kind, base_url=body.base_url.rstrip("/"), credential_id=body.credential_id,
                     verify_tls=bool(body.settings.get("verify_tls", True)), settings={}, enabled=body.enabled)
    db.add(it)
    db.flush()
    audit.record(db, "integration.create", actor=user, target_type="integration", target_id=it.id, target_name=it.name, ip=client_ip(request))
    db.commit()
    return ser.integration(it)


@router.post("/integrations/{iid}/sync")
@router.post("/integrations/{iid}/test")
def sync_integration(iid: int, request: Request, user: User = Depends(need_global("integrations:manage")), db: Session = Depends(get_db)):
    it = db.get(Integration, iid)
    if not it:
        raise NotFound("Integration not found")
    try:
        msg, ok = integrations.sync(db, it), True
    except Exception as exc:
        msg, ok = str(exc)[:500], False
        it.last_test_at, it.last_test_ok, it.last_test_message = utcnow(), False, msg
    audit.record(db, "integration.sync", actor=user, target_type="integration", target_id=it.id, target_name=it.name,
                 result="success" if ok else "failure", ip=client_ip(request), details={"message": msg})
    db.commit()
    if not ok:
        raise ValidationFailed(f"Sync failed: {msg}")
    return {"ok": True, "message": msg}


@router.delete("/integrations/{iid}")
def delete_integration(iid: int, request: Request, user: User = Depends(need_global("integrations:manage")), db: Session = Depends(get_db)):
    it = db.get(Integration, iid)
    if not it:
        raise NotFound("Integration not found")
    name = it.name
    db.delete(it)
    audit.record(db, "integration.delete", actor=user, target_type="integration", target_id=iid, target_name=name, ip=client_ip(request))
    db.commit()
    return {"message": "Integration deleted"}


# ---------------------------------------------------------------- settings & setup
@router.get("/settings")
def get_settings_all(user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    return settings_store.public(db)


class SettingsIn(BaseModel):
    values: dict


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    if "ldap.default_role" in body.values and body.values["ldap.default_role"]:
        from app.models import Role
        if not db.execute(select(Role).where(Role.name == body.values["ldap.default_role"])).first():
            raise ValidationFailed("ldap.default_role must be an existing role name")
    for role in (body.values.get("ldap.group_role_map") or {}).values():
        from app.models import Role
        if not db.execute(select(Role).where(Role.name == role)).first():
            raise ValidationFailed(f"Group mapping refers to unknown role '{role}'")
    changed = settings_store.update(db, body.values, user.id)
    audit.record(db, "settings.update", actor=user, target_type="settings", target_name=",".join(sorted(changed)), ip=client_ip(request), details=changed)
    db.commit()
    return settings_store.public(db)


class TestEmailIn(BaseModel):
    to: str = Field(pattern=r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


@router.post("/settings/test-email")
def test_email(body: TestEmailIn, request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    ok, msg = notify.send_email(db, body.to, "InfraPilot test message", "SMTP is configured correctly.")
    audit.record(db, "settings.smtp_test", actor=user, result="success" if ok else "failure", ip=client_ip(request), details={"to": body.to, "message": msg})
    db.commit()
    if not ok:
        raise ValidationFailed(f"Test e-mail failed: {msg}")
    return {"message": f"Test e-mail sent to {body.to}"}


@router.post("/settings/test-ldap")
def test_ldap(request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    cfg = settings_store.ldap_config(db)
    try:
        if not cfg.host:
            raise ValueError("Set the server URL first")
        msg, ok = ldap_auth.test_connection(cfg), True
    except Exception as exc:
        msg, ok = str(exc)[:500], False
    audit.record(db, "settings.ldap_test", actor=user, result="success" if ok else "failure", ip=client_ip(request), details={"message": msg})
    db.commit()
    if not ok:
        raise ValidationFailed(f"LDAP test failed: {msg}")
    return {"message": msg}


# ---------------------------------------------------------------- backup storage (network share)
@router.get("/backup-storage")
def backup_storage_status(user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    from app.services import offsite
    return {"status": offsite.status(db), "enabled": offsite.target(db) is not None}


@router.post("/backup-storage/test")
def backup_storage_test(request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    from app.services import offsite
    if offsite.target(db) is None:
        raise ValidationFailed("Enable backup storage and save the share settings first")
    ok, msg = offsite.test(db)
    audit.record(db, "backup.offsite_test", actor=user, ip=client_ip(request), result="success" if ok else "failure", details={"message": msg[:500]})
    db.commit()
    return {"ok": ok, "message": msg}


@router.post("/backup-storage/export-configs")
def backup_storage_export(request: Request, all: bool = False, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    """Copy device configuration backups to the share now: new ones, or all of them again (?all=true)."""
    from app.services import offsite
    if offsite.target(db) is None:
        raise ValidationFailed("Enable backup storage and save the share settings first")
    try:
        r = offsite.export_device_configs(db, from_start=all)
    except Exception as exc:  # noqa: BLE001
        offsite.record_error(db, f"Device configuration export failed: {exc}")
        raise ValidationFailed(f"Export failed: {exc}") from exc
    audit.record(db, "backup.offsite_export", actor=user, ip=client_ip(request), details={**r, "all": all})
    db.commit()
    return r


# ---------------------------------------------------------------- backup storage (folder on the server)
@router.get("/backup-folder")
def backup_folder_status(user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    from app.services import folder_export
    return {"status": folder_export.status(db), "enabled": folder_export.folder(db) is not None, "roots": folder_export.roots()}


@router.post("/backup-folder/test")
def backup_folder_test(request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    from app.services import folder_export
    ok, msg = folder_export.test(db)
    audit.record(db, "backup.folder_test", actor=user, ip=client_ip(request), result="success" if ok else "failure", details={"message": msg[:500]})
    db.commit()
    return {"ok": ok, "message": msg}


@router.post("/backup-folder/export-configs")
def backup_folder_export(request: Request, all: bool = False, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    """Copy device configuration backups into the folder now: new ones, or all of them again (?all=true)."""
    from app.services import folder_export
    try:
        r = folder_export.export(db, from_start=all)
    except Exception as exc:  # noqa: BLE001
        folder_export.record_error(db, f"Copy to folder failed: {exc}")
        audit.record(db, "backup.folder_export", actor=user, ip=client_ip(request), result="failure", details={"error": str(exc)[:500], "all": all})
        db.commit()
        raise ValidationFailed(f"Copy failed: {exc}") from exc
    audit.record(db, "backup.folder_export", actor=user, ip=client_ip(request), details={**r, "all": all})
    db.commit()
    return r


@router.get("/system/diagnostics")
def diagnostics_info(user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    """Version, database and worker status plus recent server errors (redacted) for troubleshooting."""
    from sqlalchemy import text as sql_text

    from app.models import SystemSetting
    from app.services import diagnostics

    s = get_settings()
    info = {"version": s.app_version, "mode": s.app_mode, "database": db.get_bind().dialect.name}
    try:
        info["database_version"] = (db.execute(sql_text("SELECT @@VERSION")).scalar() if info["database"] == "mssql"
                                    else db.execute(sql_text("select sqlite_version()")).scalar()).splitlines()[0][:120]
    except Exception as exc:  # noqa: BLE001
        info["database_version"] = f"unavailable ({exc.__class__.__name__})"
    try:
        info["schema_revision"] = db.execute(sql_text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001
        db.rollback()
        info["schema_revision"] = "unknown (tables created without migrations)"
    hb = db.get(SystemSetting, "worker.heartbeat")
    info["worker_last_seen"] = ser.iso(hb.updated_at) if hb else None
    return {**info, "errors": diagnostics.recent(db)}


@router.delete("/system/diagnostics/errors", status_code=204)
def diagnostics_clear(request: Request, user: User = Depends(need_global("settings:manage")), db: Session = Depends(get_db)):
    from fastapi import Response

    from app.services import diagnostics

    diagnostics.clear(db)
    audit.record(db, "diagnostics.clear", actor=user, target_type="system", ip=client_ip(request))
    db.commit()
    return Response(status_code=204)


@router.get("/branding")
def get_branding(db: Session = Depends(get_db)):
    """Public (also used on the sign-in page): product name, organisation, colour, logo and login notice."""
    return settings_store.branding(db)


@router.get("/setup/status")
def setup_status(db: Session = Depends(get_db)):
    s = get_settings()
    return {"app_name": s.app_name, "version": s.app_version, "mode": s.app_mode, "setup_completed": bool(settings_store.value(db, "setup.completed")),
            "organization": settings_store.value(db, "ui.organization_name")}

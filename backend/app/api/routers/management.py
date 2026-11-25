"""Recurring job schedules and downloadable reports."""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need
from app.core.cron import Cron, CronError
from app.core.db import get_db
from app.core.errors import Forbidden, NotFound
from app.core.timeutil import utcnow
from app.drivers.registry import driver_class
from app.models import (
    Alert, AuditLog, ConfigBackup, Device, DeviceGroupMember, Job, JobExecution, JobSchedule, JobTemplate, User,
)
from app.services import audit, auth, import_export, schedules

router = APIRouter(prefix="/api", tags=["management"])


# ---------------------------------------------------------------- schedules
class ScheduleIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str = Field("", max_length=1000)
    kind: Literal["operation", "playbook"] = "operation"
    operation_id: str | None = Field(None, max_length=100)
    template_id: int | None = None
    device_ids: list[int] = Field(min_length=1, max_length=500)
    params: dict[str, Any] = Field(default_factory=dict)
    check_mode: bool = False
    cron: str = Field(min_length=5, max_length=100)
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=150)
    description: str | None = Field(None, max_length=1000)
    kind: Literal["operation", "playbook"] | None = None
    operation_id: str | None = Field(None, max_length=100)
    template_id: int | None = None
    device_ids: list[int] | None = Field(None, min_length=1, max_length=500)
    params: dict[str, Any] | None = None
    check_mode: bool | None = None
    cron: str | None = Field(None, min_length=5, max_length=100)
    enabled: bool | None = None


def _schedule(db: Session, s: JobSchedule) -> dict:
    owner = db.get(User, s.created_by)
    t = db.get(JobTemplate, s.template_id) if s.template_id else None
    names = {d.id: d.hostname for d in db.execute(select(Device).where(Device.id.in_(s.device_ids or [-1]))).scalars()}
    last = db.get(Job, s.last_job_id) if s.last_job_id else None
    try:
        desc = Cron(s.cron).describe()
    except CronError:
        desc = s.cron
    return {"id": s.id, "name": s.name, "description": s.description, "kind": s.kind, "operation_id": s.operation_id,
            "template_id": s.template_id, "template_name": t.name if t else None, "device_ids": s.device_ids,
            "devices": [names.get(i, f"#{i}") for i in s.device_ids], "params": s.params, "check_mode": s.check_mode, "cron": s.cron,
            "cron_text": desc, "enabled": s.enabled, "owner": owner.username if owner else None, "owner_id": s.created_by,
            "next_run_at": ser.iso(s.next_run_at), "last_run_at": ser.iso(s.last_run_at), "last_job_id": s.last_job_id,
            "last_job_status": last.status if last else None, "last_error": s.last_error, "created_at": ser.iso(s.created_at)}


@router.get("/schedules")
def list_schedules(user: User = Depends(need("automation:read")), db: Session = Depends(get_db)):
    return [_schedule(db, s) for s in db.execute(select(JobSchedule).order_by(JobSchedule.name)).scalars().all()]


@router.get("/schedules/preview")
def preview_cron(cron: str, user: User = Depends(need("automation:read"))):
    """Validate a cron expression and show the next five run times (UTC)."""
    c = schedules.parse_cron(cron)
    t, runs = utcnow(), []
    for _ in range(5):
        t = c.next_after(t)
        runs.append(ser.iso(t))
    return {"cron": c.expr, "text": c.describe(), "next_runs": runs}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, request: Request, user: User = Depends(need("automation:run")), db: Session = Depends(get_db)):
    return _schedule(db, schedules.create(db, user, body.model_dump(), client_ip(request)))


@router.put("/schedules/{sid}")
def update_schedule(sid: int, body: ScheduleUpdate, request: Request, user: User = Depends(need("automation:run")), db: Session = Depends(get_db)):
    return _schedule(db, schedules.update(db, user, sid, body.model_dump(exclude_unset=True), client_ip(request)))


@router.delete("/schedules/{sid}", status_code=204)
def delete_schedule(sid: int, request: Request, user: User = Depends(need("automation:run")), db: Session = Depends(get_db)):
    schedules.delete(db, user, sid, client_ip(request))
    return Response(status_code=204)


@router.post("/schedules/{sid}/run", status_code=201)
def run_schedule_now(sid: int, request: Request, user: User = Depends(need("automation:run")), db: Session = Depends(get_db)):
    return ser.job(db, schedules.run_now(db, user, sid, client_ip(request)), detail=False)


# ---------------------------------------------------------------- reports
REPORTS = {
    "inventory": ("Inventory summary", "devices:read"),
    "backup-coverage": ("Configuration backup coverage", "devices:read"),
    "firewall-risk": ("Firewall rule risk (latest analysis per firewall)", "firewall:read"),
    "changes": ("Changes executed", "audit:read"),
    "alerts": ("Alerts", "alerts:read"),
    "jobs": ("Job outcomes", "automation:read"),
}


def _visible(db: Session, user: User) -> list[Device]:
    groups = auth.visible_device_filter(db, user)
    q = select(Device).where(Device.deleted_at.is_(None)).order_by(Device.hostname)
    devs = list(db.execute(q).scalars())
    if groups is None:
        return devs
    ids = set(db.execute(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id.in_(groups or {-1}))).scalars())
    return [d for d in devs if d.id in ids]


def _report(db: Session, user: User, key: str, days: int) -> tuple[list[str], list[list]]:
    since = utcnow() - timedelta(days=days)
    devs = _visible(db, user)
    vis = {d.id for d in devs}
    names = {d.id: d.hostname for d in devs}
    if key == "inventory":
        head = ["Hostname", "IP address", "Type", "Vendor", "Model", "OS", "Version", "Environment", "Site", "Status", "Last seen (UTC)", "Owner"]
        rows = [[d.hostname, d.ip_address, d.device_type, d.vendor, d.model, d.os_name, d.os_version, d.environment,
                 d.site.name if d.site else "", d.status, ser.iso(d.last_checked_at) or "", d.owner] for d in devs]
    elif key == "backup-coverage":
        latest = dict(db.execute(select(ConfigBackup.device_id, func.max(ConfigBackup.created_at)).group_by(ConfigBackup.device_id)).all())
        counts = dict(db.execute(select(ConfigBackup.device_id, func.count()).group_by(ConfigBackup.device_id)).all())
        head = ["Hostname", "Platform", "Latest backup (UTC)", "Age (days)", "Backups stored", "Status"]
        rows = []
        for d in devs:
            if driver_class(d.platform).category not in ("network", "firewall"):
                continue
            ts = latest.get(d.id)
            age = round((utcnow() - ts).total_seconds() / 86400, 1) if ts else None
            rows.append([d.hostname, d.platform, ser.iso(ts) or "never", age if age is not None else "", counts.get(d.id, 0),
                         "OK" if age is not None and age <= 7 else ("Stale" if ts else "Missing")])
    elif key == "firewall-risk":
        head = ["Firewall", "Analysed (UTC)", "Rule", "Severity", "Issues"]
        rows = []
        q = (select(JobExecution, Job).join(Job, Job.id == JobExecution.job_id)
             .where(Job.operation_id == "firewall.rules.analyse", JobExecution.status == "succeeded").order_by(JobExecution.id.desc()))
        seen: set[int] = set()
        for e, _j in db.execute(q.limit(2000)).all():
            if e.device_id in seen or e.device_id not in vis:
                continue
            seen.add(e.device_id)
            findings = (e.result or {}).get("findings") or []
            if not findings:
                rows.append([names[e.device_id], ser.iso(e.finished_at), "-", "none", "No overly broad rules found"])
            for f in findings:
                rows.append([names[e.device_id], ser.iso(e.finished_at), f"{f.get('rule_id')} {f.get('rule_name') or ''}".strip(), f.get("severity"),
                             "; ".join(f.get("issues") or [])])
    elif key == "changes":
        head = ["Time (UTC)", "Actor", "Action", "Target", "Result", "IP"]
        q = (select(AuditLog).where(AuditLog.ts >= since, AuditLog.action.in_(
            ["job.create", "job.execute", "job.approve", "job.reject", "job.cancel", "approval.decide", "schedule.run", "config.restore"]))
             .order_by(AuditLog.id.desc()).limit(20000))
        rows = [[ser.iso(a.ts), a.actor_name, a.action, a.target_name or a.target_id, a.result, a.ip_address or ""]
                for a in db.execute(q).scalars() if a.device_id is None or a.device_id in vis]
    elif key == "alerts":
        head = ["Opened (UTC)", "Severity", "Device", "Title", "Status", "Occurrences", "Acknowledged (UTC)", "Resolved (UTC)"]
        q = select(Alert).where(Alert.first_seen_at >= since).order_by(Alert.first_seen_at.desc()).limit(20000)
        rows = [[ser.iso(a.first_seen_at), a.severity, names.get(a.device_id, ""), a.title, a.status, a.count,
                 ser.iso(a.acknowledged_at) or "", ser.iso(a.resolved_at) or ""]
                for a in db.execute(q).scalars() if a.device_id is None or a.device_id in vis]
    elif key == "jobs":
        head = ["Created (UTC)", "Job", "Operation", "Risk", "Requested by", "Status", "Devices", "Finished (UTC)"]
        users = {u.id: u.username for u in db.execute(select(User)).scalars()}
        q = select(Job).where(Job.created_at >= since).order_by(Job.id.desc()).limit(20000)
        rows = [[ser.iso(j.created_at), j.title, j.operation_id or j.playbook, j.risk, users.get(j.requested_by, "system"), j.status,
                 len(j.executions), ser.iso(j.finished_at) or ""] for j in db.execute(q).scalars()]
    else:
        raise NotFound("Unknown report")
    return head, rows


@router.get("/reports")
def list_reports(user: User = Depends(need("dashboard:read")), db: Session = Depends(get_db)):
    return [{"key": k, "title": t, "permission": p, "allowed": auth.has_any_scope(db, user, p)} for k, (t, p) in REPORTS.items()]


@router.get("/reports/{key}")
def get_report(key: str, request: Request, days: int = Query(30, ge=1, le=366), format: Literal["json", "csv", "xlsx"] = "json",
               user: User = Depends(need("dashboard:read")), db: Session = Depends(get_db)):
    if key not in REPORTS:
        raise NotFound("Unknown report")
    title, perm = REPORTS[key]
    if not auth.has_any_scope(db, user, perm):
        raise Forbidden(f"This report needs the '{perm}' permission")
    head, rows = _report(db, user, key, days)
    if format == "json":
        return {"key": key, "title": title, "days": days, "columns": head, "rows": rows, "generated_at": ser.iso(utcnow())}
    audit.record(db, "report.export", actor=user, target_type="report", target_id=key, target_name=title, ip=client_ip(request),
                 details={"format": format, "rows": len(rows), "days": days})
    db.commit()
    stamp = utcnow().strftime("%Y%m%d-%H%M")
    if format == "csv":
        return Response(import_export.to_csv([head, *rows]), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="infrapilot-{key}-{stamp}.csv"'})
    return Response(import_export.to_xlsx([head, *rows], title=title[:31]),
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="infrapilot-{key}-{stamp}.xlsx"'})


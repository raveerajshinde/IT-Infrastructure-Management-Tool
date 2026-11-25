"""Report Center: templates, on-demand generation (PDF/Excel/CSV/HTML), scheduled e-mail delivery and report history."""
from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need, paging
from app.core.cron import Cron, CronError
from app.core.db import get_db
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.models import ReportRun, ReportSchedule, User
from app.services import audit, auth, reporting
from app.services.reporting import center
from app.services.reporting.render import MEDIA

router = APIRouter(prefix="/api", tags=["report center"])
EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


@router.get("/report-center/templates")
def templates(user: User = Depends(need("reports:read")), db: Session = Depends(get_db)):
    return [{"key": t.key, "title": t.title, "description": t.description, "permission": t.permission, "filters": list(t.filters),
             "default_days": t.default_days, "allowed": auth.has_any_scope(db, user, t.permission)} for t in center.TEMPLATES.values()]


@router.get("/report-center/reports/{key}")
def generate(key: str, request: Request, format: Literal["pdf", "xlsx", "csv", "html"] = "pdf", days: int | None = Query(None, ge=1, le=3660),
             site_id: int | None = None, department: str | None = Query(None, max_length=120), device_type: str | None = Query(None, max_length=40),
             asset: str | None = Query(None, max_length=100), severity: str | None = Query(None, max_length=60), domain_id: int | None = None,
             gpo_domain: str | None = Query(None, max_length=255), inline: bool = False,
             user: User = Depends(need("reports:read")), db: Session = Depends(get_db)):
    params = {k: v for k, v in dict(days=days, site_id=site_id, department=department, device_type=device_type, asset=asset, severity=severity,
                                    domain_id=domain_id, gpo_domain=gpo_domain).items() if v not in (None, "")}
    doc = center.build(db, user, key, params)
    return reporting.export(db, key=key, doc=doc, fmt=format, params={**params, "inline": inline}, user=user, ip=client_ip(request))


# ---------------------------------------------------------------- schedules
class ScheduleIn(BaseModel):
    name: str = Field(min_length=3, max_length=150)
    report_key: str
    params: dict = Field(default_factory=dict)
    format: Literal["pdf", "xlsx", "csv", "html"] = "pdf"
    cron: str = Field(min_length=9, max_length=100)
    recipients: str = Field("", max_length=1000)
    enabled: bool = True

    @field_validator("recipients")
    @classmethod
    def _rcpt(cls, v: str) -> str:
        items = [x.strip() for x in re.split(r"[,;\s]+", v or "") if x.strip()]
        bad = [x for x in items if not EMAIL.match(x)]
        if bad:
            raise ValueError(f"invalid e-mail address(es): {', '.join(bad)}")
        if len(items) > 30:
            raise ValueError("at most 30 recipients")
        return ", ".join(items)


def _ser_schedule(db: Session, s: ReportSchedule) -> dict:
    u = db.get(User, s.created_by)
    t = center.TEMPLATES.get(s.report_key)
    return {"id": s.id, "name": s.name, "report_key": s.report_key, "report_title": t.title if t else s.report_key, "params": s.params or {},
            "format": s.format, "cron": s.cron, "recipients": s.recipients, "enabled": s.enabled, "owner": u.username if u else None,
            "next_run_at": ser.iso(s.next_run_at), "last_run_at": ser.iso(s.last_run_at), "last_status": s.last_status, "last_message": s.last_message}


def _validate(db: Session, user: User, body: ScheduleIn) -> None:
    t = center.get_template(body.report_key)
    if not auth.has_any_scope(db, user, t.permission):
        raise Forbidden(f"You cannot schedule a report that needs '{t.permission}'")
    try:
        Cron(body.cron)
    except CronError as exc:
        raise ValidationFailed(f"Schedule: {exc}") from exc
    center.build(db, user, body.report_key, body.params)  # fail early on bad parameters (cheap: no rendering)


@router.get("/report-center/schedules")
def list_schedules(user: User = Depends(need("reports:read")), db: Session = Depends(get_db)):
    return [_ser_schedule(db, s) for s in db.execute(select(ReportSchedule).order_by(ReportSchedule.name)).scalars().all()]


@router.post("/report-center/schedules", status_code=201)
def create_schedule(body: ScheduleIn, request: Request, user: User = Depends(need("reports:manage")), db: Session = Depends(get_db)):
    _validate(db, user, body)
    if db.execute(select(ReportSchedule).where(ReportSchedule.name == body.name)).first():
        raise ValidationFailed("A schedule with this name exists")
    s = ReportSchedule(**body.model_dump(), created_by=user.id, next_run_at=Cron(body.cron).next_after(utcnow()) if body.enabled else None)
    db.add(s)
    db.flush()
    audit.record(db, "report.schedule_create", actor=user, target_type="report_schedule", target_id=s.id, target_name=s.name, ip=client_ip(request),
                 details={"report": s.report_key, "cron": s.cron, "format": s.format, "recipients": s.recipients})
    db.commit()
    return _ser_schedule(db, s)


def _get(db: Session, sid: int) -> ReportSchedule:
    s = db.get(ReportSchedule, sid)
    if s is None:
        raise NotFound("Schedule not found")
    return s


@router.put("/report-center/schedules/{sid}")
def update_schedule(sid: int, body: ScheduleIn, request: Request, user: User = Depends(need("reports:manage")), db: Session = Depends(get_db)):
    s = _get(db, sid)
    _validate(db, user, body)
    for k, v in body.model_dump().items():
        setattr(s, k, v)
    s.created_by = user.id  # the editor becomes the owner: reports run with their permissions
    s.next_run_at = Cron(body.cron).next_after(utcnow()) if body.enabled else None
    audit.record(db, "report.schedule_update", actor=user, target_type="report_schedule", target_id=s.id, target_name=s.name, ip=client_ip(request),
                 details={"report": s.report_key, "cron": s.cron, "recipients": s.recipients, "enabled": s.enabled})
    db.commit()
    return _ser_schedule(db, s)


@router.delete("/report-center/schedules/{sid}", status_code=204)
def delete_schedule(sid: int, request: Request, user: User = Depends(need("reports:manage")), db: Session = Depends(get_db)):
    s = _get(db, sid)
    audit.record(db, "report.schedule_delete", actor=user, target_type="report_schedule", target_id=s.id, target_name=s.name, ip=client_ip(request))
    db.execute(ReportRun.__table__.update().where(ReportRun.schedule_id == s.id).values(schedule_id=None))
    db.delete(s)
    db.commit()
    return Response(status_code=204)


@router.post("/report-center/schedules/{sid}/run")
def run_schedule_now(sid: int, request: Request, user: User = Depends(need("reports:manage")), db: Session = Depends(get_db)):
    s = _get(db, sid)
    run = center.run_schedule(db, s)
    s = _get(db, sid)
    if run is None:
        raise ValidationFailed(f"Report failed: {s.last_message}")
    return {"run_id": run.id, **_ser_schedule(db, s)}


# ---------------------------------------------------------------- history
@router.get("/report-runs")
def list_runs(key: str | None = None, user: User = Depends(need("reports:read")), db: Session = Depends(get_db), pg=Depends(paging)):
    stmt = select(ReportRun.id, ReportRun.report_key, ReportRun.title, ReportRun.format, ReportRun.params, ReportRun.generated_at, ReportRun.generated_by,
                  ReportRun.schedule_id, ReportRun.size, ReportRun.sha256, ReportRun.emailed_to)
    if key:
        stmt = stmt.where(ReportRun.report_key == key)
    total = db.execute(select(func.count()).select_from(ReportRun).where(ReportRun.report_key == key) if key else select(func.count()).select_from(ReportRun)).scalar()
    page, size = pg
    rows = db.execute(stmt.order_by(ReportRun.id.desc()).offset((page - 1) * size).limit(size)).all()
    return {"items": [{"id": r.id, "report_key": r.report_key, "title": r.title, "format": r.format, "params": r.params, "generated_at": ser.iso(r.generated_at),
                       "generated_by": r.generated_by, "schedule_id": r.schedule_id, "size": r.size, "sha256": r.sha256, "emailed_to": r.emailed_to,
                       "allowed": auth.has_any_scope(db, user, center.run_permission(r.report_key))} for r in rows], "total": total, "page": page, "page_size": size}


@router.get("/report-runs/{rid}/download")
def download_run(rid: int, request: Request, user: User = Depends(need("reports:read")), db: Session = Depends(get_db)):
    r = db.get(ReportRun, rid)
    if r is None:
        raise NotFound("Report not found")
    perm = center.run_permission(r.report_key)
    if not auth.has_any_scope(db, user, perm):
        raise Forbidden(f"This report needs the '{perm}' permission")
    audit.record(db, "report.download", actor=user, target_type="report_run", target_id=r.id, target_name=r.title, ip=client_ip(request),
                 details={"format": r.format, "sha256": r.sha256})
    db.commit()
    return Response(r.content, media_type=MEDIA.get(r.format, "application/octet-stream"),
                    headers={"Content-Disposition": f'attachment; filename="{reporting.filename(r.title, r.format)}"', "X-Report-SHA256": r.sha256})

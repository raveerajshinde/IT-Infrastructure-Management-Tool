"""Recurring jobs.

A schedule only stores *what* to run; each run is created by ``jobs.create_operation_job`` /
``jobs.create_playbook_job`` as the schedule's owner. Permissions are therefore re-checked at
every run (an owner who loses a role, or is disabled, stops their schedules), approval
policies still apply (a scheduled change that needs approval waits for it) and every run is
audited. Operations that take a secret parameter cannot be scheduled, so no secret is ever
stored in a schedule.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select, true
from sqlalchemy.orm import Session

from app.core.cron import Cron, CronError
from app.core.errors import Forbidden, NotFound, Unsupported, ValidationFailed
from app.core.permissions import operation_permission
from app.core.timeutil import utcnow
from app.drivers.registry import driver_class
from app.models import JobSchedule, JobTemplate, User
from app.services import audit, auth, devices, jobs

log = logging.getLogger("infrapilot.schedules")
MIN_INTERVAL = timedelta(minutes=5)


def parse_cron(expr: str) -> Cron:
    try:
        c = Cron(expr)
    except CronError as exc:
        raise ValidationFailed(f"Schedule: {exc}") from exc
    now = utcnow()
    a = c.next_after(now)
    b = c.next_after(a)
    if b - a < MIN_INTERVAL:
        raise ValidationFailed("Schedule: runs must be at least 5 minutes apart")
    return c


def _validate(db: Session, user: User, data: dict) -> dict:
    kind = data.get("kind") or "operation"
    ids = list(dict.fromkeys(data.get("device_ids") or []))
    if not ids:
        raise ValidationFailed("Select at least one device")
    if len(ids) > 500:
        raise ValidationFailed("A schedule can target at most 500 devices")
    parse_cron(data.get("cron") or "")
    devs = [devices.get_device(db, i) for i in ids]
    params = data.get("params") or {}
    if kind == "operation":
        op = data.get("operation_id") or ""
        for d in devs:
            cls = driver_class(d.platform)
            try:
                spec = cls.get_spec(op)
            except Unsupported as exc:
                raise ValidationFailed(f"{d.hostname}: {exc}") from exc
            if spec.secret_params:
                raise ValidationFailed(f"'{spec.title}' takes a secret ({', '.join(spec.secret_params)}) and cannot be scheduled")
            if data.get("check_mode") and not spec.check_mode:
                raise ValidationFailed(f"'{spec.title}' has no dry-run mode on {cls.display_name}")
            try:
                cls.validate_params(op, params)
            except Exception as exc:
                raise ValidationFailed(f"Invalid parameters: {exc}") from exc
            auth.require(db, user, operation_permission(cls.category, spec.risk), d.id)
        data["template_id"] = None
    elif kind == "playbook":
        t = db.get(JobTemplate, data.get("template_id") or 0)
        if not t or not t.enabled or t.kind != "playbook":
            raise ValidationFailed("Choose an enabled playbook template")
        for d in devs:
            auth.require(db, user, operation_permission(t.category, t.risk), d.id)
            auth.require(db, user, "automation:run", d.id)
        data["operation_id"] = None
    else:
        raise ValidationFailed("kind must be 'operation' or 'playbook'")
    data["device_ids"] = ids
    data["kind"] = kind
    return data


def _can_edit(db: Session, user: User, s: JobSchedule) -> None:
    if s.created_by != user.id and not auth.has_any_scope(db, user, "automation:manage"):
        raise Forbidden("Only the owner or a user with 'automation:manage' can change this schedule")


def get(db: Session, sid: int) -> JobSchedule:
    s = db.get(JobSchedule, sid)
    if not s:
        raise NotFound("Schedule not found")
    return s


def create(db: Session, user: User, data: dict, ip: str | None = None) -> JobSchedule:
    data = _validate(db, user, dict(data))
    if db.execute(select(JobSchedule).where(JobSchedule.name == data["name"])).first():
        raise ValidationFailed("A schedule with that name already exists")
    s = JobSchedule(name=data["name"], description=data.get("description", ""), kind=data["kind"], operation_id=data.get("operation_id"),
                    template_id=data.get("template_id"), device_ids=data["device_ids"], params=data.get("params") or {},
                    check_mode=bool(data.get("check_mode")), cron=data["cron"].strip(), enabled=data.get("enabled", True), created_by=user.id)
    s.next_run_at = Cron(s.cron).next_after(utcnow()) if s.enabled else None
    db.add(s)
    db.flush()
    audit.record(db, "schedule.create", actor=user, target_type="schedule", target_id=s.id, target_name=s.name, ip=ip,
                 details={"cron": s.cron, "operation": s.operation_id, "template_id": s.template_id, "devices": len(s.device_ids)})
    db.commit()
    return s


def update(db: Session, user: User, sid: int, data: dict, ip: str | None = None) -> JobSchedule:
    s = get(db, sid)
    _can_edit(db, user, s)
    merged = {"name": s.name, "description": s.description, "kind": s.kind, "operation_id": s.operation_id, "template_id": s.template_id,
              "device_ids": s.device_ids, "params": s.params, "check_mode": s.check_mode, "cron": s.cron, "enabled": s.enabled}
    merged.update({k: v for k, v in data.items() if v is not None})
    merged = _validate(db, user, merged)
    for k in ("name", "description", "kind", "operation_id", "template_id", "device_ids", "params", "check_mode", "cron", "enabled"):
        setattr(s, k, merged[k])
    # Whoever edits a schedule takes ownership: their permissions were just validated.
    s.created_by = user.id
    s.next_run_at = Cron(s.cron).next_after(utcnow()) if s.enabled else None
    s.last_error = None
    audit.record(db, "schedule.update", actor=user, target_type="schedule", target_id=s.id, target_name=s.name, ip=ip,
                 details={k: v for k, v in data.items() if k != "params"})
    db.commit()
    return s


def delete(db: Session, user: User, sid: int, ip: str | None = None) -> None:
    s = get(db, sid)
    _can_edit(db, user, s)
    audit.record(db, "schedule.delete", actor=user, target_type="schedule", target_id=s.id, target_name=s.name, ip=ip)
    db.delete(s)
    db.commit()


def _launch(db: Session, s: JobSchedule, owner: User, ip: str | None = None):
    reason = f"Scheduled run of '{s.name}' ({Cron(s.cron).describe()})"
    if s.kind == "playbook":
        t = db.get(JobTemplate, s.template_id)
        if not t or not t.enabled:
            raise ValidationFailed("The playbook template no longer exists or is disabled")
        return jobs.create_playbook_job(db, owner, t, s.device_ids, s.params or {}, s.check_mode, False, reason, ip)
    return jobs.create_operation_job(db, owner, operation_id=s.operation_id, device_ids=s.device_ids, params=s.params or {},
                                     check_mode=s.check_mode, reason=reason, title=f"[Scheduled] {s.name}", ip=ip)


def run_now(db: Session, user: User, sid: int, ip: str | None = None):
    s = get(db, sid)
    _can_edit(db, user, s)
    job = _launch(db, s, user, ip)
    s.last_run_at, s.last_job_id, s.last_error = utcnow(), job.id, None
    audit.record(db, "schedule.run", actor=user, target_type="schedule", target_id=s.id, target_name=s.name, ip=ip, details={"job_id": job.id, "manual": True})
    db.commit()
    return job


def run_due(db: Session) -> int:
    """Called by the worker scheduler loop. Returns the number of jobs created."""
    now = utcnow()
    due = db.execute(select(JobSchedule).where(JobSchedule.enabled == true(), JobSchedule.next_run_at.is_not(None),
                                               JobSchedule.next_run_at <= now)).scalars().all()
    created = 0
    for s in due:
        # Claim first (compare-and-set on next_run_at) so two workers never launch the same run.
        nxt = Cron(s.cron).next_after(now)
        claimed = db.execute(JobSchedule.__table__.update().where(JobSchedule.id == s.id, JobSchedule.next_run_at == s.next_run_at)
                             .values(next_run_at=nxt)).rowcount
        db.commit()
        if not claimed:
            continue
        db.refresh(s)
        owner = db.get(User, s.created_by)
        try:
            if not owner or not owner.is_active:
                raise Forbidden("schedule owner is disabled or deleted")
            job = _launch(db, s, owner)
            s.last_run_at, s.last_job_id, s.last_error = now, job.id, None
            audit.record(db, "schedule.run", actor_name="scheduler", target_type="schedule", target_id=s.id, target_name=s.name,
                         details={"job_id": job.id, "owner": owner.username})
            created += 1
        except Exception as exc:  # keep the scheduler alive; surface the reason on the schedule
            db.rollback()
            s = db.get(JobSchedule, s.id)
            s.last_run_at, s.last_error = now, str(exc)[:1000]
            if isinstance(exc, Forbidden):
                s.enabled, s.next_run_at = False, None
            audit.record(db, "schedule.run", actor_name="scheduler", target_type="schedule", target_id=s.id, target_name=s.name,
                         result="failure", details={"error": str(exc)[:500]})
            log.warning("schedule %s failed: %s", s.id, exc)
        db.commit()
    return created

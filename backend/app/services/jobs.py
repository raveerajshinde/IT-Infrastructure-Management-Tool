"""Job creation, approval gating, inline read operations and job execution.

Flow for any operation that changes something:
  validate params (server side, per driver) -> authorize per device -> evaluate approval
  policies & maintenance windows -> seal secret params into the vault -> create Job +
  one JobExecution per device -> status queued | pending_approval | waiting_window
  -> worker executes -> results, before/after, verification, rollback, config diffs and
  audit records are stored.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from sqlalchemy import or_, select, true
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, Forbidden, NotFound, Unsupported, ValidationFailed
from app.core.permissions import operation_permission
from app.core.timeutil import utcnow
from app.drivers.base import OpResult
from app.drivers.registry import driver_class
from app.models import (
    Approval, ApprovalPolicy, ConfigBackup, Device, DeviceGroupMember, Job, JobExecution, JobTemplate, MaintenanceWindow,
    Notification, User,
)
from app.services import audit, auth, configs, devices, secrets, settings_store

log = logging.getLogger("infrapilot.jobs")
RISK_ORDER = {"read": 0, "change": 1, "critical": 2}
TERMINAL = {"succeeded", "failed", "partial", "cancelled", "rejected"}


class PolicyDecision:
    def __init__(self):
        self.require_approval = False
        self.require_window = False
        self.matched: list[str] = []


def evaluate_policies(db: Session, category: str, risk: str, environments: set[str]) -> PolicyDecision:
    dec = PolicyDecision()
    for pol in db.execute(select(ApprovalPolicy).where(ApprovalPolicy.enabled == true())).scalars().all():
        if pol.risk and RISK_ORDER.get(pol.risk, 0) > RISK_ORDER[risk]:
            continue  # policy applies to risk >= pol.risk
        if pol.category and pol.category != category:
            continue
        if pol.environment and pol.environment not in environments:
            continue
        dec.matched.append(pol.name)
        dec.require_approval |= pol.require_approval
        dec.require_window |= pol.require_maintenance_window
    return dec


def in_maintenance_window(db: Session, device_list: list[Device], at: datetime | None = None, auto_approve_only: bool = False) -> bool:
    """True when every device is covered by an active window (optionally one that auto-approves medium-risk changes)."""
    at = at or utcnow()
    q = select(MaintenanceWindow).where(MaintenanceWindow.start_at <= at, MaintenanceWindow.end_at >= at)
    if auto_approve_only:
        q = q.where(MaintenanceWindow.auto_approve_change == true())
    wins = list(db.execute(q).scalars())
    if not wins:
        return False
    for d in device_list:
        groups = set(db.execute(select(DeviceGroupMember.group_id).where(DeviceGroupMember.device_id == d.id)).scalars())
        if not any((w.environment in (None, d.environment)) and (w.device_group_id in (None, *groups)) for w in wins):
            return False
    return True


def _seal_secret_params(db: Session, spec, params: dict) -> dict:
    out = dict(params)
    for k in spec.secret_params:
        if out.get(k) not in (None, ""):
            row = secrets.store(db, f"job-param:{spec.id}:{k}", str(out[k]))
            out[k] = {"__vault__": row.id}
    return out


def _unseal_params(db: Session, params: dict) -> dict:
    out = {}
    for k, val in (params or {}).items():
        if isinstance(val, dict) and "__vault__" in val:
            out[k] = secrets.load(db, val["__vault__"]).decode()
        else:
            out[k] = val
    return out


def public_params(params: dict) -> dict:
    return {k: ("***" if isinstance(val, dict) and "__vault__" in val else val) for k, val in (params or {}).items()}


def _notify(db: Session, user_id: int | None, title: str, body: str, severity: str = "info", link: str | None = None):
    if user_id:
        db.add(Notification(user_id=user_id, title=title[:300], body=body[:2000], severity=severity, link=link))


def _approvers(db: Session, exclude: int | None) -> list[User]:
    users = db.execute(select(User).where(User.is_active == true())).scalars().all()  # read fully before the per-user permission queries
    return [u for u in users if u.id != exclude and auth.has_any_scope(db, u, "approvals:decide")]


# ------------------------------------------------------------------ creation
def create_operation_job(db: Session, user: User, *, operation_id: str, device_ids: list[int], params: dict,
                         check_mode: bool = False, emergency: bool = False, reason: str = "", title: str | None = None,
                         template: JobTemplate | None = None, ip: str | None = None, _script=None) -> Job:
    from app.services.scripts import SCRIPT_OPS
    if operation_id in SCRIPT_OPS and _script is None:
        raise Forbidden("Scripts can only be run from the script library")
    devs = [devices.get_device(db, i) for i in dict.fromkeys(device_ids)]
    classes = {d.platform: driver_class(d.platform) for d in devs}
    specs = {}
    for plat, cls in classes.items():
        try:
            specs[plat] = cls.get_spec(operation_id)
        except Unsupported:
            names = ", ".join(d.hostname for d in devs if d.platform == plat)
            raise Unsupported(f"Operation '{operation_id}' is not supported by {cls.display_name} ({names})")
        if check_mode and specs[plat].risk == "read":
            pass  # read-only operations change nothing; dry-run is implicit
        elif check_mode and not specs[plat].check_mode:
            raise Unsupported(f"'{specs[plat].title}' does not support dry-run on {cls.display_name}")
        try:
            cls.validate_params(operation_id, params)
        except Exception as exc:
            raise ValidationFailed(f"Invalid parameters: {exc}") from exc
    if check_mode and all(sp.risk == "read" for sp in specs.values()):
        check_mode = False
    spec = next(iter(specs.values()))
    category = next(iter(classes.values())).category
    risk = max((s.risk for s in specs.values()), key=lambda r: RISK_ORDER[r])
    if _script is not None:
        risk = _script.risk  # the reviewed script declares its own risk (read / change / critical)
        if check_mode and risk == "read":
            check_mode = False

    perm = operation_permission(category, risk)
    for d in devs:
        auth.require(db, user, perm, d.id)
        if template is not None or _script is not None:
            auth.require(db, user, "automation:run", d.id)

    envs = {d.environment for d in devs}
    dec = evaluate_policies(db, category, risk, envs) if risk != "read" else PolicyDecision()
    if check_mode:
        dec.require_approval = dec.require_window = False  # dry-run never changes anything
    elif dec.require_approval and risk == "change" and in_maintenance_window(db, devs, auto_approve_only=True):
        dec.require_approval = False
        dec.matched.append("auto-approved: inside a maintenance window that pre-approves medium-risk changes")

    if emergency:
        if not settings_store.value(db, "security.allow_emergency_changes"):
            raise Forbidden("Emergency changes are disabled in security settings")
        auth.require(db, user, "changes:emergency")
        if len(reason.strip()) < 10:
            raise ValidationFailed("Emergency changes require a justification of at least 10 characters")
    elif dec.require_approval and len(reason.strip()) < 5:
        raise ValidationFailed("This change requires approval; please describe the reason for the change")
    if dec.require_approval and not emergency and not _approvers(db, user.id):
        raise ValidationFailed("This change needs approval (" + "; ".join(dec.matched[:2]) + "), but no other active user can approve it - "
                               "you cannot approve your own changes. Give a second person an approver role (e.g. Infrastructure "
                               "Administrator), or adjust the approval policy in Approvals -> Policies.")

    stored_params = _seal_secret_params(db, spec, params)
    summary = spec.describe(params)
    if _script is not None:
        vals = ", ".join(f"{k}={v}" for k, v in (params.get("values") or {}).items())
        summary = f"Run library script '{_script.name}' v{_script.version} ({_script.risk} risk){': ' + vals if vals else ''}"
    job = Job(title=title or f"{spec.title} on {len(devs)} device(s)", kind="operation", operation_id=operation_id,
              template_id=template.id if template else None, category=category, params=stored_params, change_summary=summary,
              requested_by=user.id, check_mode=check_mode, risk=risk, is_emergency=emergency, requires_window=dec.require_window,
              timeout_seconds=get_settings().default_job_timeout_seconds)
    db.add(job)
    db.flush()
    for d in devs:
        db.add(JobExecution(job_id=job.id, device_id=d.id, status="pending"))

    if emergency:
        job.status, job.queued_at = "queued", utcnow()
        db.add(Approval(job_id=job.id, requested_by=user.id, kind="emergency_review", reason=reason))
        for a in _approvers(db, user.id):
            _notify(db, a.id, "Emergency change executed - review required", f"{user.username}: {summary}", "warning", f"/jobs/{job.id}")
    elif dec.require_approval:
        job.status = "pending_approval"
        db.add(Approval(job_id=job.id, requested_by=user.id, kind="pre", reason=reason))
        for a in _approvers(db, user.id):
            _notify(db, a.id, "Approval requested", f"{user.username}: {summary}", "info", "/approvals")
    elif dec.require_window and not in_maintenance_window(db, devs):
        job.status = "waiting_window"
    else:
        job.status, job.queued_at = "queued", utcnow()

    audit.record(db, "job.create", actor=user, target_type="job", target_id=job.id, target_name=job.title, ip=ip,
                 details={"operation": operation_id, "devices": [d.hostname for d in devs], "risk": risk, "check_mode": check_mode,
                          "emergency": emergency, "status": job.status, "policies": dec.matched, "params": public_params(stored_params),
                          "reason": reason})
    db.commit()
    return job


def create_playbook_job(db: Session, user: User, template: JobTemplate, device_ids: list[int], params: dict, check_mode: bool,
                        emergency: bool, reason: str, ip: str | None) -> Job:
    from app.automation.runner import validate_playbook_params

    devs = [devices.get_device(db, i) for i in dict.fromkeys(device_ids)]
    perm = operation_permission(template.category, template.risk)
    for d in devs:
        auth.require(db, user, perm, d.id)
        auth.require(db, user, "automation:run", d.id)
        if driver_class(d.platform).category != template.category:
            raise ValidationFailed(f"{d.hostname} is not a {template.category} device")
    merged = validate_playbook_params(template.playbook, {**(template.default_params or {}), **params})
    dec = evaluate_policies(db, template.category, template.risk, {d.environment for d in devs}) if not check_mode else PolicyDecision()
    if emergency:
        auth.require(db, user, "changes:emergency")
    job = Job(title=f"{template.name} on {len(devs)} device(s)", kind="playbook", playbook=template.playbook, template_id=template.id,
              category=template.category, params=merged, change_summary=f"Run playbook {template.playbook} with {json.dumps(merged)}",
              requested_by=user.id, check_mode=check_mode, risk=template.risk, is_emergency=emergency, requires_window=dec.require_window,
              timeout_seconds=get_settings().default_job_timeout_seconds)
    db.add(job)
    db.flush()
    for d in devs:
        db.add(JobExecution(job_id=job.id, device_id=d.id, status="pending"))
    if emergency:
        job.status, job.queued_at = "queued", utcnow()
        db.add(Approval(job_id=job.id, requested_by=user.id, kind="emergency_review", reason=reason))
    elif dec.require_approval:
        job.status = "pending_approval"
        db.add(Approval(job_id=job.id, requested_by=user.id, kind="pre", reason=reason))
    elif dec.require_window and not in_maintenance_window(db, devs):
        job.status = "waiting_window"
    else:
        job.status, job.queued_at = "queued", utcnow()
    audit.record(db, "job.create", actor=user, target_type="job", target_id=job.id, target_name=job.title, ip=ip,
                 details={"playbook": template.playbook, "devices": [d.hostname for d in devs], "check_mode": check_mode, "status": job.status})
    db.commit()
    return job


# ------------------------------------------------------------------ approvals
def decide(db: Session, user: User, approval_id: int, approve: bool, comment: str, ip: str | None) -> Approval:
    ap = db.get(Approval, approval_id)
    if not ap:
        raise NotFound("Approval not found")
    if ap.status != "pending":
        raise AppError(f"Approval already {ap.status}")
    job = db.get(Job, ap.job_id)
    for ex in job.executions:
        auth.require(db, user, "approvals:decide", ex.device_id)
    if ap.requested_by == user.id:
        raise Forbidden("Segregation of duties: you cannot approve or reject your own change request")
    ap.status = "approved" if approve else "rejected"
    ap.decided_by, ap.decided_at, ap.decision_comment = user.id, utcnow(), comment
    if ap.kind == "pre":
        if approve:
            devs = [db.get(Device, e.device_id) for e in job.executions]
            if job.requires_window and not in_maintenance_window(db, devs):
                job.status = "waiting_window"
            else:
                job.status, job.queued_at = "queued", utcnow()
        else:
            job.status, job.finished_at = "rejected", utcnow()
            for e in job.executions:
                e.status = "skipped"
    _notify(db, ap.requested_by, f"Change {'approved' if approve else 'rejected'}: {job.title}", comment or "", "info" if approve else "warning", f"/jobs/{job.id}")
    audit.record(db, "approval.decide", actor=user, target_type="approval", target_id=ap.id, target_name=job.title, ip=ip,
                 details={"job_id": job.id, "decision": ap.status, "kind": ap.kind, "comment": comment})
    db.commit()
    return ap


def cancel(db: Session, user: User, job_id: int, ip: str | None) -> Job:
    job = db.get(Job, job_id)
    if not job:
        raise NotFound("Job not found")
    if job.status in TERMINAL:
        raise AppError(f"Job is already {job.status}")
    if job.requested_by != user.id:
        for e in job.executions:
            auth.require(db, user, operation_permission(job.category, job.risk), e.device_id)
    if job.status in ("queued", "pending_approval", "waiting_window"):
        job.status, job.finished_at = "cancelled", utcnow()
        for e in job.executions:
            if e.status == "pending":
                e.status = "cancelled"
        for ap in db.execute(select(Approval).where(Approval.job_id == job.id, Approval.status == "pending")).scalars().all():
            ap.status = "cancelled"
    else:
        job.cancel_requested = True  # running: remaining devices are skipped; an in-flight device step completes safely
    audit.record(db, "job.cancel", actor=user, target_type="job", target_id=job.id, target_name=job.title, ip=ip)
    db.commit()
    return job


# ------------------------------------------------------------------ inline (read) ops
def run_inline(db: Session, user: User, device_id: int, operation_id: str, params: dict, ip: str | None) -> dict:
    d = devices.get_device(db, device_id)
    cls = driver_class(d.platform)
    spec = cls.get_spec(operation_id)
    if spec.risk != "read":
        raise ValidationFailed("Only read-only operations can run interactively; submit changes as a job")
    auth.require(db, user, operation_permission(cls.category, "read"), d.id)
    try:
        cls.validate_params(operation_id, params)
    except Exception as exc:
        raise ValidationFailed(f"Invalid parameters: {exc}") from exc
    drv = devices.driver_for(db, d)
    status, out = "succeeded", None
    try:
        res: OpResult = devices.run_with_timeout(lambda: drv.run(operation_id, params), get_settings().operation_timeout_seconds)
        out = {"status": res.status, "output": res.output, "data": res.data}
        for kind, content in res.config_backups:
            b, changed = configs.store_backup(db, d.id, kind, content, note=f"interactive by {user.username}")
            out.setdefault("backups", []).append({"id": b.id, "kind": kind, "changed": changed})
        d.last_success_at = utcnow()
        status = res.status
    except Unsupported as exc:
        status, out = "unsupported", {"status": "unsupported", "output": exc.message}
    except Exception as exc:
        msg = getattr(exc, "message", None) or str(exc)
        status, out = "failed", {"status": "failed", "output": msg[:4000]}
    finally:
        drv.close()
    audit.record(db, "operation.read", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id,
                 result="success" if status == "succeeded" else "failure", ip=ip, details={"operation": operation_id, "params": params, "status": status})
    db.commit()
    return out


# ------------------------------------------------------------------ execution (worker)
def claim_next_job(db: Session, worker_id: str) -> Job | None:
    """Atomically claim the oldest queued job.

    Compare-and-set: UPDATE ... WHERE id = :id AND status = 'queued'. Exactly one worker can win
    the row (the UPDATE re-checks the predicate under a row lock on SQL Server, and is serialised
    on SQLite), so the claim is safe with any number of worker processes or containers.
    (SQLAlchemy's FOR UPDATE SKIP LOCKED is not rendered by the SQL Server dialect, so it is not used.)
    """
    from sqlalchemy import update

    candidates = list(db.execute(select(Job.id).where(Job.status == "queued").order_by(Job.queued_at, Job.id).limit(5)).scalars())
    for jid in candidates:
        res = db.execute(update(Job).where(Job.id == jid, Job.status == "queued")
                         .values(status="running", started_at=utcnow(), worker_id=worker_id))
        if res.rowcount == 1:
            db.commit()
            job = db.get(Job, jid)
            db.refresh(job)
            return job
        db.rollback()
    db.rollback()
    return None


def release_waiting_jobs(db: Session) -> int:
    n = 0
    for job in db.execute(select(Job).where(Job.status == "waiting_window")).scalars().all():
        devs = [db.get(Device, e.device_id) for e in job.executions]
        if in_maintenance_window(db, devs):
            job.status, job.queued_at = "queued", utcnow()
            n += 1
    if n:
        db.commit()
    return n


def recover_stale_jobs(db: Session, worker_prefix: str | None = None) -> int:
    """Jobs left 'running' by a crashed worker are marked failed (never re-run blindly: changes are not idempotent)."""
    n = 0
    for job in db.execute(select(Job).where(Job.status == "running")).scalars().all():
        if job.started_at and (utcnow() - job.started_at).total_seconds() > job.timeout_seconds + 300:
            job.status, job.finished_at, job.summary = "failed", utcnow(), "Worker stopped while job was running; verify device state manually"
            for e in job.executions:
                if e.status in ("pending", "running"):
                    e.status, e.error = "failed", "Worker interrupted"
            n += 1
    if n:
        db.commit()
    return n


def execute_job(db: Session, job: Job) -> Job:
    if job.kind == "playbook":
        from app.automation.runner import run_playbook_job
        run_playbook_job(db, job)
    else:
        _execute_operation_job(db, job)
    _finalise(db, job)
    return job


def _execute_operation_job(db: Session, job: Job) -> None:
    params = _unseal_params(db, job.params)
    from app.services import scripts
    if job.operation_id in scripts.SCRIPT_OPS:
        try:
            params = scripts.load_for_execution(db, params)  # body comes from the library, re-verified against the approved hash
        except Exception as exc:  # noqa: BLE001
            for ex in job.executions:
                if ex.status == "pending":
                    ex.status, ex.error, ex.finished_at = "failed", getattr(exc, "message", None) or str(exc), utcnow()
            db.commit()
            return
    deadline = (job.started_at or utcnow()).timestamp() + job.timeout_seconds
    for ex in job.executions:
        db.refresh(job)
        if job.cancel_requested:
            ex.status = "cancelled"
            continue
        if ex.status != "pending":
            continue
        remaining = int(deadline - utcnow().timestamp())
        if remaining <= 0:
            ex.status, ex.error = "failed", "Job timeout reached before this device was processed"
            continue
        _execute_one(db, job, ex, params, remaining)
        db.commit()


def _execute_one(db: Session, job: Job, ex: JobExecution, params: dict, remaining: int) -> None:
    d = db.get(Device, ex.device_id)
    ex.status, ex.started_at = "running", utcnow()
    db.commit()
    drv = None
    try:
        drv = devices.driver_for(db, d, timeout=min(get_settings().operation_timeout_seconds * 5, remaining))
        res: OpResult = devices.run_with_timeout(lambda: drv.run(job.operation_id, params, job.check_mode), remaining)
        ex.status = res.status
        ex.output, ex.result = res.output or "", _jsonable(res.data)
        ex.before_state, ex.after_state = _clip(res.before), _clip(res.after)
        ex.verification, ex.rollback_hint = res.verification, res.rollback
        _store_backups(db, d, ex, res)
        if res.status == "succeeded" and (not job.check_mode or job.operation_id == "windows.gpo.restore"):
            from app.services import ingest
            ingest.after_execution(db, job, ex, d, res.data)  # GPO collections/versions (restore dry-run keeps its preview diff)
        if ex.status == "succeeded":
            d.last_success_at = utcnow()
    except Unsupported as exc:
        ex.status, ex.error = "unsupported", exc.message
    except Exception as exc:
        ex.status, ex.error = "failed", (getattr(exc, "message", None) or str(exc))[:8000]
    finally:
        if drv:
            drv.close()
    ex.finished_at = utcnow()
    audit.record(db, "job.execute", actor_name=f"worker:{job.worker_id}", actor=None, target_type="device", target_id=d.id, target_name=d.hostname,
                 device_id=d.id, result="success" if ex.status == "succeeded" else "failure",
                 details={"job_id": job.id, "operation": job.operation_id, "status": ex.status, "check_mode": job.check_mode,
                          "verification": (ex.verification or "")[:500], "error": (ex.error or "")[:500], "requested_by": job.requested_by})


def _store_backups(db: Session, d: Device, ex: JobExecution, res: OpResult) -> None:
    stored: dict[str, ConfigBackup] = {}
    for kind, content in res.config_backups:
        if not content:
            continue
        b, _ = configs.store_backup(db, d.id, kind.replace("-before", "") if kind.endswith("-before") else kind, content, ex.id,
                                    note="before change" if kind.endswith("-before") else "")
        stored[kind] = b
    for kind, b in stored.items():
        if kind.endswith("-before") and kind[:-7] in stored and stored[kind[:-7]].id != b.id:
            configs.record_change(db, d.id, ex.id, b, stored[kind[:-7]])


def _finalise(db: Session, job: Job) -> None:
    db.refresh(job)
    sts = [e.status for e in job.executions]
    if job.cancel_requested and any(s == "cancelled" for s in sts):
        job.status = "cancelled"
    elif sts and all(s == "succeeded" for s in sts):
        job.status = "succeeded"
    elif any(s == "succeeded" for s in sts):
        job.status = "partial"
    else:
        job.status = "failed"
    job.finished_at = utcnow()
    counts = {s: sts.count(s) for s in set(sts)}
    job.summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    _notify(db, job.requested_by, f"Job {job.status}: {job.title}", job.summary, "info" if job.status == "succeeded" else "warning", f"/jobs/{job.id}")
    audit.record(db, "job.finish", actor_name=f"worker:{job.worker_id}", target_type="job", target_id=job.id, target_name=job.title,
                 result="success" if job.status == "succeeded" else "failure", details={"status": job.status, "summary": job.summary})
    db.commit()


def _clip(s: str | None, n: int = 2_000_000) -> str | None:
    return s[:n] if isinstance(s, str) else s


def _jsonable(data):
    try:
        json.dumps(data, default=str)
        return json.loads(json.dumps(data, default=str)) if data is not None else {}
    except (TypeError, ValueError):
        return {"repr": str(data)[:10000]}


def visible_jobs_query(db: Session, user: User):
    q = select(Job)
    if not auth.has_permission(db, user, "automation:read"):
        q = q.where(or_(Job.requested_by == user.id))
    return q


# ------------------------------------------------------------------ scheduled housekeeping (worker)
def expire_approvals(db: Session) -> int:
    from datetime import timedelta

    hours = int(settings_store.value(db, "approval.expiry_hours") or 72)
    cutoff = utcnow() - timedelta(hours=hours)
    n = 0
    for ap in db.execute(select(Approval).where(Approval.status == "pending", Approval.kind == "pre", Approval.created_at < cutoff)).scalars().all():
        ap.status, ap.decided_at, ap.decision_comment = "expired", utcnow(), f"No decision within {hours} hours"
        job = db.get(Job, ap.job_id)
        if job and job.status == "pending_approval":
            job.status, job.finished_at, job.summary = "cancelled", utcnow(), "Approval request expired"
            for e in job.executions:
                e.status = "cancelled"
            _notify(db, job.requested_by, f"Approval expired: {job.title}", "The change was not approved in time and has been cancelled.", "warning", f"/jobs/{job.id}")
        audit.record(db, "approval.expire", actor_name="system", target_type="approval", target_id=ap.id, details={"job_id": ap.job_id})
        n += 1
    if n:
        db.commit()
    return n


def schedule_config_backups(db: Session) -> int:
    """Queue read-only configuration backups for network devices and firewalls every N hours (setting backup.config_schedule_hours)."""
    from datetime import timedelta

    from sqlalchemy import func as sfunc

    hours = int(settings_store.value(db, "backup.config_schedule_hours") or 0)
    if hours <= 0:
        return 0
    cutoff = utcnow() - timedelta(hours=hours)
    if db.execute(select(Job).where(Job.title.like("Scheduled configuration backup%"), Job.created_at >= cutoff)).first():
        return 0
    latest = dict(db.execute(select(ConfigBackup.device_id, sfunc.max(ConfigBackup.created_at)).group_by(ConfigBackup.device_id)).all())
    by_op: dict[str, list[int]] = {}
    for d in db.execute(select(Device).where(Device.deleted_at.is_(None))).scalars().all():
        cls = driver_class(d.platform)
        op = {"network": "network.config.backup", "firewall": "firewall.config.backup"}.get(cls.category)
        if not op or op not in cls.operations or not (d.credential_id or d.is_simulated):
            continue
        if latest.get(d.id) and latest[d.id] >= cutoff:
            continue
        by_op.setdefault(op, []).append(d.id)
    for op, ids in by_op.items():
        job = Job(title=f"Scheduled configuration backup ({len(ids)} device(s))", kind="operation", operation_id=op,
                  category=driver_class(db.get(Device, ids[0]).platform).category, params={}, change_summary="Read-only configuration backup",
                  requested_by=None, risk="read", status="queued", queued_at=utcnow(), timeout_seconds=get_settings().default_job_timeout_seconds)
        db.add(job)
        db.flush()
        for i in ids:
            db.add(JobExecution(job_id=job.id, device_id=i, status="pending"))
        audit.record(db, "job.create", actor_name="scheduler", target_type="job", target_id=job.id, target_name=job.title,
                     details={"operation": op, "devices": len(ids)})
    db.commit()
    return sum(len(v) for v in by_op.values())

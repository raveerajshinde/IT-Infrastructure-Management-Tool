"""Operations: interactive read operations, change preview, job submission and tracking, templates."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, true
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, current_user, need, need_global, paging
from app.automation.runner import PLAYBOOKS
from app.core.db import get_db
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.permissions import operation_permission
from app.drivers.linux import APPROVED_COMMANDS
from app.drivers.registry import DRIVERS, driver_class
from app.models import Job, JobExecution, JobTemplate, User
from app.schemas import OperationRunIn, TemplateIn, TemplateRunIn
from app.services import audit, auth, devices, jobs

router = APIRouter(prefix="/api", tags=["operations"])


@router.get("/devices/{device_id}/operations")
def device_operations(device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = devices.get_device(db, device_id)
    auth.require(db, user, "devices:read", d.id)
    cls = driver_class(d.platform)
    return [ser.operation(s, cls.category, auth.has_permission(db, user, operation_permission(cls.category, s.risk), d.id), cls.operations)
            for s in cls.operations.values() if not s.id.endswith(".script.run")]


@router.post("/devices/{device_id}/operations/{operation_id}/read")
def run_read(device_id: int, operation_id: str, request: Request, params: dict | None = None,
             user: User = Depends(current_user), db: Session = Depends(get_db)):
    return jobs.run_inline(db, user, device_id, operation_id, params or {}, client_ip(request))


@router.post("/jobs/preview")
def preview(body: OperationRunIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Explain exactly what a change will do, to which devices, and which approval rules apply - before submission."""
    devs = [devices.get_device(db, i) for i in dict.fromkeys(body.device_ids)]
    specs = {}
    for d in devs:
        cls = driver_class(d.platform)
        try:
            specs[d.platform] = (cls, cls.get_spec(body.operation_id))
        except Exception:
            raise ValidationFailed(f"{cls.display_name} ({d.hostname}) does not support '{body.operation_id}'")
        try:
            cls.validate_params(body.operation_id, body.params)
        except Exception as exc:
            raise ValidationFailed(f"Invalid parameters: {exc}")
    cls, spec = next(iter(specs.values()))
    risk = max((s.risk for _, s in specs.values()), key=lambda r: jobs.RISK_ORDER[r])
    if body.check_mode and not all(s.check_mode for _, s in specs.values()):
        raise ValidationFailed(f"'{spec.title}' does not support dry-run on every selected device")
    dec = jobs.evaluate_policies(db, cls.category, risk, {d.environment for d in devs}) if risk != "read" else jobs.PolicyDecision()
    perm = operation_permission(cls.category, risk)
    need_appr = dec.require_approval and not body.check_mode
    reason = "; ".join(dec.matched) if dec.matched else ""
    if dec.require_window and not body.check_mode:
        reason += ("; " if reason else "") + ("inside a maintenance window now" if jobs.in_maintenance_window(db, devs) else "will wait for the next maintenance window")
    return {"operation": spec.title, "risk": ser.RISK_UI[risk], "mutating": risk != "read", "summary": spec.describe(body.params),
            "approval_required": need_appr, "approval_reason": reason, "requires_window": dec.require_window and not body.check_mode,
            "policies": dec.matched,
            "rollback": "Each device result records before/after state and a rollback instruction." if risk != "read" else "",
            "check_mode_available": all(s.check_mode for _, s in specs.values()),
            "targets": [{"id": d.id, "hostname": d.hostname, "environment": d.environment, "simulated": d.is_simulated,
                         "allowed": auth.has_permission(db, user, perm, d.id)} for d in devs]}


@router.post("/jobs", status_code=201)
def submit_job(body: OperationRunIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = jobs.create_operation_job(db, user, operation_id=body.operation_id, device_ids=body.device_ids, params=body.params,
                                    check_mode=body.check_mode, emergency=body.emergency, reason=body.reason, title=body.title,
                                    ip=client_ip(request))
    return ser.job(db, job, detail=False)


@router.get("/jobs")
def list_jobs(user: User = Depends(current_user), db: Session = Depends(get_db), pg=Depends(paging),
              status: str | None = None, mine: bool = False, device_id: int | None = None):
    q = jobs.visible_jobs_query(db, user)
    if status:
        q = q.where(Job.status.in_(status.split(",")))
    if mine:
        q = q.where(Job.requested_by == user.id)
    if device_id:
        q = q.where(Job.id.in_(select(JobExecution.job_id).where(JobExecution.device_id == device_id)))
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    page, size = pg
    rows = db.execute(q.order_by(Job.id.desc()).offset((page - 1) * size).limit(size)).scalars()
    return {"items": [ser.job(db, j, detail=False) for j in rows], "total": total, "page": page, "page_size": size}


@router.get("/jobs/{job_id}")
def get_job(job_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    j = db.get(Job, job_id)
    if not j:
        raise NotFound("Job not found")
    if j.requested_by != user.id and not any(auth.has_permission(db, user, "automation:read", e.device_id) for e in j.executions):
        raise Forbidden("You do not have access to this job")
    return ser.job(db, j)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return ser.job(db, jobs.cancel(db, user, job_id, client_ip(request)))


# ---------------------------------------------------------------- templates
def _tpl(t: JobTemplate) -> dict:
    return {"id": t.id, "name": t.name, "description": t.description, "kind": "ansible" if t.kind == "playbook" else t.kind,
            "category": t.category, "operation_id": t.operation_id, "playbook": t.playbook, "default_params": t.default_params or {},
            "param_schema": t.param_schema, "risk": ser.RISK_UI.get(t.risk, t.risk), "supports_check_mode": t.supports_check_mode,
            "is_builtin": t.is_builtin, "enabled": t.enabled}


@router.get("/templates")
def list_templates(user: User = Depends(need("automation:read")), db: Session = Depends(get_db)):
    return [_tpl(t) for t in db.execute(select(JobTemplate).where(JobTemplate.enabled == true()).order_by(JobTemplate.category, JobTemplate.name)).scalars()]


@router.get("/playbooks")
def list_playbooks(user: User = Depends(need("automation:read"))):
    return [{"name": k, "playbook": k, "title": v["title"], "description": f"{v['title']} ({v['category']})", "category": v["category"],
             "schema": v["vars"].model_json_schema()} for k, v in PLAYBOOKS.items()]


@router.get("/approved-commands")
def approved_commands(user: User = Depends(need("automation:read"))):
    """Server-side allow-list of maintenance commands (defined in code, changed only through change control)."""
    return [{"id": i + 1, "name": k, "description": v["desc"], "command": " ".join(v["argv"]), "arg_pattern": "", "enabled": True,
             "risk": "low" if v["risk"] == "read" else "medium", "sudo": v["sudo"]} for i, (k, v) in enumerate(APPROVED_COMMANDS.items())]


@router.post("/templates", status_code=201)
def create_template(body: TemplateIn, request: Request, user: User = Depends(need_global("automation:manage")), db: Session = Depends(get_db)):
    if db.execute(select(JobTemplate).where(JobTemplate.name == body.name)).first():
        raise ValidationFailed("A template with this name already exists")
    if body.kind == "operation":
        specs = [(c, c.operations[body.operation_id]) for c in DRIVERS.values() if body.operation_id in c.operations]
        if not specs:
            raise ValidationFailed(f"No driver provides operation '{body.operation_id}'")
        cls, spec = specs[0]
        category, risk, cm, schema = cls.category, spec.risk, spec.check_mode, spec.params.model_json_schema()
    else:
        meta = PLAYBOOKS.get(body.playbook or "")
        if not meta:
            raise ValidationFailed("Playbook is not in the approved catalogue")
        category, risk, cm, schema = meta["category"], "change", True, meta["vars"].model_json_schema()
    t = JobTemplate(name=body.name, description=body.description, kind=body.kind, category=category,
                    operation_id=body.operation_id if body.kind == "operation" else None,
                    playbook=body.playbook if body.kind == "playbook" else None, default_params=body.default_params, enabled=body.enabled,
                    risk=risk, supports_check_mode=cm, param_schema=schema)
    db.add(t)
    db.flush()
    audit.record(db, "template.create", actor=user, target_type="template", target_id=t.id, target_name=t.name, ip=client_ip(request),
                 details={"kind": t.kind, "operation": t.operation_id, "playbook": t.playbook, "defaults": t.default_params})
    db.commit()
    return _tpl(t)


@router.delete("/templates/{tid}")
def delete_template(tid: int, request: Request, user: User = Depends(need_global("automation:manage")), db: Session = Depends(get_db)):
    t = db.get(JobTemplate, tid)
    if not t:
        raise NotFound("Template not found")
    if t.is_builtin:
        raise Forbidden("Built-in templates cannot be deleted")
    t.enabled = False  # retained for job-history references
    audit.record(db, "template.delete", actor=user, target_type="template", target_id=t.id, target_name=t.name, ip=client_ip(request))
    db.commit()
    return {"message": "Template removed"}


@router.post("/templates/{tid}/run", status_code=201)
def run_template(tid: int, body: TemplateRunIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = db.get(JobTemplate, tid)
    if not t or not t.enabled:
        raise NotFound("Template not found or disabled")
    if t.kind == "operation":
        job = jobs.create_operation_job(db, user, operation_id=t.operation_id, device_ids=body.device_ids,
                                        params={**(t.default_params or {}), **body.params}, check_mode=body.check_mode,
                                        emergency=body.emergency, reason=body.reason, title=t.name, template=t, ip=client_ip(request))
    else:
        job = jobs.create_playbook_job(db, user, t, body.device_ids, body.params, body.check_mode, body.emergency, body.reason, client_ip(request))
    return ser.job(db, job, detail=False)

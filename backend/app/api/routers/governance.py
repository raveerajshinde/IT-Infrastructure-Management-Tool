"""Approvals, approval policies, maintenance windows and the audit log."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import AliasChoices, BaseModel, Field
from sqlalchemy import func, select, true
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, current_user, need, need_global, paging
from app.core.db import get_db
from app.core.errors import NotFound, ValidationFailed
from app.models import Approval, ApprovalPolicy, AuditLog, DeviceGroup, Job, MaintenanceWindow, User
from app.schemas import ApprovalPolicyIn
from app.services import audit, auth, import_export, jobs

router = APIRouter(prefix="/api", tags=["governance"])


def _naive_utc(v: datetime) -> datetime:
    return v.astimezone(timezone.utc).replace(tzinfo=None) if v.tzinfo else v


# ---------------------------------------------------------------- approvals
@router.get("/approvals")
def list_approvals(status: str = "pending,post_review", user: User = Depends(need("approvals:read")), db: Session = Depends(get_db), pg=Depends(paging)):
    wanted = {s for s in status.split(",") if s}
    rows = list(db.execute(select(Approval).order_by(Approval.id.desc()).limit(1000)).scalars())
    items = [a for a in rows if not wanted or ser.approval_status(a) in wanted]
    page, size = pg
    out = []
    for a in items[(page - 1) * size: page * size]:
        o = ser.approval(db, a)
        j = db.get(Job, a.job_id)
        o["can_decide"] = (a.status == "pending" and a.requested_by != user.id
                           and all(auth.has_permission(db, user, "approvals:decide", e.device_id) for e in j.executions))
        out.append(o)
    return {"items": out, "total": len(items), "page": page, "page_size": size}


class DecisionIn(BaseModel):
    approve: bool
    note: str = Field("", max_length=2000, validation_alias=AliasChoices("note", "comment"))


@router.post("/approvals/{aid}/decide")
@router.post("/approvals/{aid}/decision")
def decide(aid: int, body: DecisionIn, request: Request, user: User = Depends(need("approvals:decide")), db: Session = Depends(get_db)):
    if not body.approve and len(body.note.strip()) < 3:
        raise ValidationFailed("Please give a reason when rejecting or flagging a change")
    a = jobs.decide(db, user, aid, body.approve, body.note, client_ip(request))
    return ser.approval(db, a)


@router.get("/approval-policies")
def list_policies(user: User = Depends(need("approvals:read")), db: Session = Depends(get_db)):
    return [{c.name: getattr(p, c.name) for c in ApprovalPolicy.__table__.columns} for p in db.execute(select(ApprovalPolicy)).scalars()]


@router.post("/approval-policies", status_code=201)
def create_policy(body: ApprovalPolicyIn, request: Request, user: User = Depends(need_global("approvals:manage")), db: Session = Depends(get_db)):
    p = ApprovalPolicy(**body.model_dump())
    db.add(p)
    db.flush()
    audit.record(db, "policy.create", actor=user, target_type="approval_policy", target_id=p.id, target_name=p.name, ip=client_ip(request), details=body.model_dump())
    db.commit()
    return {"id": p.id}


@router.put("/approval-policies/{pid}")
def update_policy(pid: int, body: ApprovalPolicyIn, request: Request, user: User = Depends(need_global("approvals:manage")), db: Session = Depends(get_db)):
    p = db.get(ApprovalPolicy, pid)
    if not p:
        raise NotFound("Policy not found")
    before = {c.name: getattr(p, c.name) for c in ApprovalPolicy.__table__.columns}
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    audit.record(db, "policy.update", actor=user, target_type="approval_policy", target_id=p.id, target_name=p.name, ip=client_ip(request),
                 details={"before": before, "after": body.model_dump()})
    db.commit()
    return {"id": p.id}


@router.delete("/approval-policies/{pid}", status_code=204)
def delete_policy(pid: int, request: Request, user: User = Depends(need_global("approvals:manage")), db: Session = Depends(get_db)):
    p = db.get(ApprovalPolicy, pid)
    if not p:
        raise NotFound("Policy not found")
    remaining = db.execute(select(func.count()).select_from(ApprovalPolicy).where(ApprovalPolicy.id != p.id, ApprovalPolicy.enabled == true(),
                                                                                   ApprovalPolicy.require_approval == true(),
                                                                                   ApprovalPolicy.risk == "critical")).scalar()
    if p.enabled and p.require_approval and p.risk == "critical" and not remaining:
        raise ValidationFailed("This is the last policy requiring approval for critical changes; disable it explicitly instead of deleting it")
    audit.record(db, "policy.delete", actor=user, target_type="approval_policy", target_id=p.id, target_name=p.name, ip=client_ip(request),
                 details={c.name: getattr(p, c.name) for c in ApprovalPolicy.__table__.columns})
    db.delete(p)
    db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------- maintenance windows
class WindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    starts_at: datetime = Field(validation_alias=AliasChoices("starts_at", "start_at"))
    ends_at: datetime = Field(validation_alias=AliasChoices("ends_at", "end_at"))
    group_id: int | None = Field(None, validation_alias=AliasChoices("group_id", "device_group_id"))
    environment: str | None = Field(None, max_length=20)
    auto_approve_medium: bool = False


def _win(w: MaintenanceWindow) -> dict:
    return {"id": w.id, "name": w.name, "starts_at": ser.iso(w.start_at), "ends_at": ser.iso(w.end_at), "group_id": w.device_group_id,
            "environment": w.environment, "auto_approve_medium": w.auto_approve_change}


@router.get("/maintenance-windows")
def list_windows(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [_win(w) for w in db.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.start_at.desc()).limit(200)).scalars()]


@router.post("/maintenance-windows", status_code=201)
def create_window(body: WindowIn, request: Request, user: User = Depends(need_global("approvals:manage")), db: Session = Depends(get_db)):
    start, end = _naive_utc(body.starts_at), _naive_utc(body.ends_at)
    if end <= start:
        raise ValidationFailed("The window must end after it starts")
    if (end - start).days > 14:
        raise ValidationFailed("Maintenance windows are limited to 14 days")
    if body.group_id and not db.get(DeviceGroup, body.group_id):
        raise ValidationFailed("Device group does not exist")
    w = MaintenanceWindow(name=body.name, start_at=start, end_at=end, device_group_id=body.group_id, environment=body.environment,
                          auto_approve_change=body.auto_approve_medium, created_by=user.id)
    db.add(w)
    db.flush()
    audit.record(db, "maintenance_window.create", actor=user, target_type="maintenance_window", target_id=w.id, target_name=w.name,
                 ip=client_ip(request), details=_win(w))
    db.commit()
    return _win(w)


@router.delete("/maintenance-windows/{wid}")
def delete_window(wid: int, request: Request, user: User = Depends(need_global("approvals:manage")), db: Session = Depends(get_db)):
    w = db.get(MaintenanceWindow, wid)
    if not w:
        raise NotFound("Window not found")
    details = _win(w)
    db.delete(w)
    audit.record(db, "maintenance_window.delete", actor=user, target_type="maintenance_window", target_id=wid, target_name=details["name"],
                 ip=client_ip(request), details=details)
    db.commit()
    return {"message": "Window deleted"}


# ---------------------------------------------------------------- audit
def _audit_query(action, actor, target_type, device_id, result, since, until):
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    if actor:
        q = q.where(AuditLog.actor_name.like(f"%{actor}%"))
    if target_type:
        q = q.where(AuditLog.target_type == target_type)
    if device_id:
        q = q.where(AuditLog.device_id == device_id)
    if result:
        q = q.where(AuditLog.result == result)
    if since:
        q = q.where(AuditLog.ts >= _naive_utc(since))
    if until:
        q = q.where(AuditLog.ts <= _naive_utc(until))
    return q


def _row(a: AuditLog) -> dict:
    return {"id": a.id, "ts": ser.iso(a.ts), "actor": a.actor_name, "action": a.action, "target_type": a.target_type, "target_id": a.target_id,
            "target_name": a.target_name, "device_id": a.device_id, "result": a.result, "ip": a.ip_address, "details": a.details,
            "row_hash": a.hash, "prev_hash": a.prev_hash}


@router.get("/audit")
def list_audit(user: User = Depends(need_global("audit:read")), db: Session = Depends(get_db), pg=Depends(paging),
               action: str | None = None, actor: str | None = None, target_type: str | None = None, device_id: int | None = None,
               result: str | None = None, since: datetime | None = None, until: datetime | None = None):
    q = _audit_query(action, actor, target_type, device_id, result, since, until)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    page, size = pg
    rows = db.execute(q.order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(size)).scalars()
    return {"items": [_row(a) for a in rows], "total": total, "page": page, "page_size": size}


@router.get("/audit/verify")
def verify_audit(request: Request, user: User = Depends(need_global("audit:read")), db: Session = Depends(get_db)):
    res = audit.verify_chain(db)
    res["message"] = (f"Hash chain intact: {res['checked']} records verified" if res["valid"]
                      else f"Integrity failure at record #{res['broken_at']}: {res['reason']}")
    audit.record(db, "audit.verify", actor=user, ip=client_ip(request), result="success" if res["valid"] else "failure", details=res)
    db.commit()
    return res


@router.get("/audit/export")
def export_audit(request: Request, fmt: str = Query("csv", pattern="^(csv|xlsx)$"), user: User = Depends(need_global("audit:export")),
                 db: Session = Depends(get_db), action: str | None = None, actor: str | None = None, target_type: str | None = None,
                 device_id: int | None = None, result: str | None = None, since: datetime | None = None, until: datetime | None = None):
    q = _audit_query(action, actor, target_type, device_id, result, since, until).order_by(AuditLog.id).limit(200_000)
    rows = [["id", "timestamp_utc", "actor", "action", "target_type", "target_id", "target_name", "device_id", "result", "ip", "details", "hash", "prev_hash"]]
    for a in db.execute(q).scalars().all():
        rows.append([a.id, a.ts.isoformat() + "Z", a.actor_name, a.action, a.target_type, a.target_id, a.target_name, a.device_id or "",
                     a.result, a.ip_address or "", json.dumps(a.details, default=str), a.hash, a.prev_hash])
    audit.record(db, "audit.export", actor=user, ip=client_ip(request), details={"rows": len(rows) - 1, "format": fmt})
    db.commit()
    if fmt == "xlsx":
        return Response(import_export.to_xlsx(rows, "Audit"), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": 'attachment; filename="infrapilot-audit.xlsx"'})
    return Response(import_export.to_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="infrapilot-audit.csv"'})

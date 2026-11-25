"""Script library: reviewed PowerShell / shell / switch CLI / FortiGate CLI scripts and their runs."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need, need_global
from app.core.db import get_db
from app.core.errors import ValidationFailed
from app.drivers.base import render_cli
from app.drivers.registry import driver_class
from app.models import Job, Script, User
from app.services import auth, devices, scripts

router = APIRouter(prefix="/api", tags=["scripts"])


class ParamDef(BaseModel):
    name: str = Field(max_length=31)
    label: str = Field("", max_length=80)
    type: str = "string"
    required: bool = True
    default: Any = None
    choices: list[str] = Field(default_factory=list, max_length=50)
    max_length: int = 200
    help: str = Field("", max_length=200)


class ScriptIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str = Field("", max_length=1000)
    target: Literal["windows", "linux", "network", "fortigate"]
    mode: Literal["read", "change"] = "change"
    risk: Literal["read", "change", "critical"] = "change"
    body: str = Field(min_length=1, max_length=65536)
    params: list[ParamDef] = Field(default_factory=list, max_length=30)
    run_as_root: bool = False
    save_config: bool = False
    timeout_seconds: int = Field(300, ge=10, le=3600)


class ScriptUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=150)
    description: str | None = Field(None, max_length=1000)
    target: Literal["windows", "linux", "network", "fortigate"] | None = None
    mode: Literal["read", "change"] | None = None
    risk: Literal["read", "change", "critical"] | None = None
    body: str | None = Field(None, min_length=1, max_length=65536)
    params: list[ParamDef] | None = None
    run_as_root: bool | None = None
    save_config: bool | None = None
    timeout_seconds: int | None = Field(None, ge=10, le=3600)


class ReviewIn(BaseModel):
    approve: bool
    comment: str = Field("", max_length=1000)


class RunIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=500)
    values: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field("", max_length=2000)
    check_mode: bool = False
    emergency: bool = False


class PreviewIn(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


def _ser(db: Session, s: Script, user: User) -> dict:
    names = {u.id: u.username for u in db.execute(select(User).where(User.id.in_({s.created_by, s.updated_by, s.approved_by or -1}))).scalars()}
    t = scripts.TARGETS[s.target]
    return {"id": s.id, "name": s.name, "description": s.description, "target": s.target, "target_label": t["label"], "category": t["category"],
            "mode": s.mode, "risk": s.risk, "risk_ui": ser.RISK_UI.get(s.risk, s.risk), "body": s.body, "params": s.params,
            "run_as_root": s.run_as_root, "save_config": s.save_config, "timeout_seconds": s.timeout_seconds, "version": s.version,
            "sha256": s.sha256, "status": s.status, "runnable": scripts.runnable(s), "review_comment": s.review_comment,
            "created_by": names.get(s.created_by), "updated_by": names.get(s.updated_by), "approved_by": names.get(s.approved_by),
            "approved_at": ser.iso(s.approved_at), "created_at": ser.iso(s.created_at), "updated_at": ser.iso(s.updated_at),
            "can_review": s.updated_by != user.id and auth.has_any_scope(db, user, "scripts:approve") and s.status in ("pending", "rejected", "approved")}


@router.get("/scripts")
def list_scripts(user: User = Depends(need("scripts:read")), db: Session = Depends(get_db)):
    return [_ser(db, s, user) for s in db.execute(select(Script).order_by(Script.name)).scalars().all()]


@router.get("/scripts/meta")
def scripts_meta(user: User = Depends(need("scripts:read"))):
    return {"targets": [{"id": k, **v} for k, v in scripts.TARGETS.items()], "param_types": sorted(scripts.PARAM_TYPES)}


@router.get("/scripts/{sid}")
def get_script(sid: int, user: User = Depends(need("scripts:read")), db: Session = Depends(get_db)):
    return _ser(db, scripts.get(db, sid), user)


@router.post("/scripts", status_code=201)
def create_script(body: ScriptIn, request: Request, user: User = Depends(need_global("scripts:manage")), db: Session = Depends(get_db)):
    return _ser(db, scripts.create(db, user, body.model_dump(), client_ip(request)), user)


@router.put("/scripts/{sid}")
def update_script(sid: int, body: ScriptUpdate, request: Request, user: User = Depends(need_global("scripts:manage")), db: Session = Depends(get_db)):
    return _ser(db, scripts.update(db, user, sid, body.model_dump(exclude_unset=True), client_ip(request)), user)


@router.post("/scripts/{sid}/review")
def review_script(sid: int, body: ReviewIn, request: Request, user: User = Depends(need_global("scripts:approve")), db: Session = Depends(get_db)):
    return _ser(db, scripts.review(db, user, sid, body.approve, body.comment, client_ip(request)), user)


@router.post("/scripts/{sid}/retire")
def retire_script(sid: int, request: Request, user: User = Depends(need_global("scripts:manage")), db: Session = Depends(get_db)):
    return _ser(db, scripts.retire(db, user, sid, client_ip(request)), user)


@router.post("/scripts/{sid}/preview")
def preview_script(sid: int, body: PreviewIn, user: User = Depends(need("scripts:read")), db: Session = Depends(get_db)):
    """Validate values and show exactly what would run (CLI lines rendered; PowerShell/shell with bound values)."""
    s = scripts.get(db, sid)
    vals = scripts.validate_values(s, body.values)
    if s.target in ("network", "fortigate"):
        rendered = "\n".join(render_cli(s.body, vals))
    else:
        bound = "\n".join(f"{'$' if s.target == 'windows' else ''}{k} = {v!r}" for k, v in vals.items())
        rendered = (f"# parameters\n{bound}\n\n" if bound else "") + s.body
    return {"values": vals, "rendered": rendered}


@router.post("/scripts/{sid}/run", status_code=201)
def run_script(sid: int, body: RunIn, request: Request, user: User = Depends(need("automation:run")), db: Session = Depends(get_db)):
    s = scripts.get(db, sid)
    want = scripts.TARGETS[s.target]["category"]
    for i in body.device_ids:
        d = devices.get_device(db, i)
        cls = driver_class(d.platform)
        if cls.category != want or scripts.TARGETS[s.target]["operation"] not in cls.operations:
            raise ValidationFailed(f"{d.hostname} ({cls.display_name}) cannot run a {scripts.TARGETS[s.target]['label']} script")
    job = scripts.create_run(db, user, sid, body.device_ids, body.values, body.reason, body.check_mode, body.emergency, client_ip(request))
    return ser.job(db, job, detail=False)


@router.get("/scripts/{sid}/runs")
def script_runs(sid: int, user: User = Depends(need("scripts:read")), db: Session = Depends(get_db)):
    s = scripts.get(db, sid)
    q = select(Job).where(Job.operation_id == scripts.TARGETS[s.target]["operation"]).order_by(Job.id.desc()).limit(200)
    rows = [j for j in db.execute(q).scalars() if (j.params or {}).get("script_id") == s.id][:50]
    return [ser.job(db, j, detail=False) for j in rows]

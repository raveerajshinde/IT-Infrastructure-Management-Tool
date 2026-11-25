"""IT audit and compliance: frameworks, assessments, control results, findings lifecycle and evidence repository."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need, paging
from app.core.db import get_db
from app.core.errors import NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.models import Assessment, AssessmentResult, ComplianceControl, ComplianceFramework, Evidence, Finding, FindingEvent, User
from app.services import audit, reporting, settings_store
from app.services.compliance import checks, service as svc

router = APIRouter(prefix="/api/compliance", tags=["it audit"])


def _uname(db: Session, uid: int | None) -> str | None:
    u = db.get(User, uid) if uid else None
    return u.username if u else None


# ---------------------------------------------------------------- frameworks
@router.get("/frameworks")
def frameworks(user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    n = dict(db.execute(select(ComplianceControl.framework_id, func.count()).group_by(ComplianceControl.framework_id)).all())
    auto = {}
    for c in db.execute(select(ComplianceControl)).scalars().all():
        if c.check_keys:
            auto[c.framework_id] = auto.get(c.framework_id, 0) + 1
    return [{"id": f.id, "code": f.code, "name": f.name, "version": f.version, "description": f.description, "builtin": f.is_builtin, "enabled": f.enabled,
             "controls": n.get(f.id, 0), "automated_controls": auto.get(f.id, 0)} for f in db.execute(select(ComplianceFramework).order_by(ComplianceFramework.id)).scalars().all()]


class FrameworkIn(BaseModel):
    code: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=3, max_length=200)
    version: str = Field("", max_length=40)
    description: str = Field("", max_length=2000)


@router.post("/frameworks", status_code=201)
def create_framework(body: FrameworkIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    if db.execute(select(ComplianceFramework).where(ComplianceFramework.code == body.code)).first():
        raise ValidationFailed("A framework with this code exists")
    f = ComplianceFramework(**body.model_dump(), is_builtin=False)
    db.add(f)
    db.flush()
    audit.record(db, "compliance.framework_create", actor=user, target_type="framework", target_id=f.id, target_name=f.name, ip=client_ip(request))
    db.commit()
    return {"id": f.id}


@router.get("/frameworks/{fid}/controls")
def controls(fid: int, user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    return [{"id": c.id, "ref": c.ref, "title": c.title, "description": c.description, "domain": c.domain, "checks": c.check_keys or [],
             "check_titles": [checks.CHECKS[k][0] for k in c.check_keys or [] if k in checks.CHECKS], "guidance": c.guidance}
            for c in db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == fid).order_by(ComplianceControl.sort, ComplianceControl.id)).scalars().all()]


class ControlIn(BaseModel):
    ref: str = Field(min_length=1, max_length=40)
    title: str = Field(min_length=3, max_length=400)
    description: str = Field("", max_length=4000)
    domain: str = Field("", max_length=150)
    checks: list[str] = Field(default_factory=list, max_length=10)
    guidance: str = Field("", max_length=2000)


@router.post("/frameworks/{fid}/controls", status_code=201)
def add_control(fid: int, body: ControlIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    if db.get(ComplianceFramework, fid) is None:
        raise NotFound("Framework not found")
    bad = [k for k in body.checks if k not in checks.CHECKS]
    if bad:
        raise ValidationFailed(f"Unknown automated check(s): {', '.join(bad)}")
    if db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == fid, ComplianceControl.ref == body.ref)).first():
        raise ValidationFailed("A control with this reference exists in the framework")
    n = db.execute(select(func.count()).select_from(ComplianceControl).where(ComplianceControl.framework_id == fid)).scalar()
    c = ComplianceControl(framework_id=fid, ref=body.ref, title=body.title, description=body.description, domain=body.domain, check_keys=body.checks,
                          guidance=body.guidance, sort=1000 + n)
    db.add(c)
    db.flush()
    audit.record(db, "compliance.control_create", actor=user, target_type="control", target_id=c.id, target_name=f"{c.ref} {c.title}", ip=client_ip(request))
    db.commit()
    return {"id": c.id}


@router.get("/checks")
def list_checks(user: User = Depends(need("compliance:read"))):
    return [{"key": k, "title": t} for k, (t, _) in checks.CHECKS.items()]


@router.get("/checks/preview")
def preview_checks(user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    """Run every automated check now (no assessment is created) - used by the audit dashboard."""
    res = checks.run(db, list(checks.CHECKS))
    return [{"key": k, "title": checks.CHECKS[k][0], "status": r.status, "summary": r.summary, "findings": len(r.findings)} for k, r in res.items()]


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    fws = {f.id: f for f in db.execute(select(ComplianceFramework)).scalars().all()}
    latest = {}
    for a in db.execute(select(Assessment).order_by(Assessment.id.desc()).limit(200)).scalars().all():
        latest.setdefault(a.framework_id, a)
    now = utcnow()
    open_q = select(Finding).where(Finding.status.not_in(["closed", "accepted_risk"]))
    open_f = db.execute(open_q).scalars().all()
    return {"frameworks": [{"framework": fws[fid].name, "code": fws[fid].code, "assessment_id": a.id, "title": a.title, "status": a.status,
                            "date": ser.iso(a.created_at), **(a.summary or svc.summary(db, a))} for fid, a in latest.items() if fid in fws],
            "open_findings": len(open_f), "overdue": sum(1 for f in open_f if f.due_date and f.due_date < now),
            "by_severity": {s: sum(1 for f in open_f if f.severity == s) for s in svc.SEVERITIES},
            "by_status": dict(db.execute(select(Finding.status, func.count()).group_by(Finding.status)).all()),
            "evidence": db.execute(select(func.count()).select_from(Evidence)).scalar()}


# ---------------------------------------------------------------- assessments
class AssessmentIn(BaseModel):
    framework_id: int
    title: str = Field(min_length=3, max_length=300)
    period_start: datetime | None = None
    period_end: datetime | None = None
    scope: dict = Field(default_factory=dict)
    run_checks: bool = True


def _ser_assessment(db: Session, a: Assessment) -> dict:
    fw = db.get(ComplianceFramework, a.framework_id)
    return {"id": a.id, "title": a.title, "framework_id": a.framework_id, "framework": fw.name if fw else "", "framework_code": fw.code if fw else "",
            "period_start": ser.iso(a.period_start), "period_end": ser.iso(a.period_end), "scope": a.scope or {}, "status": a.status,
            "summary": a.summary or {}, "executive_summary": a.executive_summary, "created_by": _uname(db, a.created_by), "created_by_id": a.created_by,
            "created_at": ser.iso(a.created_at), "submitted_at": ser.iso(a.submitted_at), "approved_by": _uname(db, a.approved_by),
            "approved_at": ser.iso(a.approved_at), "approval_comment": a.approval_comment}


@router.get("/assessments")
def list_assessments(user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    return [_ser_assessment(db, a) for a in db.execute(select(Assessment).order_by(Assessment.id.desc()).limit(500)).scalars().all()]


@router.post("/assessments", status_code=201)
def create_assessment(body: AssessmentIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    if body.period_start and body.period_end and body.period_start > body.period_end:
        raise ValidationFailed("The period start must be before its end")
    allowed = {"description", "site_ids", "group_ids", "ad_domain_ids", "gpo_domains"}
    if set(body.scope) - allowed:
        raise ValidationFailed(f"Unknown scope keys: {', '.join(sorted(set(body.scope) - allowed))}")
    a = svc.create_assessment(db, user, framework_id=body.framework_id, title=body.title, period_start=body.period_start, period_end=body.period_end,
                              scope=body.scope, run_checks=body.run_checks, ip=client_ip(request))
    db.commit()
    return _ser_assessment(db, a)


@router.get("/assessments/{aid}")
def get_assessment(aid: int, user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    a = svc.get_assessment(db, aid)
    rows = db.execute(select(AssessmentResult, ComplianceControl).join(ComplianceControl, ComplianceControl.id == AssessmentResult.control_id)
                      .where(AssessmentResult.assessment_id == a.id).order_by(ComplianceControl.sort, ComplianceControl.id)).all()
    return {**_ser_assessment(db, a), "summary": svc.summary(db, a), "results": [
        {"control_id": c.id, "ref": c.ref, "title": c.title, "domain": c.domain, "description": c.description, "checks": c.check_keys or [],
         "status": r.status, "source": r.source, "evidence_summary": r.evidence_summary, "evidence": r.evidence or [], "assessed_at": ser.iso(r.assessed_at),
         "assessed_by": _uname(db, r.assessed_by), "auditor_notes": r.auditor_notes} for r, c in rows]}


class AssessmentEdit(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=300)
    executive_summary: str | None = Field(None, max_length=20000)
    period_start: datetime | None = None
    period_end: datetime | None = None


@router.put("/assessments/{aid}")
def edit_assessment(aid: int, body: AssessmentEdit, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    a = svc.get_assessment(db, aid)
    svc._editable(a)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    audit.record(db, "compliance.assessment_edit", actor=user, target_type="assessment", target_id=a.id, target_name=a.title, ip=client_ip(request),
                 details={"fields": list(body.model_dump(exclude_unset=True))})
    db.commit()
    return _ser_assessment(db, a)


@router.post("/assessments/{aid}/run")
def rerun(aid: int, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    r = svc.run_automated(db, svc.get_assessment(db, aid), user, ip=client_ip(request))
    db.commit()
    return r


class StatusIn(BaseModel):
    to: Literal["draft", "in_review", "approved"]
    comment: str = Field("", max_length=2000)


@router.post("/assessments/{aid}/status")
def assessment_status(aid: int, body: StatusIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    a = svc.transition(db, user, svc.get_assessment(db, aid), body.to, body.comment, ip=client_ip(request))
    db.commit()
    return _ser_assessment(db, a)


class ResultIn(BaseModel):
    status: Literal["compliant", "partial", "non_compliant", "not_assessed", "not_applicable"]
    auditor_notes: str = Field("", max_length=8000)
    evidence_summary: str | None = Field(None, max_length=20000)
    evidence_ids: list[int] = Field(default_factory=list, max_length=50)


@router.put("/assessments/{aid}/results/{control_id}")
def set_result(aid: int, control_id: int, body: ResultIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    svc.record_result(db, user, svc.get_assessment(db, aid), control_id, status=body.status, auditor_notes=body.auditor_notes,
                      evidence_summary=body.evidence_summary, evidence_ids=body.evidence_ids, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.get("/assessments/{aid}/report")
def assessment_report(aid: int, request: Request, format: Literal["pdf", "xlsx", "csv", "html"] = "pdf", inline: bool = False,
                      user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    a = svc.get_assessment(db, aid)
    doc = svc.report_doc(db, a, organisation=settings_store.value(db, "ui.organization_name") or "")
    return reporting.export(db, key="audit", doc=doc, fmt=format, params={"assessment_id": a.id, "inline": inline}, user=user, ip=client_ip(request))


# ---------------------------------------------------------------- findings
def _ser_finding(db: Session, f: Finding, detail: bool = False) -> dict:
    out = {"id": f.id, "assessment_id": f.assessment_id, "control_id": f.control_id, "title": f.title, "description": f.description, "severity": f.severity,
           "status": f.status, "source": f.source, "asset": f.asset, "root_cause": f.root_cause, "business_impact": f.business_impact,
           "recommendation": f.recommendation, "owner_department": f.owner_department, "owner_user_id": f.owner_user_id, "owner": _uname(db, f.owner_user_id),
           "due_date": ser.iso(f.due_date), "overdue": bool(f.due_date and f.due_date < utcnow() and f.status not in ("closed", "accepted_risk")),
           "risk_acceptance": f.risk_acceptance or {}, "created_by": _uname(db, f.created_by), "created_at": ser.iso(f.created_at),
           "updated_at": ser.iso(f.updated_at), "closed_at": ser.iso(f.closed_at)}
    c = db.get(ComplianceControl, f.control_id) if f.control_id else None
    out["control_ref"] = c.ref if c else None
    if detail:
        out["events"] = [{"ts": ser.iso(e.ts), "user": _uname(db, e.user_id), "from": e.from_status, "to": e.to_status, "comment": e.comment}
                         for e in db.execute(select(FindingEvent).where(FindingEvent.finding_id == f.id).order_by(FindingEvent.id)).scalars().all()]
        out["evidence"] = [_ser_evidence(db, e) for e in db.execute(select(Evidence).where(Evidence.finding_id == f.id)).scalars().all()]
        out["allowed_transitions"] = sorted(svc.TRANSITIONS[f.status])
    return out


@router.get("/findings")
def list_findings(status: str | None = None, severity: str | None = None, assessment_id: int | None = None, overdue: bool = False, mine: bool = False,
                  q: str | None = Query(None, max_length=100), user: User = Depends(need("compliance:read")), db: Session = Depends(get_db), pg=Depends(paging)):
    stmt = select(Finding)
    if status:
        stmt = stmt.where(Finding.status.in_(status.split(",")))
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity.split(",")))
    if assessment_id:
        stmt = stmt.where(Finding.assessment_id == assessment_id)
    if overdue:
        stmt = stmt.where(Finding.due_date < utcnow(), Finding.status.not_in(["closed", "accepted_risk"]))
    if mine:
        stmt = stmt.where(Finding.owner_user_id == user.id)
    if q:
        stmt = stmt.where(Finding.title.like(f"%{q}%") | Finding.asset.like(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    page, size = pg
    rows = db.execute(stmt.order_by(Finding.id.desc()).offset((page - 1) * size).limit(size)).scalars().all()
    rows.sort(key=lambda f: (svc.SEVERITIES.index(f.severity) if f.severity in svc.SEVERITIES else 9, -f.id))
    return {"items": [_ser_finding(db, f) for f in rows], "total": total, "page": page, "page_size": size}


class FindingIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field("", max_length=20000)
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    asset: str = Field("", max_length=300)
    root_cause: str = Field("", max_length=8000)
    business_impact: str = Field("", max_length=8000)
    recommendation: str = Field("", max_length=8000)
    owner_department: str = Field("", max_length=150)
    owner_user_id: int | None = None
    due_date: datetime | None = None
    assessment_id: int | None = None
    control_id: int | None = None


@router.post("/findings", status_code=201)
def create_finding(body: FindingIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    f = svc.create_finding(db, user, body.model_dump(), ip=client_ip(request))
    db.commit()
    return _ser_finding(db, f, detail=True)


@router.get("/findings/{fid}")
def get_finding(fid: int, user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    return _ser_finding(db, svc.get_finding(db, fid), detail=True)


class FindingEdit(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=300)
    description: str | None = Field(None, max_length=20000)
    severity: Literal["critical", "high", "medium", "low", "informational"] | None = None
    asset: str | None = Field(None, max_length=300)
    root_cause: str | None = Field(None, max_length=8000)
    business_impact: str | None = Field(None, max_length=8000)
    recommendation: str | None = Field(None, max_length=8000)
    owner_department: str | None = Field(None, max_length=150)
    owner_user_id: int | None = None
    due_date: datetime | None = None


@router.put("/findings/{fid}")
def edit_finding(fid: int, body: FindingEdit, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    f = svc.update_finding(db, user, svc.get_finding(db, fid), body.model_dump(exclude_unset=True), ip=client_ip(request))
    db.commit()
    return _ser_finding(db, f, detail=True)


class MoveIn(BaseModel):
    to: Literal["open", "assigned", "in_progress", "pending_verification", "closed", "accepted_risk"]
    comment: str = Field("", max_length=2000)
    accepted_until: datetime | None = None


@router.post("/findings/{fid}/status")
def move_finding(fid: int, body: MoveIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    f = svc.move_finding(db, user, svc.get_finding(db, fid), body.to, body.comment, accepted_until=body.accepted_until, ip=client_ip(request))
    db.commit()
    return _ser_finding(db, f, detail=True)


# ---------------------------------------------------------------- evidence
def _ser_evidence(db: Session, e: Evidence) -> dict:
    return {"id": e.id, "title": e.title, "description": e.description, "filename": e.filename, "content_type": e.content_type, "size": e.size,
            "sha256": e.sha256, "source": e.source, "assessment_id": e.assessment_id, "finding_id": e.finding_id, "control_ref": e.control_ref,
            "uploaded_by": _uname(db, e.uploaded_by) or "system", "uploaded_at": ser.iso(e.uploaded_at), "withdrawn_at": ser.iso(e.withdrawn_at),
            "withdrawn_reason": e.withdrawn_reason}


@router.get("/evidence")
def list_evidence(assessment_id: int | None = None, finding_id: int | None = None, user: User = Depends(need("compliance:read")),
                  db: Session = Depends(get_db), pg=Depends(paging)):
    stmt = select(Evidence)
    if assessment_id:
        stmt = stmt.where(Evidence.assessment_id == assessment_id)
    if finding_id:
        stmt = stmt.where(Evidence.finding_id == finding_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    page, size = pg
    # never load file contents for the list
    rows = db.execute(stmt.with_only_columns(Evidence.id).order_by(Evidence.id.desc()).offset((page - 1) * size).limit(size)).scalars().all()
    return {"items": [_ser_evidence(db, db.get(Evidence, i)) for i in rows], "total": total, "page": page, "page_size": size}


@router.post("/evidence", status_code=201)
async def upload_evidence(request: Request, file: UploadFile = File(...), title: str = Form(""), description: str = Form(""),
                          assessment_id: int | None = Form(None), finding_id: int | None = Form(None), control_ref: str | None = Form(None),
                          user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    data = await file.read(svc.EVIDENCE_MAX + 1)
    e = svc.upload_evidence(db, user, title=title, filename=file.filename or "evidence", content=data, description=description,
                            assessment_id=assessment_id, finding_id=finding_id, control_ref=control_ref)
    db.commit()
    return _ser_evidence(db, e)


@router.get("/evidence/{eid}/download")
def download_evidence(eid: int, request: Request, user: User = Depends(need("compliance:read")), db: Session = Depends(get_db)):
    e = db.get(Evidence, eid)
    if e is None:
        raise NotFound("Evidence not found")
    ok = svc.verify_evidence(e)
    audit.record(db, "compliance.evidence_download", actor=user, target_type="evidence", target_id=e.id, target_name=e.title, ip=client_ip(request),
                 result="success" if ok else "failure", details={"integrity": "verified" if ok else "FAILED", "sha256": e.sha256})
    db.commit()
    if not ok:
        raise ValidationFailed("Integrity check FAILED: the stored file no longer matches the SHA-256 recorded at upload. The event has been audited.")
    safe = "".join(ch for ch in e.filename if ch.isalnum() or ch in "._- ")[:150] or "evidence"
    return Response(e.content, media_type=e.content_type if e.content_type.startswith(("image/", "application/pdf", "text/plain")) else "application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"', "X-Evidence-SHA256": e.sha256, "X-Evidence-Integrity": "verified",
                             "X-Content-Type-Options": "nosniff"})


class WithdrawIn(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)


@router.post("/evidence/{eid}/withdraw")
def withdraw_evidence(eid: int, body: WithdrawIn, request: Request, user: User = Depends(need("compliance:manage")), db: Session = Depends(get_db)):
    """Evidence is never deleted; it can be withdrawn (excluded from new results) with a reason. The file and hash stay for the audit trail."""
    e = db.get(Evidence, eid)
    if e is None:
        raise NotFound("Evidence not found")
    if e.withdrawn_at:
        raise ValidationFailed("Already withdrawn")
    e.withdrawn_at, e.withdrawn_by, e.withdrawn_reason = utcnow(), user.id, body.reason
    audit.record(db, "compliance.evidence_withdraw", actor=user, target_type="evidence", target_id=e.id, target_name=e.title, ip=client_ip(request),
                 details={"reason": body.reason})
    db.commit()
    return _ser_evidence(db, e)

"""IT audit engine: assessments, control results, findings lifecycle, evidence repository and the audit report."""
from __future__ import annotations

import hashlib
import json
import mimetypes
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.models import (
    Assessment, AssessmentResult, ComplianceControl, ComplianceFramework, Device, Evidence, Finding, FindingEvent, User,
)
from app.services import audit, auth
from app.services.compliance import checks
from app.services.reporting.render import Doc, Section, Table

RESULT_STATUSES = ("compliant", "partial", "non_compliant", "not_assessed", "not_applicable")
RESULT_LABEL = {"compliant": "Compliant", "partial": "Partially compliant", "non_compliant": "Non-compliant", "not_assessed": "Not assessed",
                "not_applicable": "Not applicable"}
SEVERITIES = ("critical", "high", "medium", "low", "informational")
DUE_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
FINDING_STATUSES = ("open", "assigned", "in_progress", "pending_verification", "closed", "accepted_risk")
FINDING_LABEL = {"open": "Open", "assigned": "Assigned", "in_progress": "In progress", "pending_verification": "Pending verification",
                 "closed": "Closed", "accepted_risk": "Accepted risk"}
TRANSITIONS = {"open": {"assigned", "in_progress", "accepted_risk"}, "assigned": {"in_progress", "open", "accepted_risk"},
               "in_progress": {"pending_verification", "assigned", "accepted_risk"}, "pending_verification": {"closed", "in_progress"},
               "closed": {"open"}, "accepted_risk": {"open"}}
EVIDENCE_MAX = 25 * 1024 * 1024
EVIDENCE_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".txt", ".log", ".csv", ".xlsx", ".xls", ".docx", ".doc", ".json", ".xml", ".html", ".htm",
                ".zip", ".evtx", ".pptx", ".msg", ".eml", ".cfg", ".conf"}


# ------------------------------------------------------------------ assessments
def get_assessment(db: Session, aid: int) -> Assessment:
    a = db.get(Assessment, aid)
    if a is None:
        raise NotFound("Assessment not found")
    return a


def _editable(a: Assessment) -> None:
    if a.status == "approved":
        raise ValidationFailed("This assessment is approved and locked. Start a new assessment to re-assess.")


def create_assessment(db: Session, user: User, *, framework_id: int, title: str, period_start: datetime | None, period_end: datetime | None,
                      scope: dict, run_checks: bool = True, ip: str | None = None) -> Assessment:
    fw = db.get(ComplianceFramework, framework_id)
    if fw is None or not fw.enabled:
        raise NotFound("Framework not found")
    a = Assessment(title=title, framework_id=fw.id, period_start=period_start, period_end=period_end or utcnow(), scope=scope or {},
                   created_by=user.id, status="draft")
    db.add(a)
    db.flush()
    for c in db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == fw.id).order_by(ComplianceControl.sort)).scalars().all():
        db.add(AssessmentResult(assessment_id=a.id, control_id=c.id, status="not_assessed", source=""))
    db.flush()
    audit.record(db, "compliance.assessment_create", actor=user, target_type="assessment", target_id=a.id, target_name=a.title, ip=ip,
                 details={"framework": fw.code, "scope": scope})
    if run_checks:
        run_automated(db, a, user, ip=ip)
    return a


def run_automated(db: Session, a: Assessment, user: User | None, ip: str | None = None) -> dict:
    """Evaluate every control mapped to automated checks. Results an auditor recorded manually are never overwritten."""
    _editable(a)
    rows = db.execute(select(AssessmentResult, ComplianceControl).join(ComplianceControl, ComplianceControl.id == AssessmentResult.control_id)
                      .where(AssessmentResult.assessment_id == a.id)).all()
    keys = sorted({k for _, c in rows for k in (c.check_keys or [])})
    results = checks.run(db, keys, a.scope or {})
    now = utcnow()
    snapshot = {k: {"title": checks.CHECKS[k][0], "status": r.status, "summary": r.summary, "evidence": r.evidence} for k, r in results.items()}
    ev = None
    if results:
        content = json.dumps({"assessment_id": a.id, "generated_at": now.isoformat() + "Z", "checks": snapshot}, indent=2, default=str).encode()
        ev = _store_evidence(db, title=f"Automated check results - assessment #{a.id} ({now:%Y-%m-%d %H:%M} UTC)", filename=f"assessment-{a.id}-checks-{now:%Y%m%d-%H%M%S}.json",
                             content=content, content_type="application/json", source="system", assessment_id=a.id, user=user,
                             description="Snapshot of the data each automated check evaluated. Integrity protected by SHA-256.")
    # controls referencing each check, for finding descriptions
    refs: dict[str, list[ComplianceControl]] = {}
    for _, c in rows:
        for k in c.check_keys or []:
            refs.setdefault(k, []).append(c)
    updated = 0
    for r, c in rows:
        if not c.check_keys or r.source == "manual":
            continue
        rs = [results[k] for k in c.check_keys if k in results]
        assessed = [x for x in rs if x.status != "not_assessed"]
        if not assessed:
            status = "not_assessed"
        elif any(x.status == "non_compliant" for x in assessed):
            status = "non_compliant"
        elif any(x.status == "partial" for x in assessed) or len(assessed) < len(rs):
            status = "partial" if any(x.status in ("compliant", "partial") for x in assessed) else "non_compliant"
        else:
            status = "compliant"
        r.status = status
        r.source = "automated:" + ",".join(c.check_keys)
        r.evidence_summary = "\n".join(f"[{RESULT_LABEL.get(results[k].status, results[k].status)}] {checks.CHECKS[k][0]}: {results[k].summary}"
                                       for k in c.check_keys if k in results)
        r.evidence = ([{"type": "file", "evidence_id": ev.id, "label": ev.title, "sha256": ev.sha256}] if ev else []) + \
                     [{"type": "system", "check": k, "status": results[k].status, "ts": now.isoformat() + "Z"} for k in c.check_keys if k in results]
        r.assessed_at, r.assessed_by = now, None
        updated += 1
    created = 0
    for k, res in results.items():
        ctrls = refs.get(k, [])
        for f in res.findings:
            fp = f"a{a.id}:{k}:" + hashlib.sha1(f"{f['title']}|{f.get('asset', '')}".encode()).hexdigest()[:24]
            existing = db.execute(select(Finding).where(Finding.fingerprint == fp)).scalar_one_or_none()
            desc = f.get("description", "") + (f"\n\nControls: {', '.join(c.ref for c in ctrls)}" if ctrls else "")
            if existing:
                existing.description, existing.updated_at = desc, now
                continue
            sev = f.get("severity") if f.get("severity") in SEVERITIES else "medium"
            fd = Finding(assessment_id=a.id, control_id=ctrls[0].id if ctrls else None, title=f["title"][:300], description=desc, severity=sev,
                         status="open", source=f"automated:{k}", asset=(f.get("asset") or "")[:300], root_cause=f.get("root_cause", ""),
                         business_impact=f.get("impact", ""), recommendation=f.get("recommendation", ""), fingerprint=fp,
                         due_date=now + timedelta(days=DUE_DAYS[sev]) if sev in DUE_DAYS else None, created_by=getattr(user, "id", None))
            db.add(fd)
            db.flush()
            db.add(FindingEvent(finding_id=fd.id, user_id=getattr(user, "id", None), from_status=None, to_status="open", comment="Raised by automated check"))
            created += 1
    a.summary = summary(db, a)
    audit.record(db, "compliance.assessment_run", actor=user, actor_name=None if user else "scheduler", target_type="assessment", target_id=a.id,
                 target_name=a.title, ip=ip, details={"checks": len(results), "controls_updated": updated, "findings_created": created,
                                                       "evidence_id": ev.id if ev else None})
    db.flush()
    return {"checks": len(results), "controls_updated": updated, "findings_created": created, "evidence_id": ev.id if ev else None}


def record_result(db: Session, user: User, a: Assessment, control_id: int, *, status: str, auditor_notes: str, evidence_summary: str | None,
                  evidence_ids: list[int], ip: str | None = None) -> AssessmentResult:
    _editable(a)
    if status not in RESULT_STATUSES:
        raise ValidationFailed("Unknown status")
    r = db.execute(select(AssessmentResult).where(AssessmentResult.assessment_id == a.id, AssessmentResult.control_id == control_id)).scalar_one_or_none()
    if r is None:
        raise NotFound("Control is not part of this assessment")
    if status in ("compliant", "partial", "non_compliant") and not (evidence_ids or (evidence_summary or r.evidence_summary or "").strip() or r.evidence):
        raise ValidationFailed("Record evidence (a file or a summary of what was verified) for an assessed control")
    ev = []
    for eid in evidence_ids:
        e = db.get(Evidence, eid)
        if e is None or e.withdrawn_at:
            raise ValidationFailed(f"Evidence #{eid} not found or withdrawn")
        ev.append({"type": "file", "evidence_id": e.id, "label": e.title, "sha256": e.sha256})
    before = {"status": r.status, "source": r.source}
    r.status, r.auditor_notes = status, auditor_notes
    if evidence_summary is not None:
        r.evidence_summary = evidence_summary
    keep = [x for x in (r.evidence or []) if x.get("type") == "system" or x.get("evidence_id") not in {e["evidence_id"] for e in ev}]
    r.evidence = keep + ev
    r.source, r.assessed_at, r.assessed_by = "manual", utcnow(), user.id
    a.summary = summary(db, a)
    c = db.get(ComplianceControl, control_id)
    audit.record(db, "compliance.result", actor=user, target_type="assessment", target_id=a.id, target_name=f"{a.title} / {c.ref}", ip=ip,
                 details={"before": before, "after": {"status": status}, "evidence": [e["evidence_id"] for e in ev]})
    db.flush()
    return r


def transition(db: Session, user: User, a: Assessment, to: str, comment: str, ip: str | None = None) -> Assessment:
    if to == "in_review":
        _editable(a)
        a.status, a.submitted_at = "in_review", utcnow()
    elif to == "draft":
        _editable(a)
        a.status = "draft"
    elif to == "approved":
        if a.status != "in_review":
            raise ValidationFailed("Submit the assessment for review first")
        auth.require(db, user, "compliance:approve")
        if a.created_by == user.id:
            raise Forbidden("An assessment must be approved by someone other than its author")
        a.status, a.approved_by, a.approved_at, a.approval_comment = "approved", user.id, utcnow(), comment[:2000]
        a.summary = summary(db, a)
    else:
        raise ValidationFailed("Unknown assessment status")
    audit.record(db, f"compliance.assessment_{to}", actor=user, target_type="assessment", target_id=a.id, target_name=a.title, ip=ip, details={"comment": comment[:500]})
    db.flush()
    return a


def summary(db: Session, a: Assessment) -> dict:
    counts = dict(db.execute(select(AssessmentResult.status, func.count()).where(AssessmentResult.assessment_id == a.id).group_by(AssessmentResult.status)).all())
    c = {s: counts.get(s, 0) for s in RESULT_STATUSES}
    assessed = c["compliant"] + c["partial"] + c["non_compliant"]
    sev = dict(db.execute(select(Finding.severity, func.count()).where(Finding.assessment_id == a.id).group_by(Finding.severity)).all())
    st = dict(db.execute(select(Finding.status, func.count()).where(Finding.assessment_id == a.id).group_by(Finding.status)).all())
    return {"total_controls": sum(c.values()), "counts": c, "assessed": assessed,
            "score": round(100 * (c["compliant"] + 0.5 * c["partial"]) / assessed) if assessed else None,
            "findings_by_severity": {s: sev.get(s, 0) for s in SEVERITIES}, "findings_by_status": {s: st.get(s, 0) for s in FINDING_STATUSES}}


# ------------------------------------------------------------------ findings
def get_finding(db: Session, fid: int) -> Finding:
    f = db.get(Finding, fid)
    if f is None:
        raise NotFound("Finding not found")
    return f


def create_finding(db: Session, user: User, data: dict, ip: str | None = None) -> Finding:
    sev = data.get("severity", "medium")
    if sev not in SEVERITIES:
        raise ValidationFailed("Unknown severity")
    f = Finding(**{k: v for k, v in data.items() if k in {"assessment_id", "control_id", "title", "description", "severity", "asset", "root_cause",
                                                            "business_impact", "recommendation", "owner_department", "owner_user_id", "due_date"}},
                source="manual", status="open", created_by=user.id)
    if f.due_date is None and sev in DUE_DAYS:
        f.due_date = utcnow() + timedelta(days=DUE_DAYS[sev])
    db.add(f)
    db.flush()
    db.add(FindingEvent(finding_id=f.id, user_id=user.id, to_status="open", comment="Created"))
    audit.record(db, "compliance.finding_create", actor=user, target_type="finding", target_id=f.id, target_name=f.title, ip=ip, details={"severity": sev})
    return f


def update_finding(db: Session, user: User, f: Finding, data: dict, ip: str | None = None) -> Finding:
    allowed = {"title", "description", "severity", "asset", "root_cause", "business_impact", "recommendation", "owner_department", "owner_user_id", "due_date"}
    before = {k: getattr(f, k) for k in data if k in allowed}
    if "severity" in data and data["severity"] not in SEVERITIES:
        raise ValidationFailed("Unknown severity")
    if data.get("owner_user_id") and db.get(User, data["owner_user_id"]) is None:
        raise ValidationFailed("Owner not found")
    for k, v in data.items():
        if k in allowed:
            setattr(f, k, v)
    f.updated_at = utcnow()
    audit.record(db, "compliance.finding_update", actor=user, target_type="finding", target_id=f.id, target_name=f.title, ip=ip,
                 details={"before": {k: str(v) for k, v in before.items()}, "after": {k: str(v) for k, v in data.items() if k in allowed}})
    return f


def move_finding(db: Session, user: User, f: Finding, to: str, comment: str, *, accepted_until: datetime | None = None, ip: str | None = None) -> Finding:
    if to not in FINDING_STATUSES:
        raise ValidationFailed("Unknown status")
    if to not in TRANSITIONS[f.status]:
        raise ValidationFailed(f"A finding cannot move from {FINDING_LABEL[f.status]} to {FINDING_LABEL[to]}")
    if to in ("closed", "accepted_risk", "open") and len(comment.strip()) < 5:
        raise ValidationFailed("Add a comment explaining this decision")
    if to == "assigned" and not (f.owner_user_id or f.owner_department):
        raise ValidationFailed("Set the responsible owner or department before assigning")
    if to == "closed" and f.owner_user_id == user.id:
        raise Forbidden("Closing requires independent verification: someone other than the remediation owner must verify and close the finding")
    if to == "accepted_risk":
        auth.require(db, user, "compliance:approve")
        if f.owner_user_id == user.id:
            raise Forbidden("The remediation owner cannot accept the risk of their own finding")
        if accepted_until is None or accepted_until <= utcnow():
            raise ValidationFailed("Risk acceptance needs a future review date")
        f.risk_acceptance = {"reason": comment, "accepted_by": user.username, "accepted_at": utcnow().isoformat() + "Z", "review_by": accepted_until.isoformat()}
    db.add(FindingEvent(finding_id=f.id, user_id=user.id, from_status=f.status, to_status=to, comment=comment[:2000]))
    before = f.status
    f.status, f.updated_at = to, utcnow()
    f.closed_at = utcnow() if to in ("closed", "accepted_risk") else None
    audit.record(db, "compliance.finding_status", actor=user, target_type="finding", target_id=f.id, target_name=f.title, ip=ip,
                 details={"from": before, "to": to, "comment": comment[:500]})
    db.flush()
    return f


# ------------------------------------------------------------------ evidence
def _store_evidence(db: Session, *, title: str, filename: str, content: bytes, content_type: str, source: str, user: User | None,
                    description: str = "", assessment_id: int | None = None, finding_id: int | None = None, control_ref: str | None = None) -> Evidence:
    e = Evidence(title=title[:300], description=description[:2000], filename=filename[:255], content_type=content_type[:150], size=len(content),
                 sha256=hashlib.sha256(content).hexdigest(), content=content, source=source, assessment_id=assessment_id, finding_id=finding_id,
                 control_ref=control_ref, uploaded_by=getattr(user, "id", None))
    db.add(e)
    db.flush()
    audit.record(db, "compliance.evidence_add", actor=user, actor_name=None if user else "system", target_type="evidence", target_id=e.id, target_name=e.title,
                 details={"sha256": e.sha256, "size": e.size, "filename": e.filename, "source": source, "assessment_id": assessment_id, "finding_id": finding_id})
    return e


def upload_evidence(db: Session, user: User, *, title: str, filename: str, content: bytes, description: str = "", assessment_id: int | None = None,
                    finding_id: int | None = None, control_ref: str | None = None) -> Evidence:
    import os
    ext = os.path.splitext(filename.lower())[1]
    if ext not in EVIDENCE_EXT:
        raise ValidationFailed(f"File type {ext or '(none)'} is not accepted as evidence. Allowed: {', '.join(sorted(EVIDENCE_EXT))}")
    if not content:
        raise ValidationFailed("The file is empty")
    if len(content) > EVIDENCE_MAX:
        raise ValidationFailed("Evidence files are limited to 25 MB")
    if assessment_id:
        _editable(get_assessment(db, assessment_id))
    if finding_id:
        get_finding(db, finding_id)
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return _store_evidence(db, title=title or filename, filename=os.path.basename(filename), content=content, content_type=ctype, source="upload",
                           user=user, description=description, assessment_id=assessment_id, finding_id=finding_id, control_ref=control_ref)


def verify_evidence(e: Evidence) -> bool:
    return hashlib.sha256(e.content or b"").hexdigest() == e.sha256


# ------------------------------------------------------------------ report
def _assets_in_scope(db: Session, scope: dict) -> dict:
    ctx = checks.Ctx(db, scope or {}, utcnow())
    devs = checks._devices(ctx)
    by: dict[str, int] = {}
    for d in devs:
        by[checks._cat(d)] = by.get(checks._cat(d), 0) + 1
    return {"devices": len(devs), "by_category": by}


def report_doc(db: Session, a: Assessment, organisation: str = "") -> Doc:
    fw = db.get(ComplianceFramework, a.framework_id)
    s = summary(db, a)
    users = {u.id: u for u in db.execute(select(User)).scalars().all()}
    rows = db.execute(select(AssessmentResult, ComplianceControl).join(ComplianceControl, ComplianceControl.id == AssessmentResult.control_id)
                      .where(AssessmentResult.assessment_id == a.id).order_by(ComplianceControl.sort)).all()
    findings = db.execute(select(Finding).where(Finding.assessment_id == a.id).order_by(Finding.id)).scalars().all()
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.id))
    evid = db.execute(select(Evidence).where((Evidence.assessment_id == a.id) | (Evidence.finding_id.in_([f.id for f in findings] or [-1])))
                      .order_by(Evidence.id)).scalars().all()
    assets = _assets_in_scope(db, a.scope)
    period = f"{a.period_start:%Y-%m-%d} to {a.period_end:%Y-%m-%d}" if a.period_start and a.period_end else (f"up to {a.period_end:%Y-%m-%d}" if a.period_end else "-")
    c = s["counts"]
    doc = Doc(title=a.title, subtitle=f"IT audit report - {fw.name}", organisation=organisation,
              meta=[("Framework", f"{fw.name} ({fw.version})"), ("Audit period", period), ("Status", a.status.replace("_", " ").title()),
                    ("Prepared by", getattr(users.get(a.created_by), "display_name", None) or getattr(users.get(a.created_by), "username", "")),
                    ("Approved by", (getattr(users.get(a.approved_by), "username", "") + (f" on {a.approved_at:%Y-%m-%d}" if a.approved_at else "")) if a.approved_by else "Not approved")])
    doc.kpis = [("Controls", s["total_controls"], ""), ("Score", f"{s['score']}%" if s["score"] is not None else "n/a", "compliant" if (s["score"] or 0) >= 80 else "high"),
                ("Compliant", c["compliant"], "compliant"), ("Partially compliant", c["partial"], "partial"), ("Non-compliant", c["non_compliant"], "non_compliant"),
                ("Not assessed", c["not_assessed"], "not_assessed"), ("Critical/high findings", s["findings_by_severity"]["critical"] + s["findings_by_severity"]["high"], "critical"),
                ("Open findings", sum(v for k, v in s["findings_by_status"].items() if k not in ("closed", "accepted_risk")), "medium")]
    auto = (f"This assessment covers {s['total_controls']} controls of {fw.name}. {s['assessed']} were assessed: {c['compliant']} compliant, "
            f"{c['partial']} partially compliant and {c['non_compliant']} non-compliant; {c['not_assessed']} were not assessed and {c['not_applicable']} are not applicable. "
            f"{len(findings)} finding(s) were recorded, {s['findings_by_severity']['critical'] + s['findings_by_severity']['high']} of them critical or high. "
            "Automated results are technical evidence collected by InfraPilot; process and policy aspects rely on the auditor's review. "
            "This report does not certify compliance with any standard or regulation.")
    doc.sections.append(Section("Executive Summary", paragraphs=[p for p in (a.executive_summary.strip(), auto) if p]))
    scope = a.scope or {}
    doc.sections.append(Section("Scope and Assets Assessed", kv=[("Scope description", scope.get("description") or "All assets managed by InfraPilot"),
                                                                  ("Devices in scope", assets["devices"]), ("By category", ", ".join(f"{k}: {v}" for k, v in assets["by_category"].items()) or "-"),
                                                                  ("Sites / groups filter", f"{scope.get('site_ids') or 'all'} / {scope.get('group_ids') or 'all'}"),
                                                                  ("AD domains", scope.get("ad_domain_ids") or "all synchronised"), ("GPO domains", scope.get("gpo_domains") or "all collected")]))
    doc.sections.append(Section("Results Overview", tables=[Table(["Status", "Controls"], [[RESULT_LABEL[k], v] for k, v in c.items()]),
                                                            Table(["Severity", "Findings"], [[k.title(), v] for k, v in s["findings_by_severity"].items()]),
                                                            Table(["Finding status", "Count"], [[FINDING_LABEL[k], v] for k, v in s["findings_by_status"].items()])]))
    crit = [f for f in findings if f.severity in ("critical", "high")]
    doc.sections.append(Section("Critical and High-Risk Findings", tables=[Table(
        ["ID", "Severity", "Finding", "Asset", "Recommended corrective action", "Owner", "Target date", "Status"],
        [[f"F-{f.id}", f.severity.title(), f.title, f.asset, f.recommendation, f.owner_department or getattr(users.get(f.owner_user_id), "username", ""),
          f.due_date.strftime("%Y-%m-%d") if f.due_date else "", FINDING_LABEL[f.status]] for f in crit], widths=[0.6, 0.8, 2.4, 1.6, 3, 1.2, 0.9, 1.1],
        sheet="Critical-High")]))
    doc.sections.append(Section("Control Assessment", paragraphs=["Every control with its status, evidence source, the evidence summary and auditor notes."], tables=[Table(
        ["Ref", "Control", "Domain", "Status", "Source", "Evidence", "Assessed", "Auditor notes"],
        [[ctl.ref, ctl.title, ctl.domain, RESULT_LABEL[r.status], "Automated" if r.source.startswith("automated") else ("Auditor" if r.source == "manual" else "-"),
          (r.evidence_summary or "") + ("".join(f"\n[file] {x.get('label')} sha256 {str(x.get('sha256'))[:16]}…" for x in (r.evidence or []) if x.get("type") == "file")),
          r.assessed_at.strftime("%Y-%m-%d %H:%M") if r.assessed_at else "", r.auditor_notes] for r, ctl in rows],
        widths=[0.6, 2, 1.2, 1, 0.8, 3.6, 0.9, 1.8], sheet="Controls")]))
    det = Section("Findings Detail")
    for f in findings:
        ev = [e for e in evid if e.finding_id == f.id]
        det.children.append(Section(f"F-{f.id} [{f.severity.upper()}] {f.title}", kv=[
            ("Status", FINDING_LABEL[f.status]), ("Asset", f.asset or "-"), ("Description", f.description or "-"), ("Root cause", f.root_cause or "-"),
            ("Business impact", f.business_impact or "-"), ("Recommended corrective action", f.recommendation or "-"),
            ("Responsible owner/department", ", ".join(x for x in (getattr(users.get(f.owner_user_id), "username", ""), f.owner_department) if x) or "Unassigned"),
            ("Target completion date", f.due_date.strftime("%Y-%m-%d") if f.due_date else "-"), ("Source", f.source),
            ("Risk acceptance", f"{f.risk_acceptance.get('reason')} (by {f.risk_acceptance.get('accepted_by')}, review by {f.risk_acceptance.get('review_by', '')[:10]})" if f.risk_acceptance else "-"),
            ("Evidence", ", ".join(f"{e.filename} (sha256 {e.sha256[:16]}…)" for e in ev) or "-")]))
    doc.sections.append(det)
    doc.sections.append(Section("Evidence Register", paragraphs=["SHA-256 recorded at upload and re-verified when this report was generated."], tables=[Table(
        ["ID", "Title", "File", "Source", "Uploaded", "By", "SHA-256", "Integrity"],
        [[f"E-{e.id}", e.title, e.filename, e.source, e.uploaded_at.strftime("%Y-%m-%d %H:%M"), getattr(users.get(e.uploaded_by), "username", "system"),
          e.sha256, "Withdrawn" if e.withdrawn_at else ("Verified" if verify_evidence(e) else "FAILED")] for e in evid],
        widths=[0.5, 2, 2, 0.7, 1, 0.8, 3.4, 0.8], tone_columns=("Integrity",), sheet="Evidence")]))
    prev = db.execute(select(Assessment).where(Assessment.framework_id == a.framework_id, Assessment.id != a.id, Assessment.created_at <= a.created_at)
                      .order_by(Assessment.id.desc()).limit(6)).scalars().all()
    hist = [[a.title + " (this)", a.created_at.strftime("%Y-%m-%d"), a.status, f"{s['score']}%" if s["score"] is not None else "n/a", c["compliant"], c["partial"],
             c["non_compliant"], c["not_assessed"]]]
    for p in prev:
        ps = p.summary if p.summary and p.summary.get("counts") else summary(db, p)
        hist.append([p.title, p.created_at.strftime("%Y-%m-%d"), p.status, f"{ps['score']}%" if ps.get("score") is not None else "n/a", ps["counts"]["compliant"],
                     ps["counts"]["partial"], ps["counts"]["non_compliant"], ps["counts"]["not_assessed"]])
    doc.sections.append(Section("Historical Comparison", tables=[Table(["Assessment", "Date", "Status", "Score", "Compliant", "Partial", "Non-compliant", "Not assessed"], hist,
                                                                       sheet="History")]))
    doc.sections.append(Section("Auditor Comments and Approval", kv=[("Status", a.status.replace("_", " ").title()),
                                                                     ("Submitted for review", a.submitted_at.strftime("%Y-%m-%d %H:%M UTC") if a.submitted_at else "-"),
                                                                     ("Approved by", getattr(users.get(a.approved_by), "username", "-") if a.approved_by else "-"),
                                                                     ("Approved on", a.approved_at.strftime("%Y-%m-%d %H:%M UTC") if a.approved_at else "-"),
                                                                     ("Approval comment", a.approval_comment or "-")]))
    return doc

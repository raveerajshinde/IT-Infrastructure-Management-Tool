"""Active Directory: domains (LDAPS), inventory, reports, change history and approved bulk account actions."""
from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need, paging
from app.core.db import get_db
from app.core.errors import NotFound, ValidationFailed
from app.models import AdChange, AdDomain, AdObject, Credential, Device, User
from app.services import ad, audit, jobs, reporting, settings_store
from app.services.reporting.render import Doc, Section, Table

router = APIRouter(prefix="/api/ad", tags=["active directory"])


class DomainIn(BaseModel):
    name: str = Field(min_length=3, max_length=255, pattern=r"^[A-Za-z0-9.-]+$")
    ldap_url: str = Field(min_length=8, max_length=500)
    base_dn: str = Field(min_length=4, max_length=500)
    credential_id: int | None = None
    verify_tls: bool = True
    start_tls: bool = False
    enabled: bool = True
    sync_interval_hours: int = Field(6, ge=0, le=168)
    stale_days: int = Field(90, ge=14, le=3650)
    dc_device_id: int | None = Field(None, description="Domain controller (Windows device) used for approved account actions")
    ca_file: str | None = Field(None, max_length=300)

    @field_validator("ldap_url")
    @classmethod
    def _url(cls, v: str) -> str:
        if not re.fullmatch(r"ldaps?://[A-Za-z0-9.\-]+(:\d{2,5})?/?", v.strip()):
            raise ValueError("must look like ldaps://dc01.corp.local:636")
        return v.strip().rstrip("/")

    @field_validator("base_dn")
    @classmethod
    def _dn(cls, v: str) -> str:
        if not re.fullmatch(r"(?i)(dc=[A-Za-z0-9-]+,)*dc=[A-Za-z0-9-]+", v.replace(" ", "")):
            raise ValueError("must look like DC=corp,DC=local")
        return v.replace(" ", "")


def _dom(db: Session, did: int) -> AdDomain:
    d = db.get(AdDomain, did)
    if d is None:
        raise NotFound("Domain not found")
    return d


def _ser_domain(db: Session, d: AdDomain) -> dict:
    cred = db.get(Credential, d.credential_id) if d.credential_id else None
    return {"id": d.id, "name": d.name, "ldap_url": d.ldap_url, "base_dn": d.base_dn, "credential_id": d.credential_id,
            "credential_name": cred.name if cred else None, "verify_tls": d.verify_tls, "start_tls": d.start_tls, "enabled": d.enabled,
            "sync_interval_hours": d.sync_interval_hours, "stale_days": d.stale_days, "dc_device_id": (d.settings or {}).get("dc_device_id"),
            "ca_file": (d.settings or {}).get("ca_file"), "last_sync_at": ser.iso(d.last_sync_at), "last_sync_ok": d.last_sync_ok,
            "last_sync_message": d.last_sync_message, "last_success_at": ser.iso(d.last_success_at), "stats": d.stats or {}}


def _apply(db: Session, d: AdDomain, body: DomainIn) -> None:
    if body.credential_id:
        c = db.get(Credential, body.credential_id)
        if c is None or c.kind not in ("password", "winrm"):
            raise ValidationFailed("Choose a user name + password credential")
    if body.dc_device_id:
        dev = db.get(Device, body.dc_device_id)
        if dev is None or dev.platform != "windows":
            raise ValidationFailed("The account-action device must be a Windows domain controller (or server with RSAT-AD-PowerShell)")
    for k in ("name", "ldap_url", "base_dn", "credential_id", "verify_tls", "start_tls", "enabled", "sync_interval_hours", "stale_days"):
        setattr(d, k, getattr(body, k))
    d.name = d.name.lower()
    d.settings = {**(d.settings or {}), "dc_device_id": body.dc_device_id, "ca_file": body.ca_file}


@router.get("/domains")
def list_domains(user: User = Depends(need("ad:read")), db: Session = Depends(get_db)):
    return [_ser_domain(db, d) for d in db.execute(select(AdDomain).order_by(AdDomain.name)).scalars().all()]


@router.post("/domains", status_code=201)
def create_domain(body: DomainIn, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    if db.execute(select(AdDomain).where(AdDomain.name == body.name.lower())).first():
        raise ValidationFailed("This domain is already configured")
    d = AdDomain(name=body.name, ldap_url=body.ldap_url, base_dn=body.base_dn)
    _apply(db, d, body)
    db.add(d)
    db.flush()
    audit.record(db, "ad.domain_create", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request),
                 details={"ldap_url": d.ldap_url, "base_dn": d.base_dn})
    db.commit()
    return _ser_domain(db, d)


@router.put("/domains/{did}")
def update_domain(did: int, body: DomainIn, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    d = _dom(db, did)
    _apply(db, d, body)
    audit.record(db, "ad.domain_update", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request),
                 details={"ldap_url": d.ldap_url, "base_dn": d.base_dn, "enabled": d.enabled})
    db.commit()
    return _ser_domain(db, d)


@router.delete("/domains/{did}", status_code=204)
def delete_domain(did: int, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    d = _dom(db, did)
    ad.purge(db, d)
    audit.record(db, "ad.domain_delete", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request))
    db.delete(d)
    db.commit()
    return Response(status_code=204)


@router.post("/domains/{did}/test")
def test_domain(did: int, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    d = _dom(db, did)
    ok, msg = ad.test(db, d)
    audit.record(db, "ad.domain_test", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request),
                 result="success" if ok else "failure", details={"message": msg[:500]})
    db.commit()
    return {"ok": ok, "message": msg}


@router.post("/domains/{did}/sync")
def sync_domain(did: int, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    d = _dom(db, did)
    try:
        stats = ad.sync(db, d, actor=user)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        d = _dom(db, did)
        d.last_sync_ok, d.last_sync_message = False, str(exc)[:1000]
        audit.record(db, "ad.sync", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request),
                     result="failure", details={"error": str(exc)[:500]})
        db.commit()
        raise ValidationFailed(f"Synchronisation failed: {exc}") from exc
    db.commit()
    return stats


@router.get("/summary")
def ad_summary(user: User = Depends(need("ad:read")), db: Session = Depends(get_db)):
    doms = db.execute(select(AdDomain).order_by(AdDomain.name)).scalars().all()
    tot: dict[str, int] = {}
    for d in doms:
        for k, v in (d.stats or {}).items():
            if isinstance(v, int):
                tot[k] = tot.get(k, 0) + v
    recent = db.execute(select(AdChange).order_by(AdChange.id.desc()).limit(15)).scalars().all()
    return {"domains": [_ser_domain(db, d) for d in doms], "totals": tot,
            "recent_changes": [{"ts": ser.iso(c.ts), "domain_id": c.domain_id, "kind": c.kind, "name": c.name, "change": c.change, "details": c.details}
                               for c in recent]}


SORTS = {"name": AdObject.name, "sam": AdObject.sam, "last_logon": AdObject.last_logon, "when_created": AdObject.when_created,
         "pwd_last_set": AdObject.pwd_last_set}


@router.get("/objects")
def list_objects(domain_id: int | None = None, kind: Literal["user", "computer", "group", "ou", "dc"] = "user", q: str | None = Query(None, max_length=100),
                 enabled: bool | None = None, privileged: bool | None = None, sort: str = "name", desc: bool = False,
                 user: User = Depends(need("ad:read")), db: Session = Depends(get_db), pg=Depends(paging)):
    stmt = select(AdObject).where(AdObject.kind == kind)
    if domain_id:
        stmt = stmt.where(AdObject.domain_id == domain_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(AdObject.sam.like(like), AdObject.name.like(like), AdObject.display_name.like(like)))
    if enabled is not None:
        stmt = stmt.where(AdObject.enabled == enabled)
    if privileged is not None:
        stmt = stmt.where(AdObject.privileged == privileged)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    col = SORTS.get(sort, AdObject.name)
    page, size = pg
    rows = db.execute(stmt.order_by(col.desc() if desc else col, AdObject.id).offset((page - 1) * size).limit(size)).scalars().all()
    return {"items": [_ser_obj(o) for o in rows], "total": total, "page": page, "page_size": size}


def _ser_obj(o: AdObject, full: bool = False) -> dict:
    a = dict(o.attrs or {})
    if not full:
        a.pop("members", None)
        a.pop("member_of", None)
    return {"id": o.id, "domain_id": o.domain_id, "kind": o.kind, "guid": o.guid, "dn": o.dn, "sam": o.sam, "name": o.name, "display_name": o.display_name,
            "enabled": o.enabled, "privileged": o.privileged, "locked": o.locked, "pwd_never_expires": o.pwd_never_expires,
            "last_logon": ser.iso(o.last_logon), "pwd_last_set": ser.iso(o.pwd_last_set), "account_expires": ser.iso(o.account_expires),
            "when_created": ser.iso(o.when_created), "when_changed": ser.iso(o.when_changed), "os": o.os, "attrs": a, "synced_at": ser.iso(o.synced_at)}


@router.get("/objects/{oid}")
def get_object(oid: int, user: User = Depends(need("ad:read")), db: Session = Depends(get_db)):
    o = db.get(AdObject, oid)
    if o is None:
        raise NotFound("Object not found")
    out = _ser_obj(o, full=True)
    dns = (o.attrs or {}).get("members") or (o.attrs or {}).get("member_of") or []
    if dns:
        names = dict(db.execute(select(AdObject.dn, AdObject.sam).where(AdObject.domain_id == o.domain_id, AdObject.dn.in_(dns[:1000]))).all())
        key = "members" if (o.attrs or {}).get("members") else "member_of"
        out["attrs"][f"{key}_resolved"] = [{"dn": d, "name": names.get(d) or d.split(",", 1)[0].split("=", 1)[-1]} for d in dns[:1000]]
    return out


@router.get("/changes")
def list_changes(domain_id: int | None = None, days: int = Query(30, ge=1, le=3650), user: User = Depends(need("ad:read")), db: Session = Depends(get_db)):
    from datetime import timedelta

    from app.core.timeutil import utcnow
    stmt = select(AdChange).where(AdChange.ts >= utcnow() - timedelta(days=days)).order_by(AdChange.id.desc()).limit(2000)
    if domain_id:
        stmt = stmt.where(AdChange.domain_id == domain_id)
    return [{"ts": ser.iso(c.ts), "domain_id": c.domain_id, "kind": c.kind, "name": c.name, "change": c.change, "details": c.details}
            for c in db.execute(stmt).scalars().all()]


@router.get("/reports")
def list_ad_reports(user: User = Depends(need("ad:read"))):
    return [{"key": k, "title": t} for k, t in ad.REPORTS.items()]


def ad_doc(db: Session, d: AdDomain, key: str, days: int) -> Doc:
    head, rows, note = ad.report(db, d, key, days)
    st = d.stats or {}
    return Doc(title=f"Active Directory - {ad.REPORTS[key]}", subtitle=f"Domain {d.name}",
               meta=[("Domain", d.name), ("Last synchronised", ser.iso(d.last_success_at) or "never"), ("Rows", len(rows))],
               organisation=settings_store.value(db, "ui.organization_name") or "",
               kpis=[("Users", st.get("users", 0), ""), ("Enabled", st.get("enabled_users", 0), "compliant"), ("Privileged", st.get("privileged_users", 0), "high"),
                     ("Inactive", st.get("inactive_users", 0), "medium"), ("Stale computers", st.get("stale_computers", 0), "medium"), ("DCs", st.get("dcs", 0), "")],
               sections=[Section(ad.REPORTS[key], paragraphs=[note] if note else [], tables=[Table(head, rows, sheet=key[:28])])])


@router.get("/reports/{key}")
def get_ad_report(key: str, request: Request, domain_id: int, days: int = Query(30, ge=1, le=3650),
                  format: Literal["json", "pdf", "xlsx", "csv", "html"] = "json", user: User = Depends(need("ad:read")), db: Session = Depends(get_db)):
    d = _dom(db, domain_id)
    if format == "json":
        head, rows, note = ad.report(db, d, key, days)
        return {"key": key, "title": ad.REPORTS[key], "columns": head, "rows": [[ser.iso(v) if hasattr(v, "isoformat") else v for v in r] for r in rows], "note": note}
    return reporting.export(db, key=f"ad-{key}", doc=ad_doc(db, d, key, days), fmt=format, params={"domain_id": domain_id, "days": days}, user=user,
                            ip=client_ip(request))


# ---------------------------------------------------------------- bulk actions (preview -> approved jobs on a DC)
BULK_OPS = {"disable": ("windows.ad.user.set_enabled", lambda sam, g: {"sam_account_name": sam, "enabled": False}),
            "enable": ("windows.ad.user.set_enabled", lambda sam, g: {"sam_account_name": sam, "enabled": True}),
            "unlock": ("windows.ad.user.unlock", lambda sam, g: {"sam_account_name": sam}),
            "add_to_group": ("windows.ad.group.add_member", lambda sam, g: {"group": g, "member": sam}),
            "remove_from_group": ("windows.ad.group.remove_member", lambda sam, g: {"group": g, "member": sam})}


class BulkIn(BaseModel):
    domain_id: int
    action: Literal["disable", "enable", "unlock", "add_to_group", "remove_from_group"]
    accounts: list[str] = Field(min_length=1, max_length=200)
    group: str | None = Field(None, max_length=256)
    reason: str = Field("", max_length=1000)
    execute: bool = False


@router.post("/bulk")
def bulk_action(body: BulkIn, request: Request, user: User = Depends(need("ad:manage")), db: Session = Depends(get_db)):
    """Preview (execute=false) shows exactly what will happen; execute=true creates one job per account on the configured DC,
    subject to RBAC, approval policies and maintenance windows."""
    d = _dom(db, body.domain_id)
    if body.action in ("add_to_group", "remove_from_group") and not body.group:
        raise ValidationFailed("Choose the group")
    found = {o.sam.lower(): o for o in db.execute(select(AdObject).where(AdObject.domain_id == d.id, AdObject.kind == "user",
                                                                         AdObject.sam.in_(body.accounts))).scalars().all()}
    preview = []
    for sam in dict.fromkeys(a.strip() for a in body.accounts if a.strip()):
        o = found.get(sam.lower())
        warn = []
        if o is None:
            warn.append("Not found in the last synchronisation")
        else:
            if body.action == "disable" and o.enabled is False:
                warn.append("Already disabled")
            if body.action == "enable" and o.enabled:
                warn.append("Already enabled")
            if body.action == "unlock" and not o.locked:
                warn.append("Not locked at last synchronisation")
            if o.privileged:
                warn.append("Privileged account: " + ", ".join((o.attrs or {}).get("privileged_groups") or []))
        preview.append({"account": sam, "display_name": o.display_name if o else "", "enabled": o.enabled if o else None, "warnings": warn,
                        "will_run": o is not None})
    op, mk = BULK_OPS[body.action]
    dc = (d.settings or {}).get("dc_device_id")
    if not body.execute:
        return {"action": body.action, "operation": op, "dc_device_id": dc, "items": preview,
                "note": "Each account becomes a separate job on the domain controller; approval policies apply." if dc else
                        "Configure the domain controller device for this domain before executing."}
    if not dc:
        raise ValidationFailed("Set the domain controller device for this domain (Active Directory -> Domains -> Edit) first")
    created = []
    for p in preview:
        if not p["will_run"]:
            continue
        job = jobs.create_operation_job(db, user, operation_id=op, device_ids=[dc], params=mk(p["account"], body.group),
                                        reason=body.reason, title=f"AD bulk {body.action.replace('_', ' ')}: {p['account']}", ip=client_ip(request))
        created.append({"account": p["account"], "job_id": job.id, "status": job.status})
    audit.record(db, "ad.bulk", actor=user, target_type="ad_domain", target_id=d.id, target_name=d.name, ip=client_ip(request),
                 details={"action": body.action, "accounts": len(created), "group": body.group, "jobs": [c["job_id"] for c in created]})
    db.commit()
    return {"action": body.action, "jobs": created, "skipped": [p["account"] for p in preview if not p["will_run"]]}

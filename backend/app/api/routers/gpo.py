"""Group Policy: inventory, readable settings, baseline, comparisons, history, reports and collection."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need
from app.core.db import get_db
from app.core.errors import NotFound, ValidationFailed
from app.models import GpoCollection, User
from app.services import jobs, reporting, settings_store
from app.services.gpo import analysis, knowledge as kb, report as gporeport, store

router = APIRouter(prefix="/api/gpo", tags=["group policy"])
MAX_UPLOAD = 64 * 1024 * 1024


def _col(db: Session, collection: int | None, domain: str | None) -> GpoCollection:
    return store.get_collection(db, collection, domain)


def _col_info(c: GpoCollection) -> dict:
    return {"id": c.id, "domain": c.domain, "source": c.source, "device_id": c.device_id, "collected_at": ser.iso(c.collected_at),
            "collected_by": c.collected_by, "gpo_count": c.gpo_count, "changed_count": c.changed_count, "note": c.note,
            "warnings": (c.extra or {}).get("warnings") or [], "domain_info": c.domain_info or {}}


@router.get("/domains")
def gpo_domains(user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    return [{**d, "collected_at": ser.iso(d["collected_at"])} for d in store.domains(db)]


@router.get("/collections")
def gpo_collections(domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    q = select(GpoCollection).order_by(GpoCollection.id.desc()).limit(200)
    if domain:
        q = select(GpoCollection).where(GpoCollection.domain == domain).order_by(GpoCollection.id.desc()).limit(200)
    return [_col_info(c) | {"changed": (c.extra or {}).get("changed") or [], "deleted": (c.extra or {}).get("deleted") or []}
            for c in db.execute(q).scalars().all()]


@router.get("/overview")
def gpo_overview(collection: int | None = None, domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    c = _col(db, collection, domain)
    a = store.analyse(db, c)
    b = a.baseline()
    ov = a.overlaps()
    s = a.summary(b, ov)
    return {"collection": _col_info(c), "summary": s, "executive_summary": a.executive_summary(s), "inventory": a.inventory(),
            "categories": kb.CATEGORIES}


@router.get("/gpos/{guid}")
def gpo_detail(guid: str, collection: int | None = None, domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    c = _col(db, collection, domain)
    a = store.analyse(db, c)
    g = a.by_guid.get(guid.lower().strip("{}"))
    if g is None:
        raise NotFound("GPO not found in this collection")
    inv = next(r for r in a.inventory() if r["guid"] == g.guid)
    return {"collection": _col_info(c), "gpo": inv, "settings": a.settings[g.guid], "history": [
        {**h, "first_seen": ser.iso(h["first_seen"])} for h in store.history(db, c.domain, g.guid)],
            "precedence": [{"ou": a.display_path(p), "position": next((x["precedence"] for x in a.precedence(p) if x["guid"] == g.guid), None)}
                           for p in a.ou_paths() if any(x["guid"] == g.guid for x in a.precedence(p))]}


@router.get("/baseline")
def gpo_baseline(collection: int | None = None, domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    c = _col(db, collection, domain)
    a = store.analyse(db, c)
    b = a.baseline()
    return {"collection": _col_info(c), "summary": a.summary(b), "rules": b, "exclusions": store.exclusions(db)}


class ExclusionIn(BaseModel):
    reason: str | None = Field(None, max_length=500)


@router.put("/baseline/{rule_id}/exclusion")
def gpo_baseline_exclusion(rule_id: str, body: ExclusionIn, request: Request, user: User = Depends(need("gpo:manage")), db: Session = Depends(get_db)):
    cur = store.set_exclusion(db, rule_id, body.reason, user, client_ip(request))
    db.commit()
    return cur


@router.get("/overlaps")
def gpo_overlaps(collection: int | None = None, domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    a = store.analyse(db, _col(db, collection, domain))
    return a.overlaps()


@router.get("/precedence")
def gpo_precedence(collection: int | None = None, domain: str | None = None, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    a = store.analyse(db, _col(db, collection, domain))
    return [{"ou": a.display_path(p), "blocked": (a._ou.get(p) or {}).get("blocked"), "gpos": a.precedence(p)} for p in a.ou_paths()]


class CompareIn(BaseModel):
    guids: list[str] = Field(default_factory=list, max_length=10)
    snapshot_ids: list[int] = Field(default_factory=list, max_length=10)
    collection: int | None = None


@router.post("/compare")
def gpo_compare(body: CompareIn, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    gpos = []
    if body.snapshot_ids:
        gpos = [store.snapshot(db, i)[1] for i in body.snapshot_ids]
    else:
        a = store.analyse(db, _col(db, body.collection, None))
        for g in body.guids:
            if g.lower() not in a.by_guid:
                raise NotFound(f"GPO {g} not found in this collection")
            gpos.append(a.by_guid[g.lower()])
    if len(gpos) < 2:
        raise ValidationFailed("Select at least two GPOs (or versions) to compare")
    return analysis.compare(gpos)


@router.get("/history/{guid}")
def gpo_history(guid: str, domain: str, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    return [{**h, "first_seen": ser.iso(h["first_seen"])} for h in store.history(db, domain.lower(), guid.lower().strip("{}"))]


@router.get("/diff")
def gpo_diff(a: int, b: int, user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    sa, ga = store.snapshot(db, a)
    sb, gb = store.snapshot(db, b)
    if sa.guid != sb.guid:
        raise ValidationFailed("Both versions must belong to the same GPO (use Compare for different GPOs)")
    return {"gpo": gb.name, "before": {"snapshot_id": sa.id, "first_seen": ser.iso(sa.created_at), "modified": ga.modified},
            "after": {"snapshot_id": sb.id, "first_seen": ser.iso(sb.created_at), "modified": gb.modified}, **analysis.diff_versions(ga, gb)}


@router.post("/upload", status_code=201)
async def gpo_upload(request: Request, file: UploadFile = File(...), note: str = Form(""), user: User = Depends(need("gpo:manage")),
                     db: Session = Depends(get_db)):
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise ValidationFailed("File is larger than 64 MB")
    c = store.ingest(db, xml=data, source="upload", collected_by=user.username, note=note or f"Uploaded {file.filename}", actor=user, ip=client_ip(request))
    db.commit()
    return _col_info(c)


class CollectIn(BaseModel):
    device_id: int
    domain: str | None = Field(None, max_length=255)


@router.post("/collect", status_code=201)
def gpo_collect(body: CollectIn, request: Request, user: User = Depends(need("gpo:manage")), db: Session = Depends(get_db)):
    job = jobs.create_operation_job(db, user, operation_id="windows.gpo.collect", device_ids=[body.device_id],
                                    params={"domain": body.domain} if body.domain else {}, title="Collect Group Policy for reporting",
                                    ip=client_ip(request))
    return ser.job(db, job, detail=False)


@router.get("/rules")
def gpo_rules(user: User = Depends(need("gpo:read"))):
    return [{"id": r.id, "title": r.title, "category": r.category, "expected": r.expected, "risk": r.risk, "why": r.why, "fix": r.fix,
             "reference": r.ref, "domain_level": r.applies == "domain_account"} for r in kb.RULES]


@router.get("/report")
def gpo_report(request: Request, format: Literal["pdf", "xlsx", "csv", "html"] = "pdf", collection: int | None = None, domain: str | None = None,
               guids: str | None = Query(None, description="comma-separated GUIDs for a report on selected GPOs"), inline: bool = False,
               user: User = Depends(need("gpo:read")), db: Session = Depends(get_db)):
    c = _col(db, collection, domain)
    sel = [g.strip().lower().strip("{}") for g in guids.split(",")] if guids else None
    doc = gporeport.build(db, c, sel, organisation=settings_store.value(db, "ui.organization_name") or "")
    return reporting.export(db, key="gpo", doc=doc, fmt=format, params={"collection": c.id, "guids": sel, "inline": inline}, user=user, ip=client_ip(request))

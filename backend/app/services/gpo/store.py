"""Storage of GPO collections and snapshots, change detection and alerting."""
from __future__ import annotations

import hashlib
from collections import OrderedDict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.models import Alert, GpoCollection, GpoCollectionItem, GpoSnapshot, SystemSetting
from app.services import audit
from app.services.gpo import analysis, parser

EXCLUSIONS_KEY = "gpo.baseline_exclusions"
_CACHE: "OrderedDict[int, parser.Gpo]" = OrderedDict()


def _parsed(snap: GpoSnapshot) -> parser.Gpo:
    g = _CACHE.get(snap.id)
    if g is None:
        g = parser.parse_report(snap.xml)[0]
        _CACHE[snap.id] = g
        if len(_CACHE) > 3000:
            _CACHE.popitem(last=False)
    return g


def _snapshot(db: Session, domain: str, g: parser.Gpo, collection_id: int | None) -> tuple[GpoSnapshot, bool]:
    sha = g.sha256
    snap = db.execute(select(GpoSnapshot).where(GpoSnapshot.domain == domain, GpoSnapshot.guid == g.guid, GpoSnapshot.sha256 == sha)).scalar_one_or_none()
    if snap:
        return snap, False
    snap = GpoSnapshot(domain=domain, guid=g.guid, name=g.name[:255], sha256=sha, xml=g.xml, first_collection_id=collection_id)
    db.add(snap)
    db.flush()
    return snap, True


def latest_collection(db: Session, domain: str | None = None) -> GpoCollection | None:
    q = select(GpoCollection).order_by(GpoCollection.id.desc()).limit(1)
    if domain:
        q = select(GpoCollection).where(GpoCollection.domain == domain).order_by(GpoCollection.id.desc()).limit(1)
    return db.execute(q).scalar_one_or_none()


def ingest(db: Session, *, xml: str | bytes | None = None, gpos: list[parser.Gpo] | None = None, domain_info: dict | None = None,
           ou_data: list | None = None, extra: dict | None = None, source: str = "device", device_id: int | None = None,
           collected_by: str = "system", job_execution_id: int | None = None, note: str = "", actor=None, ip: str | None = None) -> GpoCollection:
    if gpos is None:
        try:
            gpos = parser.parse_report(xml or "")
        except parser.GpoXmlError as exc:
            raise ValidationFailed(str(exc)) from exc
    domain_info = domain_info or {}
    domain = (domain_info.get("dns_root") or (gpos[0].domain if gpos else "") or "unknown").lower()
    if any(g.domain and g.domain.lower() != domain for g in gpos):
        raise ValidationFailed("The report contains GPOs from more than one domain; collect each domain separately")
    prev = latest_collection(db, domain)
    prev_items = {}
    if prev:
        prev_items = {i.guid: i.snapshot_id for i in db.execute(select(GpoCollectionItem).where(GpoCollectionItem.collection_id == prev.id)).scalars().all()}
    extra = dict(extra or {})
    if source == "upload":
        extra.setdefault("warnings", []).append("Uploaded report: link order, block inheritance and SYSVOL consistency were not collected; "
                                                "precedence is derived from links in the report.")
    c = GpoCollection(domain=domain, source=source, device_id=device_id, job_execution_id=job_execution_id, collected_by=collected_by[:128],
                      domain_info=domain_info, ou_data=ou_data or [], extra=extra, gpo_count=len(gpos), note=note[:500])
    db.add(c)
    db.flush()
    changed = []
    for g in gpos:
        snap, _new = _snapshot(db, domain, g, c.id)
        is_changed = bool(prev) and prev_items.get(g.guid) != snap.id
        db.add(GpoCollectionItem(collection_id=c.id, snapshot_id=snap.id, guid=g.guid, changed=is_changed))
        if is_changed:
            changed.append((g, prev_items.get(g.guid), snap.id))
    deleted = []
    if prev:
        now = {g.guid for g in gpos}
        for guid, sid in prev_items.items():
            if guid not in now:
                old = db.get(GpoSnapshot, sid)
                deleted.append({"guid": guid, "name": old.name if old else guid})
    c.changed_count = len(changed) + len(deleted)
    c.extra = {**extra, "deleted": deleted, "changed": [{"guid": g.guid, "name": g.name, "before_snapshot": b, "after_snapshot": a, "new": b is None}
                                                       for g, b, a in changed]}
    for g, before, after in changed:
        what = "created" if before is None else "changed"
        _alert(db, f"gpo:{domain}:{g.guid}:{after}", f"GPO {what}: {g.name}",
               f"Group Policy Object '{g.name}' in {domain} was {what} (detected by collection #{c.id}). Review the before/after comparison.")
    for d in deleted:
        _alert(db, f"gpo:{domain}:{d['guid']}:deleted", f"GPO deleted: {d['name']}", f"Group Policy Object '{d['name']}' no longer exists in {domain}.")
    audit.record(db, "gpo.collect", actor=actor, actor_name=None if actor else collected_by, target_type="domain", target_id=domain, target_name=domain,
                 device_id=device_id, ip=ip, details={"collection_id": c.id, "source": source, "gpos": len(gpos), "changed": len(changed),
                                                      "deleted": len(deleted)})
    db.flush()
    return c


def _alert(db: Session, fp: str, title: str, message: str) -> None:
    from app.services import monitoring
    if db.execute(select(Alert.id).where(Alert.fingerprint == fp[:200])).first():
        return
    a = Alert(source="gpo", severity="warning", title=title[:300], message=message[:2000], fingerprint=fp[:200])
    db.add(a)
    db.flush()
    monitoring._announce(db, a, None)


def store_versions(db: Session, before_xml: str | None, after_xml: str | None, *, actor_name: str, device_id: int | None) -> dict:
    """Store before/after versions of one GPO (restore jobs) and return their snapshot ids."""
    out = {}
    for k, xml in (("before", before_xml), ("after", after_xml)):
        if not xml:
            continue
        try:
            g = parser.parse_report(xml)[0]
        except parser.GpoXmlError:
            continue
        snap, _ = _snapshot(db, (g.domain or "unknown").lower(), g, None)
        out[f"{k}_snapshot"] = snap.id
    return out


# ------------------------------------------------------------------ reading
def exclusions(db: Session) -> dict[str, str]:
    row = db.get(SystemSetting, EXCLUSIONS_KEY)
    return dict(row.value or {}) if row else {}


def set_exclusion(db: Session, rule_id: str, reason: str | None, user, ip: str | None) -> dict[str, str]:
    from app.services.gpo.knowledge import RULES_BY_ID
    if rule_id not in RULES_BY_ID:
        raise NotFound("Unknown baseline rule")
    row = db.get(SystemSetting, EXCLUSIONS_KEY)
    if row is None:
        row = SystemSetting(key=EXCLUSIONS_KEY, value={})
        db.add(row)
    cur = dict(row.value or {})
    if reason:
        if len(reason.strip()) < 5:
            raise ValidationFailed("Give a reason (at least 5 characters) for excluding a baseline rule")
        cur[rule_id] = reason.strip()[:500]
    else:
        cur.pop(rule_id, None)
    row.value = cur
    row.updated_by = user.id
    audit.record(db, "gpo.baseline_exclusion", actor=user, target_type="baseline_rule", target_id=rule_id, target_name=RULES_BY_ID[rule_id].title,
                 ip=ip, details={"excluded": bool(reason), "reason": reason or ""})
    db.flush()
    return cur


def collection_gpos(db: Session, c: GpoCollection) -> list[parser.Gpo]:
    rows = db.execute(select(GpoSnapshot).join(GpoCollectionItem, GpoCollectionItem.snapshot_id == GpoSnapshot.id)
                      .where(GpoCollectionItem.collection_id == c.id)).scalars().all()
    return [_parsed(s) for s in rows]


def analyse(db: Session, c: GpoCollection) -> analysis.Analysis:
    return analysis.Analysis(collection_gpos(db, c), c.domain, c.domain_info, c.ou_data, c.extra, exclusions(db))


def get_collection(db: Session, collection_id: int | None, domain: str | None = None) -> GpoCollection:
    c = db.get(GpoCollection, collection_id) if collection_id else latest_collection(db, domain)
    if c is None:
        raise NotFound("No Group Policy data yet: collect from a domain controller or upload a Get-GPOReport XML file")
    return c


def domains(db: Session) -> list[dict]:
    ids = db.execute(select(func.max(GpoCollection.id)).group_by(GpoCollection.domain)).scalars().all()
    rows = db.execute(select(GpoCollection).where(GpoCollection.id.in_(ids or [-1])).order_by(GpoCollection.domain)).scalars().all()
    return [{"domain": c.domain, "collection_id": c.id, "collected_at": c.collected_at, "source": c.source, "gpo_count": c.gpo_count} for c in rows]


def history(db: Session, domain: str, guid: str) -> list[dict]:
    """Versions of one GPO in the order they were first seen."""
    snaps = db.execute(select(GpoSnapshot).where(GpoSnapshot.domain == domain, GpoSnapshot.guid == guid).order_by(GpoSnapshot.id)).scalars().all()
    seen_in = dict(db.execute(select(GpoCollectionItem.snapshot_id, func.count()).where(GpoCollectionItem.guid == guid)
                              .group_by(GpoCollectionItem.snapshot_id)).all())
    out = []
    for s in snaps:
        g = _parsed(s)
        out.append({"snapshot_id": s.id, "first_seen": s.created_at, "name": s.name, "modified": g.modified, "sha256": s.sha256,
                    "collections": seen_in.get(s.id, 0), "settings": len(g.settings)})
    return out


def snapshot(db: Session, sid: int) -> tuple[GpoSnapshot, parser.Gpo]:
    s = db.get(GpoSnapshot, sid)
    if s is None:
        raise NotFound("GPO version not found")
    return s, _parsed(s)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

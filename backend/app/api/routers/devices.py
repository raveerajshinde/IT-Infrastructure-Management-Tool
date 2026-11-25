"""Inventory: devices, sites, groups, saved filters, import/export, discovery, connectivity, config backups."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile
from pydantic import BaseModel
from sqlalchemy import UnicodeText, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, current_user, need, need_global, paging
from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.permissions import operation_permission
from app.core.timeutil import utcnow
from app.drivers.registry import DRIVERS, catalogue, driver_class
from app.models import ConfigBackup, Device, DeviceGroup, DeviceGroupMember, SavedFilter, Site, User
from app.schemas import DeviceIn, DiscoveryIn, GroupIn, SavedFilterIn, SiteIn
from app.services import audit, auth, configs, devices, discovery, import_export

router = APIRouter(prefix="/api", tags=["inventory"])


def _scope_filter(db: Session, user: User, q):
    groups = auth.visible_device_filter(db, user)
    if groups is None:
        return q
    if not groups:
        return q.where(Device.id == -1)
    return q.where(Device.id.in_(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id.in_(groups))))


def _visible(db: Session, user: User, device_id: int) -> Device:
    d = devices.get_device(db, device_id)
    auth.require(db, user, "devices:read", d.id)
    return d


@router.get("/meta")
def meta(user: User = Depends(current_user)):
    return ser.meta(get_settings().app_mode)


@router.get("/platforms")
def platforms(user: User = Depends(current_user)):
    return catalogue()


@router.get("/operations")
def operations(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Union of all operations across drivers (first driver's schema wins; the server validates per driver)."""
    seen: dict[str, dict] = {}
    for cls in DRIVERS.values():
        for spec in cls.operations.values():
            if spec.id not in seen and not spec.id.endswith(".script.run"):  # library scripts start from Scripts
                seen[spec.id] = ser.operation(spec, cls.category, auth.has_any_scope(db, user, operation_permission(cls.category, spec.risk)))
    return list(seen.values())


def _device_query(db, user, q, device_type, platform, environment, status, site_id, group_id, department, tag):
    stmt = _scope_filter(db, user, select(Device).where(Device.deleted_at.is_(None)))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Device.hostname.ilike(like), Device.ip_address.ilike(like), Device.vendor.ilike(like), Device.model.ilike(like),
                              Device.serial_number.ilike(like), Device.owner.ilike(like), Device.os_name.ilike(like)))
    for col, val in ((Device.device_type, device_type), (Device.platform, platform), (Device.environment, environment),
                     (Device.status, status), (Device.site_id, site_id), (Device.department, department)):
        if val not in (None, ""):
            stmt = stmt.where(col == val)
    if group_id:
        stmt = stmt.where(Device.id.in_(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id == group_id)))
    if tag:
        stmt = stmt.where(cast(Device.tags, UnicodeText).ilike(f'%"{tag}"%'))
    return stmt


@router.get("/devices")
def list_devices(
    user: User = Depends(need("devices:read")), db: Session = Depends(get_db), pg=Depends(paging),
    q: str | None = Query(None, max_length=200), device_type: str | None = None, platform: str | None = None, driver: str | None = None,
    environment: str | None = None, status: str | None = None, site_id: int | None = None, group_id: int | None = None,
    department: str | None = None, tag: str | None = None, sort: str = "hostname", order: Literal["asc", "desc"] = "asc",
):
    stmt = _device_query(db, user, q, device_type, platform or driver, environment, status, site_id, group_id, department, tag)
    cols = {"hostname": Device.hostname, "ip_address": Device.ip_address, "status": Device.status, "device_type": Device.device_type,
            "environment": Device.environment, "last_seen_at": Device.last_checked_at, "driver": Device.platform, "vendor": Device.vendor}
    col = cols.get(sort, Device.hostname)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    page, size = pg
    rows = db.execute(stmt.order_by(col.desc() if order == "desc" else col.asc(), Device.id).offset((page - 1) * size).limit(size)).scalars()
    return {"items": [ser.device(db, d) for d in rows], "total": total, "page": page, "page_size": size}


@router.post("/devices", status_code=201)
def create_device(body: DeviceIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    data = body.model_dump()
    devices.validate_device_payload(db, data)
    if db.execute(select(Device).where(func.lower(Device.hostname) == body.hostname.lower(), Device.deleted_at.is_(None))).first():
        raise Conflict(f"A device named '{body.hostname}' already exists")
    gids = data.pop("group_ids")
    d = Device(**data)
    db.add(d)
    db.flush()
    devices.set_groups(db, d.id, gids)
    audit.record(db, "device.create", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id,
                 ip=client_ip(request), details={k: v for k, v in data.items() if k != "notes"})
    db.commit()
    return ser.device(db, d, user, with_ops=True)


@router.get("/devices/{device_id}")
def get_device(device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return ser.device(db, _visible(db, user, device_id), user, with_ops=True)


@router.put("/devices/{device_id}")
def update_device(device_id: int, body: DeviceIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = devices.get_device(db, device_id)
    auth.require(db, user, "devices:write", d.id)
    data = body.model_dump()
    if d.is_simulated != body.is_simulated:
        raise ValidationFailed("The simulated flag cannot be changed after creation")
    devices.validate_device_payload(db, data)
    if db.execute(select(Device).where(func.lower(Device.hostname) == body.hostname.lower(), Device.deleted_at.is_(None), Device.id != d.id)).first():
        raise Conflict(f"A device named '{body.hostname}' already exists")
    gids = data.pop("group_ids")
    before = {k: getattr(d, k) for k in data}
    for k, v in data.items():
        setattr(d, k, v)
    if "group_ids" in body.model_fields_set:
        devices.set_groups(db, d.id, gids)
    changed = {k: {"from": before[k], "to": v} for k, v in data.items() if before[k] != v}
    audit.record(db, "device.update", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id,
                 ip=client_ip(request), details=changed)
    db.commit()
    return ser.device(db, d, user, with_ops=True)


class TlsIn(BaseModel):
    verify_tls: bool


@router.post("/devices/{device_id}/tls")
def set_device_tls(device_id: int, body: TlsIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Turn certificate verification on/off for one device (e.g. firewalls with a factory self-signed certificate)."""
    d = devices.get_device(db, device_id)
    auth.require(db, user, "devices:write", d.id)
    if d.verify_tls != body.verify_tls:
        audit.record(db, "device.tls_verification", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id,
                     ip=client_ip(request), details={"from": d.verify_tls, "to": body.verify_tls})
        d.verify_tls = body.verify_tls
        db.commit()
    return ser.device(db, d, user, with_ops=True)


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = devices.get_device(db, device_id)
    auth.require(db, user, "devices:delete", d.id)
    d.deleted_at = utcnow()
    audit.record(db, "device.delete", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id, ip=client_ip(request))
    db.commit()
    return Response(status_code=204)


@router.post("/devices/{device_id}/test")
def test_device(device_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _visible(db, user, device_id)
    res = devices.test_connectivity(db, d)
    res["tested_at"] = ser.iso(utcnow())
    res.setdefault("facts", {})
    res.setdefault("latency_ms", None)
    audit.record(db, "device.test_connectivity", actor=user, target_type="device", target_id=d.id, target_name=d.hostname, device_id=d.id,
                 result="success" if res.get("ok") else "failure", ip=client_ip(request), details={"message": res.get("message")})
    db.commit()
    return res


# ---------------------------------------------------------------- import / export
@router.post("/devices-import")
async def import_devices(request: Request, file: UploadFile = File(...), dry_run: bool = Form(True), update_existing: bool = Form(False),
                         user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise ValidationFailed("File too large (max 10 MB)")
    if not (file.filename or "").lower().endswith((".csv", ".xlsx", ".xlsm")):
        raise ValidationFailed("Upload a .csv or .xlsx file")
    try:
        check = import_export.import_devices(db, file.filename, data, dry_run=True)
    except ValueError as exc:
        raise ValidationFailed(str(exc))
    db.rollback()
    errors = [{"row": r["row"], "hostname": r.get("hostname") or "", "error": "; ".join(r["errors"])} for r in check["results"] if r["status"] == "error"]
    if not update_existing:
        errors += [{"row": r["row"], "hostname": r["hostname"], "error": "device already exists (enable 'update existing' to overwrite)"}
                   for r in check["results"] if r["status"] == "update"]
    creates = sum(1 for r in check["results"] if r["status"] == "create")
    updates = sum(1 for r in check["results"] if r["status"] == "update")
    out = {"rows": check["rows"], "create": creates, "update": updates if update_existing else 0, "errors": errors, "applied": False}
    if dry_run or errors:
        return out  # all-or-nothing: nothing is written when any row is invalid
    res = import_export.import_devices(db, file.filename, data, dry_run=False)
    audit.record(db, "device.import", actor=user, target_type="inventory", target_name=file.filename, ip=client_ip(request),
                 details={k: res[k] for k in ("rows", "created", "updated")})
    db.commit()
    out.update(applied=True, create=res["created"], update=res["updated"])
    return out


@router.get("/devices-export")
def export_devices(fmt: str = Query("csv", pattern="^(csv|xlsx)$"), user: User = Depends(need("devices:read")), db: Session = Depends(get_db),
                   q: str | None = None, device_type: str | None = None, environment: str | None = None, status: str | None = None,
                   site_id: int | None = None, group_id: int | None = None, tag: str | None = None):
    stmt = _device_query(db, user, q, device_type, None, environment, status, site_id, group_id, None, tag).order_by(Device.hostname)
    rows = import_export.export_rows(db, list(db.execute(stmt).scalars()))
    if fmt == "xlsx":
        return Response(import_export.to_xlsx(rows), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": 'attachment; filename="infrapilot-devices.xlsx"'})
    return Response(import_export.to_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="infrapilot-devices.csv"'})


@router.get("/devices-import/template")
def import_template(user: User = Depends(current_user)):
    rows = [import_export.COLUMNS,
            ["web01", "10.0.10.21", "linux_server", "linux", "production", "", "", "", "", "", "", "Web team", "DC1", "IT", "Rack A3",
             "web;nginx", "linux-ssh", "", "22", "true", "true", "Web Servers", ""]]
    return Response(import_export.to_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="device-import-template.csv"'})


@router.post("/discovery")
def discover(body: DiscoveryIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    found = discovery.sweep(body.cidr, body.probe_ports)
    known = {d.ip_address for d in db.execute(select(Device).where(Device.deleted_at.is_(None))).scalars()}
    for f in found:
        f["already_registered"] = f["ip_address"] in known
    audit.record(db, "device.discovery", actor=user, target_type="network", target_name=body.cidr, ip=client_ip(request), details={"found": len(found)})
    db.commit()
    return found


# ---------------------------------------------------------------- configuration backups
def _cfg_perm(db: Session, user: User, d: Device) -> None:
    auth.require(db, user, operation_permission(driver_class(d.platform).category, "read"), d.id)


@router.get("/devices/{device_id}/backups")
def list_backups(device_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = devices.get_device(db, device_id)
    _cfg_perm(db, user, d)
    return [ser.backup(b) for b in db.execute(select(ConfigBackup).where(ConfigBackup.device_id == d.id).order_by(ConfigBackup.id.desc()).limit(500)).scalars()]


@router.get("/backups/{backup_id}")
def get_backup(backup_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    b = db.get(ConfigBackup, backup_id)
    if not b:
        raise NotFound("Backup not found")
    d = devices.get_device(db, b.device_id)
    _cfg_perm(db, user, d)
    audit.record(db, "config.view", actor=user, target_type="config_backup", target_id=b.id, target_name=d.hostname, device_id=d.id, ip=client_ip(request))
    db.commit()
    return {**ser.backup(b), "device_id": d.id, "content": configs.mask_secrets(b.content)}


@router.get("/backups-diff")
def diff_backups(a: int, b: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ba, bb = db.get(ConfigBackup, a), db.get(ConfigBackup, b)
    if not ba or not bb:
        raise NotFound("Backup not found")
    for x in {ba.device_id, bb.device_id}:
        _cfg_perm(db, user, devices.get_device(db, x))
    text = configs.diff(ba.content, bb.content, f"#{ba.id} {ba.kind} {ba.created_at:%Y-%m-%d %H:%M}", f"#{bb.id} {bb.kind} {bb.created_at:%Y-%m-%d %H:%M}")
    lines = text.splitlines()
    return {"diff": text, "added": sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++")),
            "removed": sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))}


# ---------------------------------------------------------------- sites / groups / filters
def _site_counts(db: Session) -> dict[int, int]:
    return dict(db.execute(select(Device.site_id, func.count()).where(Device.deleted_at.is_(None)).group_by(Device.site_id)).all())


@router.get("/sites")
def list_sites(user: User = Depends(current_user), db: Session = Depends(get_db)):
    counts = _site_counts(db)
    return [{**ser.site(s), "device_count": counts.get(s.id, 0)} for s in db.execute(select(Site).order_by(Site.name)).scalars()]


@router.post("/sites", status_code=201)
def create_site(body: SiteIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    if db.execute(select(Site).where(Site.name == body.name)).first():
        raise Conflict("Site already exists")
    s = Site(**body.model_dump())
    db.add(s)
    db.flush()
    audit.record(db, "site.create", actor=user, target_type="site", target_id=s.id, target_name=s.name, ip=client_ip(request))
    db.commit()
    return ser.site(s)


@router.put("/sites/{site_id}")
def update_site(site_id: int, body: SiteIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    s = db.get(Site, site_id)
    if not s:
        raise NotFound("Site not found")
    s.name, s.kind, s.address = body.name, body.kind, body.address
    audit.record(db, "site.update", actor=user, target_type="site", target_id=s.id, target_name=s.name, ip=client_ip(request))
    db.commit()
    return ser.site(s)


@router.delete("/sites/{site_id}")
def delete_site(site_id: int, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    s = db.get(Site, site_id)
    if not s:
        raise NotFound("Site not found")
    if _site_counts(db).get(s.id):
        raise Conflict("Site still has devices; move them first")
    for d in db.execute(select(Device).where(Device.site_id == s.id)).scalars().all():
        d.site_id = None  # soft-deleted devices
    db.delete(s)
    audit.record(db, "site.delete", actor=user, target_type="site", target_id=site_id, target_name=s.name, ip=client_ip(request))
    db.commit()
    return {"message": "Site deleted"}


@router.get("/groups")
def list_groups(user: User = Depends(current_user), db: Session = Depends(get_db)):
    counts = dict(db.execute(select(DeviceGroupMember.group_id, func.count()).join(Device, Device.id == DeviceGroupMember.device_id)
                             .where(Device.deleted_at.is_(None)).group_by(DeviceGroupMember.group_id)).all())
    return [{"id": g.id, "name": g.name, "description": g.description, "device_count": counts.get(g.id, 0)}
            for g in db.execute(select(DeviceGroup).order_by(DeviceGroup.name)).scalars()]


@router.post("/groups", status_code=201)
def create_group(body: GroupIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    if db.execute(select(DeviceGroup).where(DeviceGroup.name == body.name)).first():
        raise Conflict("Group already exists")
    g = DeviceGroup(name=body.name, description=body.description)
    db.add(g)
    db.flush()
    for did in body.device_ids or []:
        devices.get_device(db, did)
        db.add(DeviceGroupMember(group_id=g.id, device_id=did))
    audit.record(db, "group.create", actor=user, target_type="group", target_id=g.id, target_name=g.name, ip=client_ip(request))
    db.commit()
    return {"id": g.id, "name": g.name, "description": g.description}


@router.put("/groups/{group_id}")
def update_group(group_id: int, body: GroupIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    g = db.get(DeviceGroup, group_id)
    if not g:
        raise NotFound("Group not found")
    g.name, g.description = body.name, body.description
    if body.device_ids is not None:
        _set_members(db, g.id, body.device_ids, "set")
    audit.record(db, "group.update", actor=user, target_type="group", target_id=g.id, target_name=g.name, ip=client_ip(request),
                 details={"device_ids": body.device_ids})
    db.commit()
    return {"id": g.id, "name": g.name, "description": g.description}


def _set_members(db: Session, gid: int, ids: list[int], action: str) -> None:
    cur = set(db.execute(select(DeviceGroupMember.device_id).where(DeviceGroupMember.group_id == gid)).scalars())
    want = set(ids)
    add = want - cur if action in ("add", "set") else set()
    remove = (cur - want) if action == "set" else (want & cur if action == "remove" else set())
    for did in add:
        devices.get_device(db, did)
        db.add(DeviceGroupMember(group_id=gid, device_id=did))
    for did in remove:
        db.delete(db.get(DeviceGroupMember, (gid, did)))


class MembersIn(BaseModel):
    device_ids: list[int]
    action: Literal["add", "remove", "set"] = "add"


@router.post("/groups/{group_id}/members")
def group_members(group_id: int, body: MembersIn, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    g = db.get(DeviceGroup, group_id)
    if not g:
        raise NotFound("Group not found")
    _set_members(db, g.id, body.device_ids, body.action)
    audit.record(db, "group.members", actor=user, target_type="group", target_id=g.id, target_name=g.name, ip=client_ip(request),
                 details={"action": body.action, "device_ids": body.device_ids})
    db.commit()
    return {"message": "Group membership updated"}


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, request: Request, user: User = Depends(need_global("devices:write")), db: Session = Depends(get_db)):
    from app.models import AlertRule, MaintenanceWindow, UserRole
    g = db.get(DeviceGroup, group_id)
    if not g:
        raise NotFound("Group not found")
    for model, col in ((UserRole, UserRole.device_group_id), (AlertRule, AlertRule.device_group_id), (MaintenanceWindow, MaintenanceWindow.device_group_id)):
        if db.execute(select(model).where(col == g.id)).first():
            raise Conflict(f"Group is referenced by {model.__tablename__.replace('_', ' ')}; remove those references first")
    for m in db.execute(select(DeviceGroupMember).where(DeviceGroupMember.group_id == g.id)).scalars().all():
        db.delete(m)
    db.delete(g)
    audit.record(db, "group.delete", actor=user, target_type="group", target_id=group_id, target_name=g.name, ip=client_ip(request))
    db.commit()
    return {"message": "Group deleted"}


@router.get("/saved-filters")
def list_filters(module: str = "devices", user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [{"id": f.id, "name": f.name, "module": f.module, "filters": f.filter, "filter": f.filter}
            for f in db.execute(select(SavedFilter).where(SavedFilter.user_id == user.id, SavedFilter.module == module)).scalars()]


@router.post("/saved-filters", status_code=201)
def save_filter(body: SavedFilterIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = SavedFilter(user_id=user.id, name=body.name, module=body.module, filter=body.filter)
    db.add(f)
    db.commit()
    return {"id": f.id}


@router.delete("/saved-filters/{fid}", status_code=204)
def delete_filter(fid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = db.get(SavedFilter, fid)
    if not f or f.user_id != user.id:
        raise NotFound("Filter not found")
    db.delete(f)
    db.commit()
    return Response(status_code=204)

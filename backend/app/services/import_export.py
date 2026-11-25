"""CSV / Excel bulk import & export of the device inventory."""
from __future__ import annotations

import csv
import io

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Credential, Device, DeviceGroup, DeviceGroupMember, Site
from app.schemas import DeviceIn
from app.services import devices

COLUMNS = ["hostname", "ip_address", "device_type", "platform", "environment", "os_name", "os_version", "vendor", "model",
           "firmware", "serial_number", "owner", "site", "department", "location", "tags", "credential", "snmp_credential",
           "port", "verify_tls", "monitoring_enabled", "groups", "notes"]
MAX_ROWS = 5000


def _rows_from_upload(filename: str, data: bytes) -> list[dict]:
    if filename.lower().endswith((".xlsx", ".xlsm")):
        from openpyxl import load_workbook

        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        ws = wb.active
        it = ws.iter_rows(values_only=True)
        header = [str(h or "").strip().lower() for h in next(it, [])]
        rows = [{header[i]: ("" if c is None else str(c)).strip() for i, c in enumerate(r) if i < len(header)} for r in it]
    else:
        text = data.decode("utf-8-sig")
        rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(io.StringIO(text))]
    rows = [r for r in rows if any(r.values())]
    if len(rows) > MAX_ROWS:
        raise ValueError(f"Import is limited to {MAX_ROWS} rows per file")
    return rows


def import_devices(db: Session, filename: str, data: bytes, dry_run: bool = True) -> dict:
    rows = _rows_from_upload(filename, data)
    creds = {c.name.lower(): c.id for c in db.execute(select(Credential)).scalars()}
    sites = {s.name.lower(): s for s in db.execute(select(Site)).scalars()}
    groups = {g.name.lower(): g for g in db.execute(select(DeviceGroup)).scalars()}
    results, created, updated = [], 0, 0
    for idx, r in enumerate(rows, start=2):
        errors = []
        site_id = None
        if r.get("site"):
            s = sites.get(r["site"].lower())
            if s is None and not dry_run:
                s = Site(name=r["site"][:150])
                db.add(s)
                db.flush()
                sites[r["site"].lower()] = s
            site_id = s.id if s else None
        payload = {
            "hostname": r.get("hostname", ""), "ip_address": r.get("ip_address", ""), "device_type": r.get("device_type", ""),
            "platform": r.get("platform", ""), "environment": r.get("environment") or "production",
            **{k: r.get(k, "") for k in ("os_name", "os_version", "vendor", "model", "firmware", "serial_number", "owner", "department", "location", "notes")},
            "tags": [t for t in (r.get("tags") or "").replace(",", ";").split(";") if t.strip()],
            "site_id": site_id,
            "port": int(r["port"]) if (r.get("port") or "").isdigit() else None,
            "verify_tls": (r.get("verify_tls") or "true").lower() not in ("false", "0", "no"),
            "monitoring_enabled": (r.get("monitoring_enabled") or "true").lower() not in ("false", "0", "no"),
        }
        for key, col in (("credential_id", "credential"), ("snmp_credential_id", "snmp_credential")):
            if r.get(col):
                if r[col].lower() not in creds:
                    errors.append(f"unknown credential '{r[col]}'")
                payload[key] = creds.get(r[col].lower())
        try:
            dev = DeviceIn.model_validate(payload)
            devices.validate_device_payload(db, dev.model_dump())
        except ValidationError as exc:
            errors += [f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()]
            dev = None
        except Exception as exc:
            errors.append(getattr(exc, "message", str(exc)))
            dev = None
        if errors:
            results.append({"row": idx, "hostname": r.get("hostname"), "status": "error", "errors": errors})
            continue
        existing = db.execute(select(Device).where(func.lower(Device.hostname) == dev.hostname.lower(), Device.deleted_at.is_(None))).scalar_one_or_none()
        action = "update" if existing else "create"
        if not dry_run:
            data_ = dev.model_dump(exclude={"group_ids"})
            if existing:
                for k, val in data_.items():
                    setattr(existing, k, val)
                target = existing
                updated += 1
            else:
                target = Device(**data_)
                db.add(target)
                created += 1
            db.flush()
            for gname in [g.strip() for g in (r.get("groups") or "").split(";") if g.strip()]:
                g = groups.get(gname.lower())
                if g is None:
                    g = DeviceGroup(name=gname[:150])
                    db.add(g)
                    db.flush()
                    groups[gname.lower()] = g
                if db.get(DeviceGroupMember, (g.id, target.id)) is None:
                    db.add(DeviceGroupMember(group_id=g.id, device_id=target.id))
        results.append({"row": idx, "hostname": dev.hostname, "status": action})
    errs = sum(1 for r in results if r["status"] == "error")
    return {"dry_run": dry_run, "rows": len(rows), "errors": errs, "created": created, "updated": updated, "results": results}


def export_rows(db: Session, devs: list[Device]) -> list[list]:
    creds = {c.id: c.name for c in db.execute(select(Credential)).scalars()}
    gnames = {g.id: g.name for g in db.execute(select(DeviceGroup)).scalars()}
    memb: dict[int, list[str]] = {}
    for m in db.execute(select(DeviceGroupMember)).scalars().all():
        memb.setdefault(m.device_id, []).append(gnames.get(m.group_id, ""))
    out = [COLUMNS]
    for d in devs:
        out.append([d.hostname, d.ip_address, d.device_type, d.platform, d.environment, d.os_name, d.os_version, d.vendor, d.model,
                    d.firmware, d.serial_number, d.owner, d.site.name if d.site else "", d.department, d.location, ";".join(d.tags or []),
                    creds.get(d.credential_id, ""), creds.get(d.snmp_credential_id, ""), d.port or "", str(d.verify_tls).lower(),
                    str(d.monitoring_enabled).lower(), ";".join(memb.get(d.id, [])), d.notes])
    return out


def to_csv(rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    for r in rows:
        # neutralise spreadsheet formula injection
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in r])
    return buf.getvalue().encode("utf-8-sig")


def to_xlsx(rows: list[list], title: str = "Devices") -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = title
    for r in rows:
        ws.append([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in r])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F2937")
    ws.freeze_panes = "A2"
    for col in ws.columns:
        ws.column_dimensions[col[0].column_letter].width = min(40, max(10, max(len(str(c.value or "")) for c in col) + 2))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()

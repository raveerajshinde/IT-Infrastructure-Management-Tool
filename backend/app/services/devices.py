"""Device helpers: driver construction, connectivity testing, fact refresh."""
from __future__ import annotations

import concurrent.futures as cf
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, NotFound, Unsupported, ValidationFailed
from app.core.timeutil import utcnow
from app.drivers.base import DeviceInfo, Driver
from app.drivers.registry import DRIVERS, build_driver
from app.drivers.snmp import ping, tcp_check
from app.models import Credential, Device, DeviceGroupMember
from app.services import secrets

log = logging.getLogger("infrapilot.devices")


def get_device(db: Session, device_id: int) -> Device:
    d = db.get(Device, device_id)
    if not d or d.deleted_at is not None:
        raise NotFound(f"Device {device_id} not found")
    return d


def validate_device_payload(db: Session, data: dict) -> None:
    s = get_settings()
    if data.get("platform") not in DRIVERS:
        raise ValidationFailed(f"Unknown platform '{data.get('platform')}'. Supported: {', '.join(sorted(DRIVERS))}")
    if data.get("is_simulated") and s.app_mode != "demo":
        raise ValidationFailed("Simulated devices can only be created when the platform runs in demo mode")
    for key in ("credential_id", "snmp_credential_id"):
        if data.get(key) and not db.get(Credential, data[key]):
            raise ValidationFailed(f"{key} refers to a credential that does not exist")
    if data.get("snmp_credential_id"):
        c = db.get(Credential, data["snmp_credential_id"])
        if c.kind != "snmpv3":
            raise ValidationFailed("SNMP credential must be of kind snmpv3")


def device_info(d: Device) -> DeviceInfo:
    return DeviceInfo(id=d.id, hostname=d.hostname, address=d.ip_address, platform=d.platform, device_type=d.device_type,
                      port=d.port, verify_tls=d.verify_tls, environment=d.environment, is_simulated=d.is_simulated)


def driver_for(db: Session, d: Device, timeout: int | None = None) -> Driver:
    cred = secrets.credential_material(db, db.get(Credential, d.credential_id)) if d.credential_id else None
    snmp = secrets.credential_material(db, db.get(Credential, d.snmp_credential_id)) if d.snmp_credential_id else None
    return build_driver(device_info(d), cred, snmp, timeout=timeout or get_settings().operation_timeout_seconds)


def set_groups(db: Session, device_id: int, group_ids: list[int]) -> None:
    existing = set(db.execute(select(DeviceGroupMember.group_id).where(DeviceGroupMember.device_id == device_id)).scalars())
    for gid in set(group_ids) - existing:
        db.add(DeviceGroupMember(group_id=gid, device_id=device_id))
    for gid in existing - set(group_ids):
        db.delete(db.get(DeviceGroupMember, (gid, device_id)))


def run_with_timeout(fn, timeout: int):
    ex = cf.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn)
    try:
        return fut.result(timeout=timeout)
    except cf.TimeoutError as exc:
        raise AppError(f"Operation timed out after {timeout}s") from exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def test_connectivity(db: Session, d: Device) -> dict:
    """Layered test: ICMP, management port, then authenticated driver check."""
    result: dict = {"device_id": d.id, "steps": []}
    if d.is_simulated:
        drv = driver_for(db, d)
        r = drv.test_connection()
        result["steps"].append({"step": "simulated", "ok": True, "message": r.message})
        result.update(ok=True, message=r.message)
        d.status, d.last_checked_at, d.last_success_at, d.last_error = "up", utcnow(), utcnow(), None
        return result
    up, rtt = ping(d.ip_address)
    result["steps"].append({"step": "icmp", "ok": up, "message": f"reply in {rtt:.1f} ms" if up and rtt else ("reply" if up else "no ICMP reply (may be filtered)")})
    cls = DRIVERS[d.platform]
    port = d.port or cls.default_port
    if port:
        ok, ms = tcp_check(d.ip_address, port)
        result["steps"].append({"step": "tcp", "ok": ok, "message": f"port {port} open ({ms:.0f} ms)" if ok else f"port {port} unreachable"})
        if not ok:
            d.status, d.last_checked_at, d.last_error = ("degraded" if up else "down"), utcnow(), f"Management port {port} unreachable"
            result.update(ok=False, message=d.last_error)
            return result
    if not d.credential_id and not d.snmp_credential_id:
        result["steps"].append({"step": "auth", "ok": False, "message": "No credential assigned - assign one to test authentication"})
        d.status, d.last_checked_at = ("up" if up else "unknown"), utcnow()
        result.update(ok=False, message="Reachable, but no credential assigned")
        return result
    drv = driver_for(db, d)
    try:
        r = run_with_timeout(drv.test_connection, get_settings().operation_timeout_seconds)
        result["steps"].append({"step": "auth", "ok": r.ok, "message": r.message})
        d.status, d.last_checked_at, d.last_error = "up", utcnow(), None
        d.last_success_at = utcnow()
        _apply_facts(d, r.facts)
        result.update(ok=True, message=r.message, latency_ms=r.latency_ms, facts=r.facts)
    except Unsupported as exc:
        result["steps"].append({"step": "auth", "ok": False, "message": exc.message})
        result.update(ok=False, message=exc.message)
    except Exception as exc:
        msg = getattr(exc, "message", None) or str(exc)
        result["steps"].append({"step": "auth", "ok": False, "message": msg[:500]})
        d.status, d.last_checked_at, d.last_error = "degraded", utcnow(), msg[:1000]
        result.update(ok=False, message=msg[:500])
    finally:
        drv.close()
    return result


def _apply_facts(d: Device, facts: dict) -> None:
    for k in ("os_name", "os_version", "vendor", "model", "firmware", "serial_number"):
        val = facts.get(k)
        if val and not getattr(d, k):
            setattr(d, k, str(val)[:120])

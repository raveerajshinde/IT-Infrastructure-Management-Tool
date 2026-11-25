"""Tamper-evident audit logging (SHA-256 hash chain).

Each record's hash covers its content plus the previous record's hash, so any edit,
deletion or reordering breaks verification. On SQL Server the migration additionally
installs a trigger that rejects UPDATE and DELETE on audit_logs, and appends are
serialised with sp_getapplock so the chain cannot fork under concurrency.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.logging import redact
from app.core.timeutil import utcnow
from app.models import AuditLog

GENESIS = "0" * 64


def _canonical(rec: AuditLog) -> str:
    ts = rec.ts.isoformat(timespec="microseconds") if isinstance(rec.ts, datetime) else str(rec.ts)
    body = {
        "ts": ts, "actor_user_id": rec.actor_user_id, "actor_name": rec.actor_name, "action": rec.action,
        "target_type": rec.target_type, "target_id": rec.target_id, "target_name": rec.target_name,
        "device_id": rec.device_id, "result": rec.result, "ip": rec.ip_address, "details": rec.details,
        "prev": rec.prev_hash,
    }
    return json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))


def compute_hash(rec: AuditLog) -> str:
    return hashlib.sha256(_canonical(rec).encode()).hexdigest()


def record(
    db: Session, action: str, *, actor=None, actor_name: str | None = None, target_type: str = "",
    target_id="", target_name: str = "", device_id: int | None = None, result: str = "success",
    ip: str | None = None, details: dict | None = None,
) -> AuditLog:
    if db.get_bind().dialect.name == "mssql":
        db.execute(text("EXEC sp_getapplock @Resource='infrapilot_audit_chain', @LockMode='Exclusive', @LockOwner='Transaction', @LockTimeout=10000"))
    last = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    # Include pending (unflushed) audit rows in this session
    pending = [o for o in db.new if isinstance(o, AuditLog)]
    if pending:
        last = pending[-1].hash
    now = utcnow()
    rec = AuditLog(
        ts=now.replace(microsecond=(now.microsecond // 1000) * 1000),
        actor_user_id=getattr(actor, "id", None),
        actor_name=actor_name or getattr(actor, "username", None) or "system",
        action=action, target_type=target_type, target_id=str(target_id or ""), target_name=target_name[:300],
        device_id=device_id, result=result, ip_address=ip, details=redact(details or {}),
        prev_hash=last or GENESIS,
    )
    rec.hash = compute_hash(rec)
    db.add(rec)
    db.flush()
    return rec


def verify_chain(db: Session, limit: int | None = None) -> dict:
    prev = GENESIS
    checked = 0
    q = select(AuditLog).order_by(AuditLog.id)
    for rec in db.execute(q).scalars().all():
        if rec.prev_hash != prev:
            return {"valid": False, "checked": checked, "broken_at": rec.id, "reason": "chain link mismatch"}
        if compute_hash(rec) != rec.hash:
            return {"valid": False, "checked": checked, "broken_at": rec.id, "reason": "record content altered"}
        prev = rec.hash
        checked += 1
        if limit and checked >= limit:
            break
    return {"valid": True, "checked": checked, "broken_at": None, "reason": None}

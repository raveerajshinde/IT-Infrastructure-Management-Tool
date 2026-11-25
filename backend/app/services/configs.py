"""Configuration backup storage and diffing."""
from __future__ import annotations

import difflib
import hashlib
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ConfigBackup, ConfigChange

# Lines that change on every export and would make diffs noisy
VOLATILE = [re.compile(p) for p in (r"^! Last configuration change at", r"^! NVRAM config last updated", r"^Current configuration : \d+ bytes",
                                    r"^# \w{3}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} by RouterOS", r"^#conf_file_ver=", r"^ntp clock-period")]

SECRET_LINES = re.compile(r"(?im)^(\s*(?:enable secret|enable password|username \S+ (?:secret|password)|snmp-server community|"
                          r"set (?:password|passwd|psksecret|private-key)|key-string|pre-shared-key)\s+)(\S.*)$")


def normalise(text: str) -> str:
    return "\n".join(ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n") if not any(p.match(ln) for p in VOLATILE))


def mask_secrets(text: str) -> str:
    """Mask secret material in configs for display. Stored backups keep the original (DB access is restricted)."""
    return SECRET_LINES.sub(lambda m: m.group(1) + "<redacted>", text)


def store_backup(db: Session, device_id: int, kind: str, content: str, job_execution_id: int | None = None, note: str = "") -> tuple[ConfigBackup, bool]:
    """Store a backup; returns (backup, changed). Identical content to the latest backup of that kind is not duplicated."""
    norm = normalise(content)
    digest = hashlib.sha256(norm.encode()).hexdigest()
    latest = db.execute(select(ConfigBackup).where(ConfigBackup.device_id == device_id, ConfigBackup.kind == kind)
                        .order_by(ConfigBackup.id.desc()).limit(1)).scalar_one_or_none()
    if latest and latest.sha256 == digest:
        return latest, False
    b = ConfigBackup(device_id=device_id, kind=kind, content=content, sha256=digest, size=len(content.encode()),
                     job_execution_id=job_execution_id, note=note)
    db.add(b)
    db.flush()
    return b, True


def diff(a: str, b: str, a_name: str = "before", b_name: str = "after") -> str:
    return "".join(difflib.unified_diff(mask_secrets(normalise(a)).splitlines(keepends=True) if a else [],
                                        mask_secrets(normalise(b)).splitlines(keepends=True) if b else [],
                                        fromfile=a_name, tofile=b_name, n=3))


def record_change(db: Session, device_id: int, execution_id: int | None, before: ConfigBackup, after: ConfigBackup) -> ConfigChange:
    c = ConfigChange(device_id=device_id, job_execution_id=execution_id, backup_before_id=before.id, backup_after_id=after.id,
                     diff=diff(before.content, after.content, f"backup#{before.id}", f"backup#{after.id}"))
    db.add(c)
    db.flush()
    return c

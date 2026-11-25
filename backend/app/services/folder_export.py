"""Copy device configuration backups into a folder on the InfraPilot server.

The folder is any path under one of the export roots (IP_EXPORT_ROOTS, default /srv/infrapilot-exports, /mnt, /media).
Those roots are bind-mounted into the api and worker containers at the SAME path, so the path typed in
Settings -> Backup is exactly the path on the host: a local disk, a USB drive under /media, or a NAS/Windows share
mounted under /mnt (CIFS or NFS, mounted with write access for uid 10001).

Layout:

    <folder>/<hostname>/<YYYYmmdd-HHMMSS>_<kind>.cfg    one file per backup that changed the configuration
    <folder>/<hostname>/latest_<kind>.cfg                always the newest configuration (optional, on by default)

Every scheduled (or manual) configuration backup is copied within about a minute by the worker.
Retention (keep_days > 0) only deletes files matching the timestamped name above; nothing else in the folder is touched.
"""
from __future__ import annotations

import logging
import os
import posixpath
import uuid
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.core.timeutil import utcnow
from app.models import ConfigBackup, Device, SystemSetting
from app.services import configs, settings_store
from app.services.offsite import SAFE, LocalStore, prune

log = logging.getLogger("infrapilot.folder_export")
STATE_KEY = "devexport.state"


# ------------------------------------------------------------------ configuration
def roots() -> list[str]:
    return [posixpath.normpath(r) for r in get_settings().export_roots.split(":") if r.strip().startswith("/")]


def validate_path(v: str) -> str:
    """Absolute POSIX path under an export root, no '..'. Returns the normalised path."""
    v = str(v).strip()
    if "\\" in v or not v.startswith("/"):
        raise ValidationFailed("Folder must be an absolute path on the InfraPilot server, e.g. /mnt/nas/device-backups "
                               "(for a Windows share use the Network share (SMB) section)")
    if any(part == ".." for part in v.split("/")) or any(ord(c) < 32 for c in v) or len(v) > 400:
        raise ValidationFailed("Folder path contains invalid characters or '..'")
    norm = posixpath.normpath(v)
    allowed = roots()
    if not any(norm == r or norm.startswith(r.rstrip("/") + "/") for r in allowed):
        raise ValidationFailed(f"Folder must be inside one of: {', '.join(allowed)}. To use another disk or a NAS, mount it "
                               "under /mnt (e.g. /mnt/nas) on the server first")
    return norm


def folder(db: Session) -> Path | None:
    v = settings_store.all_values(db)
    if not v.get("devexport.enabled") or not v.get("devexport.path"):
        return None
    return Path(v["devexport.path"])


class FolderStore(LocalStore):
    """LocalStore with atomic writes (temp file + rename) and fsync, so a reader never sees half a file."""

    def put(self, local: Path | None, *parts: str, data: bytes | None = None) -> int:
        final = self._p(*parts)
        tmp = final.with_name(f".{final.name}.{uuid.uuid4().hex[:6]}.partial")
        try:
            with open(tmp, "wb") as fo:
                fo.write(data if data is not None else Path(local).read_bytes())
                fo.flush()
                os.fsync(fo.fileno())
            os.replace(tmp, final)
        finally:
            tmp.unlink(missing_ok=True)
        return final.stat().st_size


def _explain(exc: Exception, path: Path) -> str:
    msg = f"{exc.__class__.__name__}: {exc}"
    if isinstance(exc, PermissionError):
        msg += (f" - the InfraPilot containers run as uid 10001: run `sudo mkdir -p {path} && sudo chown -R 10001:10001 {path}` on the server"
                " (for a CIFS mount add uid=10001,gid=10001 to the mount options)")
    elif isinstance(exc, FileNotFoundError):
        msg += f" - {path} does not exist on the server or is not mounted"
    elif isinstance(exc, OSError) and getattr(exc, "errno", None) == 30:
        msg += " - the folder is mounted read-only"
    return msg


def _open(db: Session, create: bool = True) -> tuple[Path, FolderStore]:
    p = folder(db)
    if p is None:
        raise ValidationFailed("Enable 'Copy device backups to a folder', enter the folder and Save first")
    root = next((r for r in roots() if str(p) == r or str(p).startswith(r.rstrip("/") + "/")), None)
    if root is None:
        raise ValidationFailed(f"{p} is not inside an allowed export root ({', '.join(roots())})")
    if not Path(root).is_dir():
        raise ValidationFailed(f"{root} is not available inside InfraPilot - check the volumes in docker-compose.yml and run infrapilot-update")
    if create:
        p.mkdir(parents=True, exist_ok=True)
    return p, FolderStore(p)


# ------------------------------------------------------------------ state
def _state(db: Session) -> dict:
    row = db.get(SystemSetting, STATE_KEY)
    return dict(row.value or {}) if row else {}


def save_state(db: Session, **kw) -> None:
    row = db.get(SystemSetting, STATE_KEY)
    if row is None:
        row = SystemSetting(key=STATE_KEY, value={})
        db.add(row)
    row.value = {**(row.value or {}), **kw}
    db.commit()


def status(db: Session) -> dict:
    return _state(db)


def record_error(db: Session, message: str) -> None:
    db.rollback()
    save_state(db, last_error=message[:1000], last_error_at=utcnow().isoformat() + "Z")


def pending(db: Session) -> bool:
    newest = db.execute(select(func.max(ConfigBackup.id))).scalar() or 0
    return newest > int(_state(db).get("last_config_id") or 0)


# ------------------------------------------------------------------ operations
def test(db: Session) -> tuple[bool, str]:
    """Create the folder, write, read back and delete a small file."""
    p = folder(db)
    try:
        p, store = _open(db)
        name = f".infrapilot-write-test-{uuid.uuid4().hex[:8]}"
        payload = f"InfraPilot write test {utcnow().isoformat()}".encode()
        store.put(None, name, data=payload)
        ok = store.get(name) == payload
        store.remove(name)
        st = os.statvfs(p)
        free_gb = st.f_bavail * st.f_frsize / 1024**3
        return ok, (f"{p}: write, read and delete succeeded ({free_gb:.1f} GB free)" if ok else "Read-back did not match what was written")
    except ValidationFailed as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, _explain(exc, p) if p else str(exc)


def export(db: Session, limit: int = 2000, from_start: bool = False) -> dict:
    """Write configuration backups taken since the last export. from_start=True rewrites every stored backup."""
    if from_start:
        save_state(db, last_config_id=0)
        total = 0
        while True:
            n = export(db, limit)["exported"]
            total += n
            if n < limit:
                return {"exported": total, "folder": str(folder(db))}
    v = settings_store.all_values(db)
    p, store = _open(db)
    last = int(_state(db).get("last_config_id") or 0)
    rows = db.execute(select(ConfigBackup, Device.hostname).join(Device, Device.id == ConfigBackup.device_id)
                      .where(ConfigBackup.id > last).order_by(ConfigBackup.id).limit(limit)).all()
    full = (v.get("devexport.mode") or "full") == "full"
    write_latest = bool(v.get("devexport.write_latest", True))
    n = 0
    try:
        for cb, host in rows:
            sub = SAFE.sub("_", host)[:80] or f"device-{cb.device_id}"
            store.makedirs(sub)
            kind = SAFE.sub("_", cb.kind)
            if full:
                body = cb.content
            else:
                body = (f"! InfraPilot configuration backup - {host} - {cb.kind} - {cb.created_at.isoformat()}Z\n"
                        f"! sha256 of the original (unmasked) configuration: {cb.sha256}\n! Secrets are masked in this copy.\n"
                        + configs.mask_secrets(cb.content))
            data = body.encode()
            store.put(None, sub, f"{cb.created_at.strftime('%Y%m%d-%H%M%S')}_{kind}.cfg", data=data)
            if write_latest:
                store.put(None, sub, f"latest_{kind}.cfg", data=data)
            last = cb.id
            n += 1
        keep = int(v.get("devexport.keep_days") or 0)
        pruned = prune(_DevicesView(store), keep, only_devices=True) if keep > 0 else 0
    except OSError as exc:
        if n:  # keep progress so files already written are not rewritten
            save_state(db, last_config_id=last)
        raise ValidationFailed(_explain(exc, p)) from exc
    save_state(db, last_config_id=last, last_export_at=utcnow().isoformat() + "Z", last_export_count=n, folder=str(p), last_error=None)
    return {"exported": n, "pruned": pruned, "folder": str(p)}


class _DevicesView:
    """Lets offsite.prune (which looks under 'devices/<host>') sweep <folder>/<host> directly."""

    def __init__(self, store: FolderStore):
        self.s = store

    def listdir(self, *parts: str) -> list[str]:
        if parts and parts[0] == "devices":
            parts = parts[1:]
            if not parts:
                return [d for d in self.s.listdir() if (self.s.root / d).is_dir()]
        return self.s.listdir(*parts)

    def remove(self, *parts: str) -> None:
        self.s.remove(*(parts[1:] if parts and parts[0] == "devices" else parts))

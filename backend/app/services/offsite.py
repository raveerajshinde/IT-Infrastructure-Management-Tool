"""Copy backups to a network share (SMB 2/3 — Windows file server, NAS).

What goes to the share (each part can be switched off in Settings -> Backup storage):

    <share>\\database\\infrapilot_<label>_<ts>.bak        SQL Server backup (vault secrets inside stay encrypted)
    <share>\\config\\infrapilot_config_<label>_<ts>.tar.gz.enc
                                                      .env, compose file, secrets, certificates - ALWAYS encrypted
                                                      with the backup passphrase (OpenSSL-compatible: restore.sh /
                                                      `openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000`)
    <share>\\SHA256SUMS-<ts>                           checksums of the files above as stored on the share
    <share>\\devices\\<hostname>\\<ts>_<kind>.cfg         device configuration backups: exact copies (restorable,
                                                      default) or with secrets masked (Settings choice)

Retention only ever deletes files matching these InfraPilot names; nothing else on the share is touched.
The SMB connection requires SMB3 encryption by default (switch off only for old NAS devices).
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets as pysecrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Protocol

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.core.timeutil import utcnow
from app.models import ConfigBackup, Device, SystemSetting
from app.services import configs, settings_store

log = logging.getLogger("infrapilot.offsite")
STATE_KEY = "offsite.state"
TS_RX = re.compile(r"(\d{8}-\d{6})")
SAFE = re.compile(r"[^A-Za-z0-9._-]+")
CHUNK = 4 * 1024 * 1024


# ------------------------------------------------------------------ encryption (OpenSSL compatible)
def encrypt_file(src: Path, dst: Path, passphrase: str, iterations: int = 200_000) -> None:
    """Same format as `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt` so restore.sh can decrypt it."""
    salt = pysecrets.token_bytes(8)
    km = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=iterations).derive(passphrase.encode())
    enc = Cipher(algorithms.AES(km[:32]), modes.CBC(km[32:])).encryptor()
    pad = padding.PKCS7(128).padder()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(b"Salted__" + salt)
        while chunk := fi.read(CHUNK):
            fo.write(enc.update(pad.update(chunk)))
        fo.write(enc.update(pad.finalize()) + enc.finalize())


def decrypt_bytes(data: bytes, passphrase: str, iterations: int = 200_000) -> bytes:
    if data[:8] != b"Salted__":
        raise ValueError("not an OpenSSL salted file")
    km = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=data[8:16], iterations=iterations).derive(passphrase.encode())
    dec = Cipher(algorithms.AES(km[:32]), modes.CBC(km[32:])).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(dec.update(data[16:]) + dec.finalize()) + unpad.finalize()


# ------------------------------------------------------------------ storage
class Store(Protocol):
    def makedirs(self, *parts: str) -> None: ...
    def put(self, local: Path | None, *parts: str, data: bytes | None = None) -> int: ...
    def get(self, *parts: str) -> bytes: ...
    def listdir(self, *parts: str) -> list[str]: ...
    def remove(self, *parts: str) -> None: ...
    def close(self) -> None: ...


@dataclass
class Target:
    server: str
    share: str
    folder: list[str]
    username: str
    password: str
    domain: str
    require_encryption: bool
    port: int = 445

    @property
    def unc(self) -> str:
        return "\\\\" + "\\".join([self.server, self.share, *self.folder])


def parse_unc(unc: str) -> tuple[str, str, list[str]]:
    parts = [p for p in unc.replace("/", "\\").split("\\") if p]
    if len(parts) < 2:
        raise ValidationFailed("Share must look like \\\\fileserver\\backups")
    return parts[0], parts[1], parts[2:]


class SmbStore:
    """Thin wrapper over smbprotocol's high-level client."""

    def __init__(self, t: Target):
        import smbclient

        self._c = smbclient
        self.t = t
        user = f"{t.domain}\\{t.username}" if t.domain and "\\" not in t.username and "@" not in t.username else t.username
        # Passed on every call: if the SMB session drops mid-run, smbclient re-connects WITH these credentials.
        self._kw = {"username": user or None, "password": t.password or None, "port": t.port, "encrypt": t.require_encryption,
                    "connection_timeout": 15}
        try:
            smbclient.register_session(t.server, **self._kw)
        except Exception as exc:  # noqa: BLE001
            raise ConnectionError(_explain(exc, t)) from exc

    def _p(self, *parts: str) -> str:
        return "\\\\" + "\\".join([self.t.server, self.t.share, *self.t.folder, *parts])

    def makedirs(self, *parts: str) -> None:
        self._c.makedirs(self._p(*parts), exist_ok=True, **self._kw)

    def put(self, local: Path | None, *parts: str, data: bytes | None = None) -> int:
        tmp = self._p(*parts[:-1], f".{parts[-1]}.{uuid.uuid4().hex[:6]}.partial")
        n = 0
        with self._c.open_file(tmp, mode="wb", **self._kw) as fo:
            if data is not None:
                fo.write(data)
                n = len(data)
            else:
                with open(local, "rb") as fi:
                    while chunk := fi.read(CHUNK):
                        fo.write(chunk)
                        n += len(chunk)
        final = self._p(*parts)
        try:
            self._c.remove(final, **self._kw)
        except OSError:
            pass
        self._c.rename(tmp, final, **self._kw)  # never leave a half-written file under the real name
        if self._c.stat(final, **self._kw).st_size != n:
            raise OSError(f"size mismatch after upload of {parts[-1]}")
        return n

    def get(self, *parts: str) -> bytes:
        with self._c.open_file(self._p(*parts), mode="rb", **self._kw) as f:
            return f.read()

    def listdir(self, *parts: str) -> list[str]:
        try:
            return list(self._c.listdir(self._p(*parts), **self._kw))
        except OSError:
            return []

    def remove(self, *parts: str) -> None:
        self._c.remove(self._p(*parts), **self._kw)

    def close(self) -> None:
        try:
            self._c.delete_session(self.t.server, port=self.t.port)
        except Exception:  # noqa: BLE001
            pass


class LocalStore:
    """Directory-backed store (tests, or a share already mounted on the host)."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def _p(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def makedirs(self, *parts: str) -> None:
        self._p(*parts).mkdir(parents=True, exist_ok=True)

    def put(self, local: Path | None, *parts: str, data: bytes | None = None) -> int:
        p = self._p(*parts)
        p.write_bytes(data if data is not None else Path(local).read_bytes())
        return p.stat().st_size

    def get(self, *parts: str) -> bytes:
        return self._p(*parts).read_bytes()

    def listdir(self, *parts: str) -> list[str]:
        p = self._p(*parts)
        return sorted(os.listdir(p)) if p.is_dir() else []

    def remove(self, *parts: str) -> None:
        self._p(*parts).unlink()

    def close(self) -> None:
        pass


def _explain(exc: Exception, t: Target) -> str:
    msg = f"{exc.__class__.__name__}: {exc}"
    hints = []
    if re.search(r"LOGON_FAILURE|0xc000006d|password", msg, re.I):
        hints.append("check the user name, domain and password")
    if re.search(r"BAD_NETWORK_NAME|0xc00000cc", msg, re.I):
        hints.append(f"the share '{t.share}' does not exist on {t.server}")
    if re.search(r"ACCESS_DENIED|0xc0000022", msg, re.I):
        hints.append("the account needs Modify (read/write/delete) permission on the share and folder")
    if re.search(r"timed out|No route|unreachable|refused|Errno 11[0-3]|Name or service not known", msg, re.I):
        hints.append(f"cannot reach {t.server} on TCP 445 from the InfraPilot server (firewall/DNS)")
    if re.search(r"encrypt", msg, re.I) and t.require_encryption:
        hints.append("the server does not support SMB3 encryption - untick 'Require SMB encryption' only if the network is trusted")
    return msg + (" - " + "; ".join(hints) if hints else "")


# ------------------------------------------------------------------ configuration
def target(db: Session) -> Target | None:
    v = settings_store.all_values(db)
    if not v.get("offsite.enabled") or not v.get("offsite.share"):
        return None
    server, share, folder = parse_unc(v["offsite.share"])
    return Target(server, share, folder, v.get("offsite.username") or "", settings_store.secret(db, "offsite.password"),
                  v.get("offsite.domain") or "", bool(v.get("offsite.require_encryption", True)))


def open_store(db: Session, t: Target | None = None) -> Store:
    t = t or target(db)
    if t is None:
        raise ValidationFailed("Backup storage is not enabled or no share is configured")
    return SmbStore(t)


def _state(db: Session) -> dict:
    row = db.get(SystemSetting, STATE_KEY)
    return dict(row.value or {}) if row else {}


def _save_state(db: Session, **kw) -> None:
    row = db.get(SystemSetting, STATE_KEY)
    if row is None:
        row = SystemSetting(key=STATE_KEY, value={})
        db.add(row)
    row.value = {**(row.value or {}), **kw}
    db.commit()


def status(db: Session) -> dict:
    return _state(db)


# ------------------------------------------------------------------ operations
def test(db: Session, store: Store | None = None) -> tuple[bool, str]:
    """Connect, create the folders, write, read back and delete a small file."""
    t = target(db)
    try:
        store = store or open_store(db, t)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    try:
        for d in ("database", "config", "devices"):
            store.makedirs(d)
        name = f".infrapilot-write-test-{uuid.uuid4().hex[:8]}"
        payload = f"InfraPilot write test {utcnow().isoformat()}".encode()
        store.put(None, name, data=payload)
        ok = store.get(name) == payload
        store.remove(name)
        where = t.unc if t else "share"
        return ok, (f"Connected to {where}: write, read and delete succeeded" + (" (SMB3 encryption required)" if t and t.require_encryption else "")
                    if ok else "Read-back did not match what was written")
    except Exception as exc:  # noqa: BLE001
        return False, _explain(exc, t) if t else str(exc)
    finally:
        store.close()


def _latest_set(backup_dir: Path) -> tuple[str, list[Path]] | None:
    sums = sorted(backup_dir.glob("SHA256SUMS-*"))
    if not sums:
        return None
    latest = sums[-1]
    ts = latest.name.split("-", 1)[1]
    files = []
    for line in latest.read_text().splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        host_path = Path(parts[1].strip().lstrip("*"))
        local = backup_dir / host_path.parent.name / host_path.name  # host paths -> mounted backup dir
        if local.is_file():
            files.append(local)
    return ts, files


def upload_backup_set(db: Session, backup_dir: Path, store: Store | None = None) -> dict:
    """Upload the newest database/config backup set produced by backup.sh."""
    v = settings_store.all_values(db)
    found = _latest_set(Path(backup_dir))
    if not found:
        raise ValidationFailed(f"No backup sets found in {backup_dir}")
    ts, files = found
    passphrase = settings_store.secret(db, "offsite.passphrase")
    store = store or open_store(db)
    uploaded, skipped, sums = [], [], []
    try:
        for d in ("database", "config"):
            store.makedirs(d)
        for f in files:
            if f.suffix == ".bak":
                if not v.get("offsite.include_database", True):
                    continue
                n = store.put(f, "database", f.name)
                sums.append((_sha256(f), f"database/{f.name}"))
                uploaded.append({"file": f"database/{f.name}", "bytes": n})
            elif f.name.startswith("infrapilot_config_"):
                if not v.get("offsite.include_config", True):
                    continue
                if f.name.endswith(".enc"):
                    src, name = f, f.name  # already encrypted by backup.sh --passphrase-file
                elif not passphrase:
                    skipped.append(f"{f.name}: not uploaded - set a backup encryption passphrase (it contains the vault key)")
                    continue
                else:
                    src, name = Path("/tmp") / f"{f.name}.{uuid.uuid4().hex[:6]}.enc", f"{f.name}.enc"
                    encrypt_file(f, src, passphrase)
                try:
                    n = store.put(src, "config", name)
                    sums.append((_sha256(src), f"config/{name}"))
                    uploaded.append({"file": f"config/{name}", "bytes": n})
                finally:
                    if src is not f:
                        src.unlink(missing_ok=True)
        if sums:
            store.put(None, f"SHA256SUMS-{ts}", data="".join(f"{h}  {p}\n" for h, p in sums).encode())
        pruned = prune(store, int(v.get("offsite.keep_days") or 30))
    finally:
        store.close()
    result = {"backup_set": ts, "uploaded": uploaded, "skipped": skipped, "pruned": pruned}
    _save_state(db, last_backup_upload_at=utcnow().isoformat() + "Z", last_backup_set=ts, last_backup_ok=not skipped,
                last_backup_message=f"{len(uploaded)} file(s) uploaded" + (f"; {len(skipped)} skipped" if skipped else ""), last_error=None)
    return result


def pending_device_configs(db: Session) -> bool:
    """Whether configuration backups exist that have not been copied to the share yet."""
    from sqlalchemy import func
    newest = db.execute(select(func.max(ConfigBackup.id))).scalar() or 0
    return newest > int(_state(db).get("last_config_id") or 0)


def export_device_configs(db: Session, store: Store | None = None, limit: int = 2000, from_start: bool = False) -> dict:
    """Write configuration backups taken since the last export (exact copies or masked, per settings).

    from_start=True copies every stored backup again (e.g. after switching between masked and full copies);
    files on the share with the same name are replaced.
    """
    if from_start:
        _save_state(db, last_config_id=0)
        total = 0
        while True:
            n = export_device_configs(db, store, limit)["exported"]
            total += n
            if n < limit:
                return {"exported": total}
    v = settings_store.all_values(db)
    if not v.get("offsite.include_device_configs", True):
        return {"exported": 0}
    st = _state(db)
    last = int(st.get("last_config_id") or 0)
    rows = db.execute(select(ConfigBackup, Device.hostname).join(Device, Device.id == ConfigBackup.device_id)
                      .where(ConfigBackup.id > last).order_by(ConfigBackup.id).limit(limit)).all()
    if not rows:
        _save_state(db, last_config_export_at=utcnow().isoformat() + "Z")
        return {"exported": 0}
    full = (v.get("offsite.device_configs_mode") or "full") == "full"
    store = store or open_store(db)
    n = 0
    try:
        store.makedirs("devices")
        made: set[str] = set()
        for cb, host in rows:
            folder = SAFE.sub("_", host)[:80] or f"device-{cb.device_id}"
            if folder not in made:
                store.makedirs("devices", folder)
                made.add(folder)
            name = f"{cb.created_at.strftime('%Y%m%d-%H%M%S')}_{SAFE.sub('_', cb.kind)}.cfg"
            if full:
                # Exact configuration as taken from the device, so it can be used to restore it.
                body = cb.content
            else:
                body = (f"! InfraPilot configuration backup - {host} - {cb.kind} - {cb.created_at.isoformat()}Z\n"
                        f"! sha256 of the original (unmasked) configuration: {cb.sha256}\n! Secrets are masked in this copy.\n"
                        + configs.mask_secrets(cb.content))
            store.put(None, "devices", folder, name, data=body.encode())
            last = cb.id
            n += 1
        prune(store, int(v.get("offsite.keep_days") or 30), only_devices=True)
    finally:
        store.close()
    _save_state(db, last_config_id=last, last_config_export_at=utcnow().isoformat() + "Z", last_config_export_count=n, last_error=None)
    return {"exported": n}


def _ts_of(name: str) -> datetime | None:
    m = TS_RX.search(name)
    try:
        return datetime.strptime(m.group(1), "%Y%m%d-%H%M%S") if m else None
    except ValueError:
        return None


def prune(store: Store, keep_days: int, only_devices: bool = False) -> int:
    """Delete InfraPilot files older than keep_days. Never touches files with other names."""
    cutoff = utcnow() - timedelta(days=keep_days)
    removed = 0

    def sweep(names: Iterable[str], rx: re.Pattern, *folder: str) -> None:
        nonlocal removed
        for n in names:
            if rx.fullmatch(n) and (ts := _ts_of(n)) and ts < cutoff:
                try:
                    store.remove(*folder, n)
                    removed += 1
                except OSError as exc:
                    log.warning("could not prune %s: %s", n, exc)

    if not only_devices:
        sweep(store.listdir("database"), re.compile(r"infrapilot_[a-z0-9-]+_\d{8}-\d{6}\.bak"), "database")
        sweep(store.listdir("config"), re.compile(r"infrapilot_config_[a-z0-9-]+_\d{8}-\d{6}\.tar\.gz\.enc"), "config")
        sweep(store.listdir(), re.compile(r"SHA256SUMS-\d{8}-\d{6}"))
    for host in store.listdir("devices"):
        sweep(store.listdir("devices", host), re.compile(r"\d{8}-\d{6}_[A-Za-z0-9._-]+\.cfg"), "devices", host)
    return removed


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def record_error(db: Session, message: str) -> None:
    db.rollback()
    _save_state(db, last_error=message[:1000], last_error_at=utcnow().isoformat() + "Z")

"""Backups to a network share: encryption compatibility, upload set, device config export, retention, API."""
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.timeutil import utcnow
from app.services import offsite, settings_store
from tests.conftest import H, add_device, run_worker_once

PASS = "correct horse battery staple"


def _enable(admin, **extra):
    r = admin.put("/api/settings", headers=H, json={"values": {"offsite.enabled": True, "offsite.share": "\\\\nas01\\backups\\infrapilot",
                                                               "offsite.username": "svc_backup", "offsite.domain": "CORP",
                                                               "offsite.password": "Sh4re!pass", "offsite.passphrase": PASS, **extra}})
    assert r.status_code == 200, r.text


def _backup_dir(tmp_path: Path, ts="20261116-013000") -> Path:
    b = tmp_path / "backups"
    (b / "mssql").mkdir(parents=True)
    (b / "config").mkdir()
    bak = b / "mssql" / f"infrapilot_nightly_{ts}.bak"
    bak.write_bytes(b"TAPE" * 5000)
    cfg = b / "config" / f"infrapilot_config_nightly_{ts}.tar.gz"
    cfg.write_bytes(b"vault key and secrets" * 100)
    (b / f"SHA256SUMS-{ts}").write_text(f"aaa  /opt/infrapilot/backups/mssql/{bak.name}\nbbb  /opt/infrapilot/backups/config/{cfg.name}\n")
    return b


def test_encryption_is_openssl_compatible(tmp_path):
    src, enc, out = tmp_path / "a.tgz", tmp_path / "a.tgz.enc", tmp_path / "out.tgz"
    src.write_bytes(bytes(range(256)) * 999)
    offsite.encrypt_file(src, enc, PASS)
    pf = tmp_path / "pass"
    pf.write_text(PASS)
    subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-in", str(enc), "-out", str(out), "-pass", f"file:{pf}"], check=True)
    assert out.read_bytes() == src.read_bytes()
    assert offsite.decrypt_bytes(enc.read_bytes(), PASS) == src.read_bytes()


def test_share_settings_validation(admin):
    bad = [{"offsite.share": "nas01/backups"}, {"offsite.share": "\\\\nas01"}, {"offsite.share": "\\\\nas 01\\x"},
           {"offsite.passphrase": "short"}, {"offsite.keep_days": 0}]
    for b in bad:
        assert admin.put("/api/settings", headers=H, json={"values": b}).status_code == 422, b
    ok = admin.put("/api/settings", headers=H, json={"values": {"offsite.share": "//10.0.0.5/share/infra"}}).json()
    assert ok["offsite.share"] == "\\\\10.0.0.5\\share\\infra"
    s = admin.get("/api/settings").json()
    assert s["offsite.password"] == "" and "offsite.passphrase" not in str({k: v for k, v in s.items() if k == "offsite.passphrase" and v})


def test_upload_backup_set_encrypts_config_and_writes_checksums(admin, db, tmp_path):
    _enable(admin)
    share = tmp_path / "share"
    store = offsite.LocalStore(share)
    r = offsite.upload_backup_set(db, _backup_dir(tmp_path), store)
    assert {u["file"] for u in r["uploaded"]} == {"database/infrapilot_nightly_20261116-013000.bak",
                                                 "config/infrapilot_config_nightly_20261116-013000.tar.gz.enc"}
    enc = (share / "config" / "infrapilot_config_nightly_20261116-013000.tar.gz.enc").read_bytes()
    assert b"vault key" not in enc and offsite.decrypt_bytes(enc, PASS) == b"vault key and secrets" * 100
    sums = (share / "SHA256SUMS-20261116-013000").read_text()
    assert "database/infrapilot_nightly_20261116-013000.bak" in sums and len(sums.splitlines()) == 2
    st = admin.get("/api/backup-storage").json()["status"]
    assert st["last_backup_set"] == "20261116-013000" and st["last_backup_ok"] is True


def test_config_never_uploaded_unencrypted(admin, db, tmp_path):
    admin.put("/api/settings", headers=H, json={"values": {"offsite.enabled": True, "offsite.share": "\\\\nas01\\b"}})
    share = tmp_path / "share"
    r = offsite.upload_backup_set(db, _backup_dir(tmp_path), offsite.LocalStore(share))
    assert [u["file"] for u in r["uploaded"]] == ["database/infrapilot_nightly_20261116-013000.bak"]
    assert "passphrase" in r["skipped"][0]
    assert list((share / "config").iterdir()) == []  # nothing from the config archive reached the share


def test_device_configs_exported_masked_and_incrementally(admin, db, tmp_path):
    _enable(admin, **{"offsite.device_configs_mode": "masked"})
    from app.services import configs
    d = add_device(admin, hostname="core-sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    configs.store_backup(db, d["id"], "running", "hostname core-sw1\nsnmp-server community S3cretComm RO\nenable secret 5 $1$abc$xyz\n")
    db.commit()
    store = offsite.LocalStore(tmp_path / "share")
    assert offsite.export_device_configs(db, store)["exported"] == 1
    files = list((tmp_path / "share" / "devices" / "core-sw1").iterdir())
    text = files[0].read_text()
    assert "hostname core-sw1" in text and "S3cretComm" not in text and "Secrets are masked" in text
    assert offsite.export_device_configs(db, offsite.LocalStore(tmp_path / "share"))["exported"] == 0  # nothing new


def test_retention_only_deletes_infrapilot_files(tmp_path):
    share = tmp_path / "share"
    store = offsite.LocalStore(share)
    for d in ("database", "config", "devices/sw1"):
        (share / d).mkdir(parents=True)
    old = (utcnow() - timedelta(days=40)).strftime("%Y%m%d-%H%M%S")
    new = (utcnow() - timedelta(days=2)).strftime("%Y%m%d-%H%M%S")
    for n in (f"database/infrapilot_nightly_{old}.bak", f"database/infrapilot_nightly_{new}.bak", f"database/someone-elses_{old}.bak",
              f"config/infrapilot_config_nightly_{old}.tar.gz.enc", f"SHA256SUMS-{old}", f"devices/sw1/{old}_running.cfg",
              f"devices/sw1/{new}_running.cfg", "devices/sw1/notes.txt"):
        (share / n).write_text("x")
    assert offsite.prune(store, 30) == 4
    left = sorted(str(p.relative_to(share)) for p in share.rglob("*") if p.is_file())
    assert left == sorted([f"database/infrapilot_nightly_{new}.bak", f"database/someone-elses_{old}.bak",
                           f"devices/sw1/{new}_running.cfg", "devices/sw1/notes.txt"])


def test_api_test_and_export_endpoints(admin, monkeypatch, tmp_path):
    assert admin.post("/api/backup-storage/test", headers=H).status_code == 422  # not enabled yet
    _enable(admin)
    monkeypatch.setattr(offsite, "open_store", lambda db, t=None: offsite.LocalStore(tmp_path / "share"))
    r = admin.post("/api/backup-storage/test", headers=H).json()
    assert r["ok"] and "write, read and delete succeeded" in r["message"]
    assert (tmp_path / "share" / "devices").is_dir()
    assert admin.post("/api/backup-storage/export-configs", headers=H).json() == {"exported": 0}


def test_smb_errors_are_explained():
    t = offsite.Target("nas01", "backups", [], "u", "p", "", True)
    assert "user name, domain and password" in offsite._explain(Exception("STATUS_LOGON_FAILURE"), t)
    assert "does not exist on nas01" in offsite._explain(Exception("STATUS_BAD_NETWORK_NAME"), t)
    assert "Modify" in offsite._explain(Exception("STATUS_ACCESS_DENIED"), t)
    assert "TCP 445" in offsite._explain(OSError("[Errno 113] No route to host"), t)


def test_cli_upload_skips_when_disabled(capsys):
    from app import cli
    cli.main(["offsite-upload", "--dir", "/nonexistent"])
    assert "not enabled" in capsys.readouterr().out


CFG = "hostname core-sw1\nsnmp-server community S3cretComm RO\nusername admin secret 9 $9$abcdef\n!\nend\n"


def test_full_copies_are_exact_and_restorable(admin, db, tmp_path):
    _enable(admin)  # default: full copies
    from app.services import configs
    d = add_device(admin, hostname="core-sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    configs.store_backup(db, d["id"], "running", CFG)
    db.commit()
    offsite.export_device_configs(db, offsite.LocalStore(tmp_path / "share"))
    f = next((tmp_path / "share" / "devices" / "core-sw1").iterdir())
    assert f.read_text() == CFG and f.name.endswith("_running.cfg")


def test_worker_copies_new_backups_soon_and_reexport_all(admin, db, monkeypatch, tmp_path):
    from app.services import configs
    _enable(admin, **{"offsite.device_configs_mode": "masked"})
    monkeypatch.setattr(offsite, "open_store", lambda db, t=None: offsite.LocalStore(tmp_path / "share"))
    from app.core.db import SessionLocal
    from app.worker import main as wm
    with SessionLocal() as s:
        wm._offsite_export(s)  # nothing pending: does nothing
    assert offsite.status(db).get("last_config_export_try") is None
    d = add_device(admin, hostname="fw1", ip_address="10.0.0.9", platform="fortigate", device_type="firewall")
    configs.store_backup(db, d["id"], "full", "config system global\n    set hostname fw1\n    set admin-password ENC abc\nend\n")
    db.commit()
    with SessionLocal() as s:
        wm._offsite_export(s)
    f = next((tmp_path / "share" / "devices" / "fw1").iterdir())
    assert "Secrets are masked" in f.read_text()
    # switch to full copies and copy everything again: the same file is replaced by the exact configuration
    admin.put("/api/settings", headers=H, json={"values": {"offsite.device_configs_mode": "full"}})
    assert admin.post("/api/backup-storage/export-configs?all=true", headers=H).json() == {"exported": 1}
    assert f.read_text().startswith("config system global") and "Secrets are masked" not in f.read_text()
    assert admin.put("/api/settings", headers=H, json={"values": {"offsite.device_configs_mode": "plain"}}).status_code == 422

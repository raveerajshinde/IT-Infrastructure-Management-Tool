"""Device configuration backups copied into a folder on the server (Settings -> Backup -> Folder on the server)."""
from datetime import timedelta

import pytest

from app.core.timeutil import utcnow
from app.services import configs, folder_export
from tests.conftest import H, add_device

CFG = "hostname core-sw1\nsnmp-server community S3cretComm RO\nenable secret 5 $1$abc$xyz\n"


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "exports"
    r.mkdir()
    monkeypatch.setattr(folder_export, "roots", lambda: [str(r)])
    return r


def _enable(admin, path, **extra):
    r = admin.put("/api/settings", headers=H, json={"values": {"devexport.enabled": True, "devexport.path": str(path), **extra}})
    assert r.status_code == 200, r.text


def test_path_validation(admin, root):
    for bad in ("relative/dir", "\\\\nas\\share", "/etc/infrapilot", f"{root}/../escape", "C:\\backups"):
        r = admin.put("/api/settings", headers=H, json={"values": {"devexport.path": bad}})
        assert r.status_code == 422, bad
    ok = admin.put("/api/settings", headers=H, json={"values": {"devexport.path": f"{root}//site-a/"}}).json()
    assert ok["devexport.path"] == f"{root}/site-a"
    assert admin.put("/api/settings", headers=H, json={"values": {"devexport.mode": "zip"}}).status_code == 422


def test_full_copy_incremental_and_latest(admin, db, root):
    dest = root / "device-backups"
    _enable(admin, dest)
    d = add_device(admin, hostname="core-sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    configs.store_backup(db, d["id"], "running", CFG)
    db.commit()
    assert folder_export.pending(db)
    r = folder_export.export(db)
    assert r["exported"] == 1
    files = sorted(p.name for p in (dest / "core-sw1").iterdir())
    assert files[-1] == "latest_running.cfg" and files[0].endswith("_running.cfg")
    assert (dest / "core-sw1" / "latest_running.cfg").read_text() == CFG  # exact, restorable copy
    assert not list(dest.rglob("*.partial"))
    assert not folder_export.pending(db)
    assert folder_export.export(db)["exported"] == 0

    configs.store_backup(db, d["id"], "running", CFG + "interface Gi0/1\n")
    db.commit()
    assert folder_export.export(db)["exported"] == 1
    assert "Gi0/1" in (dest / "core-sw1" / "latest_running.cfg").read_text()
    assert len(list((dest / "core-sw1").glob("2*_running.cfg"))) >= 1


def test_masked_mode_and_copy_all_again_via_api(admin, db, root):
    dest = root / "masked"
    _enable(admin, dest, **{"devexport.mode": "masked"})
    d = add_device(admin, hostname="fw01", ip_address="10.0.0.3", platform="cisco_ios", device_type="switch")
    configs.store_backup(db, d["id"], "running", CFG)
    db.commit()
    r = admin.post("/api/backup-folder/export-configs", headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["exported"] == 1
    text = (dest / "fw01" / "latest_running.cfg").read_text()
    assert "S3cretComm" not in text and "Secrets are masked" in text
    assert admin.post("/api/backup-folder/export-configs?all=true", headers=H).json()["exported"] == 1
    st = admin.get("/api/backup-folder").json()
    assert st["enabled"] and st["status"]["last_export_count"] == 1


def test_connection_test_and_errors(admin, db, root):
    assert admin.post("/api/backup-folder/test", headers=H).json()["ok"] is False  # not enabled yet
    _enable(admin, root / "t")
    r = admin.post("/api/backup-folder/test", headers=H).json()
    assert r["ok"], r
    assert "GB free" in r["message"]
    assert [p for p in (root / "t").iterdir()] == []  # test file removed


def test_retention_only_removes_infrapilot_files(admin, db, root):
    dest = root / "ret"
    _enable(admin, dest, **{"devexport.keep_days": 30})
    (dest / "sw1").mkdir(parents=True)
    old = (utcnow() - timedelta(days=40)).strftime("%Y%m%d-%H%M%S")
    (dest / "sw1" / f"{old}_running.cfg").write_text("old")
    (dest / "sw1" / "latest_running.cfg").write_text("keep")
    (dest / "sw1" / "notes.txt").write_text("keep")
    d = add_device(admin, hostname="sw2", ip_address="10.0.0.9", platform="cisco_ios", device_type="switch")
    configs.store_backup(db, d["id"], "running", CFG)
    db.commit()
    r = folder_export.export(db)
    assert r["pruned"] == 1
    assert sorted(p.name for p in (dest / "sw1").iterdir()) == ["latest_running.cfg", "notes.txt"]


def test_worker_copies_scheduled_backups(admin, db, root):
    from app.worker.main import _folder_export
    dest = root / "auto"
    _enable(admin, dest)
    d = add_device(admin, hostname="edge-r1", ip_address="10.0.0.4", platform="cisco_ios", device_type="router")
    configs.store_backup(db, d["id"], "running", CFG)
    db.commit()
    _folder_export(db)
    assert (dest / "edge-r1" / "latest_running.cfg").exists()

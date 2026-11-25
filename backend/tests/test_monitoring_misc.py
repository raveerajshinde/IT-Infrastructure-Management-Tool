"""Monitoring/alerting, dashboard, settings, config diffs, migrations SQL."""
import os
import subprocess
import sys

from sqlalchemy import select

from app.models import Alert, Device, Notification
from app.services import configs, monitoring
from tests.conftest import H, add_device


def test_alert_open_dedupe_resolve(admin, db, monkeypatch):
    d = add_device(admin)
    dev = db.get(Device, d["id"])
    seq = iter([{"cpu_pct": 97.0}, {"cpu_pct": 98.0}, {"cpu_pct": 10.0}])
    from app.drivers.simulated import SimulatedDriver
    monkeypatch.setattr(SimulatedDriver, "collect_metrics", lambda self: next(seq))
    for _ in range(3):
        monitoring.poll_device(db, dev)
        db.commit()
    alerts = db.execute(select(Alert)).scalars().all()
    assert len(alerts) == 1 and alerts[0].count == 2 and alerts[0].status == "resolved"
    assert db.execute(select(Notification)).first()


def test_availability_alert_for_down_device(admin, db, monkeypatch):
    d = add_device(admin, is_simulated=False, hostname="real1", ip_address="192.0.2.55", environment="test")
    dev = db.get(Device, d["id"])
    monkeypatch.setattr(monitoring, "ping", lambda ip: (False, None))
    monkeypatch.setattr(monitoring, "tcp_check", lambda ip, port: (False, None))
    monitoring.poll_device(db, dev)
    db.commit()
    assert dev.status == "down"
    a = db.execute(select(Alert)).scalar_one()
    assert a.severity == "critical" and "unreachable" in a.title


def test_alert_ack_and_dashboard(admin, db, monkeypatch):
    d = add_device(admin)
    from app.drivers.simulated import SimulatedDriver
    monkeypatch.setattr(SimulatedDriver, "collect_metrics", lambda self: {"cpu_pct": 99.0, "mem_pct": 40.0, "disk_pct": 50.0})
    monitoring.poll_device(db, db.get(Device, d["id"]))
    db.commit()
    dash = admin.get("/api/dashboard").json()
    assert dash["devices"]["total"] == 1 and dash["resources"]["cpu_pct"]["avg"] == 99.0 and dash["alerts"]["counts"]["warning"] == 1
    assert dash["top_cpu"][0]["cpu_pct"] == 99.0 and dash["availability_24h_pct"] == 100.0
    aid = admin.get("/api/alerts").json()["items"][0]["id"]
    assert admin.post(f"/api/alerts/{aid}/acknowledge", headers=H).json()["status"] == "acknowledged"
    assert admin.get(f"/api/devices/{d['id']}/metrics?metric=cpu_pct").json()["points"][0]["value"] == 99.0
    assert admin.get(f"/api/devices/{d['id']}/metrics/latest").json()["cpu_pct"]["value"] == 99.0


def test_settings_secrets_write_only(admin):
    r = admin.put("/api/settings", headers=H, json={"values": {"smtp.host": "smtp.local", "smtp.password": "MailPw!"}})
    assert r.status_code == 200 and "MailPw!" not in r.text and r.json()["smtp.password_set"] is True
    assert "MailPw!" not in admin.get("/api/settings").text
    assert admin.put("/api/settings", headers=H, json={"values": {"evil": 1}}).status_code == 422
    assert admin.put("/api/settings", headers=H, json={"values": {"monitoring.interval_seconds": 5}}).status_code == 422
    assert admin.put("/api/settings", headers=H, json={"values": {"ldap.url": "http://x"}}).status_code == 422


def test_setup_status_public_and_complete(client, admin):
    assert client.get("/api/setup/status").json()["setup_completed"] is False
    admin.put("/api/settings", headers=H, json={"values": {"ui.organization_name": "Manlitics", "setup.completed": True}})
    st = client.get("/api/setup/status").json()
    assert st["organization"] == "Manlitics" and st["setup_completed"] is True


def test_production_policy_toggle(admin):
    d = add_device(admin, environment="production")
    admin.put("/api/settings", headers=H, json={"values": {"approval.medium_in_production": False}})
    r = admin.post("/api/jobs", headers=H, json={"operation_id": "linux.service.restart", "device_ids": [d["id"]], "params": {"unit": "nginx"}})
    assert r.json()["status"] == "queued"


def test_config_dedupe_mask_and_diff(admin, db):
    d = add_device(admin, hostname="sw", device_type="switch", platform="cisco_ios")
    b1, ch1 = configs.store_backup(db, d["id"], "running", "hostname sw\nenable secret 5 $1$abc\nvlan 10\n")
    b2, ch2 = configs.store_backup(db, d["id"], "running", "hostname sw\nenable secret 5 $1$abc\nvlan 10\n")
    assert ch1 and not ch2 and b1.id == b2.id
    b3, _ = configs.store_backup(db, d["id"], "running", "hostname sw\nenable secret 5 $1$abc\nvlan 20\n")
    db.commit()
    r = admin.get(f"/api/backups-diff?a={b1.id}&b={b3.id}").json()
    assert "-vlan 10" in r["diff"] and "+vlan 20" in r["diff"] and r["added"] == 1 and r["removed"] == 1
    assert len(admin.get(f"/api/devices/{d['id']}/backups").json()) == 2
    content = admin.get(f"/api/backups/{b1.id}").json()["content"]
    assert "$1$abc" not in content and "<redacted>" in content


def test_global_search(admin):
    add_device(admin, hostname="payroll-db")
    assert admin.get("/api/search?q=payroll").json()["devices"][0]["hostname"] == "payroll-db"


def test_platform_catalogue(admin):
    keys = {p["key"] for p in admin.get("/api/platforms").json()}
    assert {"windows", "linux", "cisco_ios", "aruba_aoscx", "hp_procurve", "tplink_jetstream", "mikrotik_routeros",
            "fortigate", "sophos_xgs", "proxmox", "vmware_vcenter", "snmp_generic"} <= keys


def test_connectivity_test_simulated(admin):
    d = add_device(admin)
    r = admin.post(f"/api/devices/{d['id']}/test", headers=H).json()
    assert r["ok"] and "[SIMULATED]" in r["message"]


def test_mssql_migration_sql_renders():
    env = {**os.environ, "IP_DATABASE_URL": "mssql+pyodbc://u:p@h/InfraPilot?driver=ODBC+Driver+18+for+SQL+Server"}
    root = os.path.dirname(os.path.dirname(__file__))
    out = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head", "--sql"], cwd=root, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    sql = out.stdout
    assert "CREATE TABLE audit_logs" in sql and "INSTEAD OF UPDATE, DELETE" in sql and "FOREIGN KEY" in sql
    assert sql.count("CREATE TABLE") == 46  # 45 app tables + alembic_version
    assert "CREATE TABLE job_schedules" in sql


def test_openapi_documented(client):
    spec = client.get("/api/openapi.json").json()
    assert "/api/jobs" in spec["paths"] and "/api/approvals/{aid}/decision" in spec["paths"]

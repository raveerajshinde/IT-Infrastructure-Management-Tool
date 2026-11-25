"""Management features: new operations, row actions, schedules, reports, policy delete, dashboard."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from app.core.cron import Cron, CronError
from app.core.timeutil import utcnow
from app.drivers.actions import ROW_ACTIONS, actions_for
from app.drivers.base import DeviceInfo
from app.drivers.network import CiscoIOSDriver, MikroTikDriver, TPLinkJetStreamDriver
from app.drivers.registry import DRIVERS
from app.models import AuditLog, Job, JobSchedule
from app.services import schedules
from tests.conftest import H, add_device, make_user, new_client_as, run_worker_once


# ---------------------------------------------------------------- operations catalogue
def test_new_operations_registered():
    w, lx, px = DRIVERS["windows"].operations, DRIVERS["linux"].operations, DRIVERS["proxmox"].operations
    for op in ("windows.system.info", "windows.system.reboot", "windows.processes.list", "windows.process.stop", "windows.updates.pending",
               "windows.software.list", "windows.network.config"):
        assert op in w
    for op in ("linux.system.info", "linux.system.reboot", "linux.process.kill", "linux.updates.pending", "linux.network.interfaces", "linux.cron.list"):
        assert op in lx
    assert w["windows.system.reboot"].risk == "critical" and lx["linux.system.reboot"].risk == "critical"
    assert px["virt.vm.snapshot.rollback"].risk == "critical" and px["virt.vm.snapshot.create"].risk == "change"


def test_network_ops_only_advertised_when_platform_supports_them():
    assert "network.neighbors" in CiscoIOSDriver.operations and "network.config.save" in CiscoIOSDriver.operations
    assert "network.neighbors" not in TPLinkJetStreamDriver.operations  # no reliable LLDP CLI across JetStream models
    assert "network.config.save" not in MikroTikDriver.operations  # RouterOS persists immediately


def test_param_validation_rejects_unsafe_values():
    lx = DRIVERS["linux"]
    with pytest.raises(Exception):
        lx.validate_params("linux.process.kill", {"pid": 1})  # never PID 1
    with pytest.raises(Exception):
        lx.validate_params("linux.system.reboot", {"message": "x; rm -rf /"})
    with pytest.raises(Exception):
        DRIVERS["proxmox"].validate_params("virt.vm.snapshot.create", {"node": "pve", "vmid": 101, "snapname": "1bad name"})


def _linux(outputs: dict):
    drv = DRIVERS["linux"](DeviceInfo(id=1, hostname="l1", address="10.0.0.1", platform="linux", device_type="linux_server", port=22), {"username": "u", "password": "p"})
    calls = []

    def fake_exec(argv, sudo=False, timeout=None, stdin=None):
        calls.append((argv, sudo))
        key = argv[0] if argv[0] != "sh" else "sh"
        out, rc = outputs.get(key, ("", 0))
        r = MagicMock()
        r.out, r.err, r.rc, r.ok = out, "", rc, rc == 0
        return r
    drv._exec = fake_exec
    drv._package_manager = lambda: "apt-get"
    return drv, calls


def test_linux_reboot_uses_argv_and_sudo():
    drv, calls = _linux({})
    r = drv.run("linux.system.reboot", {"delay_minutes": 5, "message": "Patch night"})
    assert r.status == "succeeded"
    assert calls[-1] == (["shutdown", "-r", "+5", "Patch night"], True)


def test_linux_updates_pending_parses_apt():
    apt = "Listing...\nopenssl/jammy-security 3.0.2-0ubuntu1.19 amd64 [upgradable from: 3.0.2-0ubuntu1.18]\ncurl/jammy-updates 7.81 amd64 [upgradable from: 7.80]\n"
    drv, _ = _linux({"apt": (apt, 0)})
    r = drv.run("linux.updates.pending", {})
    assert [x["package"] for x in r.data] == ["openssl", "curl"] and r.data[0]["security"] and not r.data[1]["security"]


# ---------------------------------------------------------------- row actions
def test_row_actions_reference_real_operations_and_params():
    fields: dict[str, set] = {}
    for c in DRIVERS.values():
        for o, s in c.operations.items():
            fields.setdefault(o, set()).update(s.params.model_fields)
    for read_op, acts in ROW_ACTIONS.items():
        assert read_op in fields, read_op
        for a in acts:
            assert a.op in fields, a.op
            assert set(a.map) | set(a.fixed) <= fields[a.op], (read_op, a.op)


def test_row_actions_filtered_per_vendor():
    forti = actions_for("firewall.rules.list", DRIVERS["fortigate"].operations)
    sophos = actions_for("firewall.rules.list", DRIVERS["sophos_xgs"].operations)
    assert {a["label"] for a in forti} == {"Enable", "Disable", "Delete"} and forti[0]["map"] == {"policy_id": "id"}
    assert {a["label"] for a in sophos} == {"Enable", "Disable"} and sophos[0]["map"] == {"rule_name": "name"}


def test_device_operations_endpoint_exposes_row_actions(admin):
    d = add_device(admin)
    ops = {o["id"]: o for o in admin.get(f"/api/devices/{d['id']}/operations").json()}
    acts = ops["linux.services.list"]["row_actions"]
    assert any(a["op"] == "linux.service.restart" and a["map"] == {"unit": "unit"} for a in acts)
    assert ops["linux.service.restart"]["row_actions"] == []


def test_simulated_read_returns_sample_rows(admin):
    d = add_device(admin)
    r = admin.post(f"/api/devices/{d['id']}/operations/linux.services.list/read", headers=H, json={}).json()
    rows = r.get("data") or r.get("result") or r
    assert "nginx.service" in str(rows)


# ---------------------------------------------------------------- cron
@pytest.mark.parametrize("expr,expected", [
    ("@daily", datetime(2026, 11, 15, 0, 0)),
    ("*/15 * * * *", datetime(2026, 11, 14, 10, 45)),
    ("0 2 * * 0", datetime(2026, 11, 15, 2, 0)),  # 14 Nov 2026 is a Saturday
    ("0 22 * * 1-5", datetime(2026, 11, 16, 22, 0)),
    ("30 1 1 * *", datetime(2026, 12, 1, 1, 30)),
    ("0 0 29 2 *", datetime(2028, 2, 29, 0, 0)),
])
def test_cron_next(expr, expected):
    assert Cron(expr).next_after(datetime(2026, 11, 14, 10, 30)) == expected


@pytest.mark.parametrize("bad", ["* * *", "61 * * * *", "a * * * *", "*/0 * * * *", "0 0 31 2 *"])
def test_cron_rejects(bad):
    with pytest.raises(CronError):
        Cron(bad).next_after(datetime(2026, 1, 1))


# ---------------------------------------------------------------- schedules
def _sched(admin, d, **kw):
    body = {"name": kw.pop("name", "nightly services"), "operation_id": kw.pop("operation_id", "linux.services.list"),
            "device_ids": [d["id"]], "cron": kw.pop("cron", "0 2 * * *"), **kw}
    return admin.post("/api/schedules", headers=H, json=body)


def test_schedule_crud_and_preview(admin):
    d = add_device(admin)
    p = admin.get("/api/schedules/preview", params={"cron": "0 2 * * 0"}).json()
    assert p["text"] == "Every Sunday at 02:00 UTC" and len(p["next_runs"]) == 5
    assert admin.get("/api/schedules/preview", params={"cron": "* * * * *"}).status_code == 422  # too frequent
    r = _sched(admin, d)
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["next_run_at"] and s["owner"] == "admin" and s["devices"] == ["srv01"]
    r = admin.put(f"/api/schedules/{s['id']}", headers=H, json={"enabled": False})
    assert r.json()["enabled"] is False and r.json()["next_run_at"] is None
    assert admin.delete(f"/api/schedules/{s['id']}", headers=H).status_code == 204
    assert admin.get("/api/schedules").json() == []


def test_schedule_rejects_secret_ops_and_bad_params(admin):
    d = add_device(admin)
    r = _sched(admin, d, name="x", operation_id="linux.service.restart", params={"unit": "bad unit;"})
    assert r.status_code == 422
    w = add_device(admin, hostname="win1", platform="windows", device_type="windows_server")
    r = admin.post("/api/schedules", headers=H, json={"name": "pw", "operation_id": "windows.ad.user.reset_password", "device_ids": [w["id"]],
                                                       "params": {"sam_account_name": "jdoe", "new_password": "S3cret!Passw0rd"}, "cron": "@daily"})
    assert r.status_code == 422 and "secret" in r.text


def test_schedule_requires_operation_permission(admin):
    d = add_device(admin)
    make_user(admin, "support", ["IT Support Engineer"])
    c = new_client_as("support")
    r = c.post("/api/schedules", headers=H, json={"name": "restart", "operation_id": "linux.service.restart", "device_ids": [d["id"]],
                                                   "params": {"unit": "nginx.service"}, "cron": "@daily"})
    assert r.status_code == 403


def test_due_schedule_creates_job_as_owner_and_respects_approval(admin, db):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # an approver other than the requester
    d = add_device(admin, environment="production")
    s = _sched(admin, d, name="restart nginx", operation_id="linux.service.restart", params={"unit": "nginx.service"}).json()
    row = db.get(JobSchedule, s["id"])
    row.next_run_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert schedules.run_due(db) == 1
    assert schedules.run_due(db) == 0  # claimed: not launched twice
    job = db.execute(select(Job).order_by(Job.id.desc())).scalars().first()
    assert job.title == "[Scheduled] restart nginx" and job.status == "pending_approval"  # production change still needs approval
    db.refresh(row)
    assert row.last_job_id == job.id and row.next_run_at > utcnow()
    assert db.execute(select(AuditLog).where(AuditLog.action == "schedule.run")).first()


def test_schedule_of_disabled_owner_is_suspended(admin, db):
    d = add_device(admin)
    make_user(admin, "ops", ["Linux Server Administrator"])
    c = new_client_as("ops")
    s = c.post("/api/schedules", headers=H, json={"name": "svc", "operation_id": "linux.services.list", "device_ids": [d["id"]], "cron": "@daily"}).json()
    from app.models import User
    u = db.execute(select(User).where(User.username == "ops")).scalar_one()
    u.is_active = False
    row = db.get(JobSchedule, s["id"])
    row.next_run_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert schedules.run_due(db) == 0
    db.refresh(row)
    assert row.enabled is False and "disabled" in row.last_error


def test_run_now_executes_read_schedule(admin):
    d = add_device(admin)
    s = _sched(admin, d).json()
    j = admin.post(f"/api/schedules/{s['id']}/run", headers=H).json()
    run_worker_once()
    assert admin.get(f"/api/jobs/{j['id']}").json()["status"] == "succeeded"


# ---------------------------------------------------------------- policies, reports, dashboard
def test_policy_delete_guards_last_critical_policy(admin):
    pols = admin.get("/api/approval-policies").json()
    crit = [p for p in pols if p["risk"] == "critical" and p["enabled"] and p["require_approval"]]
    for p in crit[:-1]:
        assert admin.delete(f"/api/approval-policies/{p['id']}", headers=H).status_code == 204
    assert admin.delete(f"/api/approval-policies/{crit[-1]['id']}", headers=H).status_code == 422
    r = admin.post("/api/approval-policies", headers=H, json={"name": "temp", "risk": "change", "require_approval": True})
    assert admin.delete(f"/api/approval-policies/{r.json()['id']}", headers=H).status_code == 204


def test_reports_json_csv_xlsx_and_permissions(admin):
    add_device(admin)
    add_device(admin, hostname="sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    keys = {r["key"] for r in admin.get("/api/reports").json()}
    assert {"inventory", "backup-coverage", "firewall-risk", "changes", "alerts", "jobs"} <= keys
    inv = admin.get("/api/reports/inventory").json()
    assert inv["columns"][0] == "Hostname" and len(inv["rows"]) == 2
    cov = admin.get("/api/reports/backup-coverage").json()
    assert cov["rows"] == [["sw1", "cisco_ios", "never", "", 0, "Missing"]]
    csv = admin.get("/api/reports/inventory", params={"format": "csv"})
    assert csv.headers["content-type"].startswith("text/csv") and b"srv01" in csv.content
    x = admin.get("/api/reports/jobs", params={"format": "xlsx"})
    assert x.content[:2] == b"PK"
    make_user(admin, "net", ["Network Administrator"])
    assert new_client_as("net").get("/api/reports/inventory").status_code == 200


def test_dashboard_enriched(admin):
    add_device(admin)
    add_device(admin, hostname="sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    d = admin.get("/api/dashboard").json()
    assert len(d["activity_7d"]) == 7 and d["backup_coverage"]["eligible"] == 1 and d["backup_coverage"]["never"] == 1
    assert d["sites"][0]["total"] == 2 and "recent_jobs" in d and "upcoming_schedules" in d and d["by_vendor"]


def test_simulated_config_backup_is_stored(admin):
    d = add_device(admin, hostname="sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch")
    admin.post("/api/jobs", headers=H, json={"operation_id": "network.config.backup", "device_ids": [d["id"]], "params": {}})
    run_worker_once()
    assert admin.get("/api/dashboard").json()["backup_coverage"]["fresh_7d"] == 1


def test_read_only_template_ignores_check_mode(admin):
    d = add_device(admin, hostname="fw1", ip_address="10.0.0.9", platform="fortigate", device_type="firewall")
    t = next(x for x in admin.get("/api/templates").json() if x["operation_id"] == "firewall.config.backup")
    r = admin.post(f"/api/templates/{t['id']}/run", headers=H, json={"device_ids": [d["id"]], "check_mode": True})
    assert r.status_code == 201, r.text
    run_worker_once()
    assert admin.get(f"/api/jobs/{r.json()['id']}").json()["status"] == "succeeded"


def test_dashboard_survives_enrichment_failure(admin, monkeypatch):
    add_device(admin)
    import app.api.routers.monitoring as mon
    monkeypatch.setattr(mon, "driver_class", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    r = admin.get("/api/dashboard")
    assert r.status_code == 200 and r.json()["devices"]["total"] == 1 and r.json()["recent_jobs"] == []


# ---------------------------------------------------------------- host firewall, TLS, branding
def test_linux_firewall_rule_add_and_guard():
    ufw_after = "Status: active\n[ 1] 22/tcp   ALLOW IN    Anywhere\n[ 2] 5432/tcp   ALLOW IN    10.10.0.0/16\n"
    drv, calls = _linux({"ufw": (ufw_after, 0)})
    drv._firewall_tool = lambda: "ufw"
    r = drv.run("linux.firewall.rule.add", {"action": "allow", "port": 5432, "source": "10.10.0.0/16", "comment": "app tier"})
    assert r.status == "succeeded" and "ufw delete allow proto tcp from 10.10.0.0/16" in r.rollback
    assert (["ufw", "allow", "proto", "tcp", "from", "10.10.0.0/16", "to", "any", "port", "5432", "comment", "app tier"], True) in calls
    with pytest.raises(Exception, match="SSH port"):
        drv.run("linux.firewall.rule.add", {"action": "deny", "port": 22})
    with pytest.raises(Exception, match="SSH port"):
        drv.run("linux.firewall.rule.delete", {"action": "allow", "port": 22})


def test_firewalld_rich_rule_spec():
    drv, _ = _linux({})
    assert drv._firewalld_spec("allow", 80, "tcp", None) == ("port", "80/tcp")
    assert drv._firewalld_spec("deny", 3306, "tcp", "10.0.0.0/8")[1] == 'rule family="ipv4" source address="10.0.0.0/8" port port="3306" protocol="tcp" drop'


def test_windows_firewall_guard_and_row_actions():
    w = DRIVERS["windows"](DeviceInfo(id=1, hostname="w", address="10.0.0.5", platform="windows", device_type="windows_server"), {})
    with pytest.raises(Exception, match="WinRM"):
        w.run("windows.firewall.rule.remove", {"display_name": "Windows Remote Management (HTTP-In)"})
    labels = {a["label"] for a in actions_for("windows.firewall.rules.list", DRIVERS["windows"].operations)}
    assert {"Edit", "Enable", "Disable", "Delete"} <= labels


def test_manage_view_actions_and_simulated_rules(admin):
    d = add_device(admin)
    ops = {o["id"]: o for o in admin.get(f"/api/devices/{d['id']}/operations").json()}
    assert ops["linux.firewall.rules"]["view_actions"] == [{"op": "linux.firewall.rule.add", "label": "Add rule"}]
    rows = admin.post(f"/api/devices/{d['id']}/operations/linux.firewall.rules/read", headers=H, json={}).json()["data"]
    assert any(r["port"] == 5432 for r in rows)


def test_tls_toggle_endpoint_and_hint(admin):
    from app.drivers.base import tls_hint
    d = add_device(admin, hostname="fw2", ip_address="10.0.0.8", platform="sophos_xgs", device_type="firewall")
    r = admin.post(f"/api/devices/{d['id']}/tls", headers=H, json={"verify_tls": False})
    assert r.status_code == 200 and r.json()["options"]["verify_tls"] is False
    assert "Verify TLS certificate" in tls_hint("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain")
    make_user(admin, "aud2", ["Auditor / Read Only"])
    assert new_client_as("aud2").post(f"/api/devices/{d['id']}/tls", headers=H, json={"verify_tls": True}).status_code == 403


def test_branding_settings(admin, client):
    logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    r = admin.put("/api/settings", headers=H, json={"values": {"branding.product_name": "Acme Ops", "branding.primary_color": "#0f766e",
                                                               "branding.logo": logo, "ui.organization_name": "Acme Corp"}})
    assert r.status_code == 200, r.text
    from fastapi.testclient import TestClient
    from app.main import app
    b = TestClient(app).get("/api/branding").json()  # public, no session
    assert b["product_name"] == "Acme Ops" and b["primary_color"] == "#0f766e" and b["logo"] == logo and b["organization"] == "Acme Corp"
    for bad in ({"branding.primary_color": "red"}, {"branding.logo": "javascript:alert(1)"}, {"branding.product_name": "<script>"}):
        assert admin.put("/api/settings", headers=H, json={"values": bad}).status_code == 422
    audit = admin.get("/api/audit", params={"action": "settings.update"}).json()
    assert "iVBOR" not in str(audit)


def test_unhandled_error_is_recorded_and_explained_to_admins(admin, monkeypatch):
    import app.api.routers.operations as ops_router
    add_device(admin)

    def boom(t):
        raise RuntimeError("bad JSON in template; password=hunter2")
    monkeypatch.setattr(ops_router, "_tpl", boom)
    from fastapi.testclient import TestClient
    from app.main import app as fastapi_app
    c = TestClient(fastapi_app, raise_server_exceptions=False)
    c.cookies = admin.cookies
    r = c.get("/api/templates")
    assert r.status_code == 500
    det = r.json()["detail"]
    assert det["reference"] and "RuntimeError: bad JSON in template" in det["error"] and "hunter2" not in det["error"]
    d = admin.get("/api/system/diagnostics").json()
    assert d["version"] == "1.1.1" and d["errors"][0]["ref"] == det["reference"] and "hunter2" not in d["errors"][0]["trace"]
    # non-admins get only a reference
    make_user(admin, "aud3", ["Auditor / Read Only"])
    c2 = TestClient(fastapi_app, raise_server_exceptions=False)
    c2.post("/api/auth/login", json={"username": "aud3", "password": "Us3r!Passw0rd#"})
    r2 = c2.get("/api/templates")
    assert r2.status_code == 500 and "error" not in r2.json()["detail"] and r2.json()["detail"]["reference"]
    assert c2.get("/api/system/diagnostics").status_code == 403


def test_background_routines_generate_sql_server_compatible_sql(admin, db):
    """Runs every periodic worker routine once; the conftest guard checks all SQL against the mssql dialect."""
    from app.services import integrations, jobs, monitoring, schedules
    d = add_device(admin)
    _sched(admin, d, name="guard check")
    admin.post("/api/integrations", headers=H, json={"name": "zbx", "kind": "zabbix", "url": "https://zbx.example.local", "enabled": True})
    for fn in (jobs.release_waiting_jobs, jobs.recover_stale_jobs, jobs.expire_approvals, jobs.schedule_config_backups,
               monitoring.escalate, monitoring.purge_old_metrics, schedules.run_due, integrations.sync_all):
        try:
            fn(db)
        except Exception as exc:  # network calls to the fake integration may fail; SQL is what we check
            assert "SQL" not in type(exc).__name__, exc
        db.rollback()
    devs = monitoring.due_devices(db, 60)
    for dev in devs:
        monitoring.evaluate_alerts(db, dev, monitoring.poll_device(db, dev))
    db.commit()  # SQLite allows one writer: release before the API writes its audit records
    for path in ("/api/search?q=srv", "/api/devices?q=srv&tag=x", "/api/approvals", "/api/audit/verify", "/api/notifications"):
        assert admin.get(path).status_code in (200, 404), path


@pytest.mark.parametrize("port,cred,expected", [
    (5985, {}, (False, 5985)), (5986, {}, (True, 5986)), (None, {}, (True, 5986)),
    (5986, {"use_ssl": False}, (False, 5985)), (5985, {"use_ssl": True}, (True, 5986)), (15985, {"use_ssl": False}, (False, 15985)),
])
def test_winrm_protocol_follows_device_port_or_credential(port, cred, expected):
    w = DRIVERS["windows"](DeviceInfo(id=1, hostname="w", address="10.0.0.5", platform="windows", device_type="windows_server", port=port), cred)
    assert w.winrm_endpoint() == expected


def test_winrm_http_refuses_basic_auth():
    w = DRIVERS["windows"](DeviceInfo(id=1, hostname="w", address="10.0.0.5", platform="windows", device_type="windows_server", port=5985),
                           {"username": "u", "password": "p", "transport": "basic"})
    with pytest.raises(Exception, match="clear text"):
        w.test_connection()


def test_winrm_http_uses_message_encryption(monkeypatch):
    import pypsrp.powershell
    import pypsrp.wsman
    seen = {}

    class FakeWSMan:
        def __init__(self, host, **kw):
            seen.update(kw)

    class FakePool:
        def __init__(self, wsman):
            pass

        def open(self):
            pass
    monkeypatch.setattr(pypsrp.wsman, "WSMan", FakeWSMan)
    monkeypatch.setattr(pypsrp.powershell, "RunspacePool", FakePool)
    w = DRIVERS["windows"](DeviceInfo(id=1, hostname="w", address="10.0.0.5", platform="windows", device_type="windows_server", port=5985),
                           {"username": "u", "password": "p"})
    w._connect()
    assert seen["ssl"] is False and seen["port"] == 5985 and seen["encryption"] == "always" and seen["auth"] == "negotiate"

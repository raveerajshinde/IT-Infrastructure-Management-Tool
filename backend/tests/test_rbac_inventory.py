"""RBAC (global and device-group scoped), inventory CRUD, validation, import/export."""
import io

from tests.conftest import H, add_device, make_user, new_client_as


def test_device_crud_and_validation(admin):
    d = add_device(admin, hostname="web01", tags=["web", "nginx"])
    assert d["is_simulated"] is True
    r = admin.post("/api/devices", headers=H, json={"hostname": "bad host;rm", "ip_address": "1.2.3.4", "device_type": "linux_server", "platform": "linux"})
    assert r.status_code == 422
    r = admin.post("/api/devices", headers=H, json={"hostname": "x1", "ip_address": "1.2.3.4", "device_type": "linux_server", "platform": "nope"})
    assert r.status_code == 422 and "Unknown platform" in r.json()["detail"]["message"]
    assert admin.post("/api/devices", headers=H, json={"hostname": "web01", "ip_address": "1.2.3.5", "device_type": "linux_server", "platform": "linux", "is_simulated": True}).status_code == 409
    lst = admin.get("/api/devices?q=web").json()
    assert lst["total"] == 1
    assert admin.get("/api/devices?tag=nginx").json()["total"] == 1
    assert admin.delete(f"/api/devices/{d['id']}", headers=H).status_code == 204
    assert admin.get("/api/devices").json()["total"] == 0


def test_simulated_devices_refused_in_production(admin, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "app_mode", "production")
    r = admin.post("/api/devices", headers=H, json={"hostname": "sim1", "ip_address": "10.1.1.1", "device_type": "linux_server", "platform": "linux", "is_simulated": True})
    assert r.status_code == 422 and "demo mode" in r.json()["detail"]["message"]


def test_auditor_is_read_only(admin):
    add_device(admin)
    make_user(admin, "aud", ["Auditor / Read Only"])
    c = new_client_as("aud")
    assert c.get("/api/devices").status_code == 200
    assert c.get("/api/audit").status_code == 200
    assert c.post("/api/devices", headers=H, json={"hostname": "x", "ip_address": "1.1.1.1", "device_type": "linux_server", "platform": "linux"}).status_code == 403
    assert c.get("/api/credentials").status_code == 403
    assert c.post("/api/users", headers=H, json={"username": "z", "password": "Aa1!aaaaaaaaaa", "roles": []}).status_code == 403


def test_group_scoped_role(admin):
    g = admin.post("/api/groups", headers=H, json={"name": "Linux Web"}).json()["id"]
    d1 = add_device(admin, hostname="in-scope")
    d2 = add_device(admin, hostname="out-scope", ip_address="10.0.0.11")
    admin.put(f"/api/groups/{g}", headers=H, json={"name": "Linux Web", "device_ids": [d1["id"]]})
    make_user(admin, "lin", ["Linux Server Administrator"], group_id=g)
    c = new_client_as("lin")
    names = [d["hostname"] for d in c.get("/api/devices").json()["items"]]
    assert names == ["in-scope"]
    assert c.get(f"/api/devices/{d2['id']}").status_code == 403
    ok = c.post("/api/jobs", headers=H, json={"operation_id": "linux.service.restart", "device_ids": [d1["id"]], "params": {"unit": "nginx"}})
    assert ok.status_code == 201, ok.text
    denied = c.post("/api/jobs", headers=H, json={"operation_id": "linux.service.restart", "device_ids": [d2["id"]], "params": {"unit": "nginx"}})
    assert denied.status_code == 403


def test_windows_admin_cannot_touch_firewall(admin):
    fw = add_device(admin, hostname="fw1", device_type="firewall", platform="fortigate")
    make_user(admin, "win", ["Windows Server Administrator"])
    c = new_client_as("win")
    r = c.post("/api/jobs", headers=H, json={"operation_id": "firewall.rule.set_enabled", "device_ids": [fw["id"]], "params": {"policy_id": 1, "enabled": False}})
    assert r.status_code == 403


def test_cannot_remove_last_super_admin(admin):
    me = admin.get("/api/auth/me").json()
    r = admin.patch(f"/api/users/{me['id']}", headers=H, json={"is_active": False})
    assert r.status_code == 403


def test_import_dry_run_then_commit_and_export(admin):
    admin.post("/api/credentials", headers=H, json={"name": "linux-ssh", "kind": "password", "username": "ops", "secret": {"password": "x" * 12}})
    csv_data = ("hostname,ip_address,device_type,platform,environment,site,tags,credential,groups\n"
                "app01,10.2.0.1,linux_server,linux,production,DC1,app;java,linux-ssh,Apps\n"
                "bad row,10.2.0.2,linux_server,linux,production,,,,\n"
                "sw01,10.2.0.3,switch,cisco_ios,production,DC1,,unknown-cred,\n")
    def send(dry, update=False):
        files = {"file": ("devices.csv", io.BytesIO(csv_data.encode()), "text/csv")}
        return admin.post("/api/devices-import", headers=H, files=files, data={"dry_run": str(dry).lower(), "update_existing": str(update).lower()}).json()
    res = send(True)
    assert len(res["errors"]) == 2 and res["create"] == 1 and not res["applied"]
    res = send(False)  # all-or-nothing: rejected while any row is invalid
    assert not res["applied"] and admin.get("/api/devices").json()["total"] == 0
    csv_data = "\n".join(csv_data.splitlines()[:2]) + "\n"
    res = send(False)
    assert res["applied"] and res["create"] == 1
    res = send(False)
    assert not res["applied"] and "already exists" in res["errors"][0]["error"]
    assert send(False, update=True)["applied"]
    dev = admin.get("/api/devices").json()["items"][0]
    assert dev["site"]["name"] == "DC1" and dev["tags"] == ["app", "java"] and len(dev["groups"]) == 1 and dev["driver"] == "linux"
    x = admin.get("/api/devices-export?fmt=xlsx")
    assert x.status_code == 200 and x.content[:2] == b"PK"
    c = admin.get("/api/devices-export?fmt=csv").text
    assert "app01" in c


def test_csv_formula_injection_neutralised():
    from app.services.import_export import to_csv
    assert b"'=cmd" in to_csv([["=cmd|' /C calc'!A0"]])


def test_saved_filters(admin):
    fid = admin.post("/api/saved-filters", headers=H, json={"name": "Prod Linux", "filter": {"environment": "production"}}).json()["id"]
    assert admin.get("/api/saved-filters").json()[0]["id"] == fid

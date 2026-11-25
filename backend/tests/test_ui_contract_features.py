"""Endpoints and behaviours the web UI relies on."""
from datetime import timedelta

import httpx
import pyotp
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.timeutil import utcnow
from app.models import Alert, Approval, Integration, Job, User
from app.services import integrations, jobs, ldap_auth
from tests.conftest import ADMIN_PW, H, add_device, make_user, new_client_as, run_worker_once


def test_meta_and_operations_catalogue(admin):
    m = admin.get("/api/meta").json()
    assert m["mode"] == "demo" and "windows_server" in m["device_types"]
    win = next(d for d in m["drivers"] if d["name"] == "windows")
    assert "windows.gpo.link" in win["operations"] and "winrm" in win["credential_kinds"]
    ops = {o["id"]: o for o in admin.get("/api/operations").json()}
    assert ops["windows.gpo.link"]["family"] == "ad" and ops["windows.gpo.link"]["risk"] == "critical" and ops["windows.gpo.link"]["allowed"]
    assert ops["windows.ad.user.create"]["schema"]["properties"]["password"]["writeOnly"] is True


def test_device_detail_includes_permission_aware_operations(admin):
    d = add_device(admin)
    make_user(admin, "aud", ["Auditor / Read Only"])
    c = new_client_as("aud")
    ops = {o["id"]: o["allowed"] for o in c.get(f"/api/devices/{d['id']}").json()["operations"]}
    assert ops["linux.services.list"] is True and ops["linux.service.restart"] is False


def test_device_accepts_ui_driver_alias(admin):
    r = admin.post("/api/devices", headers=H, json={"hostname": "fw9", "ip_address": "10.9.9.9", "device_type": "firewall", "driver": "fortigate",
                                                    "is_simulated": True, "options": {"verify_tls": False}})
    assert r.status_code == 201 and r.json()["driver"] == "fortigate" and r.json()["options"]["verify_tls"] is False


def test_approval_expiry(admin, db):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # an approver other than the requester
    d = add_device(admin, environment="production")
    job = admin.post("/api/jobs", headers=H, json={"operation_id": "linux.service.restart", "device_ids": [d["id"]], "params": {"unit": "x"},
                                                   "reason": "planned"}).json()
    ap = db.execute(select(Approval)).scalar_one()
    ap.created_at = utcnow() - timedelta(hours=100)
    db.commit()
    assert jobs.expire_approvals(db) == 1
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "cancelled"


def test_auto_approve_window_skips_medium_but_not_critical(admin):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # an approver other than the requester
    d = add_device(admin, environment="production")
    now = utcnow()
    admin.post("/api/maintenance-windows", headers=H, json={"name": "patch night", "starts_at": (now - timedelta(minutes=1)).isoformat() + "Z",
                                                              "ends_at": (now + timedelta(hours=2)).isoformat() + "Z", "auto_approve_medium": True})
    r = admin.post("/api/jobs", headers=H, json={"operation_id": "linux.service.restart", "device_ids": [d["id"]], "params": {"unit": "x"}})
    assert r.json()["status"] == "queued"
    r = admin.post("/api/jobs", headers=H, json={"operation_id": "linux.package.remove", "device_ids": [d["id"]], "params": {"packages": ["x"]},
                                                 "reason": "cleanup"})
    assert r.json()["status"] == "pending_approval"


def test_scheduled_config_backups(admin, db):
    add_device(admin, hostname="sw1", device_type="switch", platform="cisco_ios")
    add_device(admin, hostname="srv", device_type="linux_server", platform="linux")
    assert jobs.schedule_config_backups(db) == 1
    assert jobs.schedule_config_backups(db) == 0  # not twice within the interval
    run_worker_once()
    j = db.execute(select(Job)).scalar_one()
    db.refresh(j)
    assert j.status == "succeeded" and j.requested_by is None


def test_user_admin_actions(admin):
    u = make_user(admin, "ops1", ["IT Support Engineer"])
    for _ in range(5):
        admin.post("/api/auth/login", json={"username": "ops1", "password": "wrong"})
    users = {x["username"]: x for x in admin.get("/api/users").json()}
    assert users["ops1"]["locked"] is True
    assert admin.post(f"/api/users/{u['id']}/unlock", headers=H).json()["locked"] is False
    r = admin.post(f"/api/users/{u['id']}/reset-password", headers=H, json={"new_password": "N3w!Passw0rd#x"})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    c = new_client_as("ops1", "N3w!Passw0rd#x")
    assert c.get("/api/auth/me").json()["must_change_password"] is True


def test_mfa_disable_requires_password_and_code(admin):
    s = admin.post("/api/auth/mfa/setup", headers=H).json()["secret"]
    admin.post("/api/auth/mfa/enable", headers=H, json={"code": pyotp.TOTP(s).now()})
    assert admin.post("/api/auth/mfa/disable", headers=H, json={"password": "bad", "code": pyotp.TOTP(s).now()}).status_code == 422
    assert admin.post("/api/auth/mfa/disable", headers=H, json={"password": ADMIN_PW, "code": pyotp.TOTP(s).now()}).status_code == 200


def test_mfa_required_by_policy_flag(admin):
    admin.put("/api/settings", headers=H, json={"values": {"security.mfa_required": True}})
    me = admin.get("/api/auth/me").json()
    assert me["mfa_required_by_policy"] is True and me["mfa_enabled"] is False


def test_integration_sync_imports_and_resolves(admin, db, monkeypatch):
    cred = admin.post("/api/credentials", headers=H, json={"name": "zbx", "kind": "api_token", "secret": {"token": "t"}}).json()
    add_device(admin, hostname="db01")
    it = admin.post("/api/integrations", headers=H, json={"name": "Zabbix", "kind": "zabbix", "base_url": "https://zbx.local",
                                                          "credential_id": cred["id"]}).json()
    state = {"problems": [{"eventid": "11", "name": "High CPU", "severity": "4", "clock": "1", "objectid": "99"}]}

    def fake_post(url, json=None, headers=None, verify=None, timeout=None):
        assert headers["Authorization"] == "Bearer t"
        res = state["problems"] if json["method"] == "problem.get" else [{"triggerid": "99", "hosts": [{"host": "db01"}]}]
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": res, "id": 1}, request=httpx.Request("POST", url))
    monkeypatch.setattr(integrations.httpx, "post", fake_post)
    r = admin.post(f"/api/integrations/{it['id']}/sync", headers=H)
    assert r.status_code == 200, r.text
    a = db.execute(select(Alert)).scalar_one()
    assert a.severity == "critical" and a.device_id is not None and a.source == "zabbix"
    state["problems"] = []
    admin.post(f"/api/integrations/{it['id']}/sync", headers=H)
    db.refresh(a)
    assert a.status == "resolved"


def test_ldap_role_mapping_and_default_deny(db):
    from app.services import auth as auth_svc
    cfg = ldap_auth.LdapConfig(enabled=True, group_role_map={"cn=netops,dc=corp": "Network Administrator"})
    lu = ldap_auth.LdapUser(dn="cn=a", username="alice", display_name="Alice", email=None, groups=["cn=netops,dc=corp"])
    u = auth_svc._provision_ldap_user(db, None, lu, cfg)
    assert [a.role.name for a in u.role_assignments] == ["Network Administrator"]
    stranger = ldap_auth.LdapUser(dn="cn=b", username="bob", display_name="Bob", email=None, groups=["cn=other"])
    assert auth_svc._provision_ldap_user(db, None, stranger, cfg) is None
    cfg.default_role = "Auditor / Read Only"
    assert [a.role.name for a in auth_svc._provision_ldap_user(db, None, stranger, cfg).role_assignments] == ["Auditor / Read Only"]


def test_ldap_login_flow(client, monkeypatch, db):
    admin_c = client
    from tests.conftest import login
    login(admin_c)
    admin_c.put("/api/settings", headers=H, json={"values": {"ldap.enabled": True, "ldap.url": "ldaps://dc01.corp.local",
                                                             "ldap.group_role_map": {"CN=Ops,DC=corp": "IT Support Engineer"}}})
    monkeypatch.setattr(ldap_auth, "authenticate", lambda cfg, u, p: ldap_auth.LdapUser("cn=x", u, "Dir User", "d@corp", ["cn=ops,dc=corp"]) if p == "good" else None)
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"username": "diruser", "password": "bad"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "diruser", "password": "good"})
    assert r.status_code == 200 and r.json()["auth_source"] == "ldap" and "alerts:manage" in r.json()["permissions"]


def test_group_members_and_site_crud(admin):
    d = add_device(admin)
    g = admin.post("/api/groups", headers=H, json={"name": "G1"}).json()["id"]
    admin.post(f"/api/groups/{g}/members", headers=H, json={"device_ids": [d["id"]], "action": "add"})
    assert admin.get("/api/groups").json()[0]["device_count"] == 1
    s = admin.post("/api/sites", headers=H, json={"name": "Pune DC", "kind": "datacenter", "location": "Pune"}).json()
    assert s["location"] == "Pune"
    assert admin.put(f"/api/sites/{s['id']}", headers=H, json={"name": "Pune DC1", "location": "Hinjewadi"}).json()["name"] == "Pune DC1"
    assert admin.delete(f"/api/sites/{s['id']}", headers=H).status_code == 200


def test_audit_verify_message_and_rows(admin):
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] and "intact" in v["message"]
    row = admin.get("/api/audit").json()["items"][0]
    assert len(row["row_hash"]) == 64 and row["ts"].endswith("Z")


def test_credential_rotation_keeps_other_fields(admin, db):
    c = admin.post("/api/credentials", headers=H, json={"name": "sw", "kind": "password", "username": "admin",
                                                        "secret": {"password": "p1-longenough", "enable_secret": "en1"}}).json()
    admin.patch(f"/api/credentials/{c['id']}", headers=H, json={"secret": {"password": "p2-longenough"}})
    from app.models import Credential
    from app.services import secrets
    mat = secrets.credential_material(db, db.get(Credential, c["id"]))
    assert mat["password"] == "p2-longenough" and mat["enable_secret"] == "en1"
    r = admin.post("/api/credentials", headers=H, json={"name": "s3", "kind": "snmpv3", "username": "mon",
                                                        "secret": {"auth_protocol": "SHA256", "auth_key": "authpass1", "priv_protocol": "AES", "priv_key": "privpass1"}})
    assert r.status_code == 201 and r.json()["extra"] == {"auth_protocol": "SHA256", "priv_protocol": "AES"}

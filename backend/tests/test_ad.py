"""Active Directory: LDAPS sync against an in-memory directory (ldap3 MOCK_SYNC with the AD schema), privileged
detection (recursive), reports, change detection between syncs, bulk actions (preview -> jobs) and RBAC."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from app.models import AdDomain
from app.services import ad
from tests.conftest import H, add_device, make_user, new_client_as

DOM_SID = "S-1-5-21-1111-2222-3333"
BASE = "DC=corp,DC=example"


def sid_bytes(sid: str) -> bytes:
    p = sid.split("-")
    rev, auth, subs = int(p[1]), int(p[2]), [int(x) for x in p[3:]]
    return bytes([rev, len(subs)]) + auth.to_bytes(6, "big") + b"".join(s.to_bytes(4, "little") for s in subs)


def filetime(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1)).total_seconds() * 10_000_000)


NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def directory(extra_admin: bool = False, drop_bob: bool = False, disable_dave: bool = False):
    s = Server("mock-dc", get_info=OFFLINE_AD_2012_R2)
    c = Connection(s, user=f"CN=svc,{BASE}", password="pw", client_strategy=MOCK_SYNC)
    add = c.strategy.add_entry
    g = lambda n: uuid.uuid5(uuid.NAMESPACE_DNS, n).bytes_le  # noqa: E731 - stable GUIDs across syncs
    add(f"CN=svc,{BASE}", {"objectClass": ["user"], "userPassword": "pw", "sAMAccountName": "svc"})
    add(BASE, {"objectClass": ["top", "domain", "domainDNS"], "objectSid": sid_bytes(DOM_SID), "minPwdLength": 8, "lockoutThreshold": 0,
               "maxPwdAge": -36288000000000, "pwdHistoryLength": 24, "ms-DS-MachineAccountQuota": 10})
    add(f"OU=Staff,{BASE}", {"objectClass": ["organizationalUnit"], "objectGUID": g("ou-staff"), "name": "Staff", "gPOptions": "1",
                             "gPLink": "[LDAP://cn={X},cn=policies,cn=system,DC=corp,DC=example;0]", "whenCreated": "20200101000000.0Z"})
    users = {
        "alice": dict(uac=0x200 | 0x10000, logon=NOW - timedelta(days=2), spn=["MSSQLSvc/sql01.corp.example:1433"]),
        "bob": dict(uac=0x200, logon=NOW - timedelta(days=400)),
        "carol": dict(uac=0x200 | 0x2, logon=NOW - timedelta(days=10)),
        "dave": dict(uac=0x200 | 0x400000 | (0x2 if disable_dave else 0), logon=NOW - timedelta(days=1), pwdset=NOW - timedelta(days=40)),
    }
    if extra_admin:
        users["eve"] = dict(uac=0x200, logon=NOW - timedelta(days=1))
    if drop_bob:
        users.pop("bob")
    for sam, u in users.items():
        attrs = {"objectClass": ["top", "person", "organizationalPerson", "user"], "objectCategory": "person", "sAMAccountName": sam, "name": sam,
                 "displayName": sam.title(), "userAccountControl": u["uac"], "objectGUID": g(sam), "objectSid": sid_bytes(f"{DOM_SID}-{1100 + len(sam)}"),
                 "lastLogonTimestamp": filetime(u["logon"]), "pwdLastSet": filetime(u.get("pwdset", NOW - timedelta(days=5))),
                 "whenCreated": "20200101000000.0Z", "whenChanged": NOW.strftime("%Y%m%d%H%M%S.0Z")}
        if u.get("spn"):
            attrs["servicePrincipalName"] = u["spn"]
        add(f"CN={sam},OU=Staff,{BASE}", attrs)
    add(f"CN=WS01,OU=Staff,{BASE}", {"objectClass": ["computer"], "sAMAccountName": "WS01$", "name": "WS01", "userAccountControl": 0x1000,
                                    "objectGUID": g("ws01"), "lastLogonTimestamp": filetime(NOW - timedelta(days=200)), "operatingSystem": "Windows 10 Pro",
                                    "whenCreated": "20190101000000.0Z"})
    add(f"CN=DC01,OU=Domain Controllers,{BASE}", {"objectClass": ["computer"], "sAMAccountName": "DC01$", "name": "DC01", "userAccountControl": 0x2000 | 0x80000,
                                                 "objectGUID": g("dc01"), "primaryGroupID": 516, "operatingSystem": "Windows Server 2022 Datacenter",
                                                 "dNSHostName": "dc01.corp.example", "lastLogonTimestamp": filetime(NOW)})
    tier0 = [f"CN=alice,OU=Staff,{BASE}", f"CN=Tier0 Ops,OU=Staff,{BASE}"]
    add(f"CN=Tier0 Ops,OU=Staff,{BASE}", {"objectClass": ["group"], "sAMAccountName": "Tier0 Ops", "name": "Tier0 Ops", "groupType": -2147483646,
                                         "objectGUID": g("tier0"), "objectSid": sid_bytes(f"{DOM_SID}-3001"),
                                         "member": [f"CN=eve,OU=Staff,{BASE}"] if extra_admin else []})
    add(f"CN=Domain Admins,CN=Users,{BASE}", {"objectClass": ["group"], "sAMAccountName": "Domain Admins", "name": "Domain Admins", "groupType": -2147483646,
                                             "objectGUID": g("da"), "objectSid": sid_bytes(f"{DOM_SID}-512"), "member": tier0})
    add(f"CN=Administrators,CN=Builtin,{BASE}", {"objectClass": ["group"], "sAMAccountName": "Administrators", "name": "Administrators",
                                                "groupType": -2147483643, "objectGUID": g("adm"), "objectSid": sid_bytes("S-1-5-32-544"),
                                                "member": [f"CN=Domain Admins,CN=Users,{BASE}"]})
    add(f"CN=Marketing,OU=Staff,{BASE}", {"objectClass": ["group"], "sAMAccountName": "Marketing", "name": "Marketing", "groupType": 2,
                                         "objectGUID": g("mkt"), "member": [f"CN=bob,OU=Staff,{BASE}"]})
    assert c.bind()
    return c


def _domain(admin, db, **kw):
    r = admin.post("/api/credentials", headers=H, json={"name": "ldap-svc", "kind": "password", "username": "svc@corp.example", "secret": {"password": "pw"}})
    assert r.status_code == 201, r.text
    body = {"name": "corp.example", "ldap_url": "ldaps://dc01.corp.example:636", "base_dn": BASE, "credential_id": r.json()["id"], **kw}
    r = admin.post("/api/ad/domains", headers=H, json=body)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def mockdir(monkeypatch):
    state = {"conn": directory()}
    monkeypatch.setattr(ad, "connect", lambda db, dom: state["conn"])
    return state


def test_domain_validation(admin, db):
    bad = admin.post("/api/ad/domains", headers=H, json={"name": "corp.example", "ldap_url": "http://x", "base_dn": BASE})
    assert bad.status_code == 422
    d = _domain(admin, db)
    plain = admin.put(f"/api/ad/domains/{d['id']}", headers=H, json={**{k: d[k] for k in ("name", "base_dn", "credential_id")}, "ldap_url": "ldap://dc01.corp.example"})
    assert plain.status_code == 200
    dom = db.get(AdDomain, d["id"])
    with pytest.raises(Exception, match="unencrypted"):
        ad.connect(db, dom)


def test_sync_inventory_privileged_and_reports(admin, db, mockdir):
    d = _domain(admin, db, stale_days=90)
    r = admin.post(f"/api/ad/domains/{d['id']}/sync", headers=H)
    assert r.status_code == 200, r.text
    st = r.json()
    assert (st["users"], st["computers"], st["dcs"], st["groups"], st["ous"]) == (4, 1, 1, 4, 1)
    assert st["policy"]["max_pwd_age_days"] == 42 and st["policy"]["lockout_threshold"] == 0
    users = {u["sam"]: u for u in admin.get(f"/api/ad/objects?kind=user&domain_id={d['id']}&page_size=50").json()["items"]}
    assert users["alice"]["privileged"] and set(users["alice"]["attrs"]["privileged_groups"]) == {"Domain Admins", "Administrators"}
    assert not users["bob"]["privileged"] and users["carol"]["enabled"] is False
    rep = lambda k: admin.get(f"/api/ad/reports/{k}?domain_id={d['id']}").json()  # noqa: E731
    assert [r[0] for r in rep("inactive-users")["rows"]] == ["bob"]
    assert [r[0] for r in rep("stale-computers")["rows"]] == ["WS01"]
    assert rep("domain-controllers")["rows"][0][0] == "DC01"
    risky = {(r[0], r[3]) for r in rep("risky-accounts")["rows"]}
    assert ("dave", "Kerberos pre-authentication disabled (AS-REP roastable)") in risky
    assert ("alice", "Privileged account with SPN (Kerberoastable)") in risky
    da = rep("domain-admins")["rows"]
    assert any(r[0] == "Domain Admins" and r[1] == "alice" for r in da)
    exp = {r[0]: r for r in rep("password-expiry")["rows"]}
    assert exp["alice"][5] == "Never expires" and exp["dave"][5] == "Expiring"   # 42-day max age, set 40 days ago
    assert rep("ous")["rows"][0][3] is True                                       # block inheritance on Staff
    for fmt, magic in (("pdf", b"%PDF"), ("xlsx", b"PK"), ("csv", b"\xef\xbb\xbf"), ("html", b"<!DOCTYPE")):
        f = admin.get(f"/api/ad/reports/privileged?domain_id={d['id']}&format={fmt}")
        assert f.status_code == 200 and f.content.startswith(magic)


def test_changes_between_syncs_raise_alerts(admin, db, mockdir):
    d = _domain(admin, db)
    admin.post(f"/api/ad/domains/{d['id']}/sync", headers=H)
    mockdir["conn"] = directory(extra_admin=True, drop_bob=True, disable_dave=True)
    st = admin.post(f"/api/ad/domains/{d['id']}/sync", headers=H).json()
    assert st["changes"] >= 4
    ch = {(c["name"], c["change"]) for c in admin.get(f"/api/ad/changes?domain_id={d['id']}").json()}
    assert {("eve", "created"), ("eve", "privileged_added"), ("bob", "deleted"), ("dave", "disabled"), ("Tier0 Ops", "members_changed")} <= ch
    alerts = admin.get("/api/alerts").json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert any("AD privileged change" in a["title"] for a in items)
    recent = admin.get(f"/api/ad/reports/recent?domain_id={d['id']}&days=7").json()["rows"]
    assert any(r[1] == "bob" and r[3] == "Deleted" for r in recent)


def test_bulk_preview_and_jobs(admin, db, mockdir):
    dc = add_device(admin, hostname="dc01", ip_address="10.0.0.5", platform="windows", device_type="windows_server", is_simulated=False)
    d = _domain(admin, db, dc_device_id=dc["id"])
    admin.post(f"/api/ad/domains/{d['id']}/sync", headers=H)
    pv = admin.post("/api/ad/bulk", headers=H, json={"domain_id": d["id"], "action": "disable", "accounts": ["bob", "alice", "ghost"]}).json()
    items = {i["account"]: i for i in pv["items"]}
    assert items["ghost"]["will_run"] is False and any("Privileged" in w for w in items["alice"]["warnings"])
    ex = admin.post("/api/ad/bulk", headers=H, json={"domain_id": d["id"], "action": "disable", "accounts": ["bob", "ghost"], "execute": True,
                                                     "reason": "Leaver"}).json()
    assert [j["account"] for j in ex["jobs"]] == ["bob"] and ex["skipped"] == ["ghost"]
    job = admin.get(f"/api/jobs/{ex['jobs'][0]['job_id']}").json()
    assert job["operation_id"] == "windows.ad.user.set_enabled"


def test_ad_rbac(admin, db, mockdir):
    d = _domain(admin, db)
    make_user(admin, "viewer", ["Read-only Management User"])
    c = new_client_as("viewer")
    assert c.get("/api/ad/domains").status_code == 200
    assert c.post(f"/api/ad/domains/{d['id']}/sync", headers=H).status_code == 403
    assert c.post("/api/ad/bulk", headers=H, json={"domain_id": d["id"], "action": "unlock", "accounts": ["bob"]}).status_code == 403

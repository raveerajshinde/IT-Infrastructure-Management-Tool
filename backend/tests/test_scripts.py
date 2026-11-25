"""Script library: review workflow, no browser-supplied code, injection-safe parameters, per-target execution."""
from unittest.mock import MagicMock

import pytest

from app.drivers.base import DeviceInfo, ScriptRunP
from app.drivers.registry import DRIVERS
from app.models import Job, Script
from tests.conftest import H, add_device, make_user, new_client_as, run_worker_once

SW_BODY = """! set an access port
interface {{port}}
 description {{description}}
 switchport access vlan {{vlan}}
"""
SW_PARAMS = [{"name": "port", "type": "interface"}, {"name": "description", "type": "string", "max_length": 60},
             {"name": "vlan", "type": "vlan"}]


def _script(c, **kw):
    body = {"name": kw.pop("name", "Access port"), "target": kw.pop("target", "network"), "body": kw.pop("body", SW_BODY),
            "params": kw.pop("params", SW_PARAMS), **kw}
    return c.post("/api/scripts", headers=H, json=body)


def _two_people(admin):
    """netadmin writes scripts, admin (Super Administrator) reviews them."""
    make_user(admin, "netadmin", ["Network Administrator"])
    return new_client_as("netadmin")


def test_author_cannot_approve_and_editing_resets_approval(admin):
    net = _two_people(admin)
    r = _script(net)
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["status"] == "pending" and not s["runnable"] and s["version"] == 1
    assert net.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True}).status_code == 403  # no scripts:approve
    # admin edits it -> admin is now the last editor and cannot approve their own edit
    admin.put(f"/api/scripts/{s['id']}", headers=H, json={"description": "only description"})  # metadata only: no new version
    assert admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True}).status_code == 403
    net.put(f"/api/scripts/{s['id']}", headers=H, json={"description": "back to author"})
    r = admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True, "comment": "looks good"})
    assert r.status_code == 200 and r.json()["runnable"]
    # changing the body creates a new version that needs review again
    r = net.put(f"/api/scripts/{s['id']}", headers=H, json={"body": SW_BODY + " no shutdown\n"}).json()
    assert r["version"] == 2 and r["status"] == "pending" and not r["runnable"]


def test_scripts_cannot_be_submitted_as_raw_jobs(admin):
    d = add_device(admin, hostname="sw1", platform="cisco_ios", device_type="switch")
    for op in ("network.script.run", "linux.script.run", "windows.script.run", "firewall.script.run"):
        r = admin.post("/api/jobs", headers=H, json={"operation_id": op, "device_ids": [d["id"]],
                                                       "params": {"script_id": 1, "script_sha256": "0" * 64, "body": "reload"}})
        assert r.status_code in (403, 422), (op, r.text)
    ops = [o["id"] for o in admin.get("/api/operations").json()]
    assert not [o for o in ops if o.endswith(".script.run")]


def test_body_validation(admin):
    bad = [dict(body="interface {{port}}\n reload\n"), dict(body="write erase\n", params=[]), dict(body="interface {{nope}}\n", params=[]),
           dict(target="windows", body="param($x)\nGet-Service\n", params=[]), dict(target="linux", body="echo {{x}}", params=[]),
           dict(mode="read", body="conf t\n", params=[]), dict(target="fortigate", body="execute factoryreset\n", params=[]),
           dict(params=[{"name": "Bad-Name"}]), dict(target="windows", risk="read", body="Get-Date", params=[])]
    for i, b in enumerate(bad):
        r = _script(admin, name=f"bad{i}", **b)
        assert r.status_code == 422, (b, r.text)
    assert _script(admin, name="show", mode="read", body="show vlan brief\nshow ip int brief\n", params=[]).json()["risk"] == "read"


def test_values_cannot_inject_extra_lines(admin):
    net = _two_people(admin)
    s = _script(net).json()
    admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True})
    for evil in ({"port": "Gi1/0/1", "description": "x\nreload", "vlan": 10}, {"port": "Gi1/0/1; reload", "description": "x", "vlan": 10},
                 {"port": "Gi1/0/1", "description": "x", "vlan": 5000}, {"port": "Gi1/0/1", "description": "x", "vlan": 10, "extra": "y"}):
        assert admin.post(f"/api/scripts/{s['id']}/preview", headers=H, json={"values": evil}).status_code == 422, evil
    r = admin.post(f"/api/scripts/{s['id']}/preview", headers=H, json={"values": {"port": "Gi1/0/5", "description": "Printer 2F", "vlan": "20"}}).json()
    assert r["rendered"] == "interface Gi1/0/5\n description Printer 2F\n switchport access vlan 20"


def test_run_goes_through_approval_policy_and_executes(admin, db):
    net = _two_people(admin)
    s = _script(net).json()
    admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True})
    d = add_device(admin, hostname="sw-prod", platform="cisco_ios", device_type="switch", environment="production")
    vals = {"port": "Gi1/0/5", "description": "Printer", "vlan": 20}
    r = net.post(f"/api/scripts/{s['id']}/run", headers=H, json={"device_ids": [d["id"]], "values": vals, "reason": "CHG-77 printer move"})
    assert r.status_code == 201, r.text
    job = r.json()
    assert job["status"] == "pending_approval" and "Run library script 'Access port' v1" in admin.get(f"/api/jobs/{job['id']}").json()["change_summary"]
    # a Linux server cannot run a switch script
    lx = add_device(admin, hostname="lx1", ip_address="10.0.0.20")
    assert net.post(f"/api/scripts/{s['id']}/run", headers=H, json={"device_ids": [lx["id"]], "values": vals}).status_code == 422


def test_script_edited_after_job_creation_is_not_executed(admin, db):
    net = _two_people(admin)
    s = _script(net).json()
    admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True})
    d = add_device(admin, hostname="sw-test", platform="cisco_ios", device_type="switch")
    job = net.post(f"/api/scripts/{s['id']}/run", headers=H, json={"device_ids": [d["id"]], "values": {"port": "Gi1/0/5", "description": "x", "vlan": 20}}).json()
    net.put(f"/api/scripts/{s['id']}", headers=H, json={"body": SW_BODY + " shutdown\n"})  # edited before the worker picks it up
    run_worker_once()
    j = admin.get(f"/api/jobs/{job['id']}").json()
    assert j["status"] == "failed" and "changed" in j["executions"][0]["error"]


def test_simulated_run_succeeds(admin):
    net = _two_people(admin)
    s = _script(net).json()
    admin.post(f"/api/scripts/{s['id']}/review", headers=H, json={"approve": True})
    d = add_device(admin, hostname="sw-test", platform="cisco_ios", device_type="switch")
    job = net.post(f"/api/scripts/{s['id']}/run", headers=H, json={"device_ids": [d["id"]], "values": {"port": "Gi1/0/5", "description": "x", "vlan": 20}}).json()
    run_worker_once()
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "succeeded"
    assert admin.get(f"/api/scripts/{s['id']}/runs").json()[0]["id"] == job["id"]


# ---------------------------------------------------------------- per-target execution (mocked transports)
def _p(body, defs, values, **kw):
    return ScriptRunP(script_id=1, script_sha256="a" * 64, values=values, name="t", body=body, param_defs=defs, **kw)


def test_network_config_keeps_before_after_even_when_rejected():
    drv = DRIVERS["cisco_ios"](DeviceInfo(id=1, hostname="sw", address="10.0.0.2", platform="cisco_ios", device_type="switch"), {})
    shows = iter(["running-before", "running-after"])
    drv._show = lambda c: next(shows)
    drv._config = MagicMock(side_effect=RuntimeError("Device rejected configuration: % Invalid input"))
    r = drv.run("network.script.run", _p(SW_BODY, SW_PARAMS, {"port": "Gi1/0/5", "description": "x", "vlan": 20}).model_dump())
    assert r.status == "failed" and r.config_backups == [("running-before", "running-before"), ("running", "running-after")]
    assert drv._config.call_args[0][0] == ["interface Gi1/0/5", " description x", " switchport access vlan 20"]


def test_linux_values_are_shell_quoted():
    drv = DRIVERS["linux"](DeviceInfo(id=1, hostname="l", address="10.0.0.3", platform="linux", device_type="linux_server"), {})
    seen = {}

    def fake(argv, sudo=False, timeout=None, stdin=None):
        seen.update(argv=argv, sudo=sudo, stdin=stdin)
        return MagicMock(out="ok", err="", rc=0, ok=True)
    drv._exec = fake
    r = drv.run("linux.script.run", _p('echo "$name"\n', [{"name": "name", "type": "string"}], {"name": "x'; rm -rf / #"}, run_as_root=True).model_dump())
    assert r.status == "succeeded" and seen["argv"] == ["bash", "-s"] and seen["sudo"] is True
    assert seen["stdin"].startswith("name='x'\"'\"'; rm -rf / #'\n")


def test_windows_values_are_bound_not_spliced(monkeypatch):
    import pypsrp.powershell
    calls = {}

    class FakePS:
        def __init__(self, pool):
            self.streams = MagicMock(error=[])
            self.had_errors = False

        def add_script(self, s):
            calls["script"] = s

        def add_parameters(self, p):
            calls["params"] = p

        def invoke(self):
            return ["done"]
    monkeypatch.setattr(pypsrp.powershell, "PowerShell", FakePS)
    drv = DRIVERS["windows"](DeviceInfo(id=1, hostname="w", address="10.0.0.4", platform="windows", device_type="windows_server", port=5985), {})
    drv._connect = lambda: None
    r = drv.run("windows.script.run", _p("Restart-Service -Name $svc", [{"name": "svc", "type": "string"}], {"svc": "Spooler'; Stop-Computer"}).model_dump())
    assert r.status == "succeeded" and calls["params"] == {"svc": "Spooler'; Stop-Computer"}
    assert calls["script"].startswith("param([string]$svc)") and "Stop-Computer" not in calls["script"]


def test_fortigate_uploads_script_and_diffs_config():
    drv = DRIVERS["fortigate"](DeviceInfo(id=1, hostname="fw", address="10.0.0.5", platform="fortigate", device_type="firewall"), {"api_token": "t"})
    cfgs = iter(["#config-version=x\nconfig firewall address\nend\n", "#config-version=x\nconfig firewall address\n    edit \"srv\"\nend\n"])
    drv._backup_text = lambda: next(cfgs)
    sent = {}
    drv._req = lambda m, path, body=None, **k: sent.update(path=path, body=body) or {"status": "success"}
    import time as _t
    orig = _t.sleep
    _t.sleep = lambda s: None
    try:
        r = drv.run("firewall.script.run", _p('config firewall address\n edit "{{name}}"\nend\n', [{"name": "name", "type": "hostname"}], {"name": "srv"}).model_dump())
    finally:
        _t.sleep = orig
    import base64
    assert sent["path"] == "monitor/system/config-script/upload"
    assert base64.b64decode(sent["body"]["file_content"]).decode() == 'config firewall address\n edit "srv"\nend\n'
    assert r.status == "succeeded" and "changed" in r.verification and [k for k, _ in r.config_backups] == ["full-before", "full"]


def test_sophos_has_no_script_support():
    assert "firewall.script.run" not in DRIVERS["sophos_xgs"].operations


def test_driver_refuses_without_library_body():
    drv = DRIVERS["linux"](DeviceInfo(id=1, hostname="l", address="10.0.0.3", platform="linux", device_type="linux_server"), {})
    with pytest.raises(Exception, match="library"):
        drv.run("linux.script.run", {"script_id": 1, "script_sha256": "a" * 64, "values": {}})


def test_permissions(admin):
    make_user(admin, "aud4", ["Auditor / Read Only"])
    aud = new_client_as("aud4")
    assert aud.get("/api/scripts").status_code == 200
    assert _script(aud).status_code == 403

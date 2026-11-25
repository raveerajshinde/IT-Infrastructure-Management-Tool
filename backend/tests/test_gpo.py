"""Group Policy: XML parsing, readable settings, baseline statuses, precedence, conflicts, history, reports, API and RBAC."""
from pathlib import Path

import pytest

from app.services.gpo import analysis, knowledge as kb, parser
from tests.conftest import H, add_device, make_user, new_client_as

SAMPLE = Path(__file__).resolve().parents[2] / "docs" / "samples" / "sample-gpo-report.xml"


def _xml() -> bytes:
    return SAMPLE.read_bytes()


def _upload(admin, data: bytes | None = None, name="all.xml"):
    r = admin.post("/api/gpo/upload", headers=H, files={"file": (name, data or _xml(), "text/xml")})
    assert r.status_code == 201, r.text
    return r.json()


def test_parser_handles_utf16_and_rejects_entities():
    gpos = parser.parse_report(_xml().decode().encode("utf-16"))
    assert [g.name for g in gpos][:2] == ["Default Domain Policy", "Workstation Security Baseline"]
    with pytest.raises(parser.GpoXmlError):
        parser.parse_report(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><report>&a;</report>')
    with pytest.raises(parser.GpoXmlError):
        parser.parse_report(b"<report/>")


def test_readable_settings_and_statuses():
    gpos = {g.name: g for g in parser.parse_report(_xml())}
    a = analysis.Analysis(list(gpos.values()), "corp.example")
    ws = {e["name"]: e for e in a.settings[gpos["Workstation Security Baseline"].guid]}
    d = ws["Turn off Microsoft Defender Antivirus"]
    assert (d["category"], d["status"], d["risk"]) == ("Windows Defender", "non_compliant", "critical") and d["recommendation"]
    assert ws["Require Network Level Authentication for RDP"]["status"] == "compliant"
    assert ws["Do not display the lock screen"]["status"] == "no_baseline" and "lock screen" in ws["Do not display the lock screen"]["explanation"]
    assert ws["Allow log on through Remote Desktop Services"]["status"] == "non_compliant"   # Domain Users may RDP
    assert ws["Intranet update service (WSUS) location"]["status"] == "non_compliant"        # http://
    assert any(e["category"] == "Drive Maps" or e["extension"] == "Drive Maps" for e in a.settings[gpos["Workstation Security Baseline"].guid])
    # password policy outside the domain root affects local accounts only -> not applicable, never "non-compliant"
    legacy = {e["name"]: e for e in a.settings[gpos["Workstations - Legacy LLMNR"].guid]}
    assert legacy["Minimum password length"]["status"] == "not_applicable" and "domain root" in legacy["Minimum password length"]["note"]
    # the domain-level one is evaluated
    ddp = {e["name"]: e for e in a.settings[gpos["Default Domain Policy"].guid]}
    assert ddp["Minimum password length"]["status"] == "non_compliant" and ddp["Account lockout threshold"]["risk"] == "high"
    assert all(e["status"] in kb.STATUSES for g in gpos.values() for e in a.settings[g.guid])


def test_baseline_never_treats_missing_as_insecure():
    a = analysis.Analysis(parser.parse_report(_xml()), "corp.example")
    rows = {r["rule_id"]: r for r in a.baseline()}
    assert rows["AT-PS-MOD"]["status"] == "not_configured" and rows["AT-PS-MOD"]["risk"] == "informational"
    assert "not automatically insecure" in rows["AT-PS-MOD"]["note"]
    assert rows["PWD-LEN"]["status"] == "non_compliant" and rows["PWD-LEN"]["effective_values"][0]["value"] == "8"
    assert rows["SO-LMCOMPAT"]["status"] == "non_compliant"   # Workstations get 3, Servers get 5


def test_precedence_conflicts_duplicates_and_hygiene():
    a = analysis.Analysis(parser.parse_report(_xml()), "corp.example")
    assert [x["name"] for x in a.precedence("corp.example/servers")] == ["Server Hardening", "Default Domain Policy"]
    ov = a.overlaps()
    llmnr = next(c for c in ov["conflicts"] if "multicast" in c["setting_key"])
    assert llmnr["winner"] == "Workstation Security Baseline" and llmnr["ous"] == ["corp.example/Workstations"]
    assert any("SmartScreen" in d["name"] for d in ov["duplicates"])
    assert any(d["name"].startswith("Turn off multicast") for d in ov["ou_differences"])
    inv = {r["name"]: r for r in a.inventory()}
    assert {"Unlinked", "Empty (no settings)"} <= set(inv["Test - do not use"]["flags"])
    assert "Version mismatch AD/SYSVOL" in inv["Server Hardening"]["flags"]


def test_exact_precedence_from_collector_and_block_inheritance():
    gpos = parser.parse_report(_xml())
    by = {g.name: g.guid for g in gpos}
    ou = [{"path": "corp.example", "blocked": False, "links": [], "inherited": [by["Default Domain Policy"]]},
          {"path": "corp.example/Workstations", "blocked": True, "links": [],
           "inherited": [by["Workstations - Legacy LLMNR"], by["Workstation Security Baseline"]]}]
    a = analysis.Analysis(gpos, "corp.example", {"dns_root": "corp.example"}, ou)
    assert a.exact_precedence
    assert [x["name"] for x in a.precedence("corp.example/workstations")] == ["Workstations - Legacy LLMNR", "Workstation Security Baseline"]
    llmnr = next(c for c in a.overlaps()["conflicts"] if "multicast" in c["setting_key"])
    assert llmnr["winner"] == "Workstations - Legacy LLMNR"


def test_compare_and_version_diff():
    gpos = parser.parse_report(_xml())
    cmp = analysis.compare([gpos[1], gpos[3]])
    assert cmp["counts"]["different"] >= 1 and cmp["counts"]["same"] >= 1
    old = gpos[2]
    new_xml = old.xml.replace(">20480<", ">262144<")
    new = parser.parse_report(new_xml)[0]
    d = analysis.diff_versions(old, new)
    assert d["counts"]["modified"] == 1 and d["settings"][0]["before"] == "20480" and d["settings"][0]["after"] == "262144"


def test_upload_overview_history_alerts_and_reports(admin, db):
    c = _upload(admin)
    assert c["domain"] == "corp.example" and c["gpo_count"] == 5 and c["warnings"]
    ov = admin.get("/api/gpo/overview").json()
    assert ov["summary"]["gpo_count"] == 5 and ov["summary"]["baseline_counts"]["non_compliant"] > 0
    ws = next(r for r in ov["inventory"] if r["name"] == "Workstation Security Baseline")
    det = admin.get(f"/api/gpo/gpos/{ws['guid']}").json()
    assert any(s["name"] == "Turn off Microsoft Defender Antivirus" for s in det["settings"])
    # change one GPO and upload again -> new version, change alert, setting-level diff
    changed = _xml().replace(b"<q1:SettingNumber>8</q1:SettingNumber>", b"<q1:SettingNumber>14</q1:SettingNumber>")
    c2 = _upload(admin, changed)
    assert c2["changed_count"] == 1
    hist = admin.get(f"/api/gpo/history/31b2f340-016d-11d2-945f-00c04fb984f9?domain=corp.example").json()
    assert len(hist) == 2
    diff = admin.get(f"/api/gpo/diff?a={hist[0]['snapshot_id']}&b={hist[1]['snapshot_id']}").json()
    assert diff["settings"] == [{"change": "modified", "scope": "computer", "name": "Minimum password length", "category": "Password Policy",
                                 "before": "8", "after": "14"}]
    alerts = admin.get("/api/alerts").json()
    items = alerts["items"] if isinstance(alerts, dict) else alerts
    assert any("Default Domain Policy" in a["title"] for a in items)
    # baseline exclusion is audited and changes the status
    assert admin.put("/api/gpo/baseline/AT-CHROME-PWD/exclusion", headers=H, json={"reason": "x"}).status_code == 422
    assert admin.put("/api/gpo/baseline/AT-CHROME-PWD/exclusion", headers=H, json={"reason": "Chrome is not deployed"}).status_code == 200
    rules = {r["rule_id"]: r for r in admin.get("/api/gpo/baseline").json()["rules"]}
    assert rules["AT-CHROME-PWD"]["status"] == "not_applicable"
    for fmt, magic in (("pdf", b"%PDF"), ("xlsx", b"PK"), ("html", b"<!DOCTYPE html>"), ("csv", b"\xef\xbb\xbf")):
        r = admin.get(f"/api/gpo/report?format={fmt}")
        assert r.status_code == 200 and r.content.startswith(magic), (fmt, r.text[:200])
    html = admin.get("/api/gpo/report?format=html").text
    for n in range(1, 16):
        assert f">{n}. " in html, n
    assert "Turn off Microsoft Defender Antivirus" in html and "Not configured" in html
    runs = admin.get("/api/report-runs").json()
    assert len(runs["items"]) >= 4


def test_gpo_rbac(admin, client):
    _upload(admin)
    make_user(admin, "mgmt", ["Read-only Management User"])
    c = new_client_as("mgmt")
    assert c.get("/api/gpo/overview").status_code == 200
    assert c.post("/api/gpo/upload", headers=H, files={"file": ("a.xml", _xml(), "text/xml")}).status_code == 403
    make_user(admin, "helpdesk", ["IT Support Engineer"])
    h = new_client_as("helpdesk")
    assert h.put("/api/gpo/baseline/PWD-LEN/exclusion", headers=H, json={"reason": "not allowed here"}).status_code == 403


def test_collect_job_ingests_result(admin, db, monkeypatch):
    from app.drivers.windows import WindowsDriver
    from tests.conftest import run_worker_once
    d = add_device(admin, hostname="dc01", ip_address="10.0.0.5", platform="windows", device_type="windows_server", is_simulated=False,
                   environment="test")
    calls = []

    def fake_invoke(self, script, params=None):
        calls.append(script)
        return [{"domain": {"dns_root": "corp.example", "netbios": "CORP", "mode": "Windows2016Domain"}, "dcs": [{"HostName": "dc01.corp.example"}],
                 "xml": _xml().decode(), "ous": [{"path": "corp.example", "dn": "DC=corp,DC=example", "blocked": False, "links": [], "inherited": []}],
                 "sysvol_missing": [], "sysvol_orphans": ["deadbeef-0000-0000-0000-000000000000"], "warnings": []}]
    monkeypatch.setattr(WindowsDriver, "_invoke", fake_invoke)
    monkeypatch.setattr("app.services.devices.driver_for", lambda db, dev, timeout=60: WindowsDriver(
        __import__("app.drivers.base", fromlist=["DeviceInfo"]).DeviceInfo(dev.id, dev.hostname, dev.ip_address, "windows", "windows_server"), {}))
    r = admin.post("/api/gpo/collect", headers=H, json={"device_id": d["id"]})
    assert r.status_code == 201, r.text
    run_worker_once()
    job = admin.get(f"/api/jobs/{r.json()['id']}").json()
    ex = job["executions"][0]
    assert ex["status"] == "succeeded", ex
    assert ex["data"]["collection_id"] and "xml" not in ex["data"]
    ov = admin.get("/api/gpo/overview").json()
    assert ov["collection"]["source"] == "device" and any("SYSVOL folder without AD object" in r["name"] for r in ov["inventory"])


def test_report_returned_as_list_by_powershell():
    """Field report 1.1.0: PSRP returned Get-GPOReport -All as a list -> 'expected string or bytes-like object, got list'."""
    text = _xml().decode()
    lines = text.splitlines()
    chunks = ["\n".join(lines[:40]), "\n".join(lines[40:])]                 # one document split into chunks
    assert [g.name for g in parser.parse_report(chunks)] == [g.name for g in parser.parse_report(text)]
    one_each = [g.xml for g in parser.parse_report(text)]                    # one document per GPO
    assert len(parser.parse_report(one_each)) == 5


def test_collect_job_with_list_output(admin, db, monkeypatch):
    from app.drivers.base import DeviceInfo
    from app.drivers.windows import WindowsDriver
    from tests.conftest import run_worker_once
    d = add_device(admin, hostname="dc02", ip_address="10.0.0.6", platform="windows", device_type="windows_server", is_simulated=False)
    lines = _xml().decode().splitlines()
    monkeypatch.setattr(WindowsDriver, "_invoke", lambda self, script, params=None: [{
        "domain": {"dns_root": "corp.example"}, "dcs": [], "xml": ["\n".join(lines[:30]), "\n".join(lines[30:])], "ous": [], "sysvol_missing": [],
        "sysvol_orphans": [], "warnings": []}])
    monkeypatch.setattr("app.services.devices.driver_for", lambda db, dev, timeout=60: WindowsDriver(
        DeviceInfo(dev.id, dev.hostname, dev.ip_address, "windows", "windows_server"), {}))
    r = admin.post("/api/gpo/collect", headers=H, json={"device_id": d["id"]})
    run_worker_once()
    ex = admin.get(f"/api/jobs/{r.json()['id']}").json()["executions"][0]
    assert ex["status"] == "succeeded", ex.get("error")
    assert ex["data"]["gpos"] == 5

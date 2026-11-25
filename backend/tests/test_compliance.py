"""IT audit engine: built-in frameworks, automated checks from real data, manual results with evidence,
finding lifecycle rules, evidence integrity, approval segregation, report exports and RBAC."""
from datetime import timedelta
from pathlib import Path

from app.core.timeutil import utcnow
from app.models import Evidence
from app.services import configs
from tests.conftest import H, add_device, make_user, new_client_as

SAMPLE = Path(__file__).resolve().parents[2] / "docs" / "samples" / "sample-gpo-report.xml"


def _fw(admin, code):
    return next(f for f in admin.get("/api/compliance/frameworks").json() if f["code"] == code)


def _setup_data(admin, db):
    admin.post("/api/gpo/upload", headers=H, files={"file": ("all.xml", SAMPLE.read_bytes(), "text/xml")})
    sw = add_device(admin, hostname="core-sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch", is_simulated=False)
    add_device(admin, hostname="edge-fw1", ip_address="10.0.0.3", platform="fortigate", device_type="firewall", is_simulated=False)
    configs.store_backup(db, sw["id"], "running", "hostname core-sw1\n")
    db.commit()


def test_frameworks_seeded(admin):
    codes = {f["code"]: f for f in admin.get("/api/compliance/frameworks").json()}
    assert {"ISO27001-2022", "CIS-V8", "NIST-CSF-2.0", "RBI-CSF"} <= set(codes)
    assert all(f["controls"] >= 15 and f["automated_controls"] >= 8 for f in codes.values())
    ctl = admin.get(f"/api/compliance/frameworks/{codes['ISO27001-2022']['id']}/controls").json()
    assert any(c["ref"] == "A.8.7" and "gpo_malware" in c["checks"] for c in ctl)


def test_assessment_automated_results_and_findings(admin, db):
    _setup_data(admin, db)
    fw = _fw(admin, "ISO27001-2022")
    a = admin.post("/api/compliance/assessments", headers=H, json={"framework_id": fw["id"], "title": "Q4 ISO audit",
                                                                 "period_start": (utcnow() - timedelta(days=90)).isoformat()}).json()
    det = admin.get(f"/api/compliance/assessments/{a['id']}").json()
    res = {r["ref"]: r for r in det["results"]}
    assert res["A.8.7"]["status"] == "non_compliant" and "Defender" not in res["A.8.7"]["status"]   # Defender turned off by GPO
    assert res["A.8.7"]["source"] == "automated:gpo_malware" and any(e["type"] == "file" for e in res["A.8.7"]["evidence"])
    assert res["A.8.13"]["status"] in ("partial", "non_compliant")       # one of two network devices backed up; no off-site copy
    assert res["A.5.24"]["status"] == "not_assessed" and res["A.5.24"]["source"] == ""   # process control: never auto-assessed
    assert res["A.5.16"]["status"] == "not_assessed"                     # no AD domain -> not assessed, not "compliant"
    fnd = admin.get(f"/api/compliance/findings?assessment_id={a['id']}&page_size=200").json()["items"]
    crit = [f for f in fnd if f["severity"] == "critical"]
    assert any("Turn off Microsoft Defender" in f["title"] for f in crit) and all(f["due_date"] for f in crit)
    # re-running does not duplicate findings
    n = len(fnd)
    admin.post(f"/api/compliance/assessments/{a['id']}/run", headers=H)
    assert admin.get(f"/api/compliance/findings?assessment_id={a['id']}&page_size=200").json()["total"] == n


def test_manual_result_needs_evidence_and_evidence_integrity(admin, db):
    fw = _fw(admin, "NIST-CSF-2.0")
    a = admin.post("/api/compliance/assessments", headers=H, json={"framework_id": fw["id"], "title": "CSF review", "run_checks": False}).json()
    ctl = next(c for c in admin.get(f"/api/compliance/frameworks/{fw['id']}/controls").json() if c["ref"] == "RS.MA-01")
    r = admin.put(f"/api/compliance/assessments/{a['id']}/results/{ctl['id']}", headers=H, json={"status": "compliant", "auditor_notes": "ok"})
    assert r.status_code == 422                                               # no evidence
    bad = admin.post("/api/compliance/evidence", headers=H, files={"file": ("x.exe", b"MZ", "application/octet-stream")}, data={"title": "bad"})
    assert bad.status_code == 422
    up = admin.post("/api/compliance/evidence", headers=H, files={"file": ("IR-plan.pdf", b"%PDF-1.4 incident response plan", "application/pdf")},
                    data={"title": "Incident response plan v3", "assessment_id": str(a["id"]), "control_ref": "RS.MA-01"})
    assert up.status_code == 201, up.text
    ev = up.json()
    r = admin.put(f"/api/compliance/assessments/{a['id']}/results/{ctl['id']}", headers=H,
                  json={"status": "compliant", "auditor_notes": "Plan reviewed, tabletop held 2026-10-02", "evidence_ids": [ev["id"]]})
    assert r.status_code == 200, r.text
    dl = admin.get(f"/api/compliance/evidence/{ev['id']}/download")
    assert dl.status_code == 200 and dl.headers["X-Evidence-Integrity"] == "verified" and dl.content.startswith(b"%PDF")
    e = db.get(Evidence, ev["id"])
    e.content = b"tampered"
    db.commit()
    assert admin.get(f"/api/compliance/evidence/{ev['id']}/download").status_code == 422
    assert admin.post(f"/api/compliance/evidence/{ev['id']}/withdraw", headers=H, json={"reason": "superseded by v4"}).status_code == 200


def test_finding_lifecycle_rules(admin, db):
    make_user(admin, "owner1", ["Security Administrator"])
    owner = next(u for u in admin.get("/api/users").json()["items"] if u["username"] == "owner1") if isinstance(admin.get("/api/users").json(), dict) \
        else next(u for u in admin.get("/api/users").json() if u["username"] == "owner1")
    f = admin.post("/api/compliance/findings", headers=H, json={"title": "Firewall rule ANY-ANY", "severity": "high", "asset": "edge-fw1"}).json()
    mv = lambda fid, c, **kw: c.post(f"/api/compliance/findings/{fid}/status", headers=H, json=kw)  # noqa: E731
    assert mv(f["id"], admin, to="assigned").status_code == 422               # needs owner
    admin.put(f"/api/compliance/findings/{f['id']}", headers=H, json={"owner_user_id": owner["id"], "owner_department": "Network"})
    assert mv(f["id"], admin, to="closed", comment="done").status_code == 422  # not allowed from assigned/open
    for to in ("assigned", "in_progress", "pending_verification"):
        assert mv(f["id"], admin, to=to).status_code == 200, to
    oc = new_client_as("owner1")
    assert mv(f["id"], oc, to="closed", comment="I fixed it").status_code == 403   # owner cannot verify own fix
    r = mv(f["id"], admin, to="closed", comment="Verified rule removed (config diff #12)")
    assert r.status_code == 200 and r.json()["status"] == "closed" and len(r.json()["events"]) == 5
    # risk acceptance: approver permission + future review date
    g = admin.post("/api/compliance/findings", headers=H, json={"title": "Legacy app needs SMBv1", "severity": "medium"}).json()
    assert mv(g["id"], oc, to="accepted_risk", comment="business need", accepted_until=(utcnow() + timedelta(days=90)).isoformat()).status_code == 403
    assert mv(g["id"], admin, to="accepted_risk", comment="business need").status_code == 422
    ok = mv(g["id"], admin, to="accepted_risk", comment="Business need until migration", accepted_until=(utcnow() + timedelta(days=90)).isoformat())
    assert ok.status_code == 200 and ok.json()["risk_acceptance"]["accepted_by"] == "admin"


def test_approval_segregation_lock_and_report(admin, db):
    _setup_data(admin, db)
    fw = _fw(admin, "RBI-CSF")
    a = admin.post("/api/compliance/assessments", headers=H, json={"framework_id": fw["id"], "title": "RBI annual IT audit 2026",
                                                                 "scope": {"description": "Head office data centre"}}).json()
    admin.put(f"/api/compliance/assessments/{a['id']}", headers=H, json={"executive_summary": "Overall control environment needs improvement."})
    assert admin.post(f"/api/compliance/assessments/{a['id']}/status", headers=H, json={"to": "in_review"}).status_code == 200
    assert admin.post(f"/api/compliance/assessments/{a['id']}/status", headers=H, json={"to": "approved"}).status_code == 403  # own work
    make_user(admin, "auditor2", ["Auditor / Compliance Officer"])
    au = new_client_as("auditor2")
    r = au.post(f"/api/compliance/assessments/{a['id']}/status", headers=H, json={"to": "approved", "comment": "Approved for the board"})
    assert r.status_code == 200 and r.json()["approved_by"] == "auditor2"
    assert admin.post(f"/api/compliance/assessments/{a['id']}/run", headers=H).status_code == 422          # locked
    html = admin.get(f"/api/compliance/assessments/{a['id']}/report?format=html").text
    for sec in ("Executive Summary", "Scope and Assets Assessed", "Critical and High-Risk Findings", "Control Assessment", "Findings Detail",
                "Evidence Register", "Historical Comparison", "Auditor Comments and Approval", "does not certify"):
        assert sec in html, sec
    for fmt, magic in (("pdf", b"%PDF"), ("xlsx", b"PK"), ("csv", b"\xef\xbb\xbf")):
        assert admin.get(f"/api/compliance/assessments/{a['id']}/report?format={fmt}").content.startswith(magic)
    d = admin.get("/api/compliance/dashboard").json()
    assert d["frameworks"][0]["status"] == "approved" and d["open_findings"] > 0


def test_compliance_rbac(admin):
    make_user(admin, "mgmt", ["Read-only Management User"])
    c = new_client_as("mgmt")
    assert c.get("/api/compliance/dashboard").status_code == 200
    fw = _fw(admin, "CIS-V8")
    assert c.post("/api/compliance/assessments", headers=H, json={"framework_id": fw["id"], "title": "nope"}).status_code == 403
    assert c.post("/api/compliance/findings", headers=H, json={"title": "nope"}).status_code == 403

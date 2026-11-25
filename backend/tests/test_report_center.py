"""Report Center: all templates render in every format from live data, filters, permissions, schedules with e-mail, history."""
from pathlib import Path

import pytest

from app.models import Alert, ReportSchedule
from app.services import configs
from app.services.reporting import center
from tests.conftest import H, add_device, make_user, new_client_as

SAMPLE = Path(__file__).resolve().parents[2] / "docs" / "samples" / "sample-gpo-report.xml"
MAGIC = {"pdf": b"%PDF", "xlsx": b"PK", "csv": b"\xef\xbb\xbf", "html": b"<!DOCTYPE html>"}


def _data(admin, db):
    admin.post("/api/gpo/upload", headers=H, files={"file": ("all.xml", SAMPLE.read_bytes(), "text/xml")})
    sw = add_device(admin, hostname="core-sw1", ip_address="10.0.0.2", platform="cisco_ios", device_type="switch", is_simulated=False, department="IT")
    add_device(admin, hostname="edge-fw1", ip_address="10.0.0.3", platform="fortigate", device_type="firewall", is_simulated=False)
    add_device(admin, hostname="app01", ip_address="10.0.0.4", platform="linux", device_type="linux_server", is_simulated=False, department="Finance")
    configs.store_backup(db, sw["id"], "running", "hostname core-sw1\n")
    db.add(Alert(source="rule", severity="critical", title="app01: unreachable", fingerprint="t1"))
    db.commit()


def test_all_templates_all_formats(admin, db):
    _data(admin, db)
    tpl = admin.get("/api/report-center/templates").json()
    assert len(tpl) == 12 and all(t["allowed"] for t in tpl)
    for t in tpl:
        for fmt in ("pdf", "xlsx", "csv", "html"):
            r = admin.get(f"/api/report-center/reports/{t['key']}?format={fmt}")
            assert r.status_code == 200, (t["key"], fmt, r.text[:300])
            assert r.content.startswith(MAGIC[fmt]), (t["key"], fmt)
    runs = admin.get("/api/report-runs?page_size=200").json()
    assert runs["total"] == 48 and all(x["sha256"] for x in runs["items"])
    one = runs["items"][0]
    dl = admin.get(f"/api/report-runs/{one['id']}/download")
    assert dl.status_code == 200 and dl.headers["X-Report-SHA256"] == one["sha256"]


def test_filters_and_honest_empty_states(admin, db):
    _data(admin, db)
    html = admin.get("/api/report-center/reports/daily-health?format=html&department=Finance").text
    assert "app01" in html and "core-sw1" not in html and "department Finance" in html
    ad = admin.get("/api/report-center/reports/ad-security?format=html").text
    assert "No Active Directory domain is configured" in ad
    patch = admin.get("/api/report-center/reports/patch-compliance?format=html").text
    assert "not scanned" in patch and "Not assessed" in patch


def test_permissions(admin, db):
    _data(admin, db)
    make_user(admin, "mgmt", ["Read-only Management User"])
    c = new_client_as("mgmt")
    allowed = {t["key"]: t["allowed"] for t in c.get("/api/report-center/templates").json()}
    assert allowed["executive-summary"] and allowed["gpo-complete"] and not allowed["firewall-security"]
    assert c.get("/api/report-center/reports/firewall-security?format=csv").status_code == 403
    assert c.post("/api/report-center/schedules", headers=H, json={"name": "x", "report_key": "executive-summary", "cron": "0 7 * * 1"}).status_code == 403
    fw_run = admin.get("/api/report-center/reports/firewall-security?format=pdf").headers["X-Report-Run"]
    assert c.get(f"/api/report-runs/{fw_run}/download").status_code == 403


def test_schedule_runs_and_emails(admin, db, monkeypatch):
    _data(admin, db)
    sent = []
    monkeypatch.setattr("app.services.notify.send_email", lambda db, to, subject, body, attachments=None: (sent.append((to, subject, attachments)) or (True, "sent")))
    bad = admin.post("/api/report-center/schedules", headers=H, json={"name": "Weekly", "report_key": "executive-summary", "cron": "0 7 * * 1",
                                                                    "recipients": "not-an-email"})
    assert bad.status_code == 422
    s = admin.post("/api/report-center/schedules", headers=H, json={"name": "Weekly exec", "report_key": "executive-summary", "cron": "0 7 * * 1",
                                                                  "recipients": "cio@example.com; it@example.com", "format": "pdf"}).json()
    assert s["next_run_at"] and s["recipients"] == "cio@example.com, it@example.com"
    r = admin.post(f"/api/report-center/schedules/{s['id']}/run", headers=H)
    assert r.status_code == 200, r.text
    assert sent and sent[0][2][0][0].endswith(".pdf") and sent[0][2][0][1].startswith(b"%PDF")
    assert r.json()["last_status"] == "succeeded"
    # due schedules run from the worker loop
    row = db.get(ReportSchedule, s["id"])
    from app.core.timeutil import utcnow
    row.next_run_at = utcnow()
    db.commit()
    assert center.schedule_due(db) == 1 and len(sent) == 2

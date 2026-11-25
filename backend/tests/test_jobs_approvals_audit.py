"""Job lifecycle, approval policies, segregation of duties, emergency changes, maintenance
windows, secret job parameters, cancellation, config diff capture and the audit chain."""
from datetime import timedelta

from sqlalchemy import select, text

from app.core.timeutil import utcnow
from app.models import AuditLog, ConfigChange, Job
from app.services import audit
from tests.conftest import H, add_device, make_user, new_client_as, run_worker_once


def _job(c, op, ids, params, **kw):
    return c.post("/api/jobs", headers=H, json={"operation_id": op, "device_ids": ids, "params": params, **kw})


def test_change_on_test_env_runs_without_approval(admin):
    d = add_device(admin, environment="test")
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx.service"})
    assert r.status_code == 201 and r.json()["status"] == "queued"
    run_worker_once()
    j = admin.get(f"/api/jobs/{r.json()['id']}").json()
    assert j["status"] == "succeeded"
    assert j["executions"][0]["output"].startswith("[SIMULATED]")


def test_invalid_params_rejected_server_side(admin):
    d = add_device(admin)
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx; rm -rf /"})
    assert r.status_code == 422
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx", "extra": "x"})
    assert r.status_code == 422


def test_unsupported_operation_is_explicit(admin):
    d = add_device(admin, hostname="mt1", device_type="router", platform="mikrotik_routeros")
    r = _job(admin, "network.vlan.create", [d["id"]], {"vlan_id": 10, "name": "users"})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "unsupported_operation"


def test_production_change_requires_approval_and_sod(admin):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # someone other than the requester must be able to approve
    d = add_device(admin, environment="production")
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"})
    assert r.status_code == 422  # reason required
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, reason="Apply new TLS cert")
    job = r.json()
    assert job["status"] == "pending_approval"
    run_worker_once()
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "pending_approval"
    ap = admin.get("/api/approvals").json()["items"][0]
    assert ap["can_decide"] is False
    assert admin.post(f"/api/approvals/{ap['id']}/decision", headers=H, json={"approve": True}).status_code == 403
    c = new_client_as("approver")
    assert c.post(f"/api/approvals/{ap['id']}/decision", headers=H, json={"approve": True, "comment": "ok"}).status_code == 200
    run_worker_once()
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "succeeded"


def test_rejection(admin):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # someone other than the requester must be able to approve
    d = add_device(admin, environment="production")
    job = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, reason="testing").json()
    c = new_client_as("approver")
    ap = c.get("/api/approvals").json()["items"][0]
    assert c.post(f"/api/approvals/{ap['id']}/decide", headers=H, json={"approve": False}).status_code == 422
    c.post(f"/api/approvals/{ap['id']}/decide", headers=H, json={"approve": False, "note": "not now"})
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "rejected"


def test_check_mode_skips_approval(admin):
    d = add_device(admin, environment="production")
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, check_mode=True)
    assert r.json()["status"] == "queued"
    run_worker_once()
    j = admin.get(f"/api/jobs/{r.json()['id']}").json()
    assert "check mode" in j["executions"][0]["output"]


def test_check_mode_unsupported_is_rejected(admin):
    d = add_device(admin, hostname="fw", device_type="firewall", platform="fortigate", environment="test")
    r = _job(admin, "firewall.rule.set_enabled", [d["id"]], {"policy_id": 3, "enabled": False}, check_mode=True)
    assert r.status_code == 422


def test_firewall_prod_change_needs_window(admin, db):
    make_user(admin, "approver", ["Infrastructure Administrator"])  # someone other than the requester must be able to approve
    d = add_device(admin, hostname="fw", device_type="firewall", platform="fortigate", environment="production")
    job = _job(admin, "firewall.rule.set_enabled", [d["id"]], {"policy_id": 3, "enabled": False}, reason="Disable legacy rule").json()
    c = new_client_as("approver")
    ap = c.get("/api/approvals").json()["items"][0]
    c.post(f"/api/approvals/{ap['id']}/decision", headers=H, json={"approve": True, "comment": "ok"})
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "waiting_window"
    now = utcnow()
    r = admin.post("/api/maintenance-windows", headers=H, json={"name": "now", "starts_at": (now - timedelta(minutes=5)).isoformat(),
                                                                  "ends_at": (now + timedelta(hours=1)).isoformat(), "environment": "production"})
    assert r.status_code == 201, r.text
    from app.core.db import SessionLocal
    from app.services import jobs
    s = SessionLocal()
    assert jobs.release_waiting_jobs(s) == 1
    s.close()
    run_worker_once()
    j = admin.get(f"/api/jobs/{job['id']}").json()
    assert j["status"] == "succeeded"
    changes = db.execute(select(ConfigChange)).scalars().all()
    assert len(changes) == 1 and "+! change:" in changes[0].diff


def test_emergency_change(admin):
    d = add_device(admin, environment="production")
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, emergency=True, reason="short")
    assert r.status_code == 422
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, emergency=True, reason="Outage P1: nginx hung")
    assert r.json()["status"] == "queued"
    ap = admin.get("/api/approvals").json()["items"][0]
    assert ap["kind"] == "emergency_review" and ap["status"] == "post_review"
    make_user(admin, "sup", ["IT Support Engineer"])
    c = new_client_as("sup")
    r = _job(c, "linux.service.restart", [d["id"]], {"unit": "nginx"}, emergency=True, reason="Outage P1: nginx hung")
    assert r.status_code == 403


def test_secret_params_sealed(admin, db):
    d = add_device(admin, hostname="dc1", device_type="windows_server", platform="windows", environment="test")
    r = _job(admin, "windows.localuser.create", [d["id"]], {"username": "svc_app", "password": "Very$ecretPassw0rd"})
    assert r.status_code == 201
    raw = db.execute(text("SELECT params FROM jobs")).scalar()
    assert "Very$ecretPassw0rd" not in raw and "__vault__" in raw
    assert r.json()["params"]["password"] == "***"
    run_worker_once()
    j = admin.get(f"/api/jobs/{r.json()['id']}").json()
    assert j["status"] == "succeeded" and "Very$ecretPassw0rd" not in str(j)
    for a in db.execute(select(AuditLog)).scalars():
        assert "Very$ecretPassw0rd" not in str(a.details)


def test_cancel_queued_job(admin):
    d = add_device(admin)
    job = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}).json()
    assert admin.post(f"/api/jobs/{job['id']}/cancel", headers=H).json()["status"] == "cancelled"
    run_worker_once()
    assert admin.get(f"/api/jobs/{job['id']}").json()["status"] == "cancelled"


def test_multi_device_partial_failure(admin, monkeypatch):
    d1 = add_device(admin, hostname="a")
    d2 = add_device(admin, hostname="b", ip_address="10.0.0.12")
    from app.drivers.simulated import SimulatedDriver
    orig = SimulatedDriver.run

    def flaky(self, op, params, check_mode=False):
        if self.device.hostname == "b":
            raise RuntimeError("connection reset")
        return orig(self, op, params, check_mode)
    monkeypatch.setattr(SimulatedDriver, "run", flaky)
    job = _job(admin, "linux.service.restart", [d1["id"], d2["id"]], {"unit": "nginx"}).json()
    run_worker_once()
    j = admin.get(f"/api/jobs/{job['id']}").json()
    assert j["status"] == "partial"
    assert {e["hostname"]: e["status"] for e in j["executions"]} == {"a": "succeeded", "b": "failed"}


def test_audit_chain_verifies_and_detects_tampering(admin, db):
    add_device(admin)
    v = admin.get("/api/audit/verify").json()
    assert v["valid"] and v["checked"] >= 3
    rec = db.execute(select(AuditLog).order_by(AuditLog.id).offset(1).limit(1)).scalar_one()
    rec.target_name = "tampered"
    db.commit()
    assert audit.verify_chain(db)["valid"] is False


def test_audit_export(admin):
    add_device(admin)
    r = admin.get("/api/audit/export?fmt=csv")
    assert r.status_code == 200 and "device.create" in r.text
    assert admin.get("/api/audit/export?fmt=xlsx").content[:2] == b"PK"


def test_preview_explains_change(admin):
    d = add_device(admin, environment="production")
    p = admin.post("/api/jobs/preview", headers=H, json={"operation_id": "linux.package.install", "device_ids": [d["id"]],
                                                         "params": {"packages": ["htop"]}}).json()
    assert p["summary"] == "Install packages: ['htop']" and p["approval_required"] is True and p["risk"] == "medium"
    assert "Production changes need approval" in p["approval_reason"] and p["targets"][0]["allowed"] is True


def test_inline_read_operation_is_audited(admin, db):
    d = add_device(admin)
    r = admin.post(f"/api/devices/{d['id']}/operations/linux.services.list/read", headers=H, json={})
    assert r.json()["status"] == "succeeded"
    r = admin.post(f"/api/devices/{d['id']}/operations/linux.service.restart/read", headers=H, json={"unit": "x"})
    assert r.status_code == 422
    assert db.execute(select(AuditLog).where(AuditLog.action == "operation.read")).first()


def test_template_run(admin):
    d = add_device(admin)
    t = next(t for t in admin.get("/api/templates").json() if t["operation_id"] == "linux.service.restart")
    r = admin.post(f"/api/templates/{t['id']}/run", headers=H, json={"device_ids": [d["id"]], "params": {"unit": "cron"}})
    assert r.status_code == 201
    run_worker_once()
    assert admin.get(f"/api/jobs/{r.json()['id']}").json()["status"] == "succeeded"


def test_playbook_template_simulated(admin):
    d = add_device(admin)
    t = next(t for t in admin.get("/api/templates").json() if t["playbook"] == "linux_packages.yml")
    r = admin.post(f"/api/templates/{t['id']}/run", headers=H, json={"device_ids": [d["id"]], "params": {"packages": ["htop"]}})
    assert r.status_code == 201, r.text
    bad = admin.post(f"/api/templates/{t['id']}/run", headers=H, json={"device_ids": [d["id"]], "params": {"packages": ["$(reboot)"]}})
    assert bad.status_code == 422
    run_worker_once()
    assert admin.get(f"/api/jobs/{r.json()['id']}").json()["status"] == "succeeded"


def test_stale_running_job_recovered(admin, db):
    d = add_device(admin)
    job = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}).json()
    j = db.get(Job, job["id"])
    j.status, j.started_at = "running", utcnow() - timedelta(hours=3)
    db.commit()
    from app.services import jobs
    assert jobs.recover_stale_jobs(db) == 1


def test_concurrent_claims_never_double_execute(admin):
    """Many worker threads racing for the same queue: every job is claimed exactly once."""
    import threading
    from app.core.db import SessionLocal
    from app.services import jobs as jsvc
    d = add_device(admin)
    for i in range(12):
        _job(admin, "linux.service.restart", [d["id"]], {"unit": f"svc{i}"})
    claimed, lock = [], threading.Lock()

    def worker(n):
        s = SessionLocal()
        try:
            while True:
                j = jsvc.claim_next_job(s, f"w{n}")
                if j is None:
                    return
                with lock:
                    claimed.append(j.id)
        finally:
            s.close()
    ts = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(claimed) == sorted(set(claimed)) and len(claimed) == 12


def test_change_nobody_can_approve_is_rejected_up_front(admin):
    d = add_device(admin, environment="production")
    r = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, reason="Apply new TLS cert")
    assert r.status_code == 422 and "no other active user can approve" in r.text


def test_job_explains_why_it_waits(admin, db):
    make_user(admin, "approver", ["Infrastructure Administrator"])
    d = add_device(admin, environment="production")
    job = _job(admin, "linux.service.restart", [d["id"]], {"unit": "nginx"}, reason="Apply new TLS cert").json()
    w = admin.get(f"/api/jobs/{job['id']}").json()["waiting"]
    assert w["kind"] == "approval" and "approver" in w["message"]
    t = add_device(admin, hostname="t1", ip_address="10.0.0.30")
    q = _job(admin, "linux.service.restart", [t["id"]], {"unit": "nginx"}).json()  # test env: queued, no worker heartbeat yet
    w = admin.get(f"/api/jobs/{q['id']}").json()["waiting"]
    assert w["kind"] == "worker_down" and "infrapilot-health-check" in w["message"]

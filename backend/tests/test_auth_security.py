"""Authentication, sessions, CSRF, lockout, MFA, vault and redaction."""
import pyotp
from sqlalchemy import select

from app.core import vault
from app.core.logging import redact
from app.models import AuditLog, VaultSecret
from tests.conftest import ADMIN_PW, H, login


def test_login_sets_httponly_cookie_and_me(client):
    r = login(client)
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()
    me = client.get("/api/auth/me").json()
    assert me["username"] == "admin" and "settings:manage" in me["global_permissions"]


def test_unauthenticated_rejected(client):
    assert client.get("/api/devices").status_code == 401


def test_wrong_password_generic_message(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    r2 = client.post("/api/auth/login", json={"username": "ghost", "password": "nope"})
    assert r.json()["detail"]["message"] == r2.json()["detail"]["message"]


def test_lockout_after_threshold(client):
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 401 and "locked" in r.json()["detail"]["message"]


def test_csrf_header_required_for_cookie_writes(admin):
    r = admin.post("/api/sites", json={"name": "DC1"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf"
    assert admin.post("/api/sites", json={"name": "DC1"}, headers=H).status_code == 201


def test_logout_revokes_session(admin):
    assert admin.post("/api/auth/logout", headers=H).status_code == 200
    assert admin.get("/api/auth/me").status_code == 401


def test_mfa_enrolment_and_login(client):
    login(client)
    setup = client.post("/api/auth/mfa/setup", headers=H).json()
    code = pyotp.TOTP(setup["secret"]).now()
    assert client.post("/api/auth/mfa/verify", headers=H, json={"code": code}).status_code == 200
    from app.main import app
    from fastapi.testclient import TestClient
    c2 = TestClient(app)
    r = c2.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    assert r.json() == {"mfa_required": True}
    r = c2.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW, "totp": "000000"})
    assert r.status_code == 401
    r = c2.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW, "totp": pyotp.TOTP(setup["secret"]).now()})
    assert r.status_code == 200


def test_password_policy_enforced(admin):
    r = admin.post("/api/users", headers=H, json={"username": "bob", "password": "short", "roles": []})
    assert r.status_code == 422


def test_vault_roundtrip_and_tamper_detection():
    s = vault.seal("hunter2", "credential:1")
    assert b"hunter2" not in s.ciphertext
    assert vault.unseal(s, "credential:1") == b"hunter2"
    try:
        vault.unseal(s, "credential:2")
        raise AssertionError("purpose binding not enforced")
    except vault.VaultError:
        pass


def test_credentials_never_returned_and_encrypted_at_rest(admin, db):
    r = admin.post("/api/credentials", headers=H, json={"name": "lin", "kind": "password", "username": "ops", "secret": {"password": "S3cr3t-Value!"}})
    assert r.status_code == 201
    body = r.text
    assert "S3cr3t-Value!" not in body and r.json()["has_secret"] is True
    assert "S3cr3t-Value!" not in admin.get("/api/credentials").text
    for row in db.execute(select(VaultSecret)).scalars():
        assert b"S3cr3t-Value!" not in row.ciphertext
    for a in db.execute(select(AuditLog)).scalars():
        assert "S3cr3t-Value!" not in str(a.details)


def test_redaction():
    out = redact({"username": "a", "password": "x", "nested": {"api_key": "y"}, "msg": "token=abc123 ok"})
    assert out["password"] == "***" and out["nested"]["api_key"] == "***" and "abc123" not in out["msg"]


def test_security_headers(client):
    r = client.get("/api/setup/status")
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok", "vault": "ok"}

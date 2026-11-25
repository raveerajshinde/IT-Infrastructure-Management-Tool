"""CLI used by the installer and maintenance scripts."""
import io
import sys

import pytest

from app import cli
from app.core.db import SessionLocal
from app.services import settings_store


def test_create_admin_if_missing_and_verify_audit(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("An0ther!Passw0rd\n"))
    cli.main(["create-admin", "--username", "admin2", "--if-missing"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("An0ther!Passw0rd\n"))
    cli.main(["create-admin", "--username", "admin2", "--if-missing"])
    out = capsys.readouterr().out
    assert "created" in out and "left unchanged" in out
    with pytest.raises(SystemExit) as e:
        cli.main(["verify-audit"])
    assert e.value.code == 0


def test_env_settings_bootstrap_applies_once(monkeypatch, tmp_path):
    pw = tmp_path / "ldap_pw"
    pw.write_text("BindPw!")
    monkeypatch.setenv("IP_LDAP_ENABLED", "true")
    monkeypatch.setenv("IP_LDAP_URL", "ldaps://dc01.corp.local:636")
    monkeypatch.setenv("IP_LDAP_GROUP_ROLE_MAP", "CN=IP-Admins,OU=Groups,DC=corp,DC=local=Super Administrator")
    monkeypatch.setenv("IP_LDAP_BIND_PASSWORD_FILE", str(pw))
    from app.services import bootstrap
    db = SessionLocal()
    assert "ldap.url" in bootstrap.apply_env_settings(db)
    db.commit()
    cfg = settings_store.ldap_config(db)
    assert cfg.enabled and cfg.host == "dc01.corp.local" and cfg.use_ssl and cfg.bind_password == "BindPw!"
    assert cfg.group_role_map == {"cn=ip-admins,ou=groups,dc=corp,dc=local": "Super Administrator"}
    settings_store.update(db, {"ldap.url": "ldaps://dc02.corp.local"})
    db.commit()
    assert bootstrap.apply_env_settings(db) == []  # UI value wins, never re-applied
    db.close()


def test_worker_health(monkeypatch, tmp_path):
    import time
    hb = tmp_path / "hb"
    monkeypatch.setenv("IP_WORKER_HEARTBEAT", str(hb))
    with pytest.raises(SystemExit):
        cli.main(["worker-health"])
    hb.write_text(str(time.time()))
    cli.main(["worker-health", "--max-age", "60"])


def test_password_file_url_substitution(monkeypatch, tmp_path):
    from app.core.config import Settings
    f = tmp_path / "pw"
    f.write_text("p@ss:w/rd\n")
    s = Settings(database_url="mssql+pyodbc://infrapilot_app:{password}@mssql:1433/infrapilot?driver=x", database_password_file=str(f))
    assert "p%40ss%3Aw%2Frd@mssql" in s.resolved_database_url()


def test_vault_key_version_prefix(monkeypatch):
    import base64, os
    from app.core import vault
    from app.core.config import get_settings
    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "vault_master_key", "v1:" + key)
    vault.reset_master_key_cache()
    try:
        assert vault.unseal(vault.seal("x", "p"), "p") == b"x"
    finally:
        vault.reset_master_key_cache()


def test_readyz(client):
    r = client.get("/api/readyz").json()
    assert r["checks"]["database"] == "ok" and r["status"] in ("ok", "degraded")
    assert client.get("/api/healthz").json() == {"status": "ok"}

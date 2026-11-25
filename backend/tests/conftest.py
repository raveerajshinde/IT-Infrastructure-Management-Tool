"""Test fixtures. Uses SQLite through the same SQLAlchemy models (SQL Server specifics such as
the audit trigger and sp_getapplock are dialect-guarded and covered by the migration SQL test)."""
from __future__ import annotations

import base64
import os
import tempfile

os.environ.setdefault("IP_VAULT_MASTER_KEY", base64.b64encode(b"k" * 32).decode())
os.environ["IP_COOKIE_SECURE"] = "false"
os.environ["IP_APP_MODE"] = "demo"
os.environ["IP_RATE_LIMIT_LOGIN_PER_MINUTE"] = "1000"
_tmp = tempfile.mkdtemp()
os.environ["IP_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["IP_KNOWN_HOSTS_FILE"] = f"{_tmp}/known_hosts"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.db import Base, SessionLocal, get_engine, init_engine  # noqa: E402
from app.core.ratelimit import limiter  # noqa: E402

ADMIN_PW = "Adm1n!Passw0rd#"
H = {"X-Requested-With": "InfraPilot"}


# ------------------------------------------------------------------ SQL Server dialect guard
# Tests run on SQLite, which accepts SQL that Microsoft SQL Server rejects (e.g. "col IS 1").
# Every ORM/Core statement the app executes is also compiled for the mssql dialect and checked.
import re as _re  # noqa: E402

from sqlalchemy import event as _event  # noqa: E402
from sqlalchemy.dialects import mssql as _mssql  # noqa: E402
from sqlalchemy.sql import ClauseElement as _Clause  # noqa: E402

_MSSQL = _mssql.dialect()
_BAD = [(_re.compile(r"\bIS\s+(NOT\s+)?(1|0|true|false)\b", _re.I), "boolean compared with IS (use == true()/false())"),
        (_re.compile(r"\bLIMIT\s+\d", _re.I), "LIMIT is not valid on SQL Server"),
        (_re.compile(r"\bNULLS\s+(FIRST|LAST)\b", _re.I), "NULLS FIRST/LAST is not valid on SQL Server"),
        (_re.compile(r"\bILIKE\b", _re.I), "ILIKE is not valid on SQL Server")]
MSSQL_VIOLATIONS: list[str] = []


def _mssql_guard(conn, clauseelement, multiparams, params, execution_options):
    if not isinstance(clauseelement, _Clause) or getattr(clauseelement, "is_ddl", False) or clauseelement.__class__.__name__ == "TextClause":
        return
    try:
        sql = str(clauseelement.compile(dialect=_MSSQL))
    except Exception as exc:  # noqa: BLE001 - a construct SQL Server cannot express at all
        MSSQL_VIOLATIONS.append(f"cannot compile for SQL Server: {exc.__class__.__name__}: {exc}")
        return
    for rx, why in _BAD:
        if rx.search(sql):
            MSSQL_VIOLATIONS.append(f"{why}: {sql[:300]}")


# SQL Server without MARS allows one open result set per connection ("Connection is busy with results
# for another command"). Emulate that on SQLite: each DBAPI cursor that ran a SELECT stays "open" until
# SQLAlchemy closes it (which it does once all rows are read); executing anything else on the same
# connection while one is open is recorded as a violation.
import sqlite3 as _sqlite3  # noqa: E402
import weakref as _weakref  # noqa: E402

_OPEN: "_weakref.WeakKeyDictionary" = _weakref.WeakKeyDictionary()


class _TrackCursor(_sqlite3.Cursor):
    def execute(self, sql, *a):
        others = [c for c in list(_OPEN.get(self.connection, ())) if c is not self]
        if others:
            MSSQL_VIOLATIONS.append(f"new query while another result set is still open (SQL Server: 'Connection is busy'): {str(sql)[:160]}"
                                    f"  | open: {getattr(others[0], '_sql', '')[:160]}")
        res = super().execute(sql, *a)
        self._sql = str(sql)
        if self.description is not None:  # returns rows
            _OPEN.setdefault(self.connection, set()).add(self)
        return res

    def close(self):
        _OPEN.get(self.connection, set()).discard(self)
        return super().close()


class _TrackConn(_sqlite3.Connection):
    def cursor(self, factory=_TrackCursor):
        return super().cursor(factory)


def _do_connect(dialect, conn_rec, cargs, cparams):
    return _sqlite3.connect(*cargs, factory=_TrackConn, **cparams)


@pytest.fixture(autouse=True)
def mssql_compatible_sql():
    MSSQL_VIOLATIONS.clear()
    yield
    assert not MSSQL_VIOLATIONS, "SQL that SQL Server would reject:\n" + "\n".join(dict.fromkeys(MSSQL_VIOLATIONS))


@pytest.fixture(autouse=True)
def fresh_db():
    get_settings.cache_clear()
    init_engine(os.environ["IP_DATABASE_URL"])
    if not _event.contains(get_engine(), "before_execute", _mssql_guard):
        _event.listen(get_engine(), "before_execute", _mssql_guard)
        _event.listen(get_engine(), "do_connect", _do_connect)
    import app.models  # noqa: F401
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    from app.services import bootstrap
    db = SessionLocal()
    bootstrap.seed(db)
    bootstrap.create_admin(db, "admin", ADMIN_PW)
    db.commit()
    db.close()
    limiter.reset()
    yield


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


def login(client, username="admin", password=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r


@pytest.fixture
def admin(client):
    login(client)
    return client


def make_user(client, username, role_names, password="Us3r!Passw0rd#", group_id=None):
    roles = {r["name"]: r["id"] for r in client.get("/api/roles").json()}
    r = client.post("/api/users", headers=H, json={"username": username, "password": password,
                                                   "roles": [{"role_id": roles[n], "device_group_id": group_id} for n in role_names]})
    assert r.status_code == 201, r.text
    return r.json()


def new_client_as(username, password="Us3r!Passw0rd#"):
    from app.main import app
    c = TestClient(app)
    login(c, username, password)
    return c


def add_device(client, **kw):
    body = {"hostname": kw.pop("hostname", "srv01"), "ip_address": kw.pop("ip_address", "10.0.0.10"),
            "device_type": kw.pop("device_type", "linux_server"), "platform": kw.pop("platform", "linux"),
            "environment": kw.pop("environment", "test"), "is_simulated": kw.pop("is_simulated", True), **kw}
    r = client.post("/api/devices", headers=H, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def run_worker_once(db_session=None):
    from app.services import jobs
    db = SessionLocal()
    try:
        while True:
            j = jobs.claim_next_job(db, "test-worker")
            if not j:
                break
            jobs.execute_job(db, j)
    finally:
        db.close()

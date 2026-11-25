"""Administrative CLI used by install.sh and the maintenance scripts (runs in the 'tools' container).

  python -m app.cli bootstrap-db --sa-password-file F   create database + least-privilege app login (idempotent)
  python -m app.cli migrate [--sa-password-file F]      alembic upgrade head (as sa when given) + seed + env bootstrap
  python -m app.cli create-admin --username U [--email E] [--if-missing]   (password read from stdin, never argv)
  python -m app.cli reset-admin-password --username U   (password from stdin)
  python -m app.cli verify-audit                         exit 2 if the audit hash chain is broken
  python -m app.cli worker-health [--max-age 120]        exit 1 if the worker heartbeat is older than max-age
  python -m app.cli wait-db [--timeout 300]
  python -m app.cli status
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url

from app.core.config import get_settings
from app.core.db import init_engine, session_scope

APP_LOGIN = "infrapilot_app"


def _read_password() -> str:
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        sys.exit("password must be supplied on stdin")
    return pw


def _read_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def _sa_url(sa_password_file: str, database: str | None = None):
    url = make_url(get_settings().resolved_database_url())
    return url.set(username="sa", password=_read_file(sa_password_file), database=database or url.database)


def wait_db(timeout: int) -> None:
    url = make_url(get_settings().resolved_database_url())
    if url.get_backend_name() == "mssql":
        url = url.set(database="master")
    eng = create_engine(url)
    deadline = time.time() + timeout
    while True:
        try:
            with eng.connect() as c:
                c.execute(text("SELECT 1"))
            print("database reachable")
            return
        except Exception as exc:
            if time.time() > deadline:
                sys.exit(f"database not reachable after {timeout}s: {exc}")
            time.sleep(3)


def _ident(name: str) -> str:
    if not name or not name.replace("_", "").isalnum():
        sys.exit(f"invalid identifier: {name!r}")
    return name


def bootstrap_db(sa_password_file: str) -> None:
    """Create the database and a login that can only read/write data (no DDL). Idempotent; keeps the login password in sync."""
    s = get_settings()
    url = make_url(s.resolved_database_url())
    if url.get_backend_name() != "mssql":
        print("non-mssql backend; nothing to bootstrap")
        return
    db_name = _ident(url.database)
    login = _ident(url.username or APP_LOGIN)
    app_pw = url.password or (_read_file(s.database_password_file) if s.database_password_file else None)
    if not app_pw:
        sys.exit("application database password is not available")
    eng = create_engine(_sa_url(sa_password_file, "master"), isolation_level="AUTOCOMMIT")
    deadline = time.time() + 300
    while True:
        try:
            conn = eng.connect()
            break
        except Exception as exc:
            if time.time() > deadline:
                sys.exit(f"SQL Server not reachable: {exc}")
            time.sleep(3)
    with conn:
        if not conn.execute(text("SELECT 1 FROM sys.databases WHERE name = :n"), {"n": db_name}).scalar():
            conn.execute(text(f"CREATE DATABASE [{db_name}]"))
            print(f"database {db_name} created")
        conn.execute(text(f"ALTER DATABASE [{db_name}] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"))
        pw_literal = app_pw.replace("'", "''")
        if conn.execute(text("SELECT 1 FROM sys.server_principals WHERE name = :n"), {"n": login}).scalar():
            conn.execute(text(f"ALTER LOGIN [{login}] WITH PASSWORD = N'{pw_literal}', CHECK_POLICY = ON"))
        else:
            conn.execute(text(f"CREATE LOGIN [{login}] WITH PASSWORD = N'{pw_literal}', DEFAULT_DATABASE = [{db_name}], CHECK_POLICY = ON"))
            print(f"login {login} created")
    eng.dispose()
    eng = create_engine(_sa_url(sa_password_file, db_name), isolation_level="AUTOCOMMIT")
    with eng.connect() as conn:
        if not conn.execute(text("SELECT 1 FROM sys.database_principals WHERE name = :n"), {"n": login}).scalar():
            conn.execute(text(f"CREATE USER [{login}] FOR LOGIN [{login}]"))
        for role in ("db_datareader", "db_datawriter"):
            conn.execute(text(f"ALTER ROLE [{role}] ADD MEMBER [{login}]"))
    print(f"database {db_name} ready; application login {login} has read/write (no DDL) rights")


def migrate(sa_password_file: str | None) -> None:
    from alembic import command
    from alembic.config import Config

    s = get_settings()
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "migrations"))
    url = make_url(s.resolved_database_url())
    if sa_password_file and url.get_backend_name() == "mssql":
        os.environ["IP_DATABASE_URL"] = _sa_url(sa_password_file).render_as_string(hide_password=False)
        os.environ.pop("IP_DATABASE_PASSWORD_FILE", None)
        get_settings.cache_clear()
    command.upgrade(cfg, "head")
    init_engine()
    if sa_password_file and url.get_backend_name() == "mssql":
        login = _ident(url.username or APP_LOGIN)
        with session_scope() as db:
            # defence in depth on top of the trigger: the app login may never modify audit rows
            db.execute(text(f"DENY UPDATE, DELETE, ALTER ON OBJECT::dbo.audit_logs TO [{login}]"))
    from app.services import bootstrap
    with session_scope() as db:
        bootstrap.seed(db)
        applied = bootstrap.apply_env_settings(db)
    print("migrations applied; seed data ensured" + (f"; settings bootstrapped from environment: {', '.join(applied)}" if applied else ""))


def worker_health(max_age: int) -> None:
    path = os.environ.get("IP_WORKER_HEARTBEAT", "/tmp/infrapilot-worker.heartbeat")
    try:
        age = time.time() - float(open(path).read().strip())
    except (OSError, ValueError):
        sys.exit("no worker heartbeat yet")
    if age > max_age:
        sys.exit(f"worker heartbeat is {int(age)}s old")
    print(f"worker alive (heartbeat {int(age)}s ago)")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="infrapilot")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("wait-db").add_argument("--timeout", type=int, default=300)
    sub.add_parser("bootstrap-db").add_argument("--sa-password-file", required=True)
    sub.add_parser("migrate").add_argument("--sa-password-file", default=None)
    for name in ("create-admin", "reset-admin-password"):
        a = sub.add_parser(name)
        a.add_argument("--username", required=True)
        a.add_argument("--display-name", default="Administrator")
        a.add_argument("--email", default=None)
        a.add_argument("--if-missing", action="store_true")
    sub.add_parser("verify-audit")
    sub.add_parser("worker-health").add_argument("--max-age", type=int, default=120)
    sub.add_parser("status")
    sub.add_parser("offsite-upload").add_argument("--dir", default="/backups")
    sub.add_parser("offsite-test")
    args = p.parse_args(argv)

    if args.cmd == "wait-db":
        return wait_db(args.timeout)
    if args.cmd == "bootstrap-db":
        return bootstrap_db(args.sa_password_file)
    if args.cmd == "migrate":
        return migrate(args.sa_password_file)
    if args.cmd == "worker-health":
        return worker_health(args.max_age)
    init_engine()
    from app.models import User
    from app.services import audit, bootstrap

    if args.cmd == "create-admin":
        pw = _read_password()
        with session_scope() as db:
            if db.execute(select(User).where(User.username == args.username)).first():
                print(f"user {args.username} already exists - left unchanged")
                return
            bootstrap.create_admin(db, args.username, pw, args.display_name, args.email)
        print(f"administrator {args.username} created")
    elif args.cmd == "reset-admin-password":
        from app.core import security
        pw = _read_password()
        security.validate_password_policy(pw, args.username)
        with session_scope() as db:
            u = db.execute(select(User).where(User.username == args.username)).scalar_one_or_none()
            if not u:
                sys.exit("no such user")
            u.password_hash, u.failed_attempts, u.locked_until, u.is_active = security.hash_password(pw), 0, None, True
            u.mfa_enabled, u.mfa_secret_id = False, None
            audit.record(db, "user.password_reset_cli", actor_name="cli", target_type="user", target_id=u.id, target_name=u.username)
        print("password reset; MFA cleared - the user must re-enrol")
    elif args.cmd == "verify-audit":
        with session_scope() as db:
            r = audit.verify_chain(db)
        print(f"audit chain {'intact' if r['valid'] else 'BROKEN'}: {r['checked']} records verified" +
              ("" if r["valid"] else f", failure at #{r['broken_at']} ({r['reason']})"))
        sys.exit(0 if r["valid"] else 2)
    elif args.cmd in ("offsite-upload", "offsite-test"):
        from app.services import offsite
        with session_scope() as db:
            if offsite.target(db) is None:
                print("network-share backup storage is not enabled - skipped")
                return
            if args.cmd == "offsite-test":
                ok, msg = offsite.test(db)
                print(msg)
                sys.exit(0 if ok else 1)
            try:
                r = offsite.upload_backup_set(db, args.dir)
                c = offsite.export_device_configs(db)
            except Exception as exc:  # noqa: BLE001
                offsite.record_error(db, f"Upload of nightly backup failed: {exc}")
                audit.record(db, "backup.offsite_upload", actor_name="backup", result="failure", details={"error": str(exc)[:500]})
                db.commit()
                sys.exit(f"upload to network share failed: {exc}")
            audit.record(db, "backup.offsite_upload", actor_name="backup", details={**r, "device_configs": c["exported"]})
        print(f"uploaded {len(r['uploaded'])} file(s) of set {r['backup_set']} to the network share; "
              f"{c['exported']} device config(s) exported; {r['pruned']} old file(s) pruned")
        for sk in r["skipped"]:
            print(f"WARNING: {sk}")
    elif args.cmd == "status":
        with session_scope() as db:
            print({"users": db.execute(text("SELECT COUNT(*) FROM users")).scalar(),
                   "devices": db.execute(text("SELECT COUNT(*) FROM devices WHERE deleted_at IS NULL")).scalar()})


if __name__ == "__main__":
    main()

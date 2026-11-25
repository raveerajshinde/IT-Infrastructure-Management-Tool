"""Database engine and session management (Microsoft SQL Server in production)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def make_engine(url: str | None = None) -> Engine:
    s = get_settings()
    url = url or s.resolved_database_url()
    kwargs: dict = {"echo": s.db_echo, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update(pool_size=s.db_pool_size, max_overflow=10, pool_pre_ping=True, pool_recycle=1800)
        # fast_executemany is deliberately NOT enabled: with NVARCHAR(MAX)/JSON columns pyodbc can
        # mis-size parameter buffers. The bulk-insert speed-up is irrelevant for this workload.
    eng = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _fk_on(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    return eng


def init_engine(url: str | None = None) -> Engine:
    global _engine, _SessionLocal
    _engine = make_engine(url)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


def SessionLocal() -> Session:
    if _SessionLocal is None:
        init_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

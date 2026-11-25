"""Recent server errors, kept in the database so every API process and the admin UI see the same list.

Unhandled exceptions are stored with a short reference, the request path and a redacted traceback
tail (connection strings, passwords and tokens removed). Only users with settings:manage can read
them, through Settings -> Diagnostics or /api/system/diagnostics.
"""
from __future__ import annotations

import logging
import re
import traceback
import uuid

from app.core.timeutil import utcnow

log = logging.getLogger("infrapilot.diagnostics")
KEY = "diagnostics.errors"
MAX = 40
_SCRUB = [
    (re.compile(r"(mssql\+pyodbc|postgresql|mysql)://[^\s'\"]+", re.I), r"\1://***"),
    (re.compile(r"(?i)(password|pwd|secret|token|api[_-]?key)(\s*[=:]\s*)[^\s,;'\"]+"), r"\1\2***"),
    (re.compile(r"(?i)(PWD=)[^;]+"), r"\1***"),
]


def scrub(text: str) -> str:
    for rx, rep in _SCRUB:
        text = rx.sub(rep, text)
    return text


def summarize(exc: BaseException) -> str:
    return scrub(f"{exc.__class__.__name__}: {exc}")[:600]


def record(method: str, path: str, exc: BaseException) -> str:
    """Store an unhandled error; never raises. Returns the reference shown to the user."""
    ref = uuid.uuid4().hex[:8].upper()
    try:
        from app.core.db import SessionLocal
        from app.models import SystemSetting

        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        entry = {"ref": ref, "at": utcnow().isoformat() + "Z", "method": method, "path": path, "error": summarize(exc),
                 "trace": scrub("\n".join(tb.strip().splitlines()[-25:]))[:6000]}
        db = SessionLocal()
        try:
            row = db.get(SystemSetting, KEY)
            if row is None:
                row = SystemSetting(key=KEY, value={"errors": []})
                db.add(row)
            errors = list((row.value or {}).get("errors", []))
            errors.insert(0, entry)
            row.value = {"errors": errors[:MAX]}
            db.commit()
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - diagnostics must never mask the original error
        log.exception("could not store diagnostic entry %s", ref)
    return ref


def recent(db) -> list[dict]:
    from app.models import SystemSetting

    row = db.get(SystemSetting, KEY)
    return list((row.value or {}).get("errors", [])) if row else []


def clear(db) -> None:
    from app.models import SystemSetting

    row = db.get(SystemSetting, KEY)
    if row:
        row.value = {"errors": []}
        db.commit()

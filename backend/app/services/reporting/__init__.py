"""Report generation helpers shared by Group Policy, IT audit, Active Directory and the Report Center."""
from __future__ import annotations

import hashlib
import re

from fastapi import Response
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.models import ReportRun
from app.services import audit
from app.services.reporting.render import MEDIA, Doc, render

FORMATS = ("pdf", "xlsx", "csv", "html")


def save_run(db: Session, *, key: str, doc: Doc, fmt: str, params: dict, content: bytes, user=None, actor_name: str | None = None,
             schedule_id: int | None = None, emailed_to: str = "") -> ReportRun:
    run = ReportRun(report_key=key, title=doc.title[:300], format=fmt, params=params, generated_by=(actor_name or getattr(user, "username", None) or "system")[:128],
                    user_id=getattr(user, "id", None), schedule_id=schedule_id, size=len(content), sha256=hashlib.sha256(content).hexdigest(),
                    content=content, emailed_to=emailed_to[:1000])
    db.add(run)
    db.flush()
    return run


def filename(title: str, fmt: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip("-")[:80] or "report"
    return f"{base}-{utcnow().strftime('%Y%m%d-%H%M')}.{fmt}"


def export(db: Session, *, key: str, doc: Doc, fmt: str, params: dict, user, ip: str | None, keep: bool = True) -> Response:
    """Render, keep a copy in the report history, audit, and return the download."""
    if fmt not in FORMATS:
        from app.core.errors import ValidationFailed
        raise ValidationFailed(f"Format must be one of {', '.join(FORMATS)}")
    content = render(doc, fmt)
    run = save_run(db, key=key, doc=doc, fmt=fmt, params=params, content=content, user=user) if keep else None
    audit.record(db, "report.export", actor=user, target_type="report", target_id=key, target_name=doc.title[:300], ip=ip,
                 details={"format": fmt, "params": params, "sha256": run.sha256 if run else hashlib.sha256(content).hexdigest(), "size": len(content)})
    db.commit()
    disp = "inline" if fmt in ("html", "pdf") and params.get("inline") else "attachment"
    return Response(content, media_type=MEDIA[fmt], headers={"Content-Disposition": f'{disp}; filename="{filename(doc.title, fmt)}"',
                                                             "X-Report-Run": str(run.id if run else "")})

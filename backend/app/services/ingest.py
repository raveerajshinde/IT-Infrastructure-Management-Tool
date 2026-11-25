"""Post-processing of successful read/change operations whose results feed other modules (Group Policy reporting)."""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models import Device, Job, JobExecution

log = logging.getLogger("infrapilot.ingest")
HOOKED = {"windows.gpo.collect", "windows.gpo.restore", "windows.gpo.backup"}


def after_execution(db: Session, job: Job, ex: JobExecution, d: Device, data) -> None:
    if job.operation_id not in HOOKED or ex.status != "succeeded" or not isinstance(data, dict):
        return
    from app.services.gpo import store
    try:
        if job.operation_id == "windows.gpo.collect":
            c = store.ingest(db, xml=data.get("xml") or "", domain_info=data.get("domain") or {}, ou_data=data.get("ous") or [],
                             extra={"domain_controllers": data.get("dcs") or [], "sysvol_missing": data.get("sysvol_missing") or [],
                                    "sysvol_orphans": data.get("sysvol_orphans") or [], "warnings": data.get("warnings") or []},
                             source="device", device_id=d.id, collected_by=f"job #{job.id}", job_execution_id=ex.id)
            ex.result = {"collection_id": c.id, "domain": c.domain, "gpos": c.gpo_count, "changed_or_deleted": c.changed_count,
                         "warnings": data.get("warnings") or [], "link": f"/gpo?collection={c.id}"}
            ex.output = (ex.output or "") + f"\nStored as GPO collection #{c.id} ({c.changed_count} GPO(s) changed or deleted since the previous collection)."
        elif job.operation_id == "windows.gpo.restore":
            ids = {} if data.get("dry_run") else store.store_versions(db, data.get("before_xml"), data.get("after_xml"), actor_name=f"job #{job.id}", device_id=d.id)
            ex.result = {"dry_run": bool(data.get("dry_run")), "diff": data.get("diff") or {}, **ids}
        elif job.operation_id == "windows.gpo.backup":
            ids = store.store_versions(db, None, data.get("xml"), actor_name=f"job #{job.id}", device_id=d.id)
            ex.result = {k: v for k, v in data.items() if k != "xml"} | {"backed_up_snapshot": ids.get("after_snapshot")}
        db.flush()
    except Exception as exc:  # noqa: BLE001 - surface on the job, never lose the device result silently
        log.exception("post-processing of %s failed", job.operation_id)
        ex.status = "failed"
        ex.error = f"The operation ran, but storing its result failed: {getattr(exc, 'message', None) or exc}"[:8000]

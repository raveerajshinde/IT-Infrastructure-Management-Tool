"""Background worker: job queue consumer + monitoring scheduler.

Run: python -m app.worker.main
Concurrency: N job threads (IP_WORKER_CONCURRENCY) each claim jobs with row locks
(UPDLOCK/READPAST on SQL Server) so several worker containers can run safely.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app.core.config import get_settings
from app.core.db import SessionLocal, init_engine
from app.core.logging import setup_logging
from app.models import Device
from app.services import integrations, jobs, monitoring, schedules, settings_store

log = logging.getLogger("infrapilot.worker")
STOP = threading.Event()
HEARTBEAT = os.environ.get("IP_WORKER_HEARTBEAT", "/tmp/infrapilot-worker.heartbeat")


def _offsite_export(db) -> None:
    """Copy new device configuration backups to the network share within about a minute of being taken.

    Checks cheaply every loop; after a failed attempt waits 5 minutes before retrying.
    """
    from datetime import datetime, timedelta

    from app.core.timeutil import utcnow
    from app.services import offsite
    if offsite.target(db) is None or not offsite.pending_device_configs(db):
        return
    st = offsite.status(db)
    tried, failed = st.get("last_config_export_try"), st.get("last_error_at")
    now = utcnow()
    if tried and now - datetime.fromisoformat(tried.rstrip("Z")) < timedelta(seconds=45):
        return
    if failed and tried and failed >= tried and now - datetime.fromisoformat(failed.rstrip("Z")) < timedelta(minutes=5):
        return
    offsite._save_state(db, last_config_export_try=now.isoformat() + "Z")
    try:
        offsite.export_device_configs(db)
    except Exception as exc:  # noqa: BLE001 - report on the Backup storage page, keep the worker running
        offsite.record_error(db, f"Device configuration export failed: {exc}")
        log.warning("offsite export failed: %s", exc)


def _folder_export(db) -> None:
    """Copy new device configuration backups into the configured server folder within about a minute."""
    from datetime import datetime, timedelta

    from app.core.timeutil import utcnow
    from app.services import folder_export
    if folder_export.folder(db) is None or not folder_export.pending(db):
        return
    st = folder_export.status(db)
    tried, failed = st.get("last_try"), st.get("last_error_at")
    now = utcnow()
    if tried and now - datetime.fromisoformat(tried.rstrip("Z")) < timedelta(seconds=45):
        return
    if failed and tried and failed >= tried and now - datetime.fromisoformat(failed.rstrip("Z")) < timedelta(minutes=5):
        return
    folder_export.save_state(db, last_try=now.isoformat() + "Z")
    try:
        folder_export.export(db)
    except Exception as exc:  # noqa: BLE001 - shown on Settings -> Backup, keep the worker running
        folder_export.record_error(db, f"Copy to folder failed: {exc}")
        log.warning("folder export failed: %s", exc)


def _ad_sync(db) -> None:
    """Synchronise Active Directory domains whose interval has elapsed (read-only LDAPS)."""
    from app.services import ad
    for d in ad.due_domains(db):
        try:
            ad.sync(db, d)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - shown on the domain page
            db.rollback()
            d = db.get(type(d), d.id)
            from app.core.timeutil import utcnow
            d.last_sync_at, d.last_sync_ok, d.last_sync_message = utcnow(), False, str(exc)[:1000]
            db.commit()
            log.warning("AD sync of %s failed: %s", d.name, exc)


def _report_schedules(db) -> None:
    from app.services.reporting import center
    try:
        center.schedule_due(db)
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("report schedules failed")


def _purge_report_runs(db) -> None:
    """Keep generated report files for reports.retention_days (default 365)."""
    from datetime import timedelta

    from app.core.timeutil import utcnow
    from app.models import ReportRun
    from app.services import settings_store
    days = int(settings_store.value(db, "reports.retention_days") or 365)
    db.execute(ReportRun.__table__.delete().where(ReportRun.generated_at < utcnow() - timedelta(days=days)))
    db.commit()


def job_loop(worker_id: str) -> None:
    s = get_settings()
    while not STOP.is_set():
        db = SessionLocal()
        try:
            job = jobs.claim_next_job(db, worker_id)
            if job is None:
                db.close()
                STOP.wait(s.worker_poll_seconds)
                continue
            log.info("executing job %s (%s)", job.id, job.title)
            jobs.execute_job(db, job)
            log.info("job %s finished: %s", job.id, job.status)
        except Exception:
            log.exception("job loop error")
            db.rollback()
            STOP.wait(5)
        finally:
            db.close()


def scheduler_loop() -> None:
    s = get_settings()
    pool = ThreadPoolExecutor(max_workers=8)
    last_purge = 0.0
    last_sync = 0.0
    while not STOP.is_set():
        try:
            with open(HEARTBEAT, "w") as fh:
                fh.write(str(time.time()))
        except OSError:
            pass
        db = SessionLocal()
        try:
            _db_heartbeat(db)
            jobs.release_waiting_jobs(db)
            jobs.recover_stale_jobs(db)
            jobs.expire_approvals(db)
            jobs.schedule_config_backups(db)
            schedules.run_due(db)
            _offsite_export(db)
            _folder_export(db)
            _report_schedules(db)
            if time.time() - last_sync > 300:
                integrations.sync_all(db)
                _ad_sync(db)
                last_sync = time.time()
            interval = int(settings_store.value(db, "monitoring.interval_seconds") or s.monitoring_interval_seconds)
            due = [d.id for d in monitoring.due_devices(db, interval)]
            db.close()
            list(pool.map(_poll_one, due[:200]))
            db = SessionLocal()
            monitoring.escalate(db)
            if time.time() - last_purge > 3600:
                monitoring.purge_old_metrics(db)
                _purge_report_runs(db)
                last_purge = time.time()
            db.commit()
        except Exception:
            log.exception("scheduler error")
            db.rollback()
        finally:
            db.close()
        STOP.wait(15)


def _db_heartbeat(db) -> None:
    from app.core.timeutil import utcnow
    from app.models import SystemSetting
    row = db.get(SystemSetting, "worker.heartbeat")
    val = {"ts": utcnow().isoformat(), "worker": socket.gethostname()}
    if row is None:
        db.add(SystemSetting(key="worker.heartbeat", value=val))
    else:
        row.value = val
    db.commit()


def _poll_one(device_id: int) -> None:
    db = SessionLocal()
    try:
        d = db.get(Device, device_id)
        if d and d.deleted_at is None:
            monitoring.poll_device(db, d)
            db.commit()
    except Exception:
        log.exception("poll failed for device %s", device_id)
        db.rollback()
    finally:
        db.close()


def main() -> None:
    s = get_settings()
    setup_logging(s.log_level)
    init_engine()
    wid = f"{socket.gethostname()}-{os.getpid()}"
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    threads = [threading.Thread(target=job_loop, args=(f"{wid}-{i}",), daemon=True) for i in range(s.worker_concurrency)]
    threads.append(threading.Thread(target=scheduler_loop, daemon=True))
    for t in threads:
        t.start()
    log.info("worker %s started with %d job threads", wid, s.worker_concurrency)
    while not STOP.is_set():
        time.sleep(1)
    log.info("worker stopping; in-flight device steps are allowed to finish")
    for t in threads:
        t.join(timeout=120)


if __name__ == "__main__":
    main()

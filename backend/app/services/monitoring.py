"""Availability polling, metric collection, threshold alerting and escalation."""
from __future__ import annotations

import logging
import operator
from datetime import timedelta

from sqlalchemy import delete, select, true
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.drivers.registry import DRIVERS
from app.drivers.snmp import SnmpV3Client, ping, tcp_check
from app.models import Alert, AlertRule, Credential, Device, DeviceGroupMember, Metric, Notification, User
from app.services import auth, devices, notify, secrets, settings_store

log = logging.getLogger("infrapilot.monitoring")
OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le}


def poll_device(db: Session, d: Device) -> dict[str, float]:
    now = utcnow()
    metrics: dict[str, float] = {}
    if d.is_simulated:
        drv = devices.driver_for(db, d)
        metrics = drv.collect_metrics()
        metrics["availability"] = 1.0
    else:
        up, rtt = ping(d.ip_address)
        if not up:
            port = d.port or DRIVERS[d.platform].default_port
            if port:
                up, rtt = tcp_check(d.ip_address, port)
        metrics["availability"] = 1.0 if up else 0.0
        if rtt is not None:
            metrics["latency_ms"] = round(rtt, 2)
        if up and d.credential_id:
            drv = devices.driver_for(db, d, timeout=30)
            try:
                metrics.update(devices.run_with_timeout(drv.collect_metrics, 45))
                d.last_success_at = now
                d.last_error = None
            except Exception as exc:
                d.last_error = (getattr(exc, "message", None) or str(exc))[:1000]
            finally:
                drv.close()
        if up and d.snmp_credential_id and not any(k in metrics for k in ("cpu_pct", "mem_pct")):
            try:
                cred = secrets.credential_material(db, db.get(Credential, d.snmp_credential_id))
                metrics.update(devices.run_with_timeout(lambda: SnmpV3Client(d.ip_address, cred).host_resources(), 30))
            except Exception as exc:
                d.last_error = f"SNMP: {getattr(exc, 'message', None) or exc}"[:1000]
    d.last_checked_at = now
    if metrics["availability"] == 0:
        d.status = "down"
    elif d.last_error and d.credential_id:
        d.status = "degraded"
    else:
        d.status = "up"
    for k, val in metrics.items():
        db.add(Metric(device_id=d.id, metric=k, value=float(val), ts=now))
    evaluate_alerts(db, d, metrics)
    return metrics


def _rule_applies(db: Session, rule: AlertRule, d: Device) -> bool:
    if rule.device_type and rule.device_type != d.device_type:
        return False
    if rule.device_group_id:
        return db.get(DeviceGroupMember, (rule.device_group_id, d.id)) is not None
    return True


def evaluate_alerts(db: Session, d: Device, metrics: dict[str, float]) -> None:
    for rule in db.execute(select(AlertRule).where(AlertRule.enabled == true())).scalars().all():
        if rule.metric not in metrics or not _rule_applies(db, rule, d):
            continue
        val = metrics[rule.metric]
        breached = OPS[rule.operator](val, rule.threshold)
        fp = f"rule:{rule.id}:dev:{d.id}"
        cur = db.execute(select(Alert).where(Alert.fingerprint == fp, Alert.status != "resolved")).scalar_one_or_none()
        if breached:
            if cur:
                cur.count += 1
                cur.last_seen_at = utcnow()
                cur.message = f"{rule.metric} = {val:g} ({rule.operator} {rule.threshold:g})"
            else:
                title = f"{d.hostname}: {'unreachable' if rule.metric == 'availability' else rule.name}"
                a = Alert(rule_id=rule.id, device_id=d.id, source="rule", severity=rule.severity, title=title,
                          message=f"{rule.metric} = {val:g} ({rule.operator} {rule.threshold:g})", fingerprint=fp)
                db.add(a)
                db.flush()
                _announce(db, a, rule)
        elif cur:
            cur.status, cur.resolved_at = "resolved", utcnow()


def _announce(db: Session, a: Alert, rule: AlertRule | None) -> None:
    if a.severity in ("critical", "warning"):
        for u in db.execute(select(User).where(User.is_active == true())).scalars().all():
            if auth.has_any_scope(db, u, "alerts:manage"):
                db.add(Notification(user_id=u.id, title=a.title, body=a.message, severity=a.severity, link="/alerts"))
    if rule and rule.notify_email:
        notify.send_email(db, rule.notify_email, f"[InfraPilot {a.severity.upper()}] {a.title}", f"{a.title}\n\n{a.message}\n\nFirst seen: {a.first_seen_at} UTC")


def escalate(db: Session) -> int:
    n = 0
    now = utcnow()
    for a in db.execute(select(Alert).where(Alert.status == "open", Alert.escalated_at.is_(None), Alert.rule_id.is_not(None))).scalars().all():
        rule = db.get(AlertRule, a.rule_id)
        if rule and rule.escalate_after_minutes and rule.escalation_email and a.first_seen_at + timedelta(minutes=rule.escalate_after_minutes) <= now:
            notify.send_email(db, rule.escalation_email, f"[InfraPilot ESCALATION] {a.title}",
                              f"Unacknowledged for {rule.escalate_after_minutes} minutes.\n\n{a.title}\n{a.message}")
            a.escalated_at = now
            n += 1
    return n


def purge_old_metrics(db: Session) -> None:
    days = int(settings_store.value(db, "monitoring.metrics_retention_days"))
    db.execute(delete(Metric).where(Metric.ts < utcnow() - timedelta(days=days)))


def due_devices(db: Session, interval_seconds: int) -> list[Device]:
    cutoff = utcnow() - timedelta(seconds=interval_seconds)
    q = select(Device).where(Device.deleted_at.is_(None), Device.monitoring_enabled == true())
    return [d for d in db.execute(q).scalars() if not d.last_checked_at or d.last_checked_at <= cutoff]

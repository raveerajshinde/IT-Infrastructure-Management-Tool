"""Response shapes consumed by the web UI (the API contract documented in docs/API.md)."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.drivers.actions import actions_for, view_actions_for
from app.core.config import get_settings
from app.core.permissions import operation_permission
from app.drivers.base import OperationSpec
from app.drivers.registry import DRIVERS, driver_class
from app.models import (
    Alert, Approval, ConfigBackup, ConfigChange, Credential, Device, DeviceGroupMember, Integration, Job, Site, User,
)
from app.services import auth, jobs, settings_store

RISK_UI = {"read": "low", "change": "medium", "critical": "critical"}


def iso(v: datetime | None) -> str | None:
    """Timestamps are stored as naive UTC; emit explicit UTC so browsers convert correctly."""
    return v.isoformat() + "Z" if v else None


def family(spec: OperationSpec, category: str) -> str:
    if spec.id.startswith(("windows.ad.", "windows.dns.", "windows.dhcp.", "windows.gpo.", "windows.gpupdate")):
        return "ad"
    return category


def operation(spec: OperationSpec, category: str, allowed: bool, available: dict | None = None) -> dict:
    schema = spec.params.model_json_schema()
    for sp in spec.secret_params:
        if sp in schema.get("properties", {}):
            schema["properties"][sp]["format"] = "password"
            schema["properties"][sp]["writeOnly"] = True
    return {"id": spec.id, "name": spec.title, "family": family(spec, category), "permission": operation_permission(category, spec.risk),
            "risk": RISK_UI[spec.risk], "mutating": spec.risk != "read", "check_mode": spec.check_mode,
            "summary": spec.changes or spec.description, "rollback": "", "schema": schema, "allowed": allowed,
            "row_actions": actions_for(spec.id, available) if available is not None and spec.risk == "read" else [],
            "view_actions": view_actions_for(spec.id, available) if available is not None and spec.risk == "read" else []}


def site(s: Site | None) -> dict | None:
    return {"id": s.id, "name": s.name, "kind": s.kind, "location": s.address} if s else None


def device(db: Session, d: Device, user: User | None = None, with_ops: bool = False) -> dict:
    out = {
        "id": d.id, "hostname": d.hostname, "ip_address": d.ip_address, "device_type": d.device_type, "driver": d.platform,
        "vendor": d.vendor, "model": d.model, "os_name": d.os_name, "os_version": d.os_version, "firmware": d.firmware,
        "serial_number": d.serial_number, "environment": d.environment, "status": d.status, "site": site(d.site), "site_id": d.site_id,
        "department": d.department, "location": d.location, "owner": d.owner, "tags": d.tags or [], "is_simulated": d.is_simulated,
        "last_seen_at": iso(d.last_checked_at), "last_success_at": iso(d.last_success_at), "last_error": d.last_error,
        "credential_id": d.credential_id, "snmp_credential_id": d.snmp_credential_id, "port": d.port, "notes": d.notes,
        "monitoring_enabled": d.monitoring_enabled, "options": {"verify_tls": d.verify_tls},
        "groups": list(db.execute(select(DeviceGroupMember.group_id).where(DeviceGroupMember.device_id == d.id)).scalars()),
        "created_at": iso(d.created_at), "updated_at": iso(d.updated_at),
    }
    if with_ops and user is not None:
        cls = driver_class(d.platform)
        out["operations"] = [operation(s, cls.category, auth.has_permission(db, user, operation_permission(cls.category, s.risk), d.id), cls.operations)
                             for s in cls.operations.values() if not s.id.endswith(".script.run")]
    return out


def meta(mode: str) -> dict:
    from app.schemas import DEVICE_TYPES, ENVIRONMENTS

    transport = {"windows": "WinRM/PSRP", "linux": "SSH", "fortigate": "REST API", "sophos_xgs": "XML API", "proxmox": "REST API",
                 "vmware_vcenter": "vSphere REST", "snmp_generic": "SNMPv3"}
    notes = {
        "windows": "Credential options (transport, use_ssl) are set on the credential. AD/DNS/DHCP/GPO operations need the RSAT modules on the target.",
        "linux": "Changes use sudo -n (NOPASSWD) unless the credential user is root. Host keys are pinned on first use.",
        "mikrotik_routeros": "Backup, interfaces, routes and static routes. VLAN/port changes are not offered (bridge VLAN filtering is design-specific).",
        "sophos_xgs": "XML API: rules, NAT, objects, zones. No log retrieval or full appliance backup via API (object snapshot only).",
        "fortigate": "REST API admin token; add this server to the token's trusted hosts.",
        "snmp_generic": "Monitoring only (availability, interfaces, CPU/memory/storage via HOST-RESOURCES-MIB).",
        "proxmox": "API token: user@realm!tokenid with the token UUID as secret.",
        "vmware_vcenter": "vSphere 7.0U2+ REST API; performance counters are not exposed via REST (datastore usage only).",
    }
    return {"device_types": list(DEVICE_TYPES), "environments": list(ENVIRONMENTS), "mode": mode, "version": get_settings().app_version,
            "credential_kinds": ["password", "winrm", "ssh_key", "api_token", "snmpv3"],
            "drivers": [{"name": c.key, "label": c.display_name, "vendor": c.vendor, "device_types": list(c.device_types),
                         "transport": transport.get(c.key, "SSH CLI"), "default_port": c.default_port,
                         "credential_kinds": list(c.credential_kinds) + (["winrm"] if c.key == "windows" else []),
                         "operations": list(c.operations), "notes": notes.get(c.key, "")} for c in DRIVERS.values()]}


def job(db: Session, j: Job, detail: bool = True) -> dict:
    req = db.get(User, j.requested_by) if j.requested_by else None
    ap = db.execute(select(Approval).where(Approval.job_id == j.id).order_by(Approval.id.desc()).limit(1)).scalar_one_or_none()
    o = {"id": j.id, "title": j.title, "kind": j.kind, "operation_id": j.operation_id or j.playbook, "playbook": j.playbook, "status": j.status,
         "risk": RISK_UI.get(j.risk, j.risk), "check_mode": j.check_mode, "emergency": j.is_emergency, "approval_required": ap is not None and ap.kind == "pre",
         "requires_window": j.requires_window, "change_summary": j.change_summary, "summary": j.summary, "params": jobs.public_params(j.params),
         "requested_by": req.username if req else "system", "requested_by_id": j.requested_by, "created_at": iso(j.created_at), "started_at": iso(j.started_at),
         "finished_at": iso(j.finished_at), "device_count": len(j.executions), "template_id": j.template_id, "cancel_requested": j.cancel_requested}
    if detail:
        names = {d.id: d.hostname for d in db.execute(select(Device).where(Device.id.in_([e.device_id for e in j.executions] or [-1]))).scalars()}
        o["executions"] = [{"id": e.id, "device_id": e.device_id, "hostname": names.get(e.device_id), "status": e.status, "output": e.output,
                            "data": e.result or None, "error": e.error, "before_state": e.before_state, "after_state": e.after_state,
                            "verification": e.verification, "rollback_hint": e.rollback_hint, "started_at": iso(e.started_at),
                            "finished_at": iso(e.finished_at)} for e in j.executions]
        o["approval"] = approval(db, ap, include_job=False) if ap else None
        ex_ids = [e.id for e in j.executions] or [-1]
        o["waiting"] = waiting_reason(db, j, ap)
        o["config_changes"] = [{"id": c.id, "device_id": c.device_id, "hostname": names.get(c.device_id), "diff": c.diff,
                                "before_backup_id": c.backup_before_id, "after_backup_id": c.backup_after_id}
                               for c in db.execute(select(ConfigChange).where(ConfigChange.job_execution_id.in_(ex_ids))).scalars()]
    return o


def waiting_reason(db: Session, j: Job, ap) -> dict | None:
    """Plain explanation of why a job has not run yet, with what to do about it."""
    from app.core.timeutil import utcnow
    from app.models import MaintenanceWindow, SystemSetting
    from app.services import jobs as jobs_svc
    now = utcnow()
    if j.status == "pending_approval":
        others = jobs_svc._approvers(db, j.requested_by)
        if not others:
            return {"kind": "no_approver", "message": "Nobody else can approve this change. Changes can't be approved by the person who requested them, "
                    "and no other active user has the 'Approve or reject changes' permission. Give a second person an approver role "
                    "(e.g. Infrastructure Administrator), or change the approval policy in Approvals -> Policies."}
        return {"kind": "approval", "message": f"Waiting for one of: {', '.join(u.username for u in others[:8])}. They see it under Approvals."}
    if j.status == "waiting_window":
        wins = [w for w in db.execute(select(MaintenanceWindow).where(MaintenanceWindow.end_at > now)
                                      .order_by(MaintenanceWindow.start_at)).scalars()]
        nxt = wins[0] if wins else None
        return {"kind": "window", "message": "An approval policy only allows this change inside a maintenance window. "
                + (f"Next window: '{nxt.name}' from {iso(nxt.start_at)}." if nxt else "No upcoming maintenance window exists - create one under Approvals -> Maintenance windows."),
                "next_window_at": iso(nxt.start_at) if nxt else None}
    if j.status == "queued":
        hb = db.get(SystemSetting, "worker.heartbeat")
        age = (now - hb.updated_at).total_seconds() if hb and hb.updated_at else None
        if age is None or age > 120:
            return {"kind": "worker_down", "message": "The background worker that executes jobs is not running"
                    + (f" (last seen {int(age // 60)} min ago)" if age is not None else " (never seen)")
                    + ". On the server run: sudo infrapilot-health-check - and see Settings -> Diagnostics."}
        queued_for = (now - (j.queued_at or j.created_at)).total_seconds()
        if queued_for > 60:
            ahead = db.execute(select(func.count()).select_from(Job).where(Job.status.in_(["queued", "running"]), Job.id < j.id)).scalar()
            return {"kind": "busy", "message": f"Queued behind {ahead} other job(s)." if ahead else "Starting shortly."}
    return None


def approval_status(a: Approval) -> str:
    if a.kind == "emergency_review":
        return {"pending": "post_review", "approved": "reviewed", "rejected": "flagged"}.get(a.status, a.status)
    return a.status


def approval(db: Session, a: Approval, include_job: bool = True) -> dict:
    req = db.get(User, a.requested_by) if a.requested_by else None
    dec = db.get(User, a.decided_by) if a.decided_by else None
    hours = int(settings_store.value(db, "approval.expiry_hours") or 72)
    o = {"id": a.id, "job_id": a.job_id, "status": approval_status(a), "kind": a.kind, "reason": a.reason, "decision_note": a.decision_comment or "",
         "requested_by": req.username if req else None, "requested_by_id": a.requested_by, "decided_by": dec.username if dec else None,
         "created_at": iso(a.created_at), "decided_at": iso(a.decided_at),
         "expires_at": iso(a.created_at + timedelta(hours=hours)) if a.kind == "pre" and a.status == "pending" else None}
    if include_job:
        j = db.get(Job, a.job_id)
        o["job"] = job(db, j, detail=False) if j else None
        if j:
            o["job"]["targets"] = [db.get(Device, e.device_id).hostname for e in j.executions]
    return o


def alert(db: Session, a: Alert) -> dict:
    d = db.get(Device, a.device_id) if a.device_id else None
    ack = db.get(User, a.acknowledged_by) if a.acknowledged_by else None
    return {"id": a.id, "rule_id": a.rule_id, "device_id": a.device_id, "hostname": d.hostname if d else None, "severity": a.severity,
            "title": a.title, "detail": a.message, "status": a.status, "source": a.source, "count": a.count, "opened_at": iso(a.first_seen_at),
            "last_seen_at": iso(a.last_seen_at), "acknowledged_by": ack.username if ack else None, "acknowledged_at": iso(a.acknowledged_at),
            "resolved_at": iso(a.resolved_at), "escalated_at": iso(a.escalated_at)}


def credential(db: Session, c: Credential) -> dict:
    in_use = db.execute(select(func.count()).select_from(Device).where(Device.deleted_at.is_(None),
                        (Device.credential_id == c.id) | (Device.snmp_credential_id == c.id))).scalar()
    return {"id": c.id, "name": c.name, "kind": c.kind, "username": c.username, "description": c.description, "extra": c.extra or {},
            "key_version": "v1", "has_secret": c.secret_id is not None, "created_at": iso(c.created_at), "updated_at": iso(c.updated_at), "in_use": in_use}


def user(u: User) -> dict:
    from app.core.timeutil import utcnow
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "email": u.email, "auth_source": u.auth_source,
            "mfa_enabled": u.mfa_enabled, "must_change_password": u.must_change_password, "is_active": u.is_active,
            "locked": bool(u.locked_until and u.locked_until > utcnow()), "last_login_at": iso(u.last_login_at), "created_at": iso(u.created_at),
            "roles": [{"id": a.id, "role_id": a.role_id, "role": a.role.name, "scope_group_id": a.device_group_id} for a in u.role_assignments],
            "permissions": []}


def integration(it: Integration) -> dict:
    return {"id": it.id, "kind": it.kind, "name": it.name, "base_url": it.base_url, "credential_id": it.credential_id, "enabled": it.enabled,
            "settings": {**(it.settings or {}), "verify_tls": it.verify_tls}, "last_sync_at": iso(it.last_test_at),
            "last_status": ("ok" if it.last_test_ok else "error") if it.last_test_ok is not None else None, "last_message": it.last_test_message}


def backup(b: ConfigBackup) -> dict:
    return {"id": b.id, "kind": b.kind, "sha256": b.sha256, "size": b.size, "created_at": iso(b.created_at), "job_id": None,
            "job_execution_id": b.job_execution_id, "note": b.note}

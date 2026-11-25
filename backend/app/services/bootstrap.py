"""Idempotent seeding of permissions, built-in roles, default policies, alert rules and templates."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.automation.runner import PLAYBOOKS
from app.core import security
from app.core.permissions import BUILTIN_ROLES, PERMISSIONS
from app.models import AlertRule, ApprovalPolicy, JobTemplate, Permission, Role, RolePermission, User, UserRole
from app.services import audit

DEFAULT_POLICIES = [
    {"name": "Critical changes always need approval", "risk": "critical", "require_approval": True},
    {"name": "Production changes need approval", "risk": "change", "environment": "production", "require_approval": True},
    {"name": "Production firewall changes need approval and a window", "risk": "change", "category": "firewall",
     "environment": "production", "require_approval": True, "require_maintenance_window": True},
]
DEFAULT_RULES = [
    {"name": "Device unreachable", "metric": "availability", "operator": "<", "threshold": 1, "severity": "critical"},
    {"name": "CPU above 90%", "metric": "cpu_pct", "operator": ">", "threshold": 90, "severity": "warning"},
    {"name": "Memory above 90%", "metric": "mem_pct", "operator": ">", "threshold": 90, "severity": "warning"},
    {"name": "Disk above 85%", "metric": "disk_pct", "operator": ">", "threshold": 85, "severity": "warning"},
    {"name": "Disk above 95%", "metric": "disk_pct", "operator": ">", "threshold": 95, "severity": "critical"},
]
OPERATION_TEMPLATES = [
    ("Restart Windows service", "windows", "windows.service.restart", "change", True),
    ("Restart Linux service", "linux", "linux.service.restart", "change", True),
    ("Install Linux packages", "linux", "linux.package.install", "change", True),
    ("Create SMB share", "windows", "windows.share.create", "change", True),
    ("Create Windows folder", "windows", "windows.folder.create", "change", True),
    ("Back up network configuration", "network", "network.config.backup", "read", False),
    ("Back up firewall configuration", "firewall", "firewall.config.backup", "read", False),
    ("Run GPUpdate", "windows", "windows.gpupdate", "change", False),
    ("Linux: pending updates (APT)", "linux", "linux.command.approved", "change", False),
]


def seed(db: Session) -> None:
    existing = {p.code: p for p in db.execute(select(Permission)).scalars()}
    for code, desc in PERMISSIONS.items():
        if code not in existing:
            existing[code] = Permission(code=code, description=desc)
            db.add(existing[code])
    db.flush()
    roles = {r.name: r for r in db.execute(select(Role)).scalars()}
    for name, (desc, perms) in BUILTIN_ROLES.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, description=desc, is_builtin=True)
            db.add(role)
            db.flush()
        have = {rp.permission_id for rp in db.execute(select(RolePermission).where(RolePermission.role_id == role.id)).scalars()}
        for code in perms:
            if existing[code].id not in have:
                db.add(RolePermission(role_id=role.id, permission_id=existing[code].id))
    if db.execute(select(ApprovalPolicy).limit(1)).first() is None:
        for p in DEFAULT_POLICIES:
            db.add(ApprovalPolicy(**p))
    if db.execute(select(AlertRule).limit(1)).first() is None:
        for r in DEFAULT_RULES:
            db.add(AlertRule(**r))
    tnames = set(db.execute(select(JobTemplate.name)).scalars())
    for name, cat, op, risk, cm in OPERATION_TEMPLATES:
        if name not in tnames:
            params = {"command": "pending_updates_apt"} if op == "linux.command.approved" else {}
            db.add(JobTemplate(name=name, kind="operation", category=cat, operation_id=op, risk=risk, supports_check_mode=cm,
                               is_builtin=True, default_params=params, description=f"Built-in: {op}"))
    for pb, meta in PLAYBOOKS.items():
        name = f"Playbook: {meta['title']} ({meta['category']})"
        if name not in tnames:
            risk = "critical" if "baseline" in pb or "maintenance" in pb else "change"
            db.add(JobTemplate(name=name, kind="playbook", category=meta["category"], playbook=pb, risk=risk, supports_check_mode=True,
                               is_builtin=True, param_schema=meta["vars"].model_json_schema(), description=f"Ansible playbook {pb}"))
    db.flush()
    from app.services.compliance import catalog
    catalog.seed(db)


def create_admin(db: Session, username: str, password: str, display_name: str = "Administrator", email: str | None = None) -> User:
    security.validate_password_policy(password, username)
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is not None:
        raise ValueError(f"User '{username}' already exists")
    user = User(username=username, display_name=display_name, email=email, auth_source="local",
                password_hash=security.hash_password(password), is_active=True)
    db.add(user)
    db.flush()
    role = db.execute(select(Role).where(Role.name == "Super Administrator")).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    audit.record(db, "user.create", actor_name="installer", target_type="user", target_id=user.id, target_name=username,
                 details={"role": "Super Administrator", "bootstrap": True})
    db.flush()
    return user


ENV_SETTINGS = {
    "IP_LDAP_ENABLED": "ldap.enabled", "IP_LDAP_URL": "ldap.url", "IP_LDAP_BASE_DN": "ldap.base_dn", "IP_LDAP_BIND_DN": "ldap.bind_dn",
    "IP_LDAP_CA_FILE": "ldap.ca_cert_file", "IP_SMTP_HOST": "smtp.host", "IP_SMTP_PORT": "smtp.port", "IP_SMTP_USER": "smtp.username",
    "IP_SMTP_FROM": "smtp.from",
}


def apply_env_settings(db: Session) -> list[str]:
    """One-time bootstrap of LDAP/SMTP settings from the installer's environment.
    Only keys that have never been set in the database are applied, so UI changes always win."""
    import os

    from app.models import SystemSetting
    from app.services import settings_store

    row = db.get(SystemSetting, settings_store.ROW)
    stored = dict(row.value) if row and isinstance(row.value, dict) else {}
    values: dict = {}
    for env, key in ENV_SETTINGS.items():
        v = os.environ.get(env)
        if v not in (None, "") and key not in stored:
            values[key] = v.lower() in ("1", "true", "yes") if key.endswith("enabled") else v
    gmap = os.environ.get("IP_LDAP_GROUP_ROLE_MAP")
    if gmap and "ldap.group_role_map" not in stored:
        pairs = [p.rsplit("=", 1) for p in gmap.split(";") if "=" in p]
        values["ldap.group_role_map"] = {dn.strip(): role.strip() for dn, role in pairs}
    pw_file = os.environ.get("IP_LDAP_BIND_PASSWORD_FILE")
    if pw_file and os.path.exists(pw_file) and "ldap.bind_password__secret_id" not in stored:
        with open(pw_file, encoding="utf-8") as fh:
            values["ldap.bind_password"] = fh.read().strip()
    if values:
        settings_store.update(db, values)
        audit.record(db, "settings.bootstrap", actor_name="installer", target_type="settings",
                     details={k: ("***" if "password" in k else v) for k, v in values.items()})
    return sorted(values)

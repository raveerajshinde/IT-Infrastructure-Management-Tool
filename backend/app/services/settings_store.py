"""System settings: flat dotted keys (e.g. "smtp.host") stored in system_settings.

Secret values (smtp.password, ldap.bind_password) are sealed in the vault; the settings
row only keeps the vault reference and the API only reports whether one is set.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.core.timeutil import utcnow
from app.models import SystemSetting
from app.services import secrets

DEFAULTS: dict[str, object] = {
    "ui.organization_name": "",
    "branding.product_name": "InfraPilot",
    "branding.tagline": "",
    "branding.primary_color": "#2148e0",
    "branding.logo": "",
    "branding.login_message": "",
    "branding.dashboard_title": "Operations overview",
    "setup.completed": False,
    "security.mfa_required": False,
    "security.allow_emergency_changes": True,
    "approval.medium_in_production": True,
    "approval.expiry_hours": 72,
    "monitoring.interval_seconds": 120,
    "monitoring.metrics_retention_days": 30,
    "backup.config_schedule_hours": 24,
    "offsite.enabled": False, "offsite.share": "", "offsite.username": "", "offsite.domain": "", "offsite.password": "",
    "offsite.passphrase": "", "offsite.keep_days": 30, "offsite.include_database": True, "offsite.include_config": True,
    "offsite.include_device_configs": True, "offsite.require_encryption": True, "offsite.device_configs_mode": "full",
    "reports.retention_days": 365,
    "devexport.enabled": False, "devexport.path": "", "devexport.mode": "full", "devexport.keep_days": 90, "devexport.write_latest": True,
    "smtp.host": "", "smtp.port": 587, "smtp.username": "", "smtp.password": "", "smtp.from": "", "smtp.starttls": True,
    "ldap.enabled": False, "ldap.url": "", "ldap.bind_dn": "", "ldap.bind_password": "", "ldap.base_dn": "",
    "ldap.user_filter": "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))",
    "ldap.start_tls": False, "ldap.verify_cert": True, "ldap.ca_cert_file": "/opt/infrapilot/certs/ldap-ca.pem",
    "ldap.group_role_map": {}, "ldap.default_role": "",
}
SECRET_KEYS = {"smtp.password", "ldap.bind_password", "offsite.password", "offsite.passphrase"}
INT_RANGES = {"reports.retention_days": (7, 3650), "offsite.keep_days": (1, 3650), "devexport.keep_days": (0, 3650), "approval.expiry_hours": (1, 720), "monitoring.interval_seconds": (30, 3600), "monitoring.metrics_retention_days": (1, 730),
              "backup.config_schedule_hours": (0, 720), "smtp.port": (1, 65535)}
ROW = "app"
_TEXT = r"[^\x00-\x1f<>]*"
BRANDING_RULES = {
    "branding.product_name": (_TEXT, 40, "Product name: up to 40 characters, no < or >"),
    "branding.tagline": (_TEXT, 80, "Tagline: up to 80 characters, no < or >"),
    "branding.dashboard_title": (_TEXT, 60, "Dashboard title: up to 60 characters, no < or >"),
    "branding.login_message": (r"[^\x00-\x08\x0b-\x1f<>]*", 500, "Login message: up to 500 characters, no < or >"),
    "branding.primary_color": (r"#[0-9a-fA-F]{6}", 7, "Brand colour must be a hex colour like #2148e0"),
    # Logos are stored inline as data URLs (rendered only through <img>, so SVG scripts cannot run).
    "branding.logo": (r"data:image/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/]+={0,2}", 400_000,
                      "Logo must be a PNG, JPEG, WebP or SVG image under 300 KB"),
}


def branding(db: Session) -> dict:
    v = all_values(db)
    return {"product_name": v["branding.product_name"] or "InfraPilot", "tagline": v["branding.tagline"],
            "organization": v["ui.organization_name"], "primary_color": v["branding.primary_color"] or "#2148e0",
            "logo": v["branding.logo"], "login_message": v["branding.login_message"],
            "dashboard_title": v["branding.dashboard_title"] or "Operations overview"}


def _row(db: Session) -> SystemSetting:
    row = db.get(SystemSetting, ROW)
    if row is None:
        row = SystemSetting(key=ROW, value={})
        db.add(row)
        db.flush()
    return row


def all_values(db: Session) -> dict:
    row = db.get(SystemSetting, ROW)
    stored = dict(row.value) if row and isinstance(row.value, dict) else {}
    return {**DEFAULTS, **stored}


def value(db: Session, key: str):
    return all_values(db).get(key, DEFAULTS.get(key))


def secret(db: Session, key: str) -> str:
    ref = all_values(db).get(f"{key}__secret_id")
    return secrets.load(db, ref).decode() if ref else ""


def public(db: Session) -> dict:
    vals = all_values(db)
    out = {k: v for k, v in vals.items() if not k.endswith("__secret_id") and k not in SECRET_KEYS}
    for k in SECRET_KEYS:
        out[k] = ""
        out[f"{k}_set"] = bool(vals.get(f"{k}__secret_id"))
    return out


def update(db: Session, values: dict, user_id: int | None = None) -> dict:
    unknown = set(values) - set(DEFAULTS)
    if unknown:
        raise ValidationFailed(f"Unknown setting(s): {', '.join(sorted(unknown))}")
    row = _row(db)
    cur = dict(row.value or {})
    changed = {}
    for k, v in values.items():
        default = DEFAULTS[k]
        if k in SECRET_KEYS:
            if k == "offsite.passphrase" and v and len(str(v)) < 12:
                raise ValidationFailed("The backup encryption passphrase must be at least 12 characters")
            if v:  # empty = keep existing secret
                cur[f"{k}__secret_id"] = secrets.store(db, f"setting:{k}", str(v), cur.get(f"{k}__secret_id")).id
                changed[k] = "***"
            continue
        if isinstance(default, bool):
            v = bool(v)
        elif isinstance(default, int):
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise ValidationFailed(f"{k} must be a number")
            lo, hi = INT_RANGES.get(k, (0, 10**9))
            if not lo <= v <= hi:
                raise ValidationFailed(f"{k} must be between {lo} and {hi}")
        elif isinstance(default, dict):
            if not isinstance(v, dict) or not all(isinstance(a, str) and isinstance(b, str) for a, b in v.items()):
                raise ValidationFailed(f"{k} must be a mapping of text to text")
        elif k in BRANDING_RULES:
            v = "" if v is None else str(v).strip()
            pattern, limit, msg = BRANDING_RULES[k]
            if len(v) > limit or (v and pattern and not re.fullmatch(pattern, v)):
                raise ValidationFailed(msg)
            if k in ("branding.product_name", "branding.dashboard_title") and not v:
                v = DEFAULTS[k]
        else:
            v = "" if v is None else str(v)[:1000]
        if k == "offsite.device_configs_mode" and v not in ("full", "masked"):
            raise ValidationFailed("Device configuration copies must be 'full' or 'masked'")
        if k == "devexport.mode" and v not in ("full", "masked"):
            raise ValidationFailed("Device backup copies must be 'full' or 'masked'")
        if k == "devexport.path" and v:
            from app.services import folder_export
            v = folder_export.validate_path(v)
        if k == "offsite.share" and v:
            v = v.replace("/", "\\")
            if not re.fullmatch(r"\\\\[A-Za-z0-9._-]+\\[^\\/:*?\"<>|]+(\\[^\\/:*?\"<>|]+)*\\?", v):
                raise ValidationFailed("Share must look like \\\\fileserver\\backups or \\\\10.0.0.5\\share\\infrapilot")
            v = v.rstrip("\\")
        if k in ("offsite.username", "offsite.domain") and v and not re.fullmatch(r"[^\x00-\x1f<>\"]{1,150}", v):
            raise ValidationFailed(f"{k} contains invalid characters")
        if k == "ldap.url" and v:
            u = urlparse(v)
            if u.scheme not in ("ldap", "ldaps") or not u.hostname:
                raise ValidationFailed("ldap.url must look like ldaps://dc01.corp.local:636")
        cur[k] = v
        # audit the fact and a fingerprint of a logo, not the whole image
        changed[k] = f"image ({len(v) // 1024} KB, sha256 {hashlib.sha256(v.encode()).hexdigest()[:12]})" if k == "branding.logo" and v else v
    row.value = cur
    row.updated_by = user_id
    row.updated_at = utcnow()
    db.flush()
    _sync_policies(db, cur)
    return changed


def _sync_policies(db: Session, vals: dict) -> None:
    """The 'approval.medium_in_production' switch controls the default production policy."""
    from sqlalchemy import select

    from app.models import ApprovalPolicy

    pol = db.execute(select(ApprovalPolicy).where(ApprovalPolicy.name == "Production changes need approval")).scalar_one_or_none()
    if pol is not None and "approval.medium_in_production" in vals:
        pol.enabled = bool(vals["approval.medium_in_production"])


# ---------------------------------------------------------------- typed views
def ldap_config(db: Session):
    from app.services.ldap_auth import LdapConfig

    v = all_values(db)
    u = urlparse(v.get("ldap.url") or "")
    use_ssl = u.scheme == "ldaps"
    return LdapConfig(
        enabled=bool(v.get("ldap.enabled")) and bool(u.hostname), host=u.hostname or "", port=u.port or (636 if use_ssl else 389),
        use_ssl=use_ssl, start_tls=bool(v.get("ldap.start_tls")) and not use_ssl, verify_cert=bool(v.get("ldap.verify_cert", True)),
        ca_cert_file=v.get("ldap.ca_cert_file") or None, bind_dn=v.get("ldap.bind_dn", ""), bind_password=secret(db, "ldap.bind_password"),
        base_dn=v.get("ldap.base_dn", ""), user_filter=v.get("ldap.user_filter") or DEFAULTS["ldap.user_filter"],
        group_role_map={k.lower(): r for k, r in (v.get("ldap.group_role_map") or {}).items()}, default_role=v.get("ldap.default_role") or "",
    )


def smtp_config(db: Session) -> dict:
    v = all_values(db)
    return {"enabled": bool(v.get("smtp.host")), "host": v.get("smtp.host"), "port": int(v.get("smtp.port") or 587),
            "starttls": bool(v.get("smtp.starttls", True)), "username": v.get("smtp.username"), "from_address": v.get("smtp.from"),
            "password": secret(db, "smtp.password")}

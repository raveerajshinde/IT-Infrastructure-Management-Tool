"""Authentication, sessions, lockout, MFA and authorization."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import false, select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import get_settings
from app.core.errors import AppError, Forbidden
from app.core.timeutil import utcnow
from app.models import (
    DeviceGroupMember, Role, User, UserRole, UserSession,
)
from app.services import audit, ldap_auth, secrets, settings_store

log = logging.getLogger("infrapilot.auth")


class AuthFailed(AppError):
    status_code = 401
    code = "authentication_failed"


@dataclass
class LoginResult:
    token: str | None = None
    user: User | None = None
    mfa_required: bool = False
    mfa_setup_required: bool = False


GENERIC_FAIL = "Invalid username, password or verification code"


def _register_failure(db: Session, user: User | None, username: str, ip: str | None, reason: str) -> None:
    s = get_settings()
    if user is not None:
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= s.lockout_threshold:
            user.locked_until = utcnow() + timedelta(minutes=s.lockout_minutes)
            audit.record(db, "auth.lockout", actor_name=username, target_type="user", target_id=user.id,
                         target_name=username, result="failure", ip=ip, details={"failed_attempts": user.failed_attempts})
    audit.record(db, "auth.login", actor_name=username, target_type="user", target_name=username,
                 result="failure", ip=ip, details={"reason": reason})
    db.commit()


def login(db: Session, username: str, password: str, totp_code: str | None, ip: str | None, user_agent: str | None) -> LoginResult:
    username = username.strip()
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    now = utcnow()
    if user and user.locked_until and user.locked_until > now:
        audit.record(db, "auth.login", actor_name=username, result="failure", ip=ip, details={"reason": "locked"})
        db.commit()
        raise AuthFailed("Account is temporarily locked after repeated failed sign-ins. Try again later or contact an administrator.")
    if user and not user.is_active:
        _register_failure(db, None, username, ip, "disabled")
        raise AuthFailed(GENERIC_FAIL)

    authenticated = False
    if user is None or user.auth_source == "ldap":
        cfg = settings_store.ldap_config(db)
        if cfg.enabled:
            try:
                lu = ldap_auth.authenticate(cfg, username, password)
            except Exception as exc:  # network / TLS failure — never fall through silently
                log.warning("LDAP authentication error: %s", exc)
                lu = None
            if lu:
                user = _provision_ldap_user(db, user, lu, cfg)
                authenticated = user is not None
    elif user.auth_source == "local":
        authenticated = security.verify_password(password, user.password_hash)
    if user is None and not authenticated:
        security.verify_password(password, None)  # timing equalisation
    if not authenticated or user is None:
        _register_failure(db, user, username, ip, "bad_credentials")
        raise AuthFailed(GENERIC_FAIL)

    if user.mfa_enabled:
        if not totp_code:
            return LoginResult(mfa_required=True)
        secret = secrets.load(db, user.mfa_secret_id).decode() if user.mfa_secret_id else ""
        if not security.verify_totp(secret, totp_code):
            _register_failure(db, user, username, ip, "bad_totp")
            raise AuthFailed(GENERIC_FAIL)

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    token = security.new_session_token()
    s = get_settings()
    db.add(UserSession(user_id=user.id, token_hash=security.hash_token(token), expires_at=now + timedelta(minutes=s.session_ttl_minutes),
                       ip_address=ip, user_agent=(user_agent or "")[:300]))
    audit.record(db, "auth.login", actor=user, target_type="user", target_id=user.id, target_name=user.username, ip=ip,
                 details={"mfa": user.mfa_enabled, "source": user.auth_source})
    db.commit()
    require_mfa = bool(settings_store.value(db, "security.mfa_required"))
    return LoginResult(token=token, user=user, mfa_setup_required=require_mfa and not user.mfa_enabled)


def _provision_ldap_user(db: Session, user: User | None, lu: ldap_auth.LdapUser, cfg: ldap_auth.LdapConfig) -> User | None:
    mapped = {cfg.group_role_map[g] for g in lu.groups if g in cfg.group_role_map}
    if not mapped and cfg.default_role:
        mapped = {cfg.default_role}
    has_manual = bool(user and any(a.device_group_id is not None for a in user.role_assignments))
    if not mapped and not has_manual:
        return None  # directory user is in no mapped group and no default role: deny
    if user is None:
        user = User(username=lu.username, auth_source="ldap", display_name=lu.display_name, email=lu.email, is_active=True)
        db.add(user)
        db.flush()
    user.display_name, user.email = lu.display_name, lu.email
    if cfg.group_role_map or cfg.default_role:
        roles = {r.name: r for r in db.execute(select(Role)).scalars()}
        current = {a.role.name: a for a in user.role_assignments if a.device_group_id is None}
        for name in mapped - set(current):
            if name in roles:
                db.add(UserRole(user_id=user.id, role_id=roles[name].id))
        for name in set(current) - mapped:
            db.delete(current[name])
        db.flush()
        db.refresh(user)
    return user


def resolve_session(db: Session, token: str) -> User | None:
    if not token:
        return None
    s = get_settings()
    sess = db.execute(select(UserSession).where(UserSession.token_hash == security.hash_token(token))).scalar_one_or_none()
    now = utcnow()
    if not sess or sess.revoked or sess.expires_at < now:
        return None
    if sess.last_seen_at and sess.last_seen_at + timedelta(minutes=s.session_idle_minutes) < now:
        sess.revoked = True
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        return None
    if (now - sess.last_seen_at).total_seconds() > 30:
        sess.last_seen_at = now
        db.commit()
    return user


def logout(db: Session, token: str) -> None:
    sess = db.execute(select(UserSession).where(UserSession.token_hash == security.hash_token(token))).scalar_one_or_none()
    if sess:
        sess.revoked = True
        db.commit()


def revoke_user_sessions(db: Session, user_id: int) -> None:
    for sess in db.execute(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked == false())).scalars().all():
        sess.revoked = True


# ------------------------------------------------------------------ authorization
def user_permissions(db: Session, user: User) -> dict[str, set[int | None]]:
    """Map permission code -> set of device_group_ids (None = global)."""
    out: dict[str, set[int | None]] = {}
    for a in user.role_assignments:
        for p in a.role.permissions:
            out.setdefault(p.code, set()).add(a.device_group_id)
    return out


def device_group_ids(db: Session, device_id: int) -> set[int]:
    return set(db.execute(select(DeviceGroupMember.group_id).where(DeviceGroupMember.device_id == device_id)).scalars())


def has_permission(db: Session, user: User, perm: str, device_id: int | None = None) -> bool:
    perms = user_permissions(db, user)
    scopes = perms.get(perm)
    if not scopes:
        return False
    if None in scopes:
        return True
    if device_id is None:
        return False
    return bool(scopes & device_group_ids(db, device_id))


def has_any_scope(db: Session, user: User, perm: str) -> bool:
    return bool(user_permissions(db, user).get(perm))


def require(db: Session, user: User, perm: str, device_id: int | None = None) -> None:
    if not has_permission(db, user, perm, device_id):
        raise Forbidden(f"You do not have the '{perm}' permission" + (" for this device" if device_id else ""))


def visible_device_filter(db: Session, user: User):
    """Return None for unrestricted visibility, else the set of group ids the user may read."""
    scopes = user_permissions(db, user).get("devices:read", set())
    if None in scopes:
        return None
    return {g for g in scopes if g is not None}

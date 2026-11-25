from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, need_global
from app.core import security
from app.core.db import get_db
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.permissions import PERMISSIONS
from app.models import DeviceGroup, Permission, Role, RolePermission, User, UserRole
from app.schemas import RoleIn, UserCreate, UserUpdate
from app.services import audit, auth

router = APIRouter(prefix="/api", tags=["users"])


def _out(u: User) -> dict:
    from app.api.serializers import user as ser_user
    return ser_user(u)


def _apply_roles(db: Session, user: User, roles) -> None:
    for a in list(user.role_assignments):
        db.delete(a)
    db.flush()
    seen = set()
    for r in roles:
        key = (r.role_id, r.device_group_id)
        if key in seen:
            continue
        seen.add(key)
        if not db.get(Role, r.role_id):
            raise ValidationFailed(f"Role {r.role_id} does not exist")
        if r.device_group_id and not db.get(DeviceGroup, r.device_group_id):
            raise ValidationFailed(f"Device group {r.device_group_id} does not exist")
        db.add(UserRole(user_id=user.id, role_id=r.role_id, device_group_id=r.device_group_id))
    db.flush()
    db.refresh(user)


def _ensure_not_last_superadmin(db: Session, user: User) -> None:
    sa = db.execute(select(Role).where(Role.name == "Super Administrator")).scalar_one()
    holders = {a.user_id for a in db.execute(select(UserRole).where(UserRole.role_id == sa.id, UserRole.device_group_id.is_(None))).scalars()}
    active = [u for u in (db.get(User, i) for i in holders) if u and u.is_active and u.id != user.id]
    if user.id in holders and not active:
        raise Forbidden("This is the last active Super Administrator; assign another one first")


@router.get("/users")
def list_users(user: User = Depends(need_global("users:read")), db: Session = Depends(get_db)):
    return [_out(u) for u in db.execute(select(User).order_by(User.username)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    if db.execute(select(User).where(User.username == body.username)).first():
        raise Conflict(f"User '{body.username}' already exists")
    u = User(username=body.username, display_name=body.display_name, email=body.email, auth_source=body.auth_source,
             must_change_password=body.auth_source == "local" and body.must_change_password)
    if body.auth_source == "local":
        if not body.password:
            raise ValidationFailed("A password is required for local accounts")
        try:
            security.validate_password_policy(body.password, body.username)
        except security.PasswordPolicyError as exc:
            raise ValidationFailed(str(exc))
        u.password_hash = security.hash_password(body.password)
    db.add(u)
    db.flush()
    _apply_roles(db, u, body.roles)
    audit.record(db, "user.create", actor=actor, target_type="user", target_id=u.id, target_name=u.username, ip=client_ip(request),
                 details={"auth_source": u.auth_source, "roles": [r.model_dump() for r in body.roles]})
    db.commit()
    return _out(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise NotFound("User not found")
    changes = body.model_dump(exclude_unset=True, exclude={"password"})
    if body.is_active is False or (body.roles is not None):
        if body.is_active is False or not any(db.get(Role, r.role_id) and db.get(Role, r.role_id).name == "Super Administrator" and r.device_group_id is None for r in body.roles or []):
            _ensure_not_last_superadmin(db, u)
    if body.display_name is not None:
        u.display_name = body.display_name
    if body.email is not None:
        u.email = body.email
    if body.is_active is not None:
        u.is_active = body.is_active
        if not body.is_active:
            auth.revoke_user_sessions(db, u.id)
    if body.password:
        if u.auth_source != "local":
            raise ValidationFailed("Cannot set a password on a directory account")
        try:
            security.validate_password_policy(body.password, u.username)
        except security.PasswordPolicyError as exc:
            raise ValidationFailed(str(exc))
        u.password_hash = security.hash_password(body.password)
        u.must_change_password = True
        auth.revoke_user_sessions(db, u.id)
        changes["password"] = "reset"
    if body.unlock:
        u.failed_attempts, u.locked_until = 0, None
    if body.reset_mfa:
        u.mfa_enabled, u.mfa_secret_id = False, None
    if body.roles is not None:
        _apply_roles(db, u, body.roles)
    audit.record(db, "user.update", actor=actor, target_type="user", target_id=u.id, target_name=u.username, ip=client_ip(request), details=changes)
    db.commit()
    return _out(u)


@router.get("/roles")
def list_roles(user: User = Depends(need_global("users:read")), db: Session = Depends(get_db)):
    return [{"id": r.id, "name": r.name, "description": r.description, "is_builtin": r.is_builtin,
             "permissions": sorted(p.code for p in r.permissions)} for r in db.execute(select(Role).order_by(Role.id)).scalars()]


@router.get("/permissions")
def list_permissions(user: User = Depends(need_global("users:read"))):
    return [{"code": k, "module": k.split(":")[0], "description": v} for k, v in PERMISSIONS.items()]


@router.post("/users/{user_id}/unlock")
def unlock_user(user_id: int, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    u = _get(db, user_id)
    u.failed_attempts, u.locked_until = 0, None
    audit.record(db, "user.unlock", actor=actor, target_type="user", target_id=u.id, target_name=u.username, ip=client_ip(request))
    db.commit()
    return _out(u)


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(user_id: int, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    u = _get(db, user_id)
    u.mfa_enabled, u.mfa_secret_id = False, None
    auth.revoke_user_sessions(db, u.id)
    audit.record(db, "user.reset_mfa", actor=actor, target_type="user", target_id=u.id, target_name=u.username, ip=client_ip(request))
    db.commit()
    return _out(u)


class ResetPasswordIn(BaseModel):
    new_password: str = Field(max_length=256)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, body: ResetPasswordIn, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    u = _get(db, user_id)
    if u.auth_source != "local":
        raise ValidationFailed("Directory accounts are reset in Active Directory")
    try:
        security.validate_password_policy(body.new_password, u.username)
    except security.PasswordPolicyError as exc:
        raise ValidationFailed(str(exc))
    u.password_hash, u.must_change_password = security.hash_password(body.new_password), True
    u.failed_attempts, u.locked_until = 0, None
    auth.revoke_user_sessions(db, u.id)
    audit.record(db, "user.reset_password", actor=actor, target_type="user", target_id=u.id, target_name=u.username, ip=client_ip(request))
    db.commit()
    return _out(u)


def _get(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if not u:
        raise NotFound("User not found")
    return u


def _set_perms(db: Session, role: Role, codes: list[str]) -> None:
    unknown = set(codes) - set(PERMISSIONS)
    if unknown:
        raise ValidationFailed(f"Unknown permission(s): {', '.join(sorted(unknown))}")
    for rp in db.execute(select(RolePermission).where(RolePermission.role_id == role.id)).scalars().all():
        db.delete(rp)
    db.flush()
    for p in db.execute(select(Permission).where(Permission.code.in_(codes))).scalars().all():
        db.add(RolePermission(role_id=role.id, permission_id=p.id))
    db.flush()
    db.refresh(role)


@router.post("/roles", status_code=201)
def create_role(body: RoleIn, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    if db.execute(select(Role).where(Role.name == body.name)).first():
        raise Conflict("Role name already exists")
    r = Role(name=body.name, description=body.description)
    db.add(r)
    db.flush()
    _set_perms(db, r, body.permissions)
    audit.record(db, "role.create", actor=actor, target_type="role", target_id=r.id, target_name=r.name, ip=client_ip(request), details={"permissions": body.permissions})
    db.commit()
    return {"id": r.id}


@router.put("/roles/{role_id}")
def update_role(role_id: int, body: RoleIn, request: Request, actor: User = Depends(need_global("users:manage")), db: Session = Depends(get_db)):
    r = db.get(Role, role_id)
    if not r:
        raise NotFound("Role not found")
    if r.is_builtin:
        raise Forbidden("Built-in roles cannot be modified; create a custom role instead")
    r.name, r.description = body.name, body.description
    _set_perms(db, r, body.permissions)
    audit.record(db, "role.update", actor=actor, target_type="role", target_id=r.id, target_name=r.name, ip=client_ip(request), details={"permissions": body.permissions})
    db.commit()
    return {"id": r.id}

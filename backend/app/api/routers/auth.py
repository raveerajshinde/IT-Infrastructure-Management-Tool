from __future__ import annotations

from sqlalchemy import false

import base64
import io

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_user
from app.core import security
from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import ValidationFailed
from app.core.ratelimit import limiter
from app.models import User
from app.schemas import LoginIn, MfaVerifyIn, PasswordChangeIn
from app.services import audit, auth, secrets, settings_store

router = APIRouter(prefix="/api/auth", tags=["auth"])


def user_payload(db: Session, user: User) -> dict:
    from app.api.serializers import user as ser_user

    perms = auth.user_permissions(db, user)
    out = ser_user(user)
    out.update(permissions=sorted(perms), global_permissions=sorted(p for p, s in perms.items() if None in s),
               mfa_required_by_policy=bool(settings_store.value(db, "security.mfa_required")) and user.auth_source == "local",
               setup_completed=bool(settings_store.value(db, "setup.completed")))
    return out


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request)
    if not limiter.allow(ip, "login", s.rate_limit_login_per_minute):
        raise HTTPException(429, detail={"code": "rate_limited", "message": "Too many sign-in attempts. Wait a minute and try again."})
    res = auth.login(db, body.username, body.password, body.totp, ip, request.headers.get("user-agent"))
    if res.mfa_required:
        return {"mfa_required": True}
    response.set_cookie(s.cookie_name, res.token, httponly=True, secure=s.cookie_secure, samesite="strict",
                        max_age=s.session_ttl_minutes * 60, path="/")
    return user_payload(db, res.user)


@router.post("/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    token = request.cookies.get(get_settings().cookie_name) or request.headers.get("authorization", "")[7:]
    auth.logout(db, token)
    audit.record(db, "auth.logout", actor=user, ip=client_ip(request))
    db.commit()
    response.delete_cookie(get_settings().cookie_name, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return user_payload(db, user)


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.auth_source != "local":
        raise ValidationFailed("Directory (LDAP) accounts change their password in Active Directory")
    if not security.verify_password(body.current_password, user.password_hash):
        raise ValidationFailed("Current password is incorrect")
    try:
        security.validate_password_policy(body.new_password, user.username)
    except security.PasswordPolicyError as exc:
        raise ValidationFailed(str(exc))
    user.password_hash = security.hash_password(body.new_password)
    user.must_change_password = False
    current = security.hash_token(request.cookies.get(get_settings().cookie_name) or request.headers.get("authorization", "")[7:])
    from sqlalchemy import select as _select
    from app.models import UserSession
    for sess in db.execute(_select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked == false())).scalars().all():
        if sess.token_hash != current:
            sess.revoked = True  # sign out other sessions
    audit.record(db, "auth.password_change", actor=user, target_type="user", target_id=user.id, target_name=user.username, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise ValidationFailed("MFA is already enabled; ask an administrator to reset it first")
    secret = security.new_totp_secret()
    row = secrets.store(db, f"mfa:{user.id}", secret, user.mfa_secret_id)
    user.mfa_secret_id = row.id
    db.commit()
    uri = security.totp_uri(secret, user.username, get_settings().app_name)
    qr = None
    try:
        import qrcode  # optional

        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass
    return {"secret": secret, "otpauth_uri": uri, "qr_png": qr}


@router.post("/mfa/enable")
@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not user.mfa_secret_id:
        raise ValidationFailed("Start MFA setup first")
    if not security.verify_totp(secrets.load(db, user.mfa_secret_id).decode(), body.code):
        raise ValidationFailed("The code is not valid. Check your authenticator's clock and try again.")
    user.mfa_enabled = True
    audit.record(db, "auth.mfa_enabled", actor=user, target_type="user", target_id=user.id, target_name=user.username, ip=client_ip(request))
    db.commit()
    return {"ok": True}


class MfaDisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(pattern=r"^\d{6}$")


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if settings_store.value(db, "security.mfa_required") and user.auth_source == "local":
        raise ValidationFailed("Two-factor authentication is required by policy and cannot be disabled")
    if user.auth_source != "local" or not security.verify_password(body.password, user.password_hash):
        raise ValidationFailed("Password is incorrect")
    if not user.mfa_secret_id or not security.verify_totp(secrets.load(db, user.mfa_secret_id).decode(), body.code):
        raise ValidationFailed("The code is not valid")
    user.mfa_enabled, user.mfa_secret_id = False, None
    audit.record(db, "auth.mfa_disabled", actor=user, target_type="user", target_id=user.id, target_name=user.username, ip=client_ip(request))
    db.commit()
    return {"ok": True}

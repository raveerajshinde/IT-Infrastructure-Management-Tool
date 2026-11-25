"""Credential management. Secret material is write-only: the API never returns it."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api import serializers as ser
from app.api.deps import client_ip, need, need_global
from app.core.db import get_db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.models import Credential, Device, Integration, User, VaultSecret
from app.services import audit, secrets

router = APIRouter(prefix="/api/credentials", tags=["credentials"])

SECRET_FIELDS = {"password", "private_key", "passphrase", "token", "enable_secret", "auth_password", "priv_password"}
OPTION_FIELDS = {"auth_protocol": {"SHA", "SHA256", "SHA512", "MD5"}, "priv_protocol": {"AES", "AES256", "DES"},
                 "transport": {"negotiate", "kerberos", "ntlm", "credssp", "basic"}, "use_ssl": None, "become": None,
                 "host_key_policy": {"tofu", "reject"}}
ALIASES = {"auth_key": "auth_password", "priv_key": "priv_password"}
REQUIRED = {"password": ("password",), "winrm": ("password",), "ssh_key": ("private_key",), "api_token": ("token",),
            "snmpv3": ("auth_password", "priv_password")}


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["password", "ssh_key", "api_token", "snmpv3", "winrm"]
    username: str | None = Field(None, max_length=200)
    description: str = Field("", max_length=500)
    secret: dict[str, Any] = Field(default_factory=dict)


class CredentialPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=150)
    username: str | None = Field(None, max_length=200)
    description: str | None = Field(None, max_length=500)
    secret: dict[str, Any] | None = None


def _split(secret: dict) -> tuple[dict, dict]:
    sec, opts = {}, {}
    for k, v in (secret or {}).items():
        k = ALIASES.get(k, k)
        if v in (None, ""):
            continue
        if k in SECRET_FIELDS:
            if not isinstance(v, str) or len(v) > 16384:
                raise ValidationFailed(f"Invalid value for {k}")
            sec[k] = v
        elif k in OPTION_FIELDS:
            allowed = OPTION_FIELDS[k]
            if allowed is None:
                v = str(v).lower() in ("1", "true", "yes", "on") if not isinstance(v, bool) else v
            elif str(v) not in allowed:
                raise ValidationFailed(f"{k} must be one of: {', '.join(sorted(allowed))}")
            opts[k] = v
        else:
            raise ValidationFailed(f"Unknown credential field '{k}'")
    return sec, opts


@router.get("")
def list_credentials(user: User = Depends(need("credentials:read")), db: Session = Depends(get_db)):
    return [ser.credential(db, c) for c in db.execute(select(Credential).order_by(Credential.name)).scalars().all()]


@router.post("", status_code=201)
def create_credential(body: CredentialIn, request: Request, user: User = Depends(need_global("credentials:write")), db: Session = Depends(get_db)):
    if db.execute(select(Credential).where(Credential.name == body.name)).first():
        raise Conflict("A credential with this name already exists")
    sec, opts = _split(body.secret)
    missing = [f.replace("_password", " passphrase") for f in REQUIRED[body.kind] if f not in sec]
    if missing:
        raise ValidationFailed(f"{body.kind} credentials require: {', '.join(missing)}")
    if body.kind in ("snmpv3", "winrm", "password", "ssh_key") and not body.username:
        raise ValidationFailed("A username is required for this credential kind")
    if body.kind == "snmpv3" and (len(sec["auth_password"]) < 8 or len(sec["priv_password"]) < 8):
        raise ValidationFailed("SNMPv3 passphrases must be at least 8 characters")
    c = Credential(name=body.name, kind=body.kind, username=body.username, description=body.description, extra=opts, created_by=user.id)
    db.add(c)
    db.flush()
    c.secret_id = secrets.store(db, f"credential:{c.id}", sec).id
    audit.record(db, "credential.create", actor=user, target_type="credential", target_id=c.id, target_name=c.name, ip=client_ip(request),
                 details={"kind": c.kind, "username": c.username, "options": opts})
    db.commit()
    return ser.credential(db, c)


@router.patch("/{cred_id}")
def update_credential(cred_id: int, body: CredentialPatch, request: Request, user: User = Depends(need_global("credentials:write")), db: Session = Depends(get_db)):
    c = db.get(Credential, cred_id)
    if not c:
        raise NotFound("Credential not found")
    if body.name is not None:
        c.name = body.name
    if body.username is not None:
        c.username = body.username
    if body.description is not None:
        c.description = body.description
    rotated = False
    if body.secret:
        sec, opts = _split(body.secret)
        if opts:
            c.extra = {**(c.extra or {}), **opts}
        if sec:  # merge with existing material so a partial rotation keeps the other fields
            import json
            old = json.loads(secrets.load(db, c.secret_id).decode()) if c.secret_id else {}
            c.secret_id = secrets.store(db, f"credential:{c.id}", {**old, **sec}, c.secret_id).id
            rotated = True
    audit.record(db, "credential.update", actor=user, target_type="credential", target_id=c.id, target_name=c.name, ip=client_ip(request),
                 details={"secret_rotated": rotated})
    db.commit()
    return ser.credential(db, c)


@router.delete("/{cred_id}")
def delete_credential(cred_id: int, request: Request, user: User = Depends(need_global("credentials:write")), db: Session = Depends(get_db)):
    c = db.get(Credential, cred_id)
    if not c:
        raise NotFound("Credential not found")
    in_use = db.execute(select(Device.hostname).where(Device.deleted_at.is_(None), or_(Device.credential_id == c.id, Device.snmp_credential_id == c.id)).limit(5)).scalars().all()
    if in_use or db.execute(select(Integration).where(Integration.credential_id == c.id)).first():
        raise Conflict(f"Credential is in use ({', '.join(in_use) or 'integration'}); reassign it first")
    for d in db.execute(select(Device).where(or_(Device.credential_id == c.id, Device.snmp_credential_id == c.id))).scalars().all():
        d.credential_id = None if d.credential_id == c.id else d.credential_id  # detach from soft-deleted devices
        d.snmp_credential_id = None if d.snmp_credential_id == c.id else d.snmp_credential_id
    sid, name = c.secret_id, c.name
    db.delete(c)
    db.flush()
    if sid:
        db.delete(db.get(VaultSecret, sid))  # crypto-shred the material
    audit.record(db, "credential.delete", actor=user, target_type="credential", target_id=cred_id, target_name=name, ip=client_ip(request))
    db.commit()
    return {"message": "Credential deleted"}

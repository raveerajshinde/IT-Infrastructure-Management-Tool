"""Vault persistence helpers. Only this module touches plaintext secrets."""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.core import vault
from app.core.errors import NotFound
from app.core.timeutil import utcnow
from app.models import Credential, VaultSecret


def store(db: Session, purpose: str, plaintext: str | dict, existing_id: int | None = None) -> VaultSecret:
    sealed = vault.seal(plaintext, purpose)
    row = db.get(VaultSecret, existing_id) if existing_id else None
    if row is None:
        row = VaultSecret(purpose=purpose)
        db.add(row)
    else:
        row.purpose = purpose
        row.rotated_at = utcnow()
    row.ciphertext, row.nonce = sealed.ciphertext, sealed.nonce
    row.wrapped_key, row.key_nonce, row.key_version = sealed.wrapped_key, sealed.key_nonce, sealed.key_version
    db.flush()
    return row


def load(db: Session, secret_id: int) -> bytes:
    row = db.get(VaultSecret, secret_id)
    if row is None:
        raise NotFound("Secret not found")
    return vault.unseal(
        vault.SealedSecret(row.ciphertext, row.nonce, row.wrapped_key, row.key_nonce, row.key_version), row.purpose
    )


def credential_material(db: Session, cred: Credential) -> dict:
    """Return decrypted credential material for use by drivers (never returned to API)."""
    out: dict = {"kind": cred.kind, "username": cred.username, **(cred.extra or {})}
    if cred.secret_id:
        raw = load(db, cred.secret_id).decode()
        try:
            secret = json.loads(raw)
            if not isinstance(secret, dict):
                secret = {"password": raw}
        except json.JSONDecodeError:
            secret = {"password": raw}
        out.update(secret)
    return out

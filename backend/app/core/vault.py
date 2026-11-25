"""Credential vault: AES-256-GCM envelope encryption.

* The master key (32 random bytes) lives OUTSIDE the database, in a root-owned file
  mounted into the containers as a Docker secret (IP_VAULT_KEY_FILE).
* Each secret gets a random per-secret data key; the data key is wrapped with the
  master key. The DB only ever stores ciphertext, nonce and wrapped key.
* Associated data binds each ciphertext to its row purpose, so blobs cannot be swapped.
* Plaintext is never logged or returned by any API.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

KEY_VERSION = 1


class VaultError(RuntimeError):
    pass


@dataclass
class SealedSecret:
    ciphertext: bytes
    nonce: bytes
    wrapped_key: bytes
    key_nonce: bytes
    key_version: int = KEY_VERSION


_master: bytes | None = None


def load_master_key() -> bytes:
    global _master
    if _master is not None:
        return _master
    s = get_settings()
    raw: str | None = None
    if s.vault_key_file and os.path.exists(s.vault_key_file):
        with open(s.vault_key_file, "r", encoding="ascii") as fh:
            raw = fh.read().strip()
    elif s.vault_master_key:
        raw = s.vault_master_key.strip()
    if not raw:
        raise VaultError("Vault master key is not configured (IP_VAULT_KEY_FILE / IP_VAULT_MASTER_KEY)")
    if ":" in raw and raw.split(":", 1)[0].startswith("v"):  # optional "v1:" version prefix written by the installer
        raw = raw.split(":", 1)[1]
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise VaultError("Vault master key must be 32 bytes (base64-encoded)")
    _master = key
    return key


def reset_master_key_cache() -> None:
    global _master
    _master = None


def generate_master_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def seal(plaintext: str | bytes | dict, purpose: str) -> SealedSecret:
    if isinstance(plaintext, dict):
        plaintext = json.dumps(plaintext)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    master = load_master_key()
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext, purpose.encode())
    key_nonce = os.urandom(12)
    wrapped = AESGCM(master).encrypt(key_nonce, data_key, b"infrapilot-dek")
    return SealedSecret(ct, nonce, wrapped, key_nonce, KEY_VERSION)


def unseal(sealed: SealedSecret, purpose: str) -> bytes:
    master = load_master_key()
    try:
        data_key = AESGCM(master).decrypt(sealed.key_nonce, sealed.wrapped_key, b"infrapilot-dek")
        return AESGCM(data_key).decrypt(sealed.nonce, sealed.ciphertext, purpose.encode())
    except Exception as exc:  # InvalidTag etc.
        raise VaultError("Unable to decrypt secret (wrong master key or tampered data)") from exc

"""Password hashing, password policy, session tokens and TOTP helpers."""
from __future__ import annotations

import hashlib
import re
import secrets

import bcrypt
import pyotp

from app.core.config import get_settings


class PasswordPolicyError(ValueError):
    pass


def hash_password(password: str) -> str:
    # bcrypt only uses 72 bytes; pre-hash to keep full entropy of long passphrases
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest().encode()
    return bcrypt.hashpw(digest, bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed:
        # constant-ish time for unknown users
        bcrypt.checkpw(b"x", bcrypt.hashpw(b"y", bcrypt.gensalt(rounds=4)))
        return False
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest().encode()
    try:
        return bcrypt.checkpw(digest, hashed.encode())
    except ValueError:
        return False


def validate_password_policy(password: str, username: str = "") -> None:
    s = get_settings()
    problems = []
    if len(password) < s.password_min_length:
        problems.append(f"at least {s.password_min_length} characters")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        problems.append("at least 3 of: lowercase, uppercase, digit, symbol")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if problems:
        raise PasswordPolicyError("Password must have " + "; ".join(problems))


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not code or not re.fullmatch(r"\d{6}", code.strip()):
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)

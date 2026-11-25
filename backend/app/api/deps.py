"""Request dependencies: authentication, CSRF protection, permissions, paging."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.errors import Forbidden
from app.core.ratelimit import limiter
from app.models import User
from app.services import auth

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "InfraPilot"


def client_ip(request: Request) -> str:
    # nginx sets X-Real-IP; only trust it because the API is not exposed directly
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def _token(request: Request) -> tuple[str | None, bool]:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip(), True
    return request.cookies.get(get_settings().cookie_name), False


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token, is_bearer = _token(request)
    user = auth.resolve_session(db, token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail={"code": "not_authenticated", "message": "Please sign in"})
    # CSRF: cookie-authenticated state-changing requests must carry the custom header
    # (cannot be set cross-site without CORS preflight, which we do not allow).
    if not is_bearer and request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise HTTPException(status_code=403, detail={"code": "csrf", "message": "Missing anti-CSRF header"})
    s = get_settings()
    if not limiter.allow(str(user.id), "api", s.rate_limit_api_per_minute):
        raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "Too many requests, slow down"})
    request.state.user = user
    return user


def need(perm: str):
    """Permission held in at least one scope (global or a device group). Endpoints filter by scope."""
    def dep(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if not auth.has_any_scope(db, user, perm):
            raise Forbidden(f"You do not have the '{perm}' permission")
        return user
    return dep


def need_global(perm: str):
    def dep(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        auth.require(db, user, perm)
        return user
    return dep


def paging(page: int = 1, page_size: int = 25) -> tuple[int, int]:
    page = max(1, page)
    page_size = min(max(1, page_size), 500)
    return page, page_size

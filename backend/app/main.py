"""FastAPI application factory."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.routers import auth, credentials, devices, governance, management, monitoring, operations, scripts, users, gpo, ad, compliance, reportcenter
from app.core.config import get_settings
from app.core.db import get_engine
from app.core.errors import AppError
from app.core.logging import setup_logging
from app.core.vault import VaultError, load_master_key

log = logging.getLogger("infrapilot.api")


def _is_admin(request: Request) -> bool:
    """Whether the caller may see technical error details (settings:manage)."""
    try:
        from app.api.deps import _token
        from app.core.db import SessionLocal
        from app.services import auth as auth_svc

        token, _ = _token(request)
        if not token:
            return False
        db = SessionLocal()
        try:
            u = auth_svc.resolve_session(db, token)
            return bool(u and auth_svc.has_permission(db, u, "settings:manage"))
        finally:
            db.rollback()
            db.close()
    except Exception:  # noqa: BLE001
        return False


def create_app() -> FastAPI:
    s = get_settings()
    setup_logging(s.log_level)
    app = FastAPI(
        title=f"{s.app_name} API", version=s.app_version,
        description="Unified IT Infrastructure Management Platform. Authenticate with POST /api/auth/login (session cookie) "
                    "or send the session token as a Bearer token. Cookie-authenticated writes require header X-Requested-With: InfraPilot.",
        docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/api/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError):
        return JSONResponse(status_code=exc.status_code, content={"detail": {"code": exc.code, "message": exc.message, **exc.details}})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        errs = [{"field": ".".join(str(x) for x in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
        msg = "; ".join(f"{e['field']}: {e['message']}" for e in errs[:5])
        return JSONResponse(status_code=422, content={"detail": {"code": "validation_failed", "message": msg, "errors": errs}})

    @app.exception_handler(VaultError)
    async def vault_error(request: Request, exc: VaultError):
        log.error("vault error: %s", exc)
        return JSONResponse(status_code=500, content={"detail": {"code": "vault_error", "message": "Credential vault is unavailable or misconfigured"}})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        from starlette.concurrency import run_in_threadpool

        from app.services import diagnostics

        ref = await run_in_threadpool(diagnostics.record, request.method, request.url.path, exc)
        log.exception("unhandled error [ref %s] on %s %s", ref, request.method, request.url.path)
        detail = {"code": "internal_error", "reference": ref,
                  "message": f"Unexpected server error (reference {ref}). Administrators can see the cause under Settings -> Diagnostics."}
        if await run_in_threadpool(_is_admin, request):
            detail["error"] = diagnostics.summarize(exc)
            detail["message"] = f"Server error (reference {ref}): {detail['error']}"
        return JSONResponse(status_code=500, content={"detail": detail})

    for r in (auth, users, devices, credentials, operations, governance, monitoring, management, scripts, gpo, ad, compliance, reportcenter):
        app.include_router(r.router)

    @app.get("/api/healthz", tags=["system"], include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/api/readyz", tags=["system"])
    def readyz():
        """Readiness: database, vault and a recent worker heartbeat. Used by infrapilot-health-check."""
        from app.core.db import SessionLocal
        from app.models import SystemSetting
        from app.core.timeutil import utcnow
        from datetime import datetime
        checks = {}
        try:
            db = SessionLocal()
            try:
                hb = db.get(SystemSetting, "worker.heartbeat")
                checks["database"] = "ok"
                age = (utcnow() - datetime.fromisoformat(hb.value["ts"])).total_seconds() if hb and hb.value.get("ts") else None
                checks["worker"] = "ok" if age is not None and age < 120 else "stale"
            finally:
                db.close()
        except Exception as exc:
            checks["database"] = f"error: {exc.__class__.__name__}"
        try:
            load_master_key()
            checks["vault"] = "ok"
        except VaultError:
            checks["vault"] = "error"
        if checks.get("database") != "ok" or checks["vault"] != "ok":
            status, code = "fail", 503
        elif checks.get("worker") != "ok":
            status, code = "degraded", 200
        else:
            status, code = "ok", 200
        return JSONResponse(status_code=code, content={"status": status, "checks": checks, "version": s.app_version})

    @app.get("/api/health", tags=["system"])
    def health():
        checks = {}
        try:
            with get_engine().connect() as c:
                c.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:
            checks["database"] = f"error: {exc.__class__.__name__}"
        try:
            load_master_key()
            checks["vault"] = "ok"
        except VaultError:
            checks["vault"] = "error"
        ok = all(v == "ok" for v in checks.values())
        return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "degraded", "checks": checks,
                                                                     "version": s.app_version, "mode": s.app_mode})

    return app


app = create_app()

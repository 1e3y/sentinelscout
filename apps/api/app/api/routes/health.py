from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    settings = get_settings()
    checks: dict[str, str] = {}

    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"

    try:
        # Touch required config accessors; staging/production already fail-closed at boot.
        _ = settings.database_url
        _ = settings.cors_origins
        _ = settings.frontend_url
        if settings.is_production_like:
            if not (settings.clerk_issuer and settings.clerk_jwks_url and settings.clerk_secret_key):
                raise RuntimeError("missing clerk config")
        checks["configuration"] = "ok"
    except Exception:
        checks["configuration"] = "invalid"

    ready_ok = all(value == "ok" for value in checks.values())
    if not ready_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not_ready",
            "environment": settings.environment,
            "checks": checks,
        }
    return {
        "status": "ready",
        "environment": settings.environment,
        "checks": checks,
    }

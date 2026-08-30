from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    alerts,
    audit,
    candidates,
    findings,
    health,
    me,
    notifications,
    operations,
    organization_members,
    organizations,
    reports,
    security_overview,
    shared_reports,
    targets,
)
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.security import TokenVerifier
from app.services.clerk import ClerkDirectory, HttpClerkDirectory
from app.services.dns import DnsPythonTxtResolver, DnsTxtResolver


def create_app(
    *,
    token_verifier: TokenVerifier | None = None,
    clerk_directory: ClerkDirectory | None = None,
    dns_resolver: DnsTxtResolver | None = None,
) -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    directory: Any = clerk_directory or HttpClerkDirectory(settings)
    verifier = token_verifier or TokenVerifier(settings)
    resolver: DnsTxtResolver = dns_resolver or DnsPythonTxtResolver()
    owns_directory = clerk_directory is None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.token_verifier = verifier
        app.state.clerk_directory = directory
        app.state.dns_resolver = resolver
        try:
            yield
        finally:
            if owns_directory and isinstance(directory, HttpClerkDirectory):
                directory.close()

    app = FastAPI(title="Sentinel Scout API", version="0.1.0", lifespan=lifespan)
    register_exception_handlers(app)
    # Starlette executes middleware in reverse add order; add CORS last so it wraps outermost.
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )
    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(organizations.router)
    app.include_router(organization_members.router)
    app.include_router(targets.router)
    app.include_router(security_overview.router)
    app.include_router(operations.router)
    app.include_router(candidates.router)
    app.include_router(findings.router)
    app.include_router(alerts.router)
    app.include_router(notifications.router)
    app.include_router(audit.router)
    app.include_router(reports.operation_router)
    app.include_router(reports.router)
    app.include_router(reports.share_admin_router)
    app.include_router(shared_reports.router)
    return app


app = create_app()

"""HTTP middleware: request correlation IDs and safe request logging."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import bind_log_context, clear_log_context, request_id_var

logger = logging.getLogger("scout.api")

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
REQUEST_ID_HEADER = "X-Request-ID"


def resolve_request_id(incoming: str | None) -> str:
    if incoming and _SAFE_REQUEST_ID.fullmatch(incoming.strip()):
        return incoming.strip()
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """Pure ASGI middleware (avoids BaseHTTPMiddleware exception-propagation quirks)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        request_id = resolve_request_id(headers.get("x-request-id"))
        bind_log_context(request_id=request_id)
        scope["state"] = dict(scope.get("state") or {})
        scope["state"]["request_id"] = request_id

        started = time.perf_counter()
        status_code_holder = {"code": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_code_holder["code"] = message["status"]
                raw_headers = list(message.get("headers") or [])
                raw_headers.append(
                    (REQUEST_ID_HEADER.lower().encode("latin-1"), request_id.encode("latin-1"))
                )
                message = {**message, "headers": raw_headers}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            path = scope.get("path", "")
            if path not in {"/health", "/ready"}:
                duration_ms = int((time.perf_counter() - started) * 1000)
                logger.info(
                    "request completed",
                    extra={
                        "event": "request.completed",
                        "method": scope.get("method"),
                        "path": path,
                        "status_code": status_code_holder["code"],
                        "duration_ms": duration_ms,
                        "request_id": request_id,
                    },
                )
        finally:
            clear_log_context()
            request_id_var.set(request_id)

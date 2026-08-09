"""Standardized API error responses without internal leakage."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_var

logger = logging.getLogger("scout.api.errors")


def _request_id(request: Request) -> str | None:
    state_id = getattr(request.state, "request_id", None)
    if state_id:
        return str(state_id)
    scope_state = request.scope.get("state") or {}
    if isinstance(scope_state, dict) and scope_state.get("request_id"):
        return str(scope_state["request_id"])
    return request_id_var.get()


def error_body(
    *,
    code: str,
    message: str,
    request_id: str | None = None,
    details: list[Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if request_id:
        payload["error"]["request_id"] = request_id
    if details is not None:
        payload["error"]["details"] = details
    return payload


def _http_code_for_status(status_code: int) -> str:
    mapping = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        422: "validation_error",
        429: "rate_limited",
        503: "service_unavailable",
    }
    return mapping.get(status_code, "http_error")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        if isinstance(exc.detail, dict) and "message" in exc.detail:
            message = str(exc.detail["message"])
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                code=_http_code_for_status(exc.status_code),
                message=message,
                request_id=_request_id(request),
            ),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                code=_http_code_for_status(exc.status_code),
                message=message,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field locations/types only — never raw input bodies that may contain secrets.
        details = [
            {
                "loc": [str(part) for part in err.get("loc", ())],
                "msg": str(err.get("msg", "Invalid value")),
                "type": str(err.get("type", "value_error")),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=error_body(
                code="validation_error",
                message="Request validation failed",
                request_id=_request_id(request),
                details=details,
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log type only via structured formatter; avoid putting message text in response.
        logger.error(
            "unhandled exception",
            extra={
                "event": "unhandled_exception",
                "path": request.url.path,
                "error_type": type(exc).__name__,
            },
        )
        return JSONResponse(
            status_code=500,
            content=error_body(
                code="internal_error",
                message="An unexpected error occurred",
                request_id=_request_id(request),
            ),
        )

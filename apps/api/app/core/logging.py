"""Structured logging with contextvars and centralized secret redaction."""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
operation_id_var: ContextVar[str | None] = ContextVar("operation_id", default=None)
organization_id_var: ContextVar[str | None] = ContextVar("organization_id", default=None)
target_id_var: ContextVar[str | None] = ContextVar("target_id", default=None)
worker_var: ContextVar[str | None] = ContextVar("worker", default=None)

_REDACTED = "[REDACTED]"

_SENSITIVE_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
    "bearer",
    "txt_value",
    "clerk",
    "jwks",
    "prompt",
    "response_body",
    "chain_of_thought",
    "set-cookie",
    "recipient_email",
    "email_snapshot",
    "text_body",
    "subject_snapshot",
    "from_email",
    "delivery_snapshot",
)

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
_SCOUT_TXT_RE = re.compile(r"(?i)scout-verify=[^\s\"']+")


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        redacted = _BEARER_RE.sub("Bearer [REDACTED]", value)
        redacted = _SCOUT_TXT_RE.sub("scout-verify=[REDACTED]", redacted)
        return redacted
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value[:50]]
    return value


def redact_mapping(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    clean: dict[str, Any] = {}
    for key, value in data.items():
        key_l = str(key).lower()
        if key_l in {"authorization", "cookie", "set-cookie"} or any(
            fragment in key_l for fragment in _SENSITIVE_KEY_FRAGMENTS
        ):
            # Keep safe allowlisted audit-like keys that contain "authorization".
            if key_l in {"authorization_status", "authorization_id"}:
                clean[key] = redact_value(value)
            else:
                clean[key] = _REDACTED
            continue
        clean[key] = redact_value(value)
    return clean


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_value(record.getMessage()),
            "event": getattr(record, "event", record.name),
        }
        for key, var in (
            ("request_id", request_id_var),
            ("operation_id", operation_id_var),
            ("organization_id", organization_id_var),
            ("target_id", target_id_var),
            ("worker", worker_var),
        ):
            value = getattr(record, key, None) or var.get()
            if value is not None:
                payload[key] = str(value)

        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k
            not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "event",
                "request_id",
                "operation_id",
                "organization_id",
                "target_id",
                "worker",
                "taskName",
            }
            and not k.startswith("_")
        }
        if extras:
            payload["fields"] = redact_mapping(extras)
        if record.exc_info:
            # Keep exception type only — never dump stack traces into shared logs by default.
            exc_type = record.exc_info[0]
            payload["error_type"] = getattr(exc_type, "__name__", "Exception")
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def bind_log_context(
    *,
    request_id: str | None = None,
    operation_id: str | None = None,
    organization_id: str | None = None,
    target_id: str | None = None,
    worker: str | None = None,
) -> None:
    if request_id is not None:
        request_id_var.set(request_id)
    if operation_id is not None:
        operation_id_var.set(operation_id)
    if organization_id is not None:
        organization_id_var.set(organization_id)
    if target_id is not None:
        target_id_var.set(target_id)
    if worker is not None:
        worker_var.set(worker)


def clear_log_context() -> None:
    request_id_var.set(None)
    operation_id_var.set(None)
    organization_id_var.set(None)
    target_id_var.set(None)
    # Keep worker identity for process lifetime when set.

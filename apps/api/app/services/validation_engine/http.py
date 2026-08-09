"""GET/HEAD-only HTTP client for safe validation (no state-changing methods)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from app.services.validation_engine.types import SAFE_HEADER_NAMES, SAFE_HTTP_METHODS, SafeHttpObservation

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_BODY_BYTES = 16_384


class UnsafeHttpMethodError(ValueError):
    """Raised when a non-allowlisted HTTP method is requested."""


class SafeHttpClient(Protocol):
    def fetch(self, url: str, *, method: str = "GET") -> SafeHttpObservation:
        """Perform a safe observation request. Only GET/HEAD permitted."""


@dataclass
class FakeSafeHttpClient:
    """Deterministic fixture for tests — keyed by hostname."""

    by_host: dict[str, SafeHttpObservation] = field(default_factory=dict)
    default: SafeHttpObservation | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)

    def fetch(self, url: str, *, method: str = "GET") -> SafeHttpObservation:
        method_upper = method.upper()
        if method_upper not in SAFE_HTTP_METHODS:
            raise UnsafeHttpMethodError(
                f"HTTP method {method_upper!r} is not allowed for validation"
            )
        self.calls.append((method_upper, url))
        host = (urlsplit(url if "://" in url else f"https://{url}").hostname or "").lower()
        if host in self.by_host:
            return self.by_host[host]
        if self.default is not None:
            return self.default
        return SafeHttpObservation(
            url=url,
            status_code=None,
            title="",
            headers={},
            reachable=False,
        )


class HttpxSafeHttpClient:
    """Python httpx wrapper that hard-rejects non-GET/HEAD methods."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        self._timeout = timeout_seconds

    def fetch(self, url: str, *, method: str = "GET") -> SafeHttpObservation:
        method_upper = method.upper()
        if method_upper not in SAFE_HTTP_METHODS:
            raise UnsafeHttpMethodError(
                f"HTTP method {method_upper!r} is not allowed for validation"
            )
        target = url if "://" in url else f"https://{url}"
        try:
            with httpx.Client(
                timeout=self._timeout,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                response = client.request(method_upper, target)
        except httpx.HTTPError:
            return SafeHttpObservation(
                url=target,
                status_code=None,
                title="",
                headers={},
                reachable=False,
            )

        title = ""
        content_type = (response.headers.get("content-type") or "").lower()
        if method_upper == "GET" and "text/html" in content_type:
            chunk = response.content[:_MAX_BODY_BYTES]
            match = _TITLE_RE.search(chunk.decode("utf-8", errors="ignore"))
            if match:
                title = re.sub(r"\s+", " ", match.group(1)).strip()[:512]

        headers = {
            name.lower(): value[:256]
            for name, value in response.headers.items()
            if name.lower() in SAFE_HEADER_NAMES
        }
        # Never retain Set-Cookie / Authorization / etc.
        status = response.status_code
        reachable = status is not None and 100 <= status < 500
        return SafeHttpObservation(
            url=str(response.url),
            status_code=status,
            title=title,
            headers=headers,
            reachable=reachable,
        )

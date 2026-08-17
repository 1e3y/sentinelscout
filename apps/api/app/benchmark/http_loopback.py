"""Loopback Host-header HTTP for fixture sites (harness only)."""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from app.benchmark.ground_truth import GroundTruth, SiteSpec
from app.benchmark.paths import html_root
from app.services.http_evidence import sanitize_http_evidence, sanitize_url
from app.services.validation_engine.types import SAFE_HTTP_METHODS, SafeHttpObservation

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_BODY_BYTES = 16_384


def _unreachable(url: str) -> SafeHttpObservation:
    return SafeHttpObservation(
        url=url,
        status_code=None,
        title="",
        headers={},
        reachable=False,
        headers_observed=False,
    )


class LoopbackSafeHttpClient:
    """GET/HEAD to 127.0.0.1 with Host: fixture-hostname. Never hits public DNS."""

    def __init__(
        self,
        *,
        port: int,
        down_hosts: set[str] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.port = port
        self.down_hosts = down_hosts if down_hosts is not None else set()
        self.redirect_hosts: set[str] = set()
        self._timeout = timeout_seconds

    def mark_down(self, hostname: str) -> None:
        self.down_hosts.add(hostname.lower().rstrip("."))

    def mark_redirect(self, hostname: str) -> None:
        self.redirect_hosts.add(hostname.lower().rstrip("."))

    def fetch(self, url: str, *, method: str = "GET") -> SafeHttpObservation:
        method_upper = method.upper()
        if method_upper not in SAFE_HTTP_METHODS:
            raise ValueError(f"HTTP method {method_upper!r} is not allowed for validation")
        target = url if "://" in url else f"https://{url}"
        host = (urlsplit(target).hostname or "").lower().rstrip(".")
        path = urlsplit(target).path or "/"
        if host in self.down_hosts:
            return _unreachable(target)

        def _retain_fixture_host(request: httpx.Request) -> None:
            request.headers["host"] = host
            request.headers["x-scout-fixture-host"] = host

        loopback = f"http://127.0.0.1:{self.port}{path}"
        try:
            with httpx.Client(
                timeout=self._timeout,
                follow_redirects=True,
                max_redirects=3,
                trust_env=False,
                event_hooks={"request": [_retain_fixture_host]},
            ) as client:
                response = client.request(
                    method_upper,
                    loopback,
                    headers={
                        "Host": host,
                        "Accept": "text/html",
                        "X-Scout-Fixture-Host": host,
                    },
                )
        except httpx.HTTPError:
            return _unreachable(target)

        title = ""
        raw_content_type = (response.headers.get("content-type") or "").lower()
        if method_upper == "GET" and "text/html" in raw_content_type:
            chunk = response.content[:_MAX_BODY_BYTES]
            match = _TITLE_RE.search(chunk.decode("utf-8", errors="ignore"))
            if match:
                title = re.sub(r"\s+", " ", match.group(1)).strip()[:512]

        final_path = urlsplit(str(response.url)).path or "/"
        final_url = sanitize_url(f"https://{host}{final_path}") or target
        evidence = sanitize_http_evidence(
            headers_observed=True,
            raw_headers=dict(response.headers),
            requested_url=target,
            final_url=final_url,
            redirected=bool(response.history) or host in self.redirect_hosts,
            content_type=raw_content_type or None,
        )
        status = response.status_code
        reachable = status is not None and 100 <= status < 500
        return SafeHttpObservation(
            url=evidence.final_url or final_url,
            status_code=status,
            title=title,
            headers=dict(evidence.headers),
            reachable=reachable,
            headers_observed=True,
            headers_present=evidence.headers_present,
            content_type=evidence.content_type,
            requested_url=evidence.requested_url,
            final_url=evidence.final_url,
            redirected=bool(response.history) or host in self.redirect_hosts,
            location_url=evidence.location_url,
        )


def _index_sites(sites: tuple[SiteSpec, ...]) -> dict[tuple[str, str], SiteSpec]:
    mapping: dict[tuple[str, str], SiteSpec] = {}
    for site in sites:
        path = site.path if site.path.startswith("/") else f"/{site.path}"
        mapping[(site.hostname, path)] = site
        if path != "/" and site.redirect_to is None:
            mapping.setdefault((site.hostname, "/"), site)
    return mapping


class FixtureRequestHandler(BaseHTTPRequestHandler):
    site_index: ClassVar[dict[tuple[str, str], SiteSpec]] = {}
    down_hosts: ClassVar[set[str]] = set()

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        fixture_host = (self.headers.get("X-Scout-Fixture-Host") or "").split(":")[0]
        raw_host = fixture_host or (self.headers.get("Host") or "")
        host = raw_host.split(":")[0].lower().rstrip(".")
        path = self.path.split("?", 1)[0]
        if host in self.down_hosts:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            return
        site = self.site_index.get((host, path)) or self.site_index.get((host, "/"))
        if site is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if include_body:
                self.wfile.write(b"not found")
            return
        if site.redirect_to:
            self.send_response(302)
            self.send_header("Location", site.redirect_to)
            for name, value in site.response_headers:
                self.send_header(name, value)
            self.end_headers()
            return
        file_path = html_root() / site.html
        if not file_path.is_file():
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if include_body:
                self.wfile.write(b"not found")
            return
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", site.content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in site.response_headers:
            if name.lower() == "content-type":
                continue
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)


class FixtureHttpServer:
    def __init__(self, truth: GroundTruth, *, port: int = 0) -> None:
        handler = type(
            "BoundFixtureHandler",
            (FixtureRequestHandler,),
            {
                "site_index": _index_sites(truth.sites),
                "down_hosts": set(),
            },
        )
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self._thread: threading.Thread | None = None
        self.handler = handler

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> int:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def mark_down(self, hostname: str) -> None:
        self.handler.down_hosts.add(hostname.lower().rstrip("."))

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

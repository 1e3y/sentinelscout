"""Subfinder/httpx wrappers (ported from prototype) with injectable fakes for tests."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

from app.core.config import get_settings
from app.services.http_evidence import (
    http_json_headers_observed,
    media_type,
    sanitize_http_evidence,
)


class DiscoveryError(Exception):
    """Raised when discovery tooling fails in a controlled way."""


@dataclass(frozen=True)
class ProbeResult:
    url: str
    status_code: int | None
    title: str
    headers_observed: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    headers_present: tuple[str, ...] = ()
    content_type: str | None = None
    requested_url: str | None = None
    final_url: str | None = None
    redirected: bool = False
    location_url: str | None = None
    scheme: str | None = None
    # observed | host_not_reachable | probe_failed | probe_timeout
    # Absence from the result list is probe_no_result (cause not distinguishable).
    outcome: str = "observed"


class DiscoveryTools(Protocol):
    def discover_hosts(self, domain: str) -> tuple[list[str], str | None]:
        """Return hostnames and optional truncation note."""

    def probe_hosts(self, hosts: list[str]) -> list[ProbeResult]:
        """Probe allowed hosts over HTTP(S). No authenticated/destructive requests."""


class SubprocessDiscoveryTools:
    """Runs subfinder + ProjectDiscovery httpx as subprocesses."""

    def discover_hosts(self, domain: str) -> tuple[list[str], str | None]:
        settings = get_settings()
        try:
            process = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                check=False,
                timeout=settings.subfinder_timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise DiscoveryError("subfinder is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise DiscoveryError("subfinder timed out") from exc

        if process.returncode not in (0, 1):
            raise DiscoveryError("subfinder exited with an error")

        hosts = [line.strip().lower().rstrip(".") for line in process.stdout.splitlines() if line.strip()]
        if not hosts:
            hosts = [domain]

        note = None
        max_hosts = settings.max_discovered_hosts
        if len(hosts) > max_hosts:
            total = len(hosts)
            hosts = hosts[:max_hosts]
            note = f"Host list truncated to {max_hosts} of {total} discovered."
        return hosts, note

    def probe_hosts(self, hosts: list[str]) -> list[ProbeResult]:
        if not hosts:
            return []
        settings = get_settings()
        try:
            process = subprocess.run(
                [
                    "httpx",
                    "-silent",
                    "-json",
                    "-title",
                    "-status-code",
                    "-follow-redirects",
                    "-content-type",
                    "-include-response-header",
                ],
                input="\n".join(hosts),
                capture_output=True,
                text=True,
                check=False,
                timeout=settings.httpx_timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise DiscoveryError("httpx is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise DiscoveryError("httpx timed out") from exc

        if process.returncode not in (0, 1):
            raise DiscoveryError("httpx exited with an error")

        results: list[ProbeResult] = []
        for line in process.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = str(entry.get("url") or "").strip()
            if not url:
                continue
            status = entry.get("status_code")
            status_code = int(status) if isinstance(status, int) else None
            title = str(entry.get("title") or "")[:512]
            requested = str(entry.get("input") or entry.get("host") or url).strip()
            headers_observed, raw_headers = http_json_headers_observed(entry)
            top_content_type = media_type(str(entry.get("content_type") or "") or None)
            evidence = sanitize_http_evidence(
                headers_observed=headers_observed,
                raw_headers=raw_headers,
                requested_url=requested,
                final_url=url,
                redirected=bool(entry.get("chain") or entry.get("redirects")),
                content_type=top_content_type,
            )
            results.append(
                ProbeResult(
                    url=url,
                    status_code=status_code,
                    title=title,
                    headers_observed=evidence.headers_observed,
                    headers=dict(evidence.headers),
                    headers_present=evidence.headers_present,
                    content_type=evidence.content_type or top_content_type,
                    requested_url=evidence.requested_url,
                    final_url=evidence.final_url,
                    redirected=evidence.redirected,
                    location_url=evidence.location_url,
                    scheme=evidence.scheme,
                )
            )
        return results


@dataclass
class FakeDiscoveryTools:
    """Deterministic test double — no network, no subprocesses."""

    hosts_by_domain: dict[str, list[str]]
    probes_by_host: dict[str, ProbeResult]
    fail_discover_with: str | None = None
    fail_probe_with: str | None = None

    def discover_hosts(self, domain: str) -> tuple[list[str], str | None]:
        if self.fail_discover_with:
            raise DiscoveryError(self.fail_discover_with)
        hosts = list(self.hosts_by_domain.get(domain, [domain]))
        return hosts, None

    def probe_hosts(self, hosts: list[str]) -> list[ProbeResult]:
        if self.fail_probe_with:
            raise DiscoveryError(self.fail_probe_with)
        results: list[ProbeResult] = []
        for host in hosts:
            probe = self.probes_by_host.get(host)
            if probe is not None:
                results.append(probe)
        return results

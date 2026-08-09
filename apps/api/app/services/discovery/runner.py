"""Subfinder/httpx wrappers (ported from prototype) with injectable fakes for tests."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Protocol

from app.core.config import get_settings


class DiscoveryError(Exception):
    """Raised when discovery tooling fails in a controlled way."""


@dataclass(frozen=True)
class ProbeResult:
    url: str
    status_code: int | None
    title: str


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
            results.append(ProbeResult(url=url, status_code=status_code, title=title))
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

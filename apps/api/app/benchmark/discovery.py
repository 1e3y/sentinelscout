"""Harness discovery tools: seeded hosts + loopback probes. No public DNS."""

from __future__ import annotations

import json
import shutil
import subprocess

from app.benchmark.ground_truth import GroundTruth
from app.benchmark.http_loopback import LoopbackSafeHttpClient
from app.services.discovery.runner import DiscoveryError, ProbeResult


class SeededLoopbackDiscoveryTools:
    """Offline mode: fixture host list + python-httpx loopback probes."""

    def __init__(self, truth: GroundTruth, client: LoopbackSafeHttpClient) -> None:
        self.truth = truth
        self.client = client
        self.path_by_host = {site.hostname: site.path or "/" for site in truth.sites}

    def discover_hosts(self, domain: str) -> tuple[list[str], str | None]:
        root = domain.lower().rstrip(".")
        hosts = [host for host in self.truth.hostnames if host == root or host.endswith(f".{root}")]
        return hosts, None

    def probe_hosts(self, hosts: list[str]) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        for host in hosts:
            path = self.path_by_host.get(host, "/")
            canonical = f"https://{host}{path}"
            obs = self.client.fetch(canonical, method="GET")
            if not obs.reachable:
                continue
            results.append(
                ProbeResult(url=canonical, status_code=obs.status_code, title=obs.title)
            )
        return results


class LiveLoopbackDiscoveryTools:
    """local_live: optional subfinder (recorded only) + ProjectDiscovery httpx to loopback."""

    def __init__(
        self,
        truth: GroundTruth,
        client: LoopbackSafeHttpClient,
        *,
        subfinder_hosts: list[str] | None = None,
        used_httpx_binary: bool = False,
        warnings: list[str] | None = None,
    ) -> None:
        self._seeded = SeededLoopbackDiscoveryTools(truth, client)
        self.subfinder_hosts = subfinder_hosts or []
        self.used_httpx_binary = used_httpx_binary
        self.warnings = warnings or []
        self.probed_hosts: list[str] = []

    def discover_hosts(self, domain: str) -> tuple[list[str], str | None]:
        return self._seeded.discover_hosts(domain)

    def probe_hosts(self, hosts: list[str]) -> list[ProbeResult]:
        if not self.used_httpx_binary:
            results = self._seeded.probe_hosts(hosts)
            self.probed_hosts = [
                (r.url.split("://", 1)[-1].split("/", 1)[0]) for r in results
            ]
            return results
        results: list[ProbeResult] = []
        for host in hosts:
            path = self._seeded.path_by_host.get(host, "/")
            canonical = f"https://{host}{path}"
            loopback = f"http://127.0.0.1:{self._seeded.client.port}{path}"
            try:
                process = subprocess.run(
                    [
                        "httpx",
                        "-silent",
                        "-json",
                        "-title",
                        "-status-code",
                        "-follow-redirects",
                        "-u",
                        loopback,
                        "-H",
                        f"Host: {host}",
                        "-H",
                        f"X-Scout-Fixture-Host: {host}",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                    shell=False,
                )
            except FileNotFoundError as exc:
                raise DiscoveryError("httpx is not installed or not on PATH") from exc
            except subprocess.TimeoutExpired as exc:
                raise DiscoveryError("httpx timed out") from exc
            if process.returncode not in (0, 1):
                continue
            parsed = None
            for line in process.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
            if not parsed:
                continue
            status = parsed.get("status_code")
            status_code = int(status) if isinstance(status, int) else None
            title = str(parsed.get("title") or "")[:512]
            if status_code is None:
                continue
            self.probed_hosts.append(host)
            results.append(ProbeResult(url=canonical, status_code=status_code, title=title))
        return results


def invoke_subfinder(domain: str) -> tuple[list[str], str | None]:
    """Best-effort public-DNS subfinder. Expected empty for bench.example."""
    if shutil.which("subfinder") is None:
        return [], "subfinder not installed"
    try:
        process = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [], "subfinder failed or timed out"
    if process.returncode not in (0, 1):
        return [], "subfinder exited with an error"
    hosts = [line.strip().lower().rstrip(".") for line in process.stdout.splitlines() if line.strip()]
    return hosts, None

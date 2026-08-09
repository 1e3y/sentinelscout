"""Authorized-scope filtering for discovery (ported from prototype scanner)."""

from __future__ import annotations

from urllib.parse import urlsplit


def normalize_host(value: str) -> str:
    """Extract and normalize a hostname from a host or URL."""
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def host_in_scope(
    host: str,
    root_domain: str,
    *,
    include_subdomains: bool,
    exclusions: list[str] | None = None,
) -> bool:
    """Label-aware descendant check against persisted TargetScope."""
    safe_host = normalize_host(host)
    safe_root = root_domain.strip().lower().rstrip(".")
    if not safe_host or not safe_root:
        return False

    if safe_host == safe_root:
        in_root = True
    elif include_subdomains and safe_host.endswith(f".{safe_root}"):
        in_root = True
    else:
        in_root = False

    if not in_root:
        return False

    for exclusion in exclusions or []:
        safe_exclusion = exclusion.strip().lower().rstrip(".")
        if not safe_exclusion:
            continue
        if safe_host == safe_exclusion or safe_host.endswith(f".{safe_exclusion}"):
            return False
    return True


def filter_hosts_for_scope(
    hosts: list[str],
    root_domain: str,
    *,
    include_subdomains: bool,
    exclusions: list[str] | None = None,
) -> list[str]:
    seen: set[str] = set()
    allowed: list[str] = []
    for host in hosts:
        normalized = normalize_host(host)
        if not normalized or normalized in seen:
            continue
        if host_in_scope(
            normalized,
            root_domain,
            include_subdomains=include_subdomains,
            exclusions=exclusions,
        ):
            seen.add(normalized)
            allowed.append(normalized)
    return allowed

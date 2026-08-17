"""Token-aware hostname matching. Never treat arbitrary substrings as labels."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

MatchKind = Literal["dns_label", "hyphen_token"]


def hostname_labels(hostname: str) -> tuple[str, ...]:
    host = (hostname or "").lower().rstrip(".")
    return tuple(part for part in host.split(".") if part)


def tokens_in_label(label: str) -> tuple[str, ...]:
    return tuple(part for part in re.split(r"[-_]+", label.lower()) if part)


@dataclass(frozen=True)
class HostMarkerHit:
    marker: str
    kind: MatchKind
    label: str

    def describe(self) -> str:
        if self.kind == "dns_label":
            return f"hostname DNS label is '{self.marker}'"
        return f"hostname hyphen/underscore token '{self.marker}' in label '{self.label}'"


def role_or_env_hits(hostname: str, markers: Sequence[str]) -> tuple[HostMarkerHit, ...]:
    """Exact DNS labels or hyphen/underscore tokens (admin, staging, dev)."""
    hits: list[HostMarkerHit] = []
    seen: set[tuple[str, str, str]] = set()
    wanted = tuple(marker.lower() for marker in markers)
    for label in hostname_labels(hostname):
        for marker in wanted:
            if label == marker:
                key = (marker, "dns_label", label)
                if key not in seen:
                    seen.add(key)
                    hits.append(HostMarkerHit(marker, "dns_label", label))
            elif marker in tokens_in_label(label):
                key = (marker, "hyphen_token", label)
                if key not in seen:
                    seen.add(key)
                    hits.append(HostMarkerHit(marker, "hyphen_token", label))
    return tuple(hits)


def exact_dns_label_hits(hostname: str, markers: Sequence[str]) -> tuple[HostMarkerHit, ...]:
    """Named products and short/ambiguous infra: exact DNS label only."""
    labels = set(hostname_labels(hostname))
    hits: list[HostMarkerHit] = []
    for marker in markers:
        lowered = marker.lower()
        if lowered in labels:
            hits.append(HostMarkerHit(lowered, "dns_label", lowered))
    return tuple(hits)


def url_path(url: str) -> str:
    if not url:
        return "/"
    target = url if "://" in url else f"https://{url}"
    path = urlsplit(target).path or "/"
    return path.lower()


def path_prefix_hits(url: str, prefixes: Sequence[str]) -> tuple[str, ...]:
    """Match path prefixes on the URL path only — never the scheme/host."""
    path = url_path(url)
    hits: list[str] = []
    for raw in prefixes:
        prefix = raw.lower()
        if not prefix.startswith("/"):
            prefix = f"/{prefix}"
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            hits.append(prefix)
    return tuple(hits)


def title_contains(title: str, markers: Sequence[str]) -> tuple[str, ...]:
    lowered = (title or "").lower()
    return tuple(marker for marker in markers if marker.lower() in lowered)

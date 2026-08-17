"""Allowlisted HTTP response facts. Never persist bodies, cookies, or secrets."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

HSTS_HEADER = "strict-transport-security"

HEADER_VALUE_ALLOWLIST = frozenset(
    {
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "content-type",
    }
)
HEADER_PRESENCE_ONLY = frozenset(
    {
        "content-security-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    }
)
LOCATION_HEADER = "location"

HEADER_DENY_EXACT = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "www-authenticate",
        "proxy-authenticate",
        "x-api-key",
        "x-auth-token",
        "authentication-info",
    }
)
HEADER_DENY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "credential",
    "api-key",
    "apikey",
    "bearer",
)

MAX_HEADER_VALUE_CHARS = 256
MAX_METADATA_BYTES = 8192

# Combined names the HTTP clients may copy before sanitizer splits values vs presence.
SAFE_HEADER_NAMES = HEADER_VALUE_ALLOWLIST | HEADER_PRESENCE_ONLY | {LOCATION_HEADER}


@dataclass(frozen=True)
class SanitizedHttpEvidence:
    headers_observed: bool
    headers: dict[str, str]
    headers_present: tuple[str, ...]
    content_type: str | None
    location_url: str | None
    requested_url: str | None
    final_url: str | None
    redirected: bool
    scheme: str | None


def header_name_denied(name: str) -> bool:
    lowered = name.lower().strip()
    if not lowered or lowered in HEADER_DENY_EXACT:
        return True
    return any(fragment in lowered for fragment in HEADER_DENY_FRAGMENTS)


def media_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def sanitize_url(url: str | None) -> str | None:
    """Keep scheme/host/port/path. Drop userinfo, query, and fragment."""
    if not url:
        return None
    target = url if "://" in url else f"https://{url}"
    parsed = urlsplit(target)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    if len(path) > MAX_HEADER_VALUE_CHARS:
        path = path[:MAX_HEADER_VALUE_CHARS]
    scheme = (parsed.scheme or "https").lower()
    cleaned = urlunsplit((scheme, f"{host}{port}", path, "", ""))
    return cleaned[:2048]


def _normalize_raw_headers(raw: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).lower().strip()
        if not name or header_name_denied(name):
            continue
        text = value if isinstance(value, str) else str(value)
        out[name] = text[:MAX_HEADER_VALUE_CHARS]
    return out


def sanitize_http_evidence(
    *,
    headers_observed: bool,
    raw_headers: Mapping[str, Any] | None = None,
    requested_url: str | None = None,
    final_url: str | None = None,
    redirected: bool = False,
    content_type: str | None = None,
) -> SanitizedHttpEvidence:
    """Build persistable facts. Empty maps never imply headers_observed."""
    requested = sanitize_url(requested_url)
    final = sanitize_url(final_url) or requested
    scheme = None
    parsed = urlsplit(final or requested or "")
    if parsed.scheme:
        scheme = parsed.scheme.lower()

    headers: dict[str, str] = {}
    present: list[str] = []
    location_url: str | None = None
    header_content_type = media_type(content_type)

    if headers_observed:
        normalized = _normalize_raw_headers(raw_headers)
        for name, value in normalized.items():
            if name == LOCATION_HEADER:
                location_url = sanitize_url(value)
                if name not in present:
                    present.append(name)
                continue
            if name in HEADER_VALUE_ALLOWLIST:
                headers[name] = value
                if name not in present:
                    present.append(name)
                if name == "content-type" and header_content_type is None:
                    header_content_type = media_type(value)
            elif name in HEADER_PRESENCE_ONLY:
                if name not in present:
                    present.append(name)
        if header_content_type is None:
            header_content_type = media_type(headers.get("content-type"))

    hop_redirect = bool(redirected)
    if requested and final and urlsplit(requested).path != urlsplit(final).path:
        hop_redirect = True
    if requested and final and urlsplit(requested).hostname != urlsplit(final).hostname:
        hop_redirect = True

    return SanitizedHttpEvidence(
        headers_observed=bool(headers_observed),
        headers=headers,
        headers_present=tuple(present),
        content_type=header_content_type,
        location_url=location_url,
        requested_url=requested,
        final_url=final,
        redirected=hop_redirect,
        scheme=scheme,
    )


def http_json_headers_observed(entry: Mapping[str, Any]) -> tuple[bool, Mapping[str, Any] | None]:
    """ProjectDiscovery httpx: only trust an explicit header object."""
    for key in ("header", "headers", "response_headers"):
        if key in entry:
            value = entry.get(key)
            if isinstance(value, Mapping):
                return True, value
            return False, None
    return False, None


def evidence_from_probe(
    *,
    headers_observed: bool,
    headers: Mapping[str, str] | None,
    headers_present: Sequence[str] | None,
    content_type: str | None,
    location_url: str | None,
    requested_url: str | None,
    final_url: str | None,
    redirected: bool,
    scheme: str | None,
) -> SanitizedHttpEvidence:
    requested = sanitize_url(requested_url)
    final = sanitize_url(final_url) or requested
    derived_scheme = scheme
    if not derived_scheme:
        parsed = urlsplit(final or requested or "")
        derived_scheme = parsed.scheme.lower() if parsed.scheme else None
    hop = bool(redirected)
    if requested and final:
        req = urlsplit(requested)
        fin = urlsplit(final)
        if req.path != fin.path or req.hostname != fin.hostname:
            hop = True
    if not headers_observed:
        return SanitizedHttpEvidence(
            headers_observed=False,
            headers={},
            headers_present=(),
            content_type=media_type(content_type),
            location_url=None,
            requested_url=requested,
            final_url=final,
            redirected=hop,
            scheme=derived_scheme,
        )
    cleaned_headers: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key).lower()
        if header_name_denied(name) or name not in HEADER_VALUE_ALLOWLIST:
            continue
        cleaned_headers[name] = str(value)[:MAX_HEADER_VALUE_CHARS]
    present: list[str] = []
    for item in headers_present or ():
        name = str(item).lower()
        if header_name_denied(name):
            continue
        if (
            name in HEADER_VALUE_ALLOWLIST
            or name in HEADER_PRESENCE_ONLY
            or name == LOCATION_HEADER
        ) and name not in present:
            present.append(name)
    for name in cleaned_headers:
        if name not in present:
            present.append(name)
    return SanitizedHttpEvidence(
        headers_observed=True,
        headers=cleaned_headers,
        headers_present=tuple(present),
        content_type=media_type(content_type) or media_type(cleaned_headers.get("content-type")),
        location_url=sanitize_url(location_url),
        requested_url=requested,
        final_url=final,
        redirected=hop,
        scheme=derived_scheme,
    )


def observation_metadata(
    evidence: SanitizedHttpEvidence,
    *,
    hostname: str,
    status_code: int | None,
    title: str | None,
    url: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "hostname": hostname,
        "url": url,
        "status_code": status_code,
        "title": title,
        "headers_observed": evidence.headers_observed,
        "scheme": evidence.scheme,
        "content_type": evidence.content_type,
        "requested_url": evidence.requested_url,
        "final_url": evidence.final_url,
        "redirected": evidence.redirected,
        "headers": dict(evidence.headers) if evidence.headers_observed else {},
        "headers_present": list(evidence.headers_present) if evidence.headers_observed else [],
    }
    if evidence.headers_observed and evidence.location_url:
        payload["location_url"] = evidence.location_url
    encoded = json.dumps(payload, default=str)
    if len(encoded.encode("utf-8")) <= MAX_METADATA_BYTES:
        return payload
    payload["headers"] = {
        key: value[:64]
        for key, value in list(payload.get("headers") or {}).items()
        if key == HSTS_HEADER or key == "content-type"
    }
    payload["headers_present"] = [
        name
        for name in payload.get("headers_present") or []
        if name in {HSTS_HEADER, "content-type", *HEADER_PRESENCE_ONLY}
    ][:8]
    payload.pop("location_url", None)
    return payload


def hsts_header_present(headers: Mapping[str, str], headers_present: Sequence[str]) -> bool:
    if HSTS_HEADER in headers:
        return True
    return HSTS_HEADER in {name.lower() for name in headers_present}


def is_https_html_success(
    *,
    scheme: str | None,
    content_type: str | None,
    status_code: int | None,
) -> bool:
    if scheme != "https":
        return False
    if status_code is None or not (200 <= int(status_code) <= 299):
        return False
    media = media_type(content_type) or ""
    return media == "text/html" or media.startswith("text/html")

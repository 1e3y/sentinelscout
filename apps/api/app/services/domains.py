from __future__ import annotations

import re

from fastapi import HTTPException

# Labels: alnum, optional internal hyphens; TLD at least 2 alpha chars.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

_UNPROCESSABLE = 422


def normalize_domain(raw: str) -> str:
    if raw is None:
        raise HTTPException(status_code=_UNPROCESSABLE, detail="Domain required")

    value = raw.strip().lower()
    if not value:
        raise HTTPException(status_code=_UNPROCESSABLE, detail="Domain required")

    # Reject URLs / paths / credentials / ports masquerading as domains.
    if "://" in value or "/" in value or "?" in value or "#" in value or "@" in value:
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Provide a bare domain without protocol or path",
        )
    if ":" in value:
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Provide a bare domain without port",
        )
    if " " in value:
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Invalid domain",
        )

    if value.startswith("*."):
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Wildcard domains are not allowed; use include_subdomains instead",
        )

    value = value.rstrip(".")
    if value.startswith("."):
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Invalid domain",
        )

    if not _DOMAIN_RE.match(value):
        raise HTTPException(
            status_code=_UNPROCESSABLE,
            detail="Malformed domain",
        )

    return value


def is_subdomain_or_self(candidate: str, root: str) -> bool:
    return candidate == root or candidate.endswith("." + root)


TXT_NAME_PREFIX = "_sentinelscout-challenge"
TXT_VALUE_PREFIX = "sentinelscout-verify="


def build_txt_name(domain: str) -> str:
    return f"{TXT_NAME_PREFIX}.{domain}"


def build_txt_value(token: str) -> str:
    return f"{TXT_VALUE_PREFIX}{token}"

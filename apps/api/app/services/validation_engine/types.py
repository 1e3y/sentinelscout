from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.http_evidence import SAFE_HEADER_NAMES

__all__ = [
    "ALLOWLISTED_VALIDATION_METHODS",
    "CANDIDATE_TYPE_METHODS",
    "SAFE_HEADER_NAMES",
    "SAFE_HTTP_METHODS",
    "SafeHttpObservation",
    "ValidationResult",
    "method_for_candidate_type",
]


@dataclass(frozen=True)
class ValidationResult:
    status: str  # supported | unsupported | inconclusive | failed
    validation_method: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SafeHttpObservation:
    """Sanitized GET/HEAD observation — never includes bodies or secrets."""

    url: str
    status_code: int | None
    title: str
    headers: dict[str, str]
    reachable: bool
    headers_observed: bool = False
    headers_present: tuple[str, ...] = ()
    content_type: str | None = None
    requested_url: str | None = None
    final_url: str | None = None
    redirected: bool = False
    location_url: str | None = None


# Explicit allowlist — unknown types must not probe.
CANDIDATE_TYPE_METHODS: dict[str, str] = {
    "staging_dev_exposed": "staging_indicator_confirmation",
    "exposed_admin_interface": "admin_surface_confirmation",
    "auth_surface_observed": "auth_surface_confirmation",
    "sensitive_service_exposed": "sensitive_service_confirmation",
    "security_header_observation": "header_confirmation",
}

ALLOWLISTED_VALIDATION_METHODS = frozenset(CANDIDATE_TYPE_METHODS.values()) | {
    "reachability_confirmation",
}

SAFE_HTTP_METHODS = frozenset({"GET", "HEAD"})


def method_for_candidate_type(candidate_type: str) -> str | None:
    return CANDIDATE_TYPE_METHODS.get(candidate_type)

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


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

# Headers safe to retain as evidence (names only / values of public security headers).
SAFE_HEADER_NAMES = frozenset(
    {
        "server",
        "x-powered-by",
        "content-type",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "location",
    }
)


def method_for_candidate_type(candidate_type: str) -> str | None:
    return CANDIDATE_TYPE_METHODS.get(candidate_type)

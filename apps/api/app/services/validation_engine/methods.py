"""Allowlisted non-destructive validation methods over SafeHttpObservation."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from uuid import UUID

from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.services.candidate_engine.rules import (
    ADMIN_HOST_MARKERS,
    ADMIN_TITLE_MARKERS,
    AUTH_PATH_MARKERS,
    AUTH_TITLE_MARKERS,
    SENSITIVE_HOST_MARKERS,
    STAGING_HOST_MARKERS,
)
from app.services.validation_engine.http import SafeHttpClient
from app.services.validation_engine.types import (
    ALLOWLISTED_VALIDATION_METHODS,
    ValidationResult,
    method_for_candidate_type,
)

COMMON_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
)


def _observation_ids(observations: list[DiscoveryObservation]) -> list[str]:
    return [str(obs.id) for obs in observations][:50]


def _target_url(asset: Asset) -> str:
    if asset.url:
        return asset.url
    return f"https://{asset.hostname}"


def _base_evidence(
    *,
    method: str,
    asset: Asset,
    observations: list[DiscoveryObservation],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "method": method,
        "asset_id": str(asset.id),
        "hostname": asset.hostname,
        "observation_ids": _observation_ids(observations),
    }
    if extra:
        evidence.update(extra)
    return evidence


def _hostname_has_marker(hostname: str, markers: tuple[str, ...]) -> list[str]:
    host = hostname.lower()
    labels = [part for part in host.split(".") if part]
    signals: list[str] = []
    for marker in markers:
        if marker in labels or re.search(rf"(^|[-_.]){re.escape(marker)}([-_.]|$)", host):
            signals.append(marker)
    return signals


def validate_reachability(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "reachability_confirmation"
    obs = client.fetch(_target_url(asset), method="GET")
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
        },
    )
    if obs.reachable:
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary="Previously observed service remained publicly reachable during confirmation.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Previously observed service was not reachable during confirmation.",
        evidence=evidence,
    )


def validate_staging_indicators(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "staging_indicator_confirmation"
    signals = _hostname_has_marker(asset.hostname, STAGING_HOST_MARKERS)
    obs = client.fetch(_target_url(asset), method="GET")
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
            "staging_markers": signals,
        },
    )
    if obs.reachable and signals:
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary=(
                "Publicly reachable asset still shows non-production hostname indicators."
            ),
            evidence=evidence,
        )
    if not obs.reachable:
        return ValidationResult(
            status="unsupported",
            validation_method=method,
            summary="Staging/development asset was not reachable during confirmation.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Hostname no longer shows staging/development indicators.",
        evidence=evidence,
    )


def validate_admin_surface(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "admin_surface_confirmation"
    host_signals = _hostname_has_marker(asset.hostname, ADMIN_HOST_MARKERS)
    url_signals = [m for m in ADMIN_HOST_MARKERS if m in (asset.url or "").lower()]
    obs = client.fetch(_target_url(asset), method="GET")
    title = (obs.title or asset.title or "").lower()
    title_signals = [m for m in ADMIN_TITLE_MARKERS if m in title]
    signals = list(dict.fromkeys(host_signals + url_signals + title_signals))
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
            "title": (obs.title or "")[:200],
            "admin_signals": signals,
        },
    )
    if obs.reachable and signals:
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary="Public administrative interface remained reachable during confirmation.",
            evidence=evidence,
        )
    if not obs.reachable:
        return ValidationResult(
            status="unsupported",
            validation_method=method,
            summary="Administrative interface was not reachable during confirmation.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Observable admin naming/title signals were not confirmed.",
        evidence=evidence,
    )


def validate_auth_surface(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "auth_surface_confirmation"
    obs = client.fetch(_target_url(asset), method="GET")
    title = (obs.title or asset.title or "").lower()
    url = (obs.url or asset.url or "").lower()
    host_labels = [p for p in asset.hostname.lower().split(".") if p]
    signals: list[str] = []
    for marker in AUTH_TITLE_MARKERS:
        if marker in title:
            signals.append(f"title:{marker}")
    for marker in AUTH_PATH_MARKERS:
        if marker in url:
            signals.append(f"path:{marker}")
    for label in ("auth", "sso", "login"):
        if label in host_labels:
            signals.append(f"host:{label}")
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
            "title": (obs.title or "")[:200],
            "auth_signals": signals,
        },
    )
    if obs.reachable and signals:
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary="Authentication-related surface remained publicly reachable during confirmation.",
            evidence=evidence,
        )
    if not obs.reachable:
        return ValidationResult(
            status="unsupported",
            validation_method=method,
            summary="Authentication surface was not reachable during confirmation.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Authentication surface signals were not confirmed.",
        evidence=evidence,
    )


def validate_sensitive_service(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "sensitive_service_confirmation"
    signals = _hostname_has_marker(asset.hostname, SENSITIVE_HOST_MARKERS)
    obs = client.fetch(_target_url(asset), method="GET")
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
            "sensitive_markers": signals,
        },
    )
    if obs.reachable and signals:
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary=(
                "Potentially sensitive service hostname remained publicly reachable "
                "during confirmation."
            ),
            evidence=evidence,
        )
    if not obs.reachable:
        return ValidationResult(
            status="unsupported",
            validation_method=method,
            summary="Potentially sensitive service was not reachable during confirmation.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Sensitive-service hostname indicators were not confirmed.",
        evidence=evidence,
    )


def validate_security_headers(
    client: SafeHttpClient,
    *,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    method = "header_confirmation"
    expected_missing: list[str] = []
    for obs_row in observations:
        meta = obs_row.observation_metadata or {}
        headers = meta.get("security_headers_missing")
        if isinstance(headers, list):
            expected_missing.extend(str(h).lower() for h in headers)
    # Also accept candidate evidence signals.
    signals = (candidate.evidence or {}).get("signals") or []
    if isinstance(signals, list):
        for item in signals:
            if isinstance(item, str) and item.lower() in COMMON_SECURITY_HEADERS:
                expected_missing.append(item.lower())
    expected_missing = list(dict.fromkeys(expected_missing))

    obs = client.fetch(_target_url(asset), method="GET")
    present = [name for name in expected_missing if name in obs.headers]
    still_missing = [name for name in expected_missing if name not in obs.headers]
    evidence = _base_evidence(
        method=method,
        asset=asset,
        observations=observations,
        extra={
            "status_code": obs.status_code,
            "final_url": obs.url,
            "reachable": obs.reachable,
            "expected_missing": expected_missing,
            "still_missing": still_missing,
            "observed_header_names": sorted(obs.headers.keys()),
        },
    )
    if not expected_missing:
        return ValidationResult(
            status="inconclusive",
            validation_method=method,
            summary="No prior missing-header observation was available to confirm.",
            evidence=evidence,
        )
    if not obs.reachable:
        return ValidationResult(
            status="unsupported",
            validation_method=method,
            summary="Asset was not reachable while confirming HTTP security headers.",
            evidence=evidence,
        )
    if still_missing:
        evidence["observed_header"] = still_missing[0]
        return ValidationResult(
            status="supported",
            validation_method=method,
            summary="Security-relevant HTTP header configuration observation was reconfirmed.",
            evidence=evidence,
        )
    return ValidationResult(
        status="unsupported",
        validation_method=method,
        summary="Previously missing security headers were present during confirmation.",
        evidence={**evidence, "present_headers": present},
    )


MethodFn = Callable[..., ValidationResult]

METHOD_HANDLERS: dict[str, MethodFn] = {
    "reachability_confirmation": validate_reachability,
    "staging_indicator_confirmation": validate_staging_indicators,
    "admin_surface_confirmation": validate_admin_surface,
    "auth_surface_confirmation": validate_auth_surface,
    "sensitive_service_confirmation": validate_sensitive_service,
    "header_confirmation": validate_security_headers,
}


def run_allowlisted_method(
    client: SafeHttpClient,
    *,
    method: str,
    candidate: SecurityCandidate,
    asset: Asset,
    observations: list[DiscoveryObservation],
) -> ValidationResult:
    if method not in ALLOWLISTED_VALIDATION_METHODS:
        return ValidationResult(
            status="inconclusive",
            validation_method=method,
            summary="Validation method is not on the safe allowlist.",
            evidence={"method": method, "asset_id": str(asset.id)},
        )
    handler = METHOD_HANDLERS.get(method)
    if handler is None:
        return ValidationResult(
            status="inconclusive",
            validation_method=method,
            summary="No allowlisted handler is registered for this validation method.",
            evidence={"method": method, "asset_id": str(asset.id)},
        )
    return handler(
        client,
        candidate=candidate,
        asset=asset,
        observations=observations,
    )


def resolve_method_for_candidate(candidate: SecurityCandidate) -> str | None:
    return method_for_candidate_type(candidate.candidate_type)


def inconclusive_unknown_type(candidate_id: UUID, candidate_type: str) -> ValidationResult:
    return ValidationResult(
        status="inconclusive",
        validation_method="none",
        summary=(
            "No allowlisted safe validation method is defined for this candidate type; "
            "no probe was performed."
        ),
        evidence={
            "method": "none",
            "candidate_id": str(candidate_id),
            "candidate_type": candidate_type,
            "probed": False,
        },
    )

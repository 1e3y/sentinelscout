"""Deterministic severity, impact, and remediation guidance for findings.

Severity is conservative and evidence-based. No CVSS is calculated.
Prefer the lower reasonable severity when only exposure/naming is observed.
"""

from __future__ import annotations

# candidate_type → severity
# Exposure/naming evidence only — not proof of compromise or data loss.
SEVERITY_BY_CANDIDATE_TYPE: dict[str, str] = {
    "security_header_observation": "low",
    "auth_surface_observed": "low",
    "staging_dev_exposed": "medium",
    "sensitive_service_exposed": "medium",
    # Public admin UI observed; without auth-bypass evidence stay at medium.
    "exposed_admin_interface": "medium",
}

BUSINESS_IMPACT_BY_CANDIDATE_TYPE: dict[str, str] = {
    "exposed_admin_interface": (
        "An administrative interface is publicly reachable, increasing the chance "
        "of unauthorized management access if credentials or flaws exist."
    ),
    "staging_dev_exposed": (
        "An externally reachable staging or development environment increases "
        "exposed attack surface outside typical production controls."
    ),
    "sensitive_service_exposed": (
        "A potentially sensitive infrastructure service is reachable from the "
        "public internet based on hostname and reachability evidence."
    ),
    "auth_surface_observed": (
        "A publicly reachable authentication-related surface expands the "
        "externally visible login attack surface."
    ),
    "security_header_observation": (
        "A captured HTTPS HTML response did not include Strict-Transport-Security, "
        "which can reduce browser-side transport protections. This is a "
        "configuration observation, not proof of an exploitable vulnerability."
    ),
}

REMEDIATION_GUIDANCE_BY_CANDIDATE_TYPE: dict[str, str] = {
    "exposed_admin_interface": (
        "Restrict administrative interfaces to trusted networks or VPN access, "
        "require strong authentication, and remove unnecessary public exposure."
    ),
    "staging_dev_exposed": (
        "Separate staging and development services from production-facing "
        "infrastructure, and remove or tightly control public internet exposure."
    ),
    "sensitive_service_exposed": (
        "Remove unnecessary public exposure of infrastructure services and "
        "restrict access to trusted networks with appropriate authentication."
    ),
    "auth_surface_observed": (
        "Confirm the authentication surface is intentional, apply rate limiting "
        "and MFA where appropriate, and avoid exposing unused login endpoints."
    ),
    "security_header_observation": (
        "If the service is served over HTTPS, add Strict-Transport-Security with "
        "an appropriate max-age. Treat this as a configuration improvement, not "
        "as evidence of compromise."
    ),
}


def severity_for_candidate_type(candidate_type: str) -> str | None:
    return SEVERITY_BY_CANDIDATE_TYPE.get(candidate_type)


def business_impact_for_candidate_type(candidate_type: str) -> str:
    return BUSINESS_IMPACT_BY_CANDIDATE_TYPE.get(
        candidate_type,
        "Publicly observable security-relevant exposure was confirmed by evidence.",
    )


def remediation_guidance_for_candidate_type(candidate_type: str) -> str:
    return REMEDIATION_GUIDANCE_BY_CANDIDATE_TYPE.get(
        candidate_type,
        "Review public exposure, restrict access to trusted networks where "
        "appropriate, and remove unnecessary internet-facing surfaces.",
    )

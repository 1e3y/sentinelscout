"""Versioned Scout capability manifest. Historical copies are persisted per operation."""

from __future__ import annotations

from typing import Any

MANIFEST_VERSION = 1
TESTING_PROFILE_SAFE_PRODUCTION = "safe_production"

SUPPORTED_CLASSES: tuple[dict[str, str], ...] = (
    {
        "id": "hostname_discovery",
        "title": "In-scope hostname discovery",
        "applies_to": "Authorized hostnames within the operation control snapshot",
        "evidence_required": "Hostname observed by discovery tooling or the seeded host list",
    },
    {
        "id": "unauthenticated_http_get_head",
        "title": "Unauthenticated HTTP GET/HEAD observations",
        "applies_to": "In-scope hostnames submitted to the HTTP observation stage",
        "evidence_required": "Usable HTTP response observation from GET or HEAD",
    },
    {
        "id": "exposed_admin_interface",
        "title": "Exposed admin-interface observations",
        "applies_to": "Reachable HTTP services with administrative naming or title evidence",
        "evidence_required": "Deterministic admin-surface candidate from observable facts",
    },
    {
        "id": "staging_dev_exposed",
        "title": "Staging/dev exposure observations",
        "applies_to": "Reachable HTTP services with staging or development naming evidence",
        "evidence_required": "Deterministic staging/dev candidate from observable facts",
    },
    {
        "id": "sensitive_service_exposed",
        "title": "Sensitive-service observations",
        "applies_to": "Reachable HTTP services with infrastructure or named-product evidence",
        "evidence_required": "Deterministic sensitive-service candidate from observable facts",
    },
    {
        "id": "auth_surface_observed",
        "title": "Authentication-surface observations",
        "applies_to": "Reachable HTTP services with authentication title or path evidence",
        "evidence_required": "Deterministic auth-surface candidate from observable facts",
    },
    {
        "id": "security_header_observation",
        "title": "Selected passive HTTP configuration observations",
        "applies_to": (
            "Captured, non-redirected HTTPS HTML 2xx responses missing Strict-Transport-Security"
        ),
        "evidence_required": "headers_observed=true and conservative missing-HSTS facts",
    },
    {
        "id": "safe_validation",
        "title": "Safe re-observation validation",
        "applies_to": "Emitted candidates of the supported observation classes",
        "evidence_required": "Allowlisted GET/HEAD confirmation of the same observable facts",
    },
    {
        "id": "finding_retest",
        "title": "Finding retest of the same observation class",
        "applies_to": "Findings marked ready for retest",
        "evidence_required": "Repeat of the original allowlisted validation method",
    },
    {
        "id": "scheduled_monitoring",
        "title": "Scheduled repeat of the same pipeline",
        "applies_to": "Authorized targets with monitoring enabled",
        "evidence_required": "A new operation using the same safe_production profile",
    },
)

UNSUPPORTED_CLASSES: tuple[dict[str, str], ...] = (
    {
        "id": "authenticated_testing",
        "title": "Authenticated / session testing",
        "explanation": "Scout does not authenticate or test inside an established session.",
    },
    {
        "id": "input_validation_classes",
        "title": "Input-validation / injection classes",
        "explanation": "Scout does not test input-validation or injection classes.",
    },
    {
        "id": "access_control",
        "title": "Access-control and object-level authorization",
        "explanation": "Scout does not test access-control or object-level authorization.",
    },
    {
        "id": "csrf_session",
        "title": "CSRF / session fixation",
        "explanation": "Scout does not test CSRF or session-fixation classes.",
    },
    {
        "id": "business_logic",
        "title": "Business logic",
        "explanation": "Scout does not test application business-logic classes.",
    },
    {
        "id": "tls_protocol_assessment",
        "title": "TLS protocol and certificate assessment",
        "explanation": "Scout records whether HTTPS was used; it does not assess TLS protocols or certificates.",
    },
    {
        "id": "cookie_and_csp_policy",
        "title": "Cookie flags and full CSP/Permissions-Policy evaluation",
        "explanation": "Scout does not evaluate cookie flags or full content-security policies.",
    },
    {
        "id": "response_body_secrets",
        "title": "Response-body secret scanning",
        "explanation": "Scout does not persist or scan response bodies for secrets.",
    },
    {
        "id": "non_http_services",
        "title": "Non-HTTP services beyond hostname discovery",
        "explanation": "Scout does not probe non-HTTP services beyond observing in-scope hostnames.",
    },
    {
        "id": "cloud_iam_infrastructure",
        "title": "Cloud/IAM/infrastructure misconfiguration",
        "explanation": "Scout does not assess cloud, IAM, or infrastructure configuration.",
    },
    {
        "id": "dependency_source_review",
        "title": "Dependency / source-code review",
        "explanation": "Scout does not review source code or software dependencies.",
    },
    {
        "id": "exploit_confirmation",
        "title": "Exploit confirmation or destructive checks",
        "explanation": "Scout does not confirm exploits or perform destructive checks.",
    },
)


def manifest_snapshot(*, version: int = MANIFEST_VERSION) -> dict[str, Any]:
    """Immutable copy persisted with an operation. Unknown versions still freeze v1 contents."""
    return {
        "version": int(version),
        "testing_profile": TESTING_PROFILE_SAFE_PRODUCTION,
        "supported": [dict(item) for item in SUPPORTED_CLASSES],
        "unsupported": [dict(item) for item in UNSUPPORTED_CLASSES],
    }

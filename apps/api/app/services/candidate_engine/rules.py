"""Deterministic candidate rules over observable discovery facts only."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.models.asset import Asset, DiscoveryObservation
from app.services.candidate_engine.matching import (
    exact_dns_label_hits,
    path_prefix_hits,
    role_or_env_hits,
    title_contains,
)
from app.services.candidate_engine.types import CandidateDraft

# Kept for validation_engine imports — emission uses the categorized tuples below.
ADMIN_HOST_MARKERS = (
    "admin",
    "administrator",
    "cpanel",
    "wp-admin",
    "phpmyadmin",
    "portainer",
    "jenkins",
    "grafana",
    "kibana",
    "prometheus",
)
ADMIN_TITLE_MARKERS = (
    "admin",
    "dashboard",
    "control panel",
    "login - jenkins",
    "grafana",
    "portainer",
)
STAGING_HOST_MARKERS = (
    "staging",
    "stage",
    "stg",
    "dev",
    "develop",
    "development",
    "test",
    "qa",
    "uat",
    "sandbox",
    "preview",
)
SENSITIVE_HOST_MARKERS = (
    "vpn",
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "jenkins",
    "ci",
    "cd",
    "registry",
    "docker",
    "db",
    "database",
    "mongo",
    "redis",
    "elastic",
    "solr",
    "smtp",
    "mail",
    "webmail",
    "sso",
    "idp",
    "auth",
    "okta",
    "keycloak",
)
AUTH_TITLE_MARKERS = (
    "sign in",
    "sign-in",
    "log in",
    "login",
    "authenticate",
    "sso",
    "single sign",
)
AUTH_PATH_MARKERS = ("/login", "/signin", "/sign-in", "/auth", "/sso", "/oauth")

# Emission categories. Hyphen-token semantics are not shared across classes.
ADMIN_ROLE_MARKERS = ("admin",)
ADMIN_EXACT_LABEL_MARKERS = ("administrator",)
ADMIN_PRODUCT_MARKERS = (
    "jenkins",
    "grafana",
    "kibana",
    "prometheus",
    "portainer",
    "phpmyadmin",
    "cpanel",
    "wp-admin",
)
ADMIN_PRODUCT_TITLES = (
    "login - jenkins",
    "grafana",
    "portainer",
    "phpmyadmin",
    "cpanel",
    "kibana",
    "prometheus",
)
ADMIN_WEAK_TITLES = ("dashboard", "control panel")
ADMIN_PATHS = (
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/grafana",
    "/jenkins",
    "/kibana",
    "/prometheus",
    "/portainer",
)

STAGING_ENV_MARKERS = STAGING_HOST_MARKERS

SENSITIVE_ROLE_MARKERS = ("vpn", "smtp", "webmail", "database", "registry")
SENSITIVE_PRODUCT_MARKERS = (
    "jenkins",
    "gitlab",
    "github",
    "bitbucket",
    "docker",
    "mongo",
    "redis",
    "elastic",
    "solr",
)
SENSITIVE_SHORT_MARKERS = ("ci", "cd", "db", "git", "mail")
SENSITIVE_PRODUCT_TITLES = (
    "login - jenkins",
    "gitlab",
    "github",
    "bitbucket",
    "portainer",
)
SENSITIVE_PATHS = (
    "/jenkins",
    "/gitlab",
    "/github",
    "/bitbucket",
    "/docker",
)


@dataclass(frozen=True)
class AssetContext:
    asset: Asset
    observations: tuple[DiscoveryObservation, ...]

    @property
    def hostname(self) -> str:
        return (self.asset.hostname or "").lower()

    @property
    def url(self) -> str:
        return (self.asset.url or "").lower()

    @property
    def title(self) -> str:
        return (self.asset.title or "").lower()


def _obs_ids(ctx: AssetContext, *types: str) -> tuple[str, ...]:
    wanted = set(types)
    return tuple(
        str(obs.id)
        for obs in ctx.observations
        if not wanted or obs.observation_type in wanted
    )


def _has_reachable(ctx: AssetContext) -> bool:
    return any(
        obs.observation_type in {"service_reachable", "http_response_observed"}
        for obs in ctx.observations
    )


def rule_exposed_admin_interface(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None

    strong: list[str] = []
    supporting: list[str] = []
    weak: list[str] = []

    for hit in role_or_env_hits(ctx.hostname, ADMIN_ROLE_MARKERS):
        strong.append(f"strong: {hit.describe()}")
    for hit in exact_dns_label_hits(ctx.hostname, ADMIN_EXACT_LABEL_MARKERS):
        strong.append(f"strong: {hit.describe()}")
    for hit in exact_dns_label_hits(ctx.hostname, ADMIN_PRODUCT_MARKERS):
        strong.append(f"strong: {hit.describe()}")

    product_hyphen = [
        hit
        for hit in role_or_env_hits(ctx.hostname, ADMIN_PRODUCT_MARKERS)
        if hit.kind == "hyphen_token"
    ]
    for hit in product_hyphen:
        supporting.append(f"supporting: {hit.describe()} (named product, not sufficient alone)")

    product_titles = title_contains(ctx.title, ADMIN_PRODUCT_TITLES)
    for marker in product_titles:
        strong.append(f"strong: page title contains '{marker}'")

    weak_titles = title_contains(ctx.title, ADMIN_WEAK_TITLES)
    if "admin" in ctx.title and "admin" not in product_titles:
        weak_titles = tuple(dict.fromkeys([*weak_titles, "admin"]))
    for marker in weak_titles:
        weak.append(f"weak: page title contains '{marker}'")

    paths = path_prefix_hits(ctx.url, ADMIN_PATHS)
    for prefix in paths:
        strong.append(f"strong: URL path starts with '{prefix}'")

    emit = bool(strong) or (bool(product_hyphen) and (bool(product_titles) or bool(paths)))
    if not emit:
        return None

    signals = tuple(dict.fromkeys([*strong, *supporting, *weak]))
    reasons = (
        "Asset responded publicly over HTTP(S).",
        *tuple(item.split(": ", 1)[1] if ": " in item else item for item in strong[:8]),
    )
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="exposed_admin_interface",
        title="Potentially exposed administrative interface",
        summary=(
            "A publicly reachable HTTP service matches administrative hostname, "
            "path, or product-UI title evidence. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=reasons,
        signals=signals,
    )


def rule_staging_dev_exposed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None
    hits = role_or_env_hits(ctx.hostname, STAGING_ENV_MARKERS)
    if not hits:
        return None
    signals = tuple(f"strong: {hit.describe()}" for hit in hits)
    reasons = (
        "Asset responded publicly over HTTP(S).",
        *(hit.describe() for hit in hits[:8]),
    )
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="staging_dev_exposed",
        title="Publicly reachable staging/development asset",
        summary=(
            "Asset responded publicly and a DNS label or hyphen/underscore token "
            "matches a non-production environment marker. Candidate — not validated."
        ),
        observation_ids=_obs_ids(
            ctx, "service_reachable", "http_response_observed", "subdomain_discovered"
        ),
        reasons=reasons,
        signals=signals,
    )


def rule_sensitive_service_exposed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None

    strong: list[str] = []
    supporting: list[str] = []

    for hit in role_or_env_hits(ctx.hostname, SENSITIVE_ROLE_MARKERS):
        strong.append(f"strong: {hit.describe()}")
    for hit in exact_dns_label_hits(ctx.hostname, SENSITIVE_PRODUCT_MARKERS):
        strong.append(f"strong: {hit.describe()}")
    for hit in exact_dns_label_hits(ctx.hostname, SENSITIVE_SHORT_MARKERS):
        strong.append(f"strong: {hit.describe()}")

    product_hyphen = [
        hit
        for hit in role_or_env_hits(ctx.hostname, SENSITIVE_PRODUCT_MARKERS)
        if hit.kind == "hyphen_token"
    ]
    for hit in product_hyphen:
        supporting.append(f"supporting: {hit.describe()} (named product, not sufficient alone)")

    product_titles = title_contains(ctx.title, SENSITIVE_PRODUCT_TITLES)
    for marker in product_titles:
        strong.append(f"strong: page title contains '{marker}'")
    paths = path_prefix_hits(ctx.url, SENSITIVE_PATHS)
    for prefix in paths:
        strong.append(f"strong: URL path starts with '{prefix}'")

    emit = bool(strong) or (bool(product_hyphen) and (bool(product_titles) or bool(paths)))
    if not emit:
        return None

    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="sensitive_service_exposed",
        title="Potentially sensitive service reachable externally",
        summary=(
            "A publicly reachable hostname matches an infrastructure or named "
            "service marker at DNS-label strength, or a named product plus "
            "title/path corroboration. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            *tuple(item.split(": ", 1)[1] if ": " in item else item for item in strong[:8]),
        ),
        signals=tuple(dict.fromkeys([*strong, *supporting])),
    )


def rule_auth_surface_observed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None
    titles = title_contains(ctx.title, AUTH_TITLE_MARKERS)
    paths = path_prefix_hits(ctx.url, AUTH_PATH_MARKERS)
    if not titles and not paths:
        return None
    strong: list[str] = []
    supporting: list[str] = []
    for marker in titles:
        strong.append(f"strong: page title contains '{marker}'")
    for prefix in paths:
        strong.append(f"strong: URL path starts with '{prefix}'")
    host_hits = exact_dns_label_hits(ctx.hostname, ("auth", "sso", "login"))
    for hit in host_hits:
        supporting.append(f"supporting: {hit.describe()} (not sufficient without title or path)")
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="auth_surface_observed",
        title="Unusual or notable authentication surface",
        summary=(
            "Public HTTP response title or path indicates an authentication or "
            "SSO-related surface. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            *tuple(item.split(": ", 1)[1] if ": " in item else item for item in strong[:8]),
        ),
        signals=tuple(dict.fromkeys([*strong, *supporting])),
    )


def rule_security_header_observation(ctx: AssetContext) -> CandidateDraft | None:
    """Reserved for future header-based facts. Inactive until observations include headers."""
    for obs in ctx.observations:
        meta = obs.observation_metadata or {}
        headers = meta.get("security_headers_missing")
        if isinstance(headers, list) and headers:
            return CandidateDraft(
                asset_id=ctx.asset.id,
                candidate_type="security_header_observation",
                title="Security-relevant HTTP configuration observation",
                summary=(
                    "HTTP response metadata indicated missing common security headers. "
                    "Candidate — not validated."
                ),
                observation_ids=(str(obs.id),),
                reasons=(
                    "Observable HTTP response metadata reported missing security headers.",
                ),
                signals=tuple(str(item) for item in headers[:10]),
            )
    return None


RuleFn = Callable[[AssetContext], CandidateDraft | None]

RULES: Sequence[RuleFn] = (
    rule_exposed_admin_interface,
    rule_staging_dev_exposed,
    rule_sensitive_service_exposed,
    rule_auth_surface_observed,
    rule_security_header_observation,
)


def evaluate_asset(ctx: AssetContext) -> list[CandidateDraft]:
    drafts: list[CandidateDraft] = []
    for rule in RULES:
        draft = rule(ctx)
        if draft is not None:
            if draft.status not in {"candidate", "dismissed", "needs_review", "supported"}:
                continue
            drafts.append(draft)
    return drafts

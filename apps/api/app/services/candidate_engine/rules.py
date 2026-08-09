"""Deterministic candidate rules over observable discovery facts only."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.models.asset import Asset, DiscoveryObservation
from app.services.candidate_engine.types import CandidateDraft

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

    @property
    def labels(self) -> list[str]:
        return [part for part in self.hostname.split(".") if part]


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
    signals: list[str] = []
    for marker in ADMIN_HOST_MARKERS:
        if marker in ctx.hostname or marker in ctx.url:
            signals.append(f"hostname/url contains '{marker}'")
    for marker in ADMIN_TITLE_MARKERS:
        if marker in ctx.title:
            signals.append(f"page title contains '{marker}'")
    if not signals:
        return None
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="exposed_admin_interface",
        title="Potentially exposed administrative interface",
        summary=(
            "A publicly reachable HTTP service appears related to an administrative "
            "or management interface based on hostname/title signals. "
            "This is a candidate for review, not a validated vulnerability."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            "Observable naming/title signals suggest an administrative surface.",
        ),
        signals=tuple(signals),
    )


def rule_staging_dev_exposed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None
    signals: list[str] = []
    for label in ctx.labels:
        if label in STAGING_HOST_MARKERS:
            signals.append(f"hostname label '{label}' suggests non-production")
    if not signals:
        # Also check compound labels like "staging-api"
        for marker in STAGING_HOST_MARKERS:
            if re.search(rf"(^|[-_.]){re.escape(marker)}([-_.]|$)", ctx.hostname):
                signals.append(f"hostname contains non-production marker '{marker}'")
                break
    if not signals:
        return None
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="staging_dev_exposed",
        title="Publicly reachable staging/development asset",
        summary=(
            "Asset responded publicly and appears to represent a non-production "
            "environment based on hostname naming. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed", "subdomain_discovered"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            "Hostname naming suggests staging/development/test usage.",
        ),
        signals=tuple(dict.fromkeys(signals)),
    )


def rule_sensitive_service_exposed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None
    # Avoid double-counting pure admin cases already covered more specifically.
    signals: list[str] = []
    for marker in SENSITIVE_HOST_MARKERS:
        if marker in ctx.labels or re.search(
            rf"(^|[-_.]){re.escape(marker)}([-_.]|$)", ctx.hostname
        ):
            signals.append(f"hostname suggests sensitive service '{marker}'")
    if not signals:
        return None
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="sensitive_service_exposed",
        title="Potentially sensitive service reachable externally",
        summary=(
            "A publicly reachable service hostname suggests infrastructure that is "
            "often sensitive when exposed to the internet. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            "Hostname signals a potentially sensitive service class.",
        ),
        signals=tuple(dict.fromkeys(signals)),
    )


def rule_auth_surface_observed(ctx: AssetContext) -> CandidateDraft | None:
    if not _has_reachable(ctx):
        return None
    signals: list[str] = []
    for marker in AUTH_TITLE_MARKERS:
        if marker in ctx.title:
            signals.append(f"page title contains '{marker}'")
    for marker in AUTH_PATH_MARKERS:
        if marker in ctx.url:
            signals.append(f"URL path contains '{marker}'")
    if "auth" in ctx.labels or "sso" in ctx.labels or "login" in ctx.labels:
        signals.append("hostname label suggests authentication surface")
    if not signals:
        return None
    return CandidateDraft(
        asset_id=ctx.asset.id,
        candidate_type="auth_surface_observed",
        title="Unusual or notable authentication surface",
        summary=(
            "Public HTTP response metadata suggests an authentication or SSO-related "
            "surface. Candidate — not validated."
        ),
        observation_ids=_obs_ids(ctx, "service_reachable", "http_response_observed"),
        reasons=(
            "Asset responded publicly over HTTP(S).",
            "Title/URL/hostname signals suggest an authentication surface.",
        ),
        signals=tuple(dict.fromkeys(signals)),
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
            # Enforce allowed statuses only (rules should emit candidate/needs_review).
            if draft.status not in {"candidate", "dismissed", "needs_review", "supported"}:
                continue
            drafts.append(draft)
    return drafts

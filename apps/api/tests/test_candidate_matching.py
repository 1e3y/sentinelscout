from __future__ import annotations

from uuid import uuid4

from app.models.asset import Asset, DiscoveryObservation
from app.services.candidate_engine.matching import (
    exact_dns_label_hits,
    path_prefix_hits,
    role_or_env_hits,
)
from app.services.candidate_engine.rules import (
    ADMIN_HOST_MARKERS,
    ADMIN_TITLE_MARKERS,
    AUTH_PATH_MARKERS,
    AUTH_TITLE_MARKERS,
    SENSITIVE_HOST_MARKERS,
    STAGING_HOST_MARKERS,
    AssetContext,
    evaluate_asset,
)


def _asset(hostname: str, *, url: str | None = None, title: str | None = None) -> Asset:
    return Asset(
        id=uuid4(),
        organization_id=uuid4(),
        target_id=uuid4(),
        hostname=hostname,
        url=url or f"https://{hostname}/",
        title=title,
        asset_type="http_service",
        status_code=200,
        source="test",
    )


def _reachable(asset: Asset) -> tuple[DiscoveryObservation, ...]:
    return (
        DiscoveryObservation(
            id=uuid4(),
            organization_id=asset.organization_id,
            operation_id=uuid4(),
            asset_id=asset.id,
            observation_type="service_reachable",
            summary="reachable",
            observation_metadata={},
            source="test",
        ),
        DiscoveryObservation(
            id=uuid4(),
            organization_id=asset.organization_id,
            operation_id=uuid4(),
            asset_id=asset.id,
            observation_type="http_response_observed",
            summary="http",
            observation_metadata={},
            source="test",
        ),
    )


def _types(hostname: str, *, url: str | None = None, title: str | None = None) -> set[str]:
    asset = _asset(hostname, url=url, title=title)
    drafts = evaluate_asset(AssetContext(asset=asset, observations=_reachable(asset)))
    return {draft.candidate_type for draft in drafts}


def test_role_env_matches_label_and_hyphen_token_not_substring():
    admin_label = role_or_env_hits("admin.example.com", ("admin",))
    assert any(hit.kind == "dns_label" and hit.marker == "admin" for hit in admin_label)
    admin_hyphen = role_or_env_hits("admin-api.example.com", ("admin",))
    assert any(hit.kind == "hyphen_token" and hit.marker == "admin" for hit in admin_hyphen)
    assert role_or_env_hits("administrator-training.example.com", ("admin",)) == ()
    assert role_or_env_hits("devshop.example.com", ("dev",)) == ()
    assert role_or_env_hits("staging-api.example.com", ("staging",))


def test_product_and_short_markers_are_exact_dns_labels():
    assert exact_dns_label_hits("grafana.example.com", ("grafana", "jenkins"))
    assert exact_dns_label_hits("grafana-training.example.com", ("grafana",)) == ()
    assert exact_dns_label_hits("jenkins-docs.example.com", ("jenkins",)) == ()
    assert exact_dns_label_hits("ci.example.com", ("ci", "cd", "db"))
    assert exact_dns_label_hits("ci-runner.example.com", ("ci",)) == ()


def test_path_prefix_does_not_match_hostname_in_url():
    assert path_prefix_hits("https://auth.example.com/", ("/auth", "/login")) == ()
    assert path_prefix_hits("https://login.example.com/login", ("/login",)) == ("/login",)


def test_admin_role_and_exact_administrator_label():
    assert "exposed_admin_interface" in _types("admin.example.com", title="Home")
    assert "exposed_admin_interface" in _types("admin-api.example.com", title="Home")
    assert "exposed_admin_interface" in _types("administrator.example.com", title="Home")
    assert "exposed_admin_interface" not in _types(
        "administrator-training.example.com", title="Training"
    )
    assert "exposed_admin_interface" not in _types("administer.example.com", title="About")


def test_generic_dashboard_title_is_not_enough():
    assert "exposed_admin_interface" not in _types("www.example.com", title="Dashboard")


def test_named_product_hyphen_tokens_need_corroboration():
    assert "exposed_admin_interface" in _types("grafana.example.com", title="Welcome")
    assert "exposed_admin_interface" in _types("jenkins.example.com", title="Welcome")
    assert "exposed_admin_interface" not in _types(
        "grafana-training.example.com", title="Training catalog"
    )
    assert "exposed_admin_interface" not in _types(
        "grafana-docs.example.com", title="Documentation"
    )
    assert "exposed_admin_interface" not in _types(
        "jenkins-docs.example.com", title="Documentation"
    )
    assert "exposed_admin_interface" not in _types(
        "jenkins-training.example.com", title="Training catalog"
    )
    assert "sensitive_service_exposed" in _types("jenkins.example.com", title="Welcome")
    assert "sensitive_service_exposed" not in _types(
        "jenkins-docs.example.com", title="Documentation"
    )
    assert "sensitive_service_exposed" not in _types(
        "jenkins-training.example.com", title="Training catalog"
    )


def test_product_hyphen_plus_path_is_enough():
    assert "exposed_admin_interface" in _types(
        "jenkins-west.example.com",
        url="https://jenkins-west.example.com/jenkins",
        title="Home",
    )


def test_staging_token_aware():
    assert "staging_dev_exposed" in _types("staging.example.com")
    assert "staging_dev_exposed" in _types("staging-api.example.com")
    assert "staging_dev_exposed" not in _types("devshop.example.com")
    assert "staging_dev_exposed" not in _types("testimonial.example.com")


def test_auth_requires_title_or_path_not_hostname_alone():
    assert "auth_surface_observed" not in _types(
        "auth.example.com", title="API documentation"
    )
    assert "auth_surface_observed" not in _types(
        "auth-docs.example.com", title="API documentation"
    )
    assert "sensitive_service_exposed" not in _types(
        "auth.example.com", title="API documentation"
    )
    assert "auth_surface_observed" in _types(
        "login.example.com",
        url="https://login.example.com/login",
        title="Sign in",
    )


def test_short_infra_is_exact_label_only():
    assert "sensitive_service_exposed" in _types("vpn.example.com")
    assert "sensitive_service_exposed" in _types("git.example.com")
    assert "sensitive_service_exposed" in _types("ci.example.com")
    assert "sensitive_service_exposed" not in _types("ci-runner.example.com")
    assert "sensitive_service_exposed" not in _types("git-docs.example.com")


def test_product_title_corroboration_is_not_a_training_docs_denylist():
    """Hyphenated product hosts still emit when a product UI title is observed."""
    assert "exposed_admin_interface" in _types(
        "grafana-training.example.com", title="Grafana"
    )
    assert "exposed_admin_interface" in _types(
        "jenkins-docs.example.com", title="Login - Jenkins"
    )


def test_admin_title_substring_alone_is_weak():
    assert "exposed_admin_interface" not in _types(
        "www.example.com", title="Administrator Training"
    )


def test_emitted_signals_are_strength_prefixed():
    asset = _asset("admin-api.example.com", title="Home")
    drafts = evaluate_asset(AssetContext(asset=asset, observations=_reachable(asset)))
    admin = next(d for d in drafts if d.candidate_type == "exposed_admin_interface")
    assert admin.signals
    assert all(s.startswith(("strong:", "supporting:", "weak:")) for s in admin.signals)
    assert any(s.startswith("strong:") for s in admin.signals)


def test_validation_import_tuples_keep_original_identity_markers():
    """Emission narrowed; validation still imports the original marker tuples."""
    assert "admin" in ADMIN_HOST_MARKERS
    assert "administrator" in ADMIN_HOST_MARKERS
    assert "grafana" in ADMIN_HOST_MARKERS
    assert "dashboard" in ADMIN_TITLE_MARKERS
    assert "test" in STAGING_HOST_MARKERS
    assert "auth" in SENSITIVE_HOST_MARKERS
    assert "sso" in SENSITIVE_HOST_MARKERS
    assert "okta" in SENSITIVE_HOST_MARKERS
    assert "login" in AUTH_TITLE_MARKERS
    assert "/auth" in AUTH_PATH_MARKERS

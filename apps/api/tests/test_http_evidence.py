from __future__ import annotations

from uuid import uuid4

from app.models.asset import Asset, DiscoveryObservation
from app.services.candidate_engine.rules import AssetContext, evaluate_asset
from app.services.http_evidence import (
    HSTS_HEADER,
    http_json_headers_observed,
    observation_metadata,
    sanitize_http_evidence,
    sanitize_url,
)


def test_sanitize_drops_cookies_and_auth_and_strips_location_query():
    evidence = sanitize_http_evidence(
        headers_observed=True,
        raw_headers={
            "Set-Cookie": "session=abc",
            "Cookie": "session=abc",
            "Authorization": "Bearer secret-token",
            "X-Api-Key": "k",
            "Strict-Transport-Security": "max-age=1",
            "Server": "nginx/1.27",
            "X-Powered-By": "PHP",
            "Location": "https://login.example/callback?code=oauth&state=1",
            "Content-Type": "text/html; charset=utf-8",
        },
        requested_url="https://www.example.com/",
        final_url="https://www.example.com/",
        redirected=False,
    )
    assert evidence.headers_observed is True
    assert "set-cookie" not in evidence.headers
    assert "cookie" not in evidence.headers
    assert "authorization" not in evidence.headers
    assert "server" not in evidence.headers
    assert "x-powered-by" not in evidence.headers
    assert evidence.headers[HSTS_HEADER] == "max-age=1"
    assert evidence.location_url == "https://login.example/callback"
    assert "code=" not in (evidence.location_url or "")
    assert evidence.content_type == "text/html"


def test_empty_header_map_does_not_imply_observed():
    missing_tool = sanitize_http_evidence(
        headers_observed=False,
        raw_headers={},
        requested_url="https://www.example.com/",
        final_url="https://www.example.com/",
    )
    captured_empty = sanitize_http_evidence(
        headers_observed=True,
        raw_headers={"set-cookie": "x=1"},
        requested_url="https://www.example.com/",
        final_url="https://www.example.com/",
    )
    assert missing_tool.headers_observed is False
    assert missing_tool.headers == {}
    assert captured_empty.headers_observed is True
    assert captured_empty.headers == {}
    meta_missing = observation_metadata(
        missing_tool, hostname="www.example.com", status_code=200, title="Welcome", url="https://www.example.com/"
    )
    meta_empty = observation_metadata(
        captured_empty, hostname="www.example.com", status_code=200, title="Welcome", url="https://www.example.com/"
    )
    assert meta_missing["headers_observed"] is False
    assert meta_empty["headers_observed"] is True


def test_httpx_json_requires_explicit_header_object():
    assert http_json_headers_observed({"url": "https://x", "status_code": 200}) == (False, None)
    observed, raw = http_json_headers_observed({"header": {}})
    assert observed is True
    assert raw == {}
    observed, raw = http_json_headers_observed({"headers": {"content-type": "text/html"}})
    assert observed is True
    assert raw["content-type"] == "text/html"


def test_sanitize_url_drops_userinfo_and_query():
    assert sanitize_url("https://user:pass@www.example.com/path?token=1#frag") == (
        "https://www.example.com/path"
    )


def _asset(hostname: str, url: str) -> Asset:
    return Asset(
        id=uuid4(),
        organization_id=uuid4(),
        target_id=uuid4(),
        hostname=hostname,
        url=url,
        title="Welcome",
        asset_type="http_service",
        status_code=200,
        source="test",
    )


def _reachable_with_meta(asset: Asset, meta: dict) -> tuple[DiscoveryObservation, ...]:
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
            observation_metadata=meta,
            source="test",
        ),
    )


def _types_for(meta: dict, hostname: str = "www.example.com") -> set[str]:
    url = f"https://{hostname}/"
    asset = _asset(hostname, url)
    drafts = evaluate_asset(AssetContext(asset=asset, observations=_reachable_with_meta(asset, meta)))
    return {d.candidate_type for d in drafts}


def _html_meta(**overrides) -> dict:
    base = {
        "hostname": "www.example.com",
        "url": "https://www.example.com/",
        "status_code": 200,
        "title": "Welcome",
        "headers_observed": True,
        "scheme": "https",
        "content_type": "text/html",
        "requested_url": "https://www.example.com/",
        "final_url": "https://www.example.com/",
        "redirected": False,
        "headers": {"content-type": "text/html; charset=utf-8"},
        "headers_present": ["content-type"],
    }
    base.update(overrides)
    return base


def test_hsts_missing_on_https_html_emits():
    assert "security_header_observation" in _types_for(_html_meta())


def test_hsts_present_does_not_emit():
    assert "security_header_observation" not in _types_for(
        _html_meta(
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
            },
            headers_present=["content-type", "strict-transport-security"],
        )
    )


def test_headers_unavailable_does_not_emit():
    assert "security_header_observation" not in _types_for(
        _html_meta(headers_observed=False, headers={}, headers_present=[])
    )
    assert "security_header_observation" not in _types_for(
        _html_meta(headers_observed=False, headers={"content-type": "text/html"})
    )


def test_redirected_final_headers_do_not_emit():
    assert "security_header_observation" not in _types_for(
        _html_meta(
            redirected=True,
            requested_url="https://www.example.com/",
            final_url="https://www.example.com/home",
        )
    )


def test_json_and_http_scheme_do_not_emit():
    assert "security_header_observation" not in _types_for(
        _html_meta(content_type="application/json", headers={"content-type": "application/json"})
    )
    assert "security_header_observation" not in _types_for(_html_meta(scheme="http"))


def test_csp_missing_alone_does_not_emit_when_hsts_present():
    assert "security_header_observation" not in _types_for(
        _html_meta(
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=1",
            },
            headers_present=["content-type", "strict-transport-security"],
        )
    )

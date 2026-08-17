from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.asset import Asset, DiscoveryObservation
from app.models.target import AuthorizedTarget
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.discovery.scope import filter_hosts_for_scope, host_in_scope
from app.services.operations import stop_operation
from app.services.worker_runtime import (
    SAFE_AUTHZ_FAILURE_CODE,
    claim_next_operation,
    execute_discovery_job,
    process_one_operation,
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()[
        "verified"
    ]
    return target_id


def _enable_subdomains(client, token: str, target_id: str, exclusions: list[str] | None = None):
    response = client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": exclusions or []},
    )
    assert response.status_code == 200, response.text


def _queue_operation(client, token: str, target_id: str) -> str:
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201
    return created.json()["id"]


def _tools_for(domain: str) -> FakeDiscoveryTools:
    return FakeDiscoveryTools(
        hosts_by_domain={
            domain: [
                domain,
                f"www.{domain}",
                f"dev.{domain}",
                f"evil.other.example",
            ]
        },
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}", status_code=200, title="WWW"
            ),
            f"dev.{domain}": ProbeResult(
                url=f"https://dev.{domain}", status_code=200, title="Dev"
            ),
        },
    )


def test_host_in_scope_and_exclusions():
    assert host_in_scope("www.example.com", "example.com", include_subdomains=True)
    assert not host_in_scope("www.example.com", "example.com", include_subdomains=False)
    assert not host_in_scope(
        "dev.example.com",
        "example.com",
        include_subdomains=True,
        exclusions=["dev.example.com"],
    )
    allowed = filter_hosts_for_scope(
        ["example.com", "www.example.com", "dev.example.com", "evil.other.example"],
        "example.com",
        include_subdomains=True,
        exclusions=["dev.example.com"],
    )
    assert allowed == ["example.com", "www.example.com"]


def test_verified_target_discovery_persists_assets_and_observations(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "discover.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=_tools_for(domain))
    assert result is not None
    assert result.status == "completed"

    assets = client.get(f"/v1/operations/{operation_id}/assets", headers=_auth(token))
    assert assets.status_code == 200
    body = assets.json()
    hostnames = {item["hostname"] for item in body}
    assert "discover.example" in hostnames
    assert "www.discover.example" in hostnames
    assert "evil.other.example" not in hostnames

    observations = client.get(
        f"/v1/operations/{operation_id}/observations", headers=_auth(token)
    ).json()
    types = {item["observation_type"] for item in observations}
    assert "subdomain_discovered" in types
    assert "service_reachable" in types
    assert "http_response_observed" in types
    assert not any("vulnerab" in t for t in types)
    assert not any("finding" in t for t in types)

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    event_types = [e["event_type"] for e in events]
    assert event_types[0] == "operation.created"
    assert "operation.started" in event_types
    assert "discovery.started" in event_types
    assert "asset.discovered" in event_types
    assert "discovery.completed" in event_types
    assert event_types[-1] == "operation.completed"
    assert "operation.stage" not in event_types
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))

    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(Asset)) >= 1
    assert db_session.scalar(select(func.count()).select_from(DiscoveryObservation)) >= 1


def test_http_observation_persists_capture_state_and_strips_secrets(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "headers.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"www.{domain}", f"skip.{domain}"]},
        probes_by_host={
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}/",
                status_code=200,
                title="Welcome",
                headers_observed=True,
                headers={
                    "content-type": "text/html",
                    "set-cookie": "session=abc",
                    "authorization": "Bearer secret-token",
                    "server": "nginx",
                    "x-powered-by": "php",
                },
                content_type="text/html",
                requested_url=f"https://www.{domain}/",
                final_url=f"https://www.{domain}/",
                redirected=False,
                scheme="https",
            ),
            f"skip.{domain}": ProbeResult(
                url=f"https://skip.{domain}/",
                status_code=200,
                title="Welcome",
                headers_observed=False,
                headers={},
                content_type="text/html",
                requested_url=f"https://skip.{domain}/",
                final_url=f"https://skip.{domain}/",
                redirected=False,
                scheme="https",
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    observations = client.get(
        f"/v1/operations/{operation_id}/observations", headers=_auth(token)
    ).json()
    http_rows = [
        row
        for row in observations
        if row["observation_type"] == "http_response_observed"
    ]
    by_host = {row["metadata"]["hostname"]: row["metadata"] for row in http_rows}
    www_meta = by_host[f"www.{domain}"]
    skip_meta = by_host[f"skip.{domain}"]
    blob = str(www_meta).lower()
    assert www_meta["headers_observed"] is True
    assert skip_meta["headers_observed"] is False
    assert "set-cookie" not in blob
    assert "secret-token" not in blob
    assert "authorization" not in (www_meta.get("headers") or {})
    assert "server" not in (www_meta.get("headers") or {})
    assert "x-powered-by" not in (www_meta.get("headers") or {})
    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    pairs = {(c["asset_hostname"], c["candidate_type"]) for c in candidates}
    assert (f"www.{domain}", "security_header_observation") in pairs
    assert (f"skip.{domain}", "security_header_observation") not in pairs
    header = next(c for c in candidates if c["candidate_type"] == "security_header_observation")
    assert header["evidence"].get("observation_ids")


def test_exclusions_enforced_before_probing(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "exclude.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id, exclusions=[f"dev.{domain}"])
    operation_id = _queue_operation(client, token, target_id)

    probed: list[str] = []

    class TrackingTools(FakeDiscoveryTools):
        def probe_hosts(self, hosts: list[str]):
            probed.extend(hosts)
            return super().probe_hosts(hosts)

    tools = TrackingTools(
        hosts_by_domain={domain: [domain, f"www.{domain}", f"dev.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}", status_code=200, title="WWW"
            ),
            f"dev.{domain}": ProbeResult(
                url=f"https://dev.{domain}", status_code=200, title="Dev"
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    assert f"dev.{domain}" not in probed

    assets = client.get(f"/v1/operations/{operation_id}/assets", headers=_auth(token)).json()
    assert all(item["hostname"] != f"dev.{domain}" for item in assets)


def test_out_of_scope_assets_discarded():
    allowed = filter_hosts_for_scope(
        ["evil.other.com", "out.example.net"],
        "scope.example",
        include_subdomains=True,
        exclusions=[],
    )
    assert allowed == []
    allowed = filter_hosts_for_scope(
        ["scope.example", "a.scope.example", "b.other.com"],
        "scope.example",
        include_subdomains=True,
        exclusions=[],
    )
    assert allowed == ["scope.example", "a.scope.example"]


def test_duplicate_assets_upserted(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "dup.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="One")
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    op1 = _queue_operation(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    op2 = _queue_operation(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"

    db_session.expire_all()
    count = db_session.scalar(
        select(func.count())
        .select_from(Asset)
        .where(Asset.hostname == domain, Asset.url == f"https://{domain}")
    )
    assert count == 1

    # Both operations should still expose the asset via observations.
    assert client.get(f"/v1/operations/{op1}/assets", headers=_auth(token)).json()
    assert client.get(f"/v1/operations/{op2}/assets", headers=_auth(token)).json()


def test_unverified_and_revoked_rejected_at_worker_execution(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "authz.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    # Revoke after queueing.
    assert client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token)).status_code == 200

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=_tools_for(domain))
    assert result is not None
    assert result.status == "failed"
    assert result.error_code == SAFE_AUTHZ_FAILURE_CODE

    # Unverified path: force status back to unverified on a fresh op.
    target = db_session.get(AuthorizedTarget, UUID(target_id))
    assert target is not None
    target.status = "unverified"
    target.revoked_at = None
    db_session.commit()
    # Cannot create via API when unverified; claim an op created while verified then flip.
    # Create another verified then flip before worker:
    domain2 = "authz2.example"
    target2 = _create_verified_target(client, token, domain2, dns_resolver)
    op2 = _queue_operation(client, token, target2)
    t2 = db_session.get(AuthorizedTarget, UUID(target2))
    assert t2 is not None
    t2.status = "unverified"
    db_session.commit()
    result2 = process_one_operation(factory, tools=_tools_for(domain2))
    assert result2.status == "failed"
    assert result2.error_code == SAFE_AUTHZ_FAILURE_CODE
    assert str(result2.id) == op2


def test_scanner_timeout_fails_operation(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "timeout.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={},
        fail_discover_with="subfinder timed out",
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=tools)
    assert result.status == "failed"
    assert result.error_code == "discovery_timeout"
    assert "timed out" in (result.error_message or "").lower()
    assert "Traceback" not in (result.error_message or "")


def test_stop_request_respected_during_discovery(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "stopdisc.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    claim_db = factory()
    try:
        claimed = claim_next_operation(claim_db)
        assert claimed is not None
    finally:
        claim_db.close()

    me = client.get("/v1/me", headers=_auth(token)).json()
    stop_db = factory()
    try:
        stop_operation(stop_db, operation_id=UUID(operation_id), user_id=UUID(me["id"]))
    finally:
        stop_db.close()

    exec_db = factory()
    try:
        result = execute_discovery_job(exec_db, UUID(operation_id), _tools_for(domain))
    finally:
        exec_db.close()
    assert result.status == "stopped"


def test_cross_org_asset_and_observation_access_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    domain = "private-disc.example"
    target_id = _create_verified_target(client, token_a, domain, dns_resolver)
    _enable_subdomains(client, token_a, target_id)
    operation_id = _queue_operation(client, token_a, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=_tools_for(domain)).status == "completed"

    assert (
        client.get(f"/v1/operations/{operation_id}/assets", headers=_auth(token_b)).status_code
        == 404
    )
    assert (
        client.get(
            f"/v1/operations/{operation_id}/observations", headers=_auth(token_b)
        ).status_code
        == 404
    )

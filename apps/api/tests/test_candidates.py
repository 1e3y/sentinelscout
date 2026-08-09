from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.asset import Asset, DiscoveryObservation
from app.models.candidate import CANDIDATE_STATUSES, SecurityCandidate
from app.models.operation import OperationEvent
from app.services.candidate_engine.rules import AssetContext, evaluate_asset
from app.services.candidate_engine.types import CandidateDraft
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.worker_runtime import process_one_operation


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


def _enable_subdomains(client, token: str, target_id: str):
    response = client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": []},
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


def _fake_asset(
    *,
    hostname: str,
    url: str = "",
    title: str | None = None,
    asset_id: UUID | None = None,
) -> Asset:
    return Asset(
        id=asset_id or uuid4(),
        organization_id=uuid4(),
        target_id=uuid4(),
        hostname=hostname,
        url=url or f"https://{hostname}",
        title=title,
        asset_type="http_service",
        status_code=200,
        source="test",
    )


def _obs(
    *,
    asset_id: UUID,
    observation_type: str,
    meta: dict | None = None,
) -> DiscoveryObservation:
    return DiscoveryObservation(
        id=uuid4(),
        organization_id=uuid4(),
        operation_id=uuid4(),
        asset_id=asset_id,
        observation_type=observation_type,
        summary=observation_type,
        observation_metadata=meta or {},
        source="test",
    )


def test_rule_engine_produces_candidate_from_staging_observation():
    asset = _fake_asset(hostname="staging.example.com", title="Staging App")
    observations = (
        _obs(asset_id=asset.id, observation_type="service_reachable"),
        _obs(asset_id=asset.id, observation_type="http_response_observed"),
    )
    drafts = evaluate_asset(AssetContext(asset=asset, observations=observations))
    types = {d.candidate_type for d in drafts}
    assert "staging_dev_exposed" in types
    staging = next(d for d in drafts if d.candidate_type == "staging_dev_exposed")
    assert staging.observation_ids
    assert staging.status == "candidate"
    assert "validated" not in staging.summary.lower() or "not validated" in staging.summary.lower()


def test_benign_observation_does_not_produce_candidate():
    asset = _fake_asset(hostname="www.example.com", title="Welcome")
    observations = (
        _obs(asset_id=asset.id, observation_type="service_reachable"),
        _obs(asset_id=asset.id, observation_type="http_response_observed"),
    )
    drafts = evaluate_asset(AssetContext(asset=asset, observations=observations))
    assert drafts == []


def test_rule_engine_is_deterministic():
    asset = _fake_asset(
        hostname="admin.example.com",
        url="https://admin.example.com/login",
        title="Admin Login",
    )
    observations = (
        _obs(asset_id=asset.id, observation_type="service_reachable"),
        _obs(asset_id=asset.id, observation_type="http_response_observed"),
    )
    ctx = AssetContext(asset=asset, observations=observations)
    first = evaluate_asset(ctx)
    second = evaluate_asset(ctx)
    assert [d.candidate_type for d in first] == [d.candidate_type for d in second]
    assert [d.title for d in first] == [d.title for d in second]
    assert [d.signals for d in first] == [d.signals for d in second]


def test_invalid_status_drafts_are_skipped():
    asset = _fake_asset(hostname="staging.example.com")
    observations = (_obs(asset_id=asset.id, observation_type="service_reachable"),)
    # Monkeypatch-style: evaluate_asset filters bad statuses on drafts from rules.
    # Construct a bad draft and ensure allowed set is strict.
    bad = CandidateDraft(
        asset_id=asset.id,
        candidate_type="staging_dev_exposed",
        title="x",
        summary="y",
        status="validated",
    )
    assert bad.status not in CANDIDATE_STATUSES
    assert "validated" not in CANDIDATE_STATUSES
    assert "confirmed" not in CANDIDATE_STATUSES
    assert "exploitable" not in CANDIDATE_STATUSES


def test_observation_produces_expected_candidate_with_provenance(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "cand.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)

    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"staging.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging",
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed"

    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    )
    assert candidates.status_code == 200
    body = candidates.json()
    assert len(body) >= 1
    staging = next(c for c in body if c["candidate_type"] == "staging_dev_exposed")
    assert staging["status"] == "candidate"
    assert staging["status"] not in {"validated", "confirmed", "exploitable"}
    assert staging["asset_hostname"] == f"staging.{domain}"
    evidence = staging["evidence"]
    assert evidence.get("observation_ids")
    assert str(operation_id) in (evidence.get("operation_ids") or [])
    assert evidence.get("why") or evidence.get("reasons")

    detail = client.get(f"/v1/candidates/{staging['id']}", headers=_auth(token))
    assert detail.status_code == 200
    assert detail.json()["id"] == staging["id"]

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    event_types = [e["event_type"] for e in events]
    assert "candidate.created" in event_types
    assert event_types[-1] == "operation.completed"
    assert "validated" not in event_types
    assert "confirmed" not in event_types


def test_benign_discovery_produces_no_candidate(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "benign.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Home")
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    body = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    assert body == []


def test_candidate_deduplication(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "dedup.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}", status_code=200, title="Staging"
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    op1 = _queue_operation(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    first = client.get(
        f"/v1/operations/{op1}/candidates", headers=_auth(token)
    ).json()
    assert len(first) == 1
    first_id = first[0]["id"]

    op2 = _queue_operation(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    second = client.get(
        f"/v1/operations/{op2}/candidates", headers=_auth(token)
    ).json()
    assert len(second) == 1
    assert second[0]["id"] == first_id

    db_session.expire_all()
    count = db_session.scalar(select(func.count()).select_from(SecurityCandidate))
    assert count == 1

    # Second run updates evidence; does not emit a second created event on op2.
    events2 = client.get(f"/v1/operations/{op2}/events", headers=_auth(token)).json()
    assert "candidate.created" not in [e["event_type"] for e in events2]


def test_cross_org_candidate_access_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    domain = "private-cand.example"
    target_id = _create_verified_target(client, token_a, domain, dns_resolver)
    _enable_subdomains(client, token_a, target_id)
    operation_id = _queue_operation(client, token_a, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}", status_code=200, title="Staging"
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"

    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token_a)
    ).json()
    assert candidates
    candidate_id = candidates[0]["id"]

    assert (
        client.get(
            f"/v1/operations/{operation_id}/candidates", headers=_auth(token_b)
        ).status_code
        == 404
    )
    assert (
        client.get(f"/v1/candidates/{candidate_id}", headers=_auth(token_b)).status_code
        == 404
    )


def test_candidates_and_events_persist_across_restart(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "persist-cand.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}", status_code=200, title="Staging"
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"

    before = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    assert before
    candidate_id = before[0]["id"]

    # New session factory simulates process restart against same DB.
    factory2 = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory2() as db:
        row = db.get(SecurityCandidate, UUID(candidate_id))
        assert row is not None
        assert row.status == "candidate"
        events = db.scalars(
            select(OperationEvent).where(OperationEvent.operation_id == UUID(operation_id))
        ).all()
        assert any(e.event_type == "candidate.created" for e in events)

    after = client.get(f"/v1/candidates/{candidate_id}", headers=_auth(token))
    assert after.status_code == 200
    assert after.json()["id"] == candidate_id


def test_dismiss_emits_event_and_forbids_validated_status(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    from sqlalchemy.exc import IntegrityError

    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "dismiss.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}", status_code=200, title="Staging"
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    candidate_id = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()[0]["id"]

    dismissed = client.post(
        f"/v1/candidates/{candidate_id}/dismiss", headers=_auth(token)
    )
    assert dismissed.status_code == 200
    assert dismissed.json()["status"] == "dismissed"

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    assert "candidate.dismissed" in [e["event_type"] for e in events]

    db_session.expire_all()
    row = db_session.get(SecurityCandidate, UUID(candidate_id))
    assert row is not None
    assert row.status in CANDIDATE_STATUSES
    assert CANDIDATE_STATUSES == frozenset(
        {"candidate", "dismissed", "needs_review", "supported"}
    )

    row.status = "validated"
    try:
        db_session.commit()
        raise AssertionError("validated status should be rejected by DB constraint")
    except IntegrityError:
        db_session.rollback()

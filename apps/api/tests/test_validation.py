from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.candidate import CANDIDATE_STATUSES, SecurityCandidate
from app.models.operation import OperationEvent
from app.models.target import TargetScope
from app.models.validation import ValidationAttempt
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.validation_engine.http import FakeSafeHttpClient, UnsafeHttpMethodError
from app.services.validation_engine.types import SAFE_HTTP_METHODS, SafeHttpObservation
from app.services.validation_runtime import process_one_validation
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


def _discover_staging(
    client, token, dns_resolver, engine, domain: str
) -> tuple[str, str, str]:
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging App",
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    assert candidates
    return operation_id, candidates[0]["id"], target_id


def test_safe_http_methods_reject_state_changing():
    assert SAFE_HTTP_METHODS == frozenset({"GET", "HEAD"})
    client = FakeSafeHttpClient(
        default=SafeHttpObservation(
            url="https://example.test",
            status_code=200,
            title="ok",
            headers={},
            reachable=True,
        )
    )
    for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        try:
            client.fetch("https://example.test", method=method)
            raise AssertionError(f"{method} should be rejected")
        except UnsafeHttpMethodError:
            pass
    obs = client.fetch("https://example.test", method="GET")
    assert obs.reachable is True


def test_supported_validation_with_deterministic_evidence(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-support.example"
    operation_id, candidate_id, _ = _discover_staging(
        client, token, dns_resolver, engine, domain
    )

    queued = client.post(
        f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
    )
    assert queued.status_code == 202
    assert queued.json()["status"] == "pending"
    assert queued.json()["validation_method"] == "staging_indicator_confirmation"

    http = FakeSafeHttpClient(
        by_host={
            f"staging.{domain}": SafeHttpObservation(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging App",
                headers={"content-type": "text/html"},
                reachable=True,
            )
        }
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    attempt = process_one_validation(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "supported"
    assert attempt.evidence.get("method") == "staging_indicator_confirmation"
    assert attempt.evidence.get("reachable") is True
    assert attempt.evidence.get("observation_ids")
    assert attempt.completed_at is not None

    detail = client.get(f"/v1/candidates/{candidate_id}", headers=_auth(token)).json()
    assert detail["status"] == "supported"
    assert detail["status"] not in {"exploitable", "validated_exploit", "compromised"}

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    types = [e["event_type"] for e in events]
    assert "validation.started" in types
    assert "validation.supported" in types
    started_idx = types.index("validation.started")
    supported_idx = types.index("validation.supported")
    assert started_idx < supported_idx
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))

    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(ValidationAttempt)) == 1


def test_unsupported_validation(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-unsupport.example"
    _, candidate_id, _ = _discover_staging(client, token, dns_resolver, engine, domain)

    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    http = FakeSafeHttpClient(
        by_host={
            f"staging.{domain}": SafeHttpObservation(
                url=f"https://staging.{domain}",
                status_code=None,
                title="",
                headers={},
                reachable=False,
            )
        }
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    attempt = process_one_validation(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "unsupported"

    cand = client.get(f"/v1/candidates/{candidate_id}", headers=_auth(token)).json()
    assert cand["status"] == "needs_review"


def test_inconclusive_unknown_candidate_type_does_not_probe(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-unknown.example"
    _, candidate_id, _ = _discover_staging(client, token, dns_resolver, engine, domain)

    db_session.expire_all()
    row = db_session.get(SecurityCandidate, UUID(candidate_id))
    assert row is not None
    row.candidate_type = "unknown_future_type"
    db_session.commit()

    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    http = FakeSafeHttpClient(
        default=SafeHttpObservation(
            url="https://should-not-be-called.example",
            status_code=200,
            title="x",
            headers={},
            reachable=True,
        )
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    attempt = process_one_validation(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "inconclusive"
    assert attempt.evidence.get("probed") is False
    assert http.calls == []


def test_revoked_target_blocks_validation(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-revoke.example"
    operation_id, candidate_id, target_id = _discover_staging(
        client, token, dns_resolver, engine, domain
    )
    assert client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token)).status_code == 200
    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    http = FakeSafeHttpClient(
        default=SafeHttpObservation(
            url=f"https://staging.{domain}",
            status_code=200,
            title="Staging",
            headers={},
            reachable=True,
        )
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    attempt = process_one_validation(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "failed"
    assert "not authorized" in attempt.summary.lower() or "out of scope" in attempt.summary.lower()
    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    assert "validation.failed" in [e["event_type"] for e in events]
    assert http.calls == []


def test_excluded_asset_blocks_validation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-exclude.example"
    _, candidate_id, target_id = _discover_staging(
        client, token, dns_resolver, engine, domain
    )

    # After discovery, exclude the staging host from scope.
    _enable_subdomains(client, token, target_id, exclusions=[f"staging.{domain}"])
    scope = db_session.scalar(
        select(TargetScope).where(TargetScope.target_id == UUID(target_id))
    )
    assert scope is not None
    assert f"staging.{domain}" in (scope.exclusions or [])

    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    http = FakeSafeHttpClient(
        default=SafeHttpObservation(
            url=f"https://staging.{domain}",
            status_code=200,
            title="Staging",
            headers={},
            reachable=True,
        )
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    attempt = process_one_validation(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "failed"
    assert http.calls == []


def test_duplicate_concurrent_validation_prevented(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-dup.example"
    _, candidate_id, _ = _discover_staging(client, token, dns_resolver, engine, domain)

    first = client.post(f"/v1/candidates/{candidate_id}/validate", headers=_auth(token))
    assert first.status_code == 202
    second = client.post(f"/v1/candidates/{candidate_id}/validate", headers=_auth(token))
    assert second.status_code == 409


def test_cross_org_validation_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    domain = "val-private.example"
    _, candidate_id, _ = _discover_staging(
        client, token_a, dns_resolver, engine, domain
    )

    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token_b)
        ).status_code
        == 404
    )
    assert (
        client.get(
            f"/v1/candidates/{candidate_id}/validation-attempts",
            headers=_auth(token_b),
        ).status_code
        == 404
    )


def test_validation_events_and_evidence_persist(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "val-persist.example"
    operation_id, candidate_id, _ = _discover_staging(
        client, token, dns_resolver, engine, domain
    )
    assert (
        client.post(
            f"/v1/candidates/{candidate_id}/validate", headers=_auth(token)
        ).status_code
        == 202
    )
    http = FakeSafeHttpClient(
        by_host={
            f"staging.{domain}": SafeHttpObservation(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging",
                headers={},
                reachable=True,
            )
        }
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_validation(factory, http_client=http).status == "supported"

    attempts = client.get(
        f"/v1/candidates/{candidate_id}/validation-attempts", headers=_auth(token)
    ).json()
    assert len(attempts) == 1
    assert attempts[0]["evidence"]["method"] == "staging_indicator_confirmation"
    assert "credentials" not in attempts[0]["evidence"]
    assert "body" not in attempts[0]["evidence"]

    factory2 = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory2() as db:
        row = db.get(ValidationAttempt, UUID(attempts[0]["id"]))
        assert row is not None
        assert row.status == "supported"
        events = db.scalars(
            select(OperationEvent).where(OperationEvent.operation_id == UUID(operation_id))
        ).all()
        assert any(e.event_type == "validation.supported" for e in events)

    assert "supported" in CANDIDATE_STATUSES
    assert "exploitable" not in CANDIDATE_STATUSES

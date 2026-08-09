from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.finding import Finding
from app.models.operation import OperationEvent
from app.models.retest import RetestAttempt
from app.models.target import TargetScope
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.retest_runtime import map_validation_to_retest, process_one_retest
from app.services.validation_engine.http import FakeSafeHttpClient
from app.services.validation_engine.types import SafeHttpObservation, ValidationResult
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


def _ready_finding(
    client, token, dns_resolver, engine, domain: str
) -> tuple[str, str, str, str]:
    """Return operation_id, candidate_id, finding_id, target_id at ready_for_retest."""
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"staging.{domain}"]},
        probes_by_host={
            f"staging.{domain}": ProbeResult(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging",
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    candidate_id = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()[0]["id"]
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
    assert process_one_validation(factory, http_client=http).status == "supported"
    finding_id = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()["id"]
    assert (
        client.post(
            f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token)
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/findings/{finding_id}/ready-for-retest", headers=_auth(token)
        ).status_code
        == 200
    )
    return operation_id, candidate_id, finding_id, target_id


def test_map_validation_to_retest_meanings():
    status, _ = map_validation_to_retest(
        ValidationResult(status="unsupported", validation_method="x", summary="s")
    )
    assert status == "passed"
    status, _ = map_validation_to_retest(
        ValidationResult(status="supported", validation_method="x", summary="s")
    )
    assert status == "failed"
    status, _ = map_validation_to_retest(
        ValidationResult(status="inconclusive", validation_method="x", summary="s")
    )
    assert status == "inconclusive"
    status, _ = map_validation_to_retest(
        ValidationResult(status="failed", validation_method="x", summary="s")
    )
    assert status == "error"


def test_only_ready_for_retest_can_be_retested(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-elig.example"
    # Build through promote but stop before ready_for_retest.
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]
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
    assert process_one_validation(factory, http_client=http).status == "supported"
    finding_id = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()["id"]
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
        == 400
    )


def test_passed_retest_resolves_finding(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-pass.example"
    operation_id, _, finding_id, _ = _ready_finding(
        client, token, dns_resolver, engine, domain
    )

    queued = client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token))
    assert queued.status_code == 202
    assert queued.json()["status"] == "pending"
    assert queued.json()["method"] == "staging_indicator_confirmation"
    original_id = queued.json()["original_validation_attempt_id"]

    # Condition gone → validation unsupported → retest passed
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
    attempt = process_one_retest(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "passed"
    assert attempt.method == "staging_indicator_confirmation"
    assert str(attempt.original_validation_attempt_id) == original_id
    assert attempt.evidence.get("original_validation_attempt_id") == original_id

    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["status"] == "resolved"
    assert detail["resolved_at"] is not None
    assert detail["evidence"]["resolving_retest_id"] == str(attempt.id)

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    types = [e["event_type"] for e in events]
    assert "retest.started" in types
    assert "retest.passed" in types
    assert "finding.resolved" in types
    assert types.index("retest.started") < types.index("retest.passed")
    assert types.index("retest.passed") < types.index("finding.resolved")

    db_session.expire_all()
    row = db_session.get(Finding, UUID(finding_id))
    assert row is not None
    assert row.status == "resolved"
    assert row.resolved_at is not None


def test_failed_retest_keeps_ready_for_retest(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-fail.example"
    _, _, finding_id, _ = _ready_finding(client, token, dns_resolver, engine, domain)
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
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
    attempt = process_one_retest(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "failed"
    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["status"] == "ready_for_retest"
    assert detail["resolved_at"] is None


def test_inconclusive_and_error_do_not_resolve(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-inc.example"
    _, candidate_id, finding_id, _ = _ready_finding(
        client, token, dns_resolver, engine, domain
    )

    # Force method to header_confirmation with no expected headers → inconclusive
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
        == 202
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        pending = db.scalar(
            select(RetestAttempt).where(RetestAttempt.finding_id == UUID(finding_id))
        )
        assert pending is not None
        pending.method = "header_confirmation"
        db.commit()

    http = FakeSafeHttpClient(
        by_host={
            f"staging.{domain}": SafeHttpObservation(
                url=f"https://staging.{domain}",
                status_code=200,
                title="Staging",
                headers={"content-type": "text/html"},
                reachable=True,
            )
        }
    )
    attempt = process_one_retest(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "inconclusive"
    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["status"] == "ready_for_retest"
    assert detail["resolved_at"] is None


def test_revoked_target_blocks_retest(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-rev.example"
    operation_id, _, finding_id, target_id = _ready_finding(
        client, token, dns_resolver, engine, domain
    )
    assert client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token)).status_code == 200
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
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
    attempt = process_one_retest(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "error"
    assert http.calls == []
    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["status"] == "ready_for_retest"
    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    assert "retest.error" in [e["event_type"] for e in events]


def test_out_of_scope_asset_blocks_retest(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-scope.example"
    _, _, finding_id, target_id = _ready_finding(
        client, token, dns_resolver, engine, domain
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": [f"staging.{domain}"]},
        ).status_code
        == 200
    )
    scope = db_session.scalar(
        select(TargetScope).where(TargetScope.target_id == UUID(target_id))
    )
    assert f"staging.{domain}" in (scope.exclusions or [])

    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
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
    attempt = process_one_retest(factory, http_client=http)
    assert attempt is not None
    assert attempt.status == "error"
    assert http.calls == []


def test_duplicate_concurrent_retest_prevented(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    _, _, finding_id, _ = _ready_finding(
        client, token, dns_resolver, engine, "rt-dup.example"
    )
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
        == 202
    )
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
        == 409
    )


def test_cross_org_retest_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    _, _, finding_id, _ = _ready_finding(
        client, token_a, dns_resolver, engine, "rt-priv.example"
    )
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token_b)).status_code
        == 404
    )
    assert (
        client.get(f"/v1/findings/{finding_id}/retests", headers=_auth(token_b)).status_code
        == 404
    )


def test_no_manual_resolve_and_provenance_persist(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "rt-prov.example"
    operation_id, candidate_id, finding_id, _ = _ready_finding(
        client, token, dns_resolver, engine, domain
    )
    assert (
        client.post(f"/v1/findings/{finding_id}/resolve", headers=_auth(token)).status_code
        == 404
    )
    assert (
        client.patch(
            f"/v1/findings/{finding_id}",
            headers=_auth(token),
            json={"status": "resolved"},
        ).status_code
        == 405
    )

    queued = client.post(
        f"/v1/findings/{finding_id}/retest", headers=_auth(token)
    ).json()
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
    attempt = process_one_retest(factory, http_client=http)
    assert attempt.status == "passed"

    retests = client.get(
        f"/v1/findings/{finding_id}/retests", headers=_auth(token)
    ).json()
    assert len(retests) == 1
    assert retests[0]["id"] == str(attempt.id)
    assert retests[0]["original_validation_attempt_id"] == queued[
        "original_validation_attempt_id"
    ]
    assert retests[0]["method"] == "staging_indicator_confirmation"

    finding = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    provenance = finding["evidence"]["provenance"]
    assert provenance["candidate_id"] == candidate_id
    assert provenance["operation_id"] == operation_id
    assert finding["evidence"]["resolving_retest_id"] == str(attempt.id)

    factory2 = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory2() as db:
        assert db.get(RetestAttempt, attempt.id) is not None
        assert db.scalar(select(func.count()).select_from(RetestAttempt)) == 1
        events = db.scalars(
            select(OperationEvent).where(OperationEvent.operation_id == UUID(operation_id))
        ).all()
        assert any(e.event_type == "finding.resolved" for e in events)

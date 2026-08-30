from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.finding import Finding
from app.models.operation import OperationEvent
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.findings.catalog import (
    SEVERITY_BY_CANDIDATE_TYPE,
    business_impact_for_candidate_type,
    remediation_guidance_for_candidate_type,
    severity_for_candidate_type,
)
from app.services.validation_engine.http import FakeSafeHttpClient
from app.services.validation_engine.types import SafeHttpObservation
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


def _enable_subdomains(client, token: str, target_id: str):
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )


def _supported_staging_candidate(
    client, token, dns_resolver, engine, domain: str
) -> tuple[str, str]:
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
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
    return operation_id, candidate_id


def test_deterministic_severity_mapping_is_conservative():
    assert severity_for_candidate_type("security_header_observation") == "low"
    assert severity_for_candidate_type("auth_surface_observed") == "low"
    assert severity_for_candidate_type("staging_dev_exposed") == "medium"
    assert severity_for_candidate_type("exposed_admin_interface") == "medium"
    assert severity_for_candidate_type("sensitive_service_exposed") == "medium"
    assert "critical" not in SEVERITY_BY_CANDIDATE_TYPE.values()
    impact = business_impact_for_candidate_type("staging_dev_exposed")
    assert "stolen" not in impact.lower()
    assert "customer records" not in impact.lower()
    guidance = remediation_guidance_for_candidate_type("exposed_admin_interface")
    assert "trusted networks" in guidance.lower()
    assert "exploit" not in guidance.lower()


def test_unsupported_candidate_cannot_become_finding(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "find-unsup.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
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
    # Candidate exists but is not supported.
    response = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    )
    assert response.status_code == 400


def test_supported_candidate_promotes_with_provenance(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "find-ok.example"
    operation_id, candidate_id = _supported_staging_candidate(
        client, token, dns_resolver, engine, domain
    )

    promoted = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    )
    assert promoted.status_code == 200, promoted.text
    body = promoted.json()
    assert body["status"] == "open"
    assert body["severity"] == "medium"
    assert body["resolved_at"] is None
    assert "staging" in body["business_impact"].lower()
    assert body["remediation_guidance"]
    evidence = body["evidence"]
    assert evidence["evidence_supported"] is True
    provenance = evidence["provenance"]
    assert provenance["candidate_id"] == candidate_id
    assert provenance["operation_id"] == operation_id
    assert provenance["validation_attempt_id"]
    assert provenance["observation_ids"]
    assert provenance["asset_id"] == body["asset_id"]

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    assert "finding.created" in [e["event_type"] for e in events]

    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(Finding)) == 1


def test_duplicate_promotion_does_not_create_duplicate(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    _, candidate_id = _supported_staging_candidate(
        client, token, dns_resolver, engine, "find-dup.example"
    )
    first = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()
    second = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()
    assert first["id"] == second["id"]
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(Finding)) == 1


def test_remediation_lifecycle_and_resolved_blocked(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    operation_id, candidate_id = _supported_staging_candidate(
        client, token, dns_resolver, engine, "find-life.example"
    )
    finding_id = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()["id"]

    # Invalid: open → ready_for_retest
    assert (
        client.post(
            f"/v1/findings/{finding_id}/ready-for-retest", headers=_auth(token)
        ).status_code
        == 400
    )

    started = client.post(
        f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token)
    )
    assert started.status_code == 200
    assert started.json()["status"] == "in_progress"

    # Invalid second start
    assert (
        client.post(
            f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token)
        ).status_code
        == 400
    )

    assert (
        client.post(
            f"/v1/findings/{finding_id}/remediation",
            headers=_auth(token),
            json={"summary": "Updated the application configuration."},
        ).status_code
        == 201
    )
    ready = client.post(
        f"/v1/findings/{finding_id}/ready-for-retest", headers=_auth(token)
    )
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready_for_retest"
    assert ready.json()["resolved_at"] is None

    # No endpoint to set resolved; direct status endpoint must not exist.
    assert (
        client.post(
            f"/v1/findings/{finding_id}/resolve", headers=_auth(token)
        ).status_code
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

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    types = [e["event_type"] for e in events]
    assert "finding.remediation_started" in types
    assert "finding.ready_for_retest" in types
    assert types.index("finding.remediation_started") < types.index(
        "finding.ready_for_retest"
    )


def test_cross_org_finding_access_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    _, candidate_id = _supported_staging_candidate(
        client, token_a, dns_resolver, engine, "find-priv.example"
    )
    finding_id = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token_a)
    ).json()["id"]

    assert (
        client.get(f"/v1/findings/{finding_id}", headers=_auth(token_b)).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token_b)
        ).status_code
        == 404
    )
    listed = client.get("/v1/findings", headers=_auth(token_b)).json()
    assert all(item["id"] != finding_id for item in listed)


def test_findings_list_and_persistence(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    operation_id, candidate_id = _supported_staging_candidate(
        client, token, dns_resolver, engine, "find-list.example"
    )
    finding_id = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()["id"]

    listed = client.get("/v1/findings", headers=_auth(token)).json()
    assert any(item["id"] == finding_id for item in listed)
    assert all(item["organization_id"] for item in listed)

    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["asset_hostname"] == "staging.find-list.example"
    assert detail["evidence"]["evidence_supported"] is True

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        row = db.get(Finding, UUID(finding_id))
        assert row is not None
        assert row.status == "open"
        events = db.scalars(
            select(OperationEvent).where(OperationEvent.operation_id == UUID(operation_id))
        ).all()
        assert any(e.event_type == "finding.created" for e in events)

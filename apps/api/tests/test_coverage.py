from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.capabilities.manifest import MANIFEST_VERSION, manifest_snapshot
from app.models.coverage import OperationCoverageSummary
from app.services.coverage import (
    CLEARANCE_HEADLINE_RE,
    REASON_HOST_NOT_REACHABLE,
    REASON_PROBE_NO_RESULT,
    freeze_operation_coverage,
)
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.authorization import explicit_org_actor
from app.services.operations import stop_operation
from app.services.validation_engine.http import FakeSafeHttpClient
from app.services.validation_engine.types import SafeHttpObservation
from app.services.validation_runtime import execute_validation_job
from app.services.worker_runtime import (
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


def test_manifest_snapshot_is_explicit_and_versioned():
    snap = manifest_snapshot()
    assert snap["version"] == MANIFEST_VERSION
    ids = {item["id"] for item in snap["supported"]}
    assert "exposed_admin_interface" in ids
    assert "security_header_observation" in ids
    unsupported = {item["id"] for item in snap["unsupported"]}
    assert "authenticated_testing" in unsupported
    assert "exploit_confirmation" in unsupported
    later = manifest_snapshot(version=MANIFEST_VERSION)
    assert later["unsupported"] == snap["unsupported"]


def test_probe_omission_is_no_result_not_unreachable(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "noresult.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"silent.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"

    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert coverage["surface"]["in_scope_discovered"] == 2
    assert coverage["surface"]["submitted_for_http_observation"] == 2
    assert coverage["surface"]["http_observation_obtained"] == 1
    assert coverage["surface"]["http_observation_not_obtained"] == 1
    gaps = coverage["surface"]["hostnames"]["http_observation_not_obtained"]
    assert gaps[0]["hostname"] == f"silent.{domain}"
    assert gaps[0]["reason_code"] == REASON_PROBE_NO_RESULT
    assert gaps[0]["reason_code"] != REASON_HOST_NOT_REACHABLE
    assert "not distinguishable" in gaps[0]["explanation"].lower()
    assert CLEARANCE_HEADLINE_RE.search(coverage["headline"]) is None
    assert "not evidence that the application is secure" in coverage["headline"]


def test_explicit_probe_outcome_is_host_not_reachable(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "downhost.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"down.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"down.{domain}": ProbeResult(
                url=f"https://down.{domain}/",
                status_code=None,
                title="",
                outcome=REASON_HOST_NOT_REACHABLE,
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    gaps = {
        item["hostname"]: item["reason_code"]
        for item in coverage["surface"]["hostnames"]["http_observation_not_obtained"]
    }
    assert gaps[f"down.{domain}"] == REASON_HOST_NOT_REACHABLE


def test_header_unavailability_is_subordinate_to_http_observation(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "hdrgap.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(
                url=f"https://{domain}/",
                status_code=200,
                title="Root",
                headers_observed=False,
                headers={},
                content_type="text/html",
                scheme="https",
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert coverage["surface"]["http_observation_obtained"] == 1
    assert coverage["surface"]["http_observation_not_obtained"] == 0
    assert coverage["http_evidence"]["http_observations"] == 1
    assert coverage["http_evidence"]["header_evidence_unavailable"] == 1
    assert coverage["http_evidence"]["headers_captured"] == 0
    assert coverage["surface"]["unit"] == "in_scope_hostname"
    assert coverage["http_evidence"]["unit"] == "http_observation"


def test_exclusions_are_not_failures(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "exclcov.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id, exclusions=[f"skip.{domain}"])
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"skip.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"skip.{domain}": ProbeResult(
                url=f"https://skip.{domain}", status_code=200, title="Skip"
            ),
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert f"skip.{domain}" not in coverage["surface"]["hostnames"]["in_scope_discovered"]
    assert coverage["scope_boundaries"]["discovered_results_discarded"] >= 1
    assert f"skip.{domain}" in coverage["scope_boundaries"]["configured_exclusions"]
    not_obtained_reasons = {
        item["reason_code"]
        for item in coverage["surface"]["hostnames"]["http_observation_not_obtained"]
    }
    assert REASON_PROBE_NO_RESULT not in not_obtained_reasons or f"skip.{domain}" not in {
        item["hostname"]
        for item in coverage["surface"]["hostnames"]["http_observation_not_obtained"]
    }
    assert all(
        item["hostname"] != f"skip.{domain}"
        for item in coverage["surface"]["hostnames"]["http_observation_not_obtained"]
    )


def test_stopped_before_probe_is_incomplete_not_unreachable(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "stopcov.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)

    class StopAfterDiscover(FakeDiscoveryTools):
        def discover_hosts(self, domain_name: str):
            hosts, note = super().discover_hosts(domain_name)
            me = client.get("/v1/me", headers=_auth(token)).json()
            stop_operation(
                db_session,
                operation_id=UUID(operation_id),
                actor=explicit_org_actor(
                    user_id=UUID(me["id"]),
                    organization_id=UUID(me["active_organization_id"]),
                    normalized_role="admin",
                ),
            )
            db_session.commit()
            return hosts, note

        def probe_hosts(self, hosts: list[str]):
            raise AssertionError("HTTP probe must not run after stop")

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    claim_db = factory()
    try:
        claimed = claim_next_operation(claim_db)
        assert claimed is not None
    finally:
        claim_db.close()

    exec_db = factory()
    try:
        result = execute_discovery_job(
            exec_db,
            UUID(operation_id),
            StopAfterDiscover(
                hosts_by_domain={domain: [domain, f"www.{domain}"]},
                probes_by_host={},
            ),
        )
    finally:
        exec_db.close()
    assert result.status == "stopped"
    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert coverage["surface"]["in_scope_discovered"] >= 1
    assert coverage["surface"]["submitted_for_http_observation"] == 0
    assert coverage["surface"]["incomplete"] >= 1
    assert coverage["surface"]["http_observation_not_obtained"] == 0
    assert coverage["operation_status_at_freeze"] == "stopped"


def test_coverage_freeze_is_idempotent_and_recoverable(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "freezecov.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    operation = process_one_operation(factory, tools=tools)
    assert operation is not None
    first = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    second = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert first["surface"] == second["surface"]
    assert first["capability"]["unsupported"] == second["capability"]["unsupported"]

    db_session.expire_all()
    row = db_session.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == UUID(operation_id)
        )
    )
    assert row is not None
    snapshot_id = row.id
    stored_surface = dict(row.surface)
    db_session.delete(row)
    db_session.commit()

    recovered = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert recovered["source"] == "recovered"
    assert recovered["surface"]["http_observation_obtained"] == stored_surface[
        "http_observation_obtained"
    ]
    db_session.expire_all()
    new_row = db_session.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == UUID(operation_id)
        )
    )
    assert new_row is not None
    assert new_row.id != snapshot_id

    freeze_operation_coverage(db_session, operation, source="frozen")
    freeze_operation_coverage(db_session, operation, source="frozen")
    count = db_session.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == UUID(operation_id)
        )
    )
    assert count is not None


def test_follow_up_changes_after_validation_but_frozen_surface_does_not(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "followup.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    _enable_subdomains(client, token, target_id)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [f"admin.{domain}"]},
        probes_by_host={
            f"admin.{domain}": ProbeResult(
                url=f"https://admin.{domain}/",
                status_code=200,
                title="Admin Dashboard",
                headers_observed=True,
                headers={"content-type": "text/html"},
                content_type="text/html",
                scheme="https",
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    before = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert before["follow_up"]["validations_attempted"] == 0
    candidates = client.get(
        f"/v1/operations/{operation_id}/candidates", headers=_auth(token)
    ).json()
    assert candidates
    queued = client.post(
        f"/v1/candidates/{candidates[0]['id']}/validate",
        headers=_auth(token),
    )
    assert queued.status_code == 202
    factory_db = factory()
    try:
        host = f"admin.{domain}"
        execute_validation_job(
            factory_db,
            UUID(queued.json()["id"]),
            http_client=FakeSafeHttpClient(
                by_host={
                    host: SafeHttpObservation(
                        url=f"https://{host}/",
                        status_code=200,
                        title="Admin Dashboard",
                        headers={"content-type": "text/html"},
                        reachable=True,
                        headers_observed=True,
                        content_type="text/html",
                    )
                }
            ),
        )
    finally:
        factory_db.close()
    after = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert after["surface"] == before["surface"]
    assert after["http_evidence"] == before["http_evidence"]
    assert after["capability"] == before["capability"]
    assert after["follow_up"]["validations_attempted"] >= 1
    assert after["follow_up"]["validations_attempted"] != before["follow_up"][
        "validations_attempted"
    ]


def test_zero_candidates_headline_is_not_a_clearance(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "emptycov.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(
                url=f"https://{domain}/",
                status_code=200,
                title="Marketing",
                headers_observed=True,
                headers={
                    "content-type": "text/html",
                    "strict-transport-security": "max-age=31536000",
                },
                content_type="text/html",
                scheme="https",
            )
        },
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=tools).status == "completed"
    coverage = client.get(
        f"/v1/operations/{operation_id}/coverage", headers=_auth(token)
    ).json()
    assert coverage["follow_up"]["candidates_generated"] == 0
    assert coverage["follow_up"]["findings"] == 0
    assert CLEARANCE_HEADLINE_RE.search(coverage["headline"]) is None
    assert "not evidence that the application is secure" in coverage["headline"]
    assert "secure" not in coverage["headline"].lower().replace(
        "not evidence that the application is secure", ""
    )


def test_coverage_endpoint_is_org_scoped(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    domain = "private-cov.example"
    target_id = _create_verified_target(client, token_a, domain, dns_resolver)
    operation_id = _queue_operation(client, token_a, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    assert (
        client.get(
            f"/v1/operations/{operation_id}/coverage", headers=_auth(token_b)
        ).status_code
        == 404
    )

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.models.audit import AuditEvent
from app.models.operation_controls import OperationControlSnapshot
from app.models.target import TargetScope
from app.services.audit import sanitize_audit_metadata
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.retest_runtime import process_one_retest
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
    assert started.status_code == 200
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    verified = client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token))
    assert verified.status_code == 200
    assert verified.json()["verified"] is True
    return target_id


def _actions(events: list[dict]) -> list[str]:
    return [row["action"] for row in events]


def test_target_creation_and_verification_produce_audit_events(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-target.example", dns_resolver
    )

    events = client.get("/v1/audit-events", headers=_auth(token)).json()
    actions = _actions(events)
    assert "target.created" in actions
    assert "target.verification_started" in actions
    assert "target.verified" in actions
    assert any(
        e["resource_type"] == "target" and e["resource_id"] == target_id for e in events
    )


def test_scope_change_produces_audit_event(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-scope.example", dns_resolver
    )
    response = client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": ["admin.audit-scope.example"]},
    )
    assert response.status_code == 200

    events = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"action": "target.scope_updated"},
    ).json()
    assert len(events) >= 1
    assert events[0]["resource_id"] == target_id
    assert events[0]["metadata"].get("include_subdomains") is True


def test_operation_creation_stores_immutable_control_snapshot(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-snapshot.example", dns_resolver
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={
                "include_subdomains": True,
                "exclusions": ["secret.audit-snapshot.example"],
            },
        ).status_code
        == 200
    )

    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["testing_profile"] == "safe_production"
    snapshot = body["control_snapshot"]
    assert snapshot is not None
    assert snapshot["target_domain"] == "audit-snapshot.example"
    assert snapshot["authorization_status"] == "verified"
    assert snapshot["scope_root"] == "audit-snapshot.example"
    assert snapshot["include_subdomains"] is True
    assert snapshot["exclusions"] == ["secret.audit-snapshot.example"]
    assert snapshot["testing_profile"] == "safe_production"
    assert snapshot["operation_source"] == "manual"
    assert snapshot["created_by_user_id"] == body["created_by_user_id"]

    # Later scope change must not mutate the historical snapshot.
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
                json={
                    "include_subdomains": False,
                    "exclusions": ["later.audit-snapshot.example"],
                },
            ).status_code
            == 200
        )
    detail = client.get(f"/v1/operations/{body['id']}", headers=_auth(token)).json()
    assert detail["control_snapshot"]["include_subdomains"] is True
    assert detail["control_snapshot"]["exclusions"] == ["secret.audit-snapshot.example"]

    db_session.expire_all()
    row = db_session.scalar(
        select(OperationControlSnapshot).where(
            OperationControlSnapshot.operation_id == body["id"]
        )
    )
    assert row is not None
    assert row.include_subdomains is True
    assert row.exclusions == ["secret.audit-snapshot.example"]

    scope = db_session.scalar(
        select(TargetScope).where(TargetScope.target_id == target_id)
    )
    assert scope is not None
    assert scope.include_subdomains is False


def test_operation_lifecycle_produces_audit_events(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "audit-lifecycle.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: []},
        probes_by_host={},
    )
    assert process_one_operation(factory, tools=tools).status == "completed"

    events = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"resource_id": operation_id},
    ).json()
    actions = _actions(events)
    assert "operation.created" in actions
    assert "operation.started" in actions
    assert "operation.completed" in actions


def test_monitoring_changes_produce_audit_events(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-monitor.example", dns_resolver
    )
    enabled = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "daily"},
    )
    assert enabled.status_code == 200
    disabled = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": False, "frequency": "daily"},
    )
    assert disabled.status_code == 200

    events = client.get("/v1/audit-events", headers=_auth(token)).json()
    actions = _actions(events)
    assert "monitoring.enabled" in actions
    assert "monitoring.disabled" in actions


def test_validation_finding_retest_audits_and_provenance(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "audit-finding.example"
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

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
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

    finding = client.post(
        f"/v1/candidates/{candidate_id}/promote", headers=_auth(token)
    ).json()
    finding_id = finding["id"]
    provenance = finding["provenance"]
    assert provenance["finding_id"] == finding_id
    assert provenance["candidate_id"] == candidate_id
    assert provenance["operation_id"] == operation_id
    assert provenance["validation_attempt_id"]
    assert provenance["observation_ids"]
    assert provenance["control_snapshot"]["testing_profile"] == "safe_production"

    assert (
        client.post(
            f"/v1/findings/{finding_id}/start-remediation", headers=_auth(token)
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/findings/{finding_id}/remediation",
            headers=_auth(token),
            json={"summary": "Updated the application configuration."},
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/v1/findings/{finding_id}/ready-for-retest", headers=_auth(token)
        ).status_code
        == 200
    )
    assert (
        client.post(f"/v1/findings/{finding_id}/retest", headers=_auth(token)).status_code
        == 202
    )

    # Passing retest: condition no longer present.
    http_pass = FakeSafeHttpClient(
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
    result = process_one_retest(factory, http_client=http_pass)
    assert result is not None
    assert result.status == "passed"

    detail = client.get(f"/v1/findings/{finding_id}", headers=_auth(token)).json()
    assert detail["status"] == "resolved"
    assert detail["provenance"]["retest_attempt_id"]
    assert "retest" in detail["provenance"]["chain"]

    events = client.get("/v1/audit-events", headers=_auth(token)).json()
    actions = _actions(events)
    assert "validation.requested" in actions
    assert "validation.completed" in actions
    assert "finding.created" in actions
    assert "finding.remediation_started" in actions
    assert "finding.ready_for_retest" in actions
    assert "retest.requested" in actions
    assert "retest.completed" in actions
    assert "finding.resolved" in actions


def test_cross_org_audit_access_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    _create_verified_target(client, token_a, "audit-cross.example", dns_resolver)

    events_a = client.get("/v1/audit-events", headers=_auth(token_a)).json()
    assert any(e["action"] == "target.created" for e in events_a)

    events_b = client.get("/v1/audit-events", headers=_auth(token_b)).json()
    assert all(e["organization_id"] != events_a[0]["organization_id"] for e in events_b)
    assert not any(e["action"] == "target.created" and "audit-cross" in e["summary"] for e in events_b)


def test_audit_events_immutable_through_api(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    _create_verified_target(client, token, "audit-immutable.example", dns_resolver)
    events = client.get("/v1/audit-events", headers=_auth(token)).json()
    assert events
    event_id = events[0]["id"]

    assert client.patch(
        f"/v1/audit-events/{event_id}",
        headers=_auth(token),
        json={"summary": "tampered"},
    ).status_code in {404, 405}
    assert client.put(
        f"/v1/audit-events/{event_id}",
        headers=_auth(token),
        json={"summary": "tampered"},
    ).status_code in {404, 405}
    assert client.delete(
        f"/v1/audit-events/{event_id}",
        headers=_auth(token),
    ).status_code in {404, 405}


def test_sensitive_metadata_rejected_or_redacted():
    clean = sanitize_audit_metadata(
        {
            "domain": "safe.example",
            "authorization_status": "verified",
            "authorization_id": "11111111-1111-1111-1111-111111111111",
            "token": "clerk_secret",
            "txt_value": "scout-verify=abc",
            "authorization": "Bearer xyz",
            "cookie": "session=1",
            "api_key": "k",
            "prompt": "ignore",
            "response_body": "<html>secret</html>",
            "chain_of_thought": "thinking",
            "not_allowlisted": "drop-me",
        }
    )
    assert clean["domain"] == "safe.example"
    assert clean["authorization_status"] == "verified"
    assert clean["authorization_id"] == "11111111-1111-1111-1111-111111111111"
    assert "token" not in clean
    assert "txt_value" not in clean
    assert "authorization" not in clean
    assert "cookie" not in clean
    assert "api_key" not in clean
    assert "prompt" not in clean
    assert "response_body" not in clean
    assert "chain_of_thought" not in clean
    assert "not_allowlisted" not in clean


def test_audit_filters_work(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-filter.example", dns_resolver
    )
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]

    by_action = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"action": "operation.created"},
    ).json()
    assert by_action
    assert all(e["action"] == "operation.created" for e in by_action)

    by_type = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"resource_type": "operation", "resource_id": operation_id},
    ).json()
    assert by_type
    assert all(
        e["resource_type"] == "operation" and e["resource_id"] == operation_id
        for e in by_type
    )

    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    empty = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"created_after": future},
    ).json()
    assert empty == []


def test_audit_events_persisted_separately_from_operation_events(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-separate.example", dns_resolver
    )
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]

    op_events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    audit_events = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"resource_id": operation_id},
    ).json()
    assert op_events
    assert audit_events
    assert all("sequence" in e for e in op_events)
    assert all("actor_type" in e for e in audit_events)

    db_session.expire_all()
    persisted = db_session.scalars(
        select(AuditEvent).where(AuditEvent.resource_id == operation_id)
    ).all()
    assert persisted

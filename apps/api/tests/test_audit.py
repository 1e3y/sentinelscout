"""Audit write-path regression + M37 customer contract adaptation."""

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


def _list(client, token: str, **params):
    return client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params=params or None,
    )


def _actions(body: dict) -> list[str]:
    return [row["action"] for row in body["items"]]


def test_target_creation_and_verification_produce_audit_events(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "audit-target.example", dns_resolver
    )

    response = _list(client, token, page_size=50)
    assert response.status_code == 200, response.text
    body = response.json()
    assert "metadata" not in body
    assert "items" in body
    actions = _actions(body)
    assert "target_created" in actions
    assert "target_verification_started" in actions
    assert "target_verified" in actions
    assert any(
        e["resource"]["kind"] == "target" and e["resource"]["id"] == target_id
        for e in body["items"]
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

    events = _list(
        client, token, action="target_scope_changed", page_size=50
    ).json()
    assert len(events["items"]) >= 1
    row = events["items"][0]
    assert row["resource"]["id"] == target_id
    assert row["detail"]["include_subdomains"] is True
    assert "metadata" not in row


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

    events = _list(
        client, token, resource_type="assessment", page_size=50
    ).json()
    actions = _actions(events)
    assert "assessment_created" in actions
    assert "assessment_started" in actions
    assert "assessment_completed" in actions
    assert any(e["resource"]["id"] == operation_id for e in events["items"])


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

    events = _list(
        client, token, action="monitoring_changed", page_size=50
    ).json()
    labels = {row["label"] for row in events["items"]}
    assert "Monitoring enabled" in labels
    assert "Monitoring disabled" in labels


def test_validation_finding_retest_audits_and_provenance(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
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

    # Hidden pipeline actions remain durable in DB but not customer-visible.
    db_actions = set(
        db_session.scalars(select(AuditEvent.action)).all()
    )
    assert "validation.requested" in db_actions
    assert "validation.completed" in db_actions

    events = _list(client, token, page_size=50).json()
    actions = _actions(events)
    assert "validation.requested" not in actions
    assert "validation.completed" not in actions
    assert "finding_created" in actions
    assert "remediation_started" in actions
    assert "ready_for_retest" in actions
    assert "retest_requested" in actions
    assert "retest_completed" in actions
    assert "finding_resolved" in actions


def test_cross_org_audit_access_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    _create_verified_target(client, token_a, "audit-cross.example", dns_resolver)

    events_a = _list(client, token_a, page_size=50).json()
    assert any(e["action"] == "target_created" for e in events_a["items"])

    events_b = _list(client, token_b, page_size=50).json()
    assert not any(
        e["action"] == "target_created" and "audit-cross" in (e["resource"]["label"] or "")
        for e in events_b["items"]
    )


def test_audit_events_immutable_through_api(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    _create_verified_target(client, token, "audit-immutable.example", dns_resolver)
    events = _list(client, token, page_size=50).json()
    assert events["items"]
    event_id = db_session.scalar(select(AuditEvent.id).limit(1))
    assert event_id is not None

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

    by_action = _list(client, token, action="assessment_created", page_size=50).json()
    assert by_action["items"]
    assert all(e["action"] == "assessment_created" for e in by_action["items"])
    assert any(e["resource"]["id"] == operation_id for e in by_action["items"])

    by_type = _list(client, token, resource_type="assessment", page_size=50).json()
    assert by_type["items"]
    assert all(e["resource"]["kind"] == "assessment" for e in by_type["items"])

    # Internal action strings no longer accepted as filters.
    invalid = _list(client, token, action="operation.created")
    assert invalid.status_code == 422

    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    empty = _list(client, token, **{"from": future}).json()
    assert empty["items"] == []


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
    audit_events = _list(
        client, token, action="assessment_created", page_size=50
    ).json()
    assert op_events
    assert audit_events["items"]
    assert all("sequence" in e for e in op_events)
    assert all("actor" in e for e in audit_events["items"])
    assert all("metadata" not in e for e in audit_events["items"])

    db_session.expire_all()
    persisted = db_session.scalars(
        select(AuditEvent).where(AuditEvent.resource_id == operation_id)
    ).all()
    assert persisted

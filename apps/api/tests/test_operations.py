from sqlalchemy import select

from app.models.operation import Operation, OperationEvent
from app.models.target import AuthorizedTarget, TargetAuthorization
from app.services.operations import append_event


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


def test_unauthenticated_operation_creation_rejected(client):
    response = client.post(
        "/v1/operations",
        json={"target_id": "00000000-0000-0000-0000-000000000001"},
    )
    assert response.status_code == 401


def test_unverified_target_cannot_create_operation(
    client, make_token, seed_user_a
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    created = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "unverified-ops.example"},
    )
    target_id = created.json()["id"]

    response = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert response.status_code == 400


def test_revoked_target_cannot_create_operation(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "revoked-ops.example", dns_resolver
    )
    revoked = client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token))
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    response = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert response.status_code == 400


def test_verified_target_creates_queued_operation(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "ops-create.example", dns_resolver
    )

    response = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    assert body["target_id"] == target_id
    assert body["target_domain"] == "ops-create.example"
    assert body["started_at"] is None

    db_session.expire_all()
    operation = db_session.scalar(select(Operation).where(Operation.id == body["id"]))
    assert operation is not None
    assert operation.status == "queued"
    assert str(operation.target_id) == target_id

    # organization/creator derived server-side (not client-supplied)
    me = client.get("/v1/me", headers=_auth(token)).json()
    assert body["organization_id"] == me["active_organization_id"]
    assert body["created_by_user_id"] == me["id"]
    assert str(operation.organization_id) == me["active_organization_id"]
    assert str(operation.created_by_user_id) == me["id"]


def test_cross_org_target_cannot_be_used(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    target_id = _create_verified_target(
        client, token_a, "cross-ops.example", dns_resolver
    )

    response = client.post(
        "/v1/operations",
        headers=_auth(token_b),
        json={"target_id": target_id},
    )
    assert response.status_code == 404


def test_cross_org_operation_access_returns_404(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    target_id = _create_verified_target(
        client, token_a, "cross-op-get.example", dns_resolver
    )
    created = client.post(
        "/v1/operations",
        headers=_auth(token_a),
        json={"target_id": target_id},
    )
    operation_id = created.json()["id"]

    assert client.get(f"/v1/operations/{operation_id}", headers=_auth(token_b)).status_code == 404
    assert (
        client.get(f"/v1/operations/{operation_id}/events", headers=_auth(token_b)).status_code
        == 404
    )


def test_operation_and_created_event_persist(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "persist-ops.example", dns_resolver
    )
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    operation_id = created.json()["id"]

    fetched = client.get(f"/v1/operations/{operation_id}", headers=_auth(token))
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "queued"

    events = client.get(f"/v1/operations/{operation_id}/events", headers=_auth(token))
    assert events.status_code == 200
    body = events.json()
    assert len(body) >= 1
    assert body[0]["event_type"] == "operation.created"
    assert body[0]["summary"] == "Scout operation queued."
    assert body[0]["sequence"] == 1
    assert "token" not in body[0]["metadata"]
    assert "prompt" not in body[0]["metadata"]

    db_session.expire_all()
    persisted = db_session.scalar(
        select(OperationEvent).where(OperationEvent.operation_id == operation_id)
    )
    assert persisted is not None
    assert persisted.event_type == "operation.created"


def test_event_ordering(client, make_token, seed_user_a, dns_resolver, db_session):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "event-order.example", dns_resolver
    )
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    operation_id = created.json()["id"]

    operation = db_session.scalar(select(Operation).where(Operation.id == operation_id))
    assert operation is not None
    append_event(
        db_session,
        operation,
        event_type="operation.note",
        summary="Second event.",
        metadata={"status": "queued"},
    )
    append_event(
        db_session,
        operation,
        event_type="operation.note",
        summary="Third event.",
        metadata={"status": "queued"},
    )
    db_session.commit()

    events = client.get(f"/v1/operations/{operation_id}/events", headers=_auth(token)).json()
    sequences = [event["sequence"] for event in events]
    assert sequences == sorted(sequences)
    assert [event["summary"] for event in events] == [
        "Scout operation queued.",
        "Second event.",
        "Third event.",
    ]


def test_operation_list_only_exposes_permitted_orgs(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)

    target_a = _create_verified_target(client, token_a, "list-a.example", dns_resolver)
    target_b = _create_verified_target(client, token_b, "list-b.example", dns_resolver)
    op_a = client.post(
        "/v1/operations", headers=_auth(token_a), json={"target_id": target_a}
    ).json()["id"]
    op_b = client.post(
        "/v1/operations", headers=_auth(token_b), json={"target_id": target_b}
    ).json()["id"]

    listed_a = client.get("/v1/operations", headers=_auth(token_a)).json()
    listed_b = client.get("/v1/operations", headers=_auth(token_b)).json()
    assert {item["id"] for item in listed_a} == {op_a}
    assert {item["id"] for item in listed_b} == {op_b}


def test_target_revoke_persists_and_keeps_history(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "revoke-history.example", dns_resolver
    )
    operation_id = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    ).json()["id"]

    revoked = client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token))
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoked_at"] is not None
    # Authorization challenge history remains.
    assert revoked.json()["authorization"] is not None

    db_session.expire_all()
    target = db_session.scalar(
        select(AuthorizedTarget).where(AuthorizedTarget.id == target_id)
    )
    authz = db_session.scalar(
        select(TargetAuthorization).where(TargetAuthorization.target_id == target_id)
    )
    operation = db_session.scalar(select(Operation).where(Operation.id == operation_id))
    assert target is not None and target.status == "revoked"
    assert authz is not None
    assert operation is not None
    assert operation.status == "queued"

    fetched_op = client.get(f"/v1/operations/{operation_id}", headers=_auth(token))
    assert fetched_op.status_code == 200
    assert fetched_op.json()["id"] == operation_id

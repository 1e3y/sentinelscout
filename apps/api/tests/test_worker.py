from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

from sqlalchemy.orm import sessionmaker

from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.authorization import explicit_org_actor
from app.services.operations import stop_operation
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


def _queue_operation(client, token: str, target_id: str) -> str:
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201
    assert created.json()["status"] == "queued"
    return created.json()["id"]


def _tools(domain: str) -> FakeDiscoveryTools:
    return FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="OK")
        },
    )


def test_worker_claims_and_completes_operation(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "worker-complete.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    result = process_one_operation(factory, tools=_tools(domain))
    assert result is not None
    assert str(result.id) == operation_id
    assert result.status == "completed"
    assert result.started_at is not None
    assert result.completed_at is not None

    polled = client.get(f"/v1/operations/{operation_id}", headers=_auth(token)).json()
    assert polled["status"] == "completed"

    events = client.get(
        f"/v1/operations/{operation_id}/events", headers=_auth(token)
    ).json()
    types = [event["event_type"] for event in events]
    assert types[0] == "operation.created"
    assert "operation.started" in types
    assert "discovery.started" in types
    assert "discovery.completed" in types
    assert types[-1] == "operation.completed"


def test_two_workers_cannot_claim_same_operation(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "worker-race.example", dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    barrier = threading.Barrier(2)
    results: list[str | None] = []

    def claim() -> None:
        db = factory()
        try:
            barrier.wait(timeout=5)
            claimed = claim_next_operation(db)
            results.append(str(claimed.id) if claimed else None)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(claim), pool.submit(claim)]
        for future in futures:
            future.result(timeout=10)

    assert results.count(operation_id) == 1
    assert results.count(None) == 1


def test_queued_operation_can_be_stopped_and_not_claimed(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "worker-stop-queued.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    stopped = client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token))
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=_tools(domain)) is None


def test_running_operation_cooperatively_stops(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "worker-stop-running.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    claim_db = factory()
    try:
        claimed = claim_next_operation(claim_db)
        assert claimed is not None
        assert claimed.status == "running"
    finally:
        claim_db.close()

    me = client.get("/v1/me", headers=_auth(token)).json()
    stop_db = factory()
    try:
        stop_operation(
            stop_db,
            operation_id=UUID(operation_id),
            actor=explicit_org_actor(
                user_id=UUID(me["id"]),
                organization_id=UUID(me["active_organization_id"]),
                normalized_role="admin",
            ),
        )
    finally:
        stop_db.close()

    exec_db = factory()
    try:
        result = execute_discovery_job(exec_db, UUID(operation_id), _tools(domain))
    finally:
        exec_db.close()

    assert result.status == "stopped"
    assert result.stopped_at is not None


def test_completed_operation_cannot_be_stopped(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "worker-stop-completed.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue_operation(client, token, target_id)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=_tools(domain)).status == "completed"

    response = client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token))
    assert response.status_code == 400


def test_process_one_returns_none_when_queue_empty(engine, db_session):
    assert db_session.bind is not None
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_operation(factory, tools=_tools("none.example")) is None

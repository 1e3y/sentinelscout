from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.monitoring import MonitoringConfiguration
from app.models.operation import Operation
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.monitoring import compute_next_run_at
from app.services.scheduler_runtime import process_one_scheduled_monitoring
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
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    return target_id


def test_compute_next_run_at():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert compute_next_run_at("daily", from_time=base) == base + timedelta(days=1)
    assert compute_next_run_at("weekly", from_time=base) == base + timedelta(days=7)


def test_verified_target_can_enable_monitoring(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "mon-ok.example", dns_resolver)
    response = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "weekly"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] is True
    assert body["frequency"] == "weekly"
    assert body["next_run_at"] is not None

    got = client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token))
    assert got.status_code == 200
    assert got.json()["enabled"] is True


def test_unverified_and_revoked_cannot_enable_monitoring(
    client, make_token, seed_user_a, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    created = client.post(
        "/v1/targets", headers=_auth(token), json={"domain": "mon-unv.example"}
    )
    target_id = created.json()["id"]
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 400
    )

    verified = _create_verified_target(client, token, "mon-rev.example", dns_resolver)
    assert client.post(f"/v1/targets/{verified}/revoke", headers=_auth(token)).status_code == 200
    assert (
        client.put(
            f"/v1/targets/{verified}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 400
    )


def test_scheduler_creates_scheduled_operation_and_updates_next_run(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "mon-sched.example", dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 200
    )

    before = client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token)).json()
    # Make due immediately.
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    assert config is not None
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    config.next_run_at = past
    db_session.commit()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    operation = process_one_scheduled_monitoring(factory)
    assert operation is not None
    assert operation.source == "scheduled"
    assert operation.status == "queued"
    assert str(operation.target_id) == target_id

    events = client.get(
        f"/v1/operations/{operation.id}/events", headers=_auth(token)
    ).json()
    types = [e["event_type"] for e in events]
    assert "operation.created" in types
    assert "monitoring.operation_scheduled" in types
    assert client.get(f"/v1/operations/{operation.id}", headers=_auth(token)).json()[
        "source"
    ] == "scheduled"

    after = client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token)).json()
    assert after["last_run_at"] is not None
    assert after["next_run_at"] is not None
    assert after["next_run_at"] != before["next_run_at"]
    # Not due again immediately.
    assert process_one_scheduled_monitoring(factory) is None


def test_duplicate_scheduler_instances_do_not_duplicate_operations(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "mon-dup.example", dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "weekly"},
        ).status_code
        == 200
    )
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    config.next_run_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    first = process_one_scheduled_monitoring(factory)
    second = process_one_scheduled_monitoring(factory)
    assert first is not None
    assert second is None

    db_session.expire_all()
    count = db_session.scalar(
        select(func.count())
        .select_from(Operation)
        .where(Operation.target_id == UUID(target_id), Operation.source == "scheduled")
    )
    assert count == 1


def test_disabled_monitoring_does_not_run(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "mon-off.example", dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 200
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": False, "frequency": "daily"},
        ).status_code
        == 200
    )
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    config.next_run_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_scheduled_monitoring(factory) is None


def test_revoked_before_run_disables_monitoring(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(client, token, "mon-block.example", dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 200
    )
    assert client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token)).status_code == 200
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    config.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    config.enabled = True
    db_session.commit()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert process_one_scheduled_monitoring(factory) is None
    db_session.expire_all()
    config = db_session.get(MonitoringConfiguration, config.id)
    assert config.enabled is False
    assert config.disabled_reason
    assert "revoked" in config.disabled_reason.lower()


def test_cross_org_monitoring_blocked(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    target_id = _create_verified_target(client, token_a, "mon-priv.example", dns_resolver)
    assert (
        client.get(f"/v1/targets/{target_id}/monitoring", headers=_auth(token_b)).status_code
        == 404
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token_b),
            json={"enabled": True, "frequency": "weekly"},
        ).status_code
        == 404
    )


def test_change_detection_new_gone_and_changed(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "mon-chg.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    op1 = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    tools1 = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"www.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}", status_code=200, title="WWW"
            ),
        },
    )
    assert process_one_operation(factory, tools=tools1).status == "completed"

    op2 = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    ).json()["id"]
    # www gone, api new, root title/status changed
    tools2 = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"api.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=301, title="Moved"),
            f"api.{domain}": ProbeResult(
                url=f"https://api.{domain}", status_code=200, title="API"
            ),
        },
    )
    assert process_one_operation(factory, tools=tools2).status == "completed"

    events = client.get(f"/v1/operations/{op2}/events", headers=_auth(token)).json()
    types = [e["event_type"] for e in events]
    assert "asset.new_since_previous" in types
    assert "asset.no_longer_observed" in types
    assert "asset.response_changed" in types
    # First op should not have change events (no previous).
    events1 = client.get(f"/v1/operations/{op1}/events", headers=_auth(token)).json()
    assert "asset.new_since_previous" not in [e["event_type"] for e in events1]

    monitoring = client.get(
        f"/v1/targets/{target_id}/monitoring", headers=_auth(token)
    ).json()
    assert monitoring["latest_changes"]["new"] >= 1
    assert monitoring["latest_changes"]["gone"] >= 1
    assert monitoring["latest_changes"]["changed"] >= 1


def test_monitoring_data_persists_and_synthetic_cycle(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "mon-e2e.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 200
    )
    db_session.expire_all()
    config = db_session.scalar(
        select(MonitoringConfiguration).where(
            MonitoringConfiguration.target_id == UUID(target_id)
        )
    )
    config.next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    next_before = config.next_run_at

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    scheduled = process_one_scheduled_monitoring(factory)
    assert scheduled is not None
    assert scheduled.source == "scheduled"

    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Home")
        },
    )
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed"
    assert str(result.id) == str(scheduled.id)

    db_session.expire_all()
    config = db_session.get(MonitoringConfiguration, config.id)
    assert config.last_run_at is not None
    assert config.next_run_at is not None
    assert config.next_run_at > next_before
    assert config.enabled is True

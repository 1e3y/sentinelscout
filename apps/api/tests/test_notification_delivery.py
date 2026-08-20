from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings, reset_settings_cache
from app.models.alert import Alert, NotificationOutbox
from app.models.organization import Organization
from app.models.user import User
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.email_provider import EmailSendResult, FakeEmailProvider, build_email_provider
from app.services.notification_runtime import (
    SKIP_RECIPIENT_IDENTITY_CHANGED,
    SKIP_STAGING_DESTINATION,
    NotificationWorkerNotReady,
    claim_email_outbox,
    complete_claimed_outbox,
    process_one_email_delivery,
    request_from_snapshot,
)
from app.services.worker_runtime import process_one_operation


@pytest.fixture(autouse=True)
def _reset_settings():
    reset_settings_cache()
    yield
    reset_settings_cache()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _https_html(host: str, *, hsts: bool = True) -> ProbeResult:
    headers = {"content-type": "text/html"}
    present = ["content-type"]
    if hsts:
        headers["strict-transport-security"] = "max-age=31536000"
        present.append("strict-transport-security")
    return ProbeResult(
        url=f"https://{host}/",
        status_code=200,
        title="Home",
        headers_observed=True,
        headers=headers,
        headers_present=tuple(present),
        content_type="text/html",
        scheme="https",
        redirected=False,
        requested_url=f"https://{host}/",
        final_url=f"https://{host}/",
        outcome="observed",
    )


def _tools(domain: str, probes: dict[str, ProbeResult]):
    hosts = [domain, *list(probes)]
    unique = list(dict.fromkeys(hosts))
    return FakeDiscoveryTools(hosts_by_domain={domain: unique}, probes_by_host=probes)


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()["verified"]
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    return target_id


def _queue(client, token: str, target_id: str) -> str:
    created = client.post(
        "/v1/operations", headers=_auth(token), json={"target_id": target_id}
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _run(factory, tools):
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed", result.error_message
    return result


def _org_id(client, token: str) -> str:
    rows = client.get("/v1/organizations", headers=_auth(token)).json()
    assert rows
    return rows[0]["id"]


def _enable_org_email(client, token: str, recipient_user_ids: list[str], *, min_priority="medium"):
    org_id = _org_id(client, token)
    response = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
        json={
            "email_enabled": True,
            "email_min_priority": min_priority,
            "recipient_user_ids": recipient_user_ids,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _local_user(db, clerk_user_id: str) -> User:
    user = db.scalar(select(User).where(User.clerk_user_id == clerk_user_id))
    assert user is not None
    return user


def _email_rows(db) -> list[NotificationOutbox]:
    return list(
        db.scalars(select(NotificationOutbox).where(NotificationOutbox.channel == "email")).all()
    )


def _hsts_alert(
    client, token, dns_resolver, engine, domain: str, *, host: str | None = None
):
    host = host or f"hsts.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    present = {domain: _https_html(domain), host: _https_html(host, hsts=True)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False)}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    return factory, target_id, host


def _delivery_settings(monkeypatch, **env: str):
    monkeypatch.setenv("EMAIL_DELIVERY_ENABLED", env.get("EMAIL_DELIVERY_ENABLED", "true"))
    monkeypatch.setenv("EMAIL_PROVIDER", env.get("EMAIL_PROVIDER", "fake"))
    monkeypatch.setenv(
        "EMAIL_FROM", env.get("EMAIL_FROM", "Scout Alerts <alerts@example.test>")
    )
    if "EMAIL_API_KEY" in env:
        monkeypatch.setenv("EMAIL_API_KEY", env["EMAIL_API_KEY"])
    if "EMAIL_STAGING_ALLOWLIST" in env:
        monkeypatch.setenv("EMAIL_STAGING_ALLOWLIST", env["EMAIL_STAGING_ALLOWLIST"])
    if "FRONTEND_URL" in env:
        monkeypatch.setenv("FRONTEND_URL", env["FRONTEND_URL"])
    reset_settings_cache()
    return get_settings()


def test_build_email_provider_is_fake_in_tests():
    provider = build_email_provider(get_settings())
    assert isinstance(provider, FakeEmailProvider)


def test_member_cannot_modify_settings_admin_can_and_cross_org_isolated(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_admin = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_member_wrong_jwt = make_token(sub=clerk_a, org_id=org_a, org_role="org:member")
    assert client.get("/v1/me", headers=_auth(token_admin)).status_code == 200
    user_a = _local_user(db_session, clerk_a)
    org_id = _org_id(client, token_admin)

    member_put = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token_member_wrong_jwt),
        json={
            "email_enabled": True,
            "email_min_priority": "medium",
            "recipient_user_ids": [str(user_a.id)],
        },
    )
    assert member_put.status_code == 403, member_put.text

    admin_put = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token_admin),
        json={
            "email_enabled": True,
            "email_min_priority": "medium",
            "recipient_user_ids": [str(user_a.id)],
        },
    )
    assert admin_put.status_code == 200, admin_put.text
    body = admin_put.json()
    assert "recipient_email_snapshot" not in body
    assert body["email_enabled"] is True
    assert body["can_manage"] is True

    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    client.get("/v1/me", headers=_auth(token_b))
    cross = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token_b),
        json={
            "email_enabled": False,
            "email_min_priority": "medium",
            "recipient_user_ids": [],
        },
    )
    assert cross.status_code == 404


def test_unverified_member_cannot_be_email_recipient(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    clerk_u = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_u] = ClerkUserInfo(
        clerk_user_id=clerk_u,
        email="unverified@example.com",
        name="Unverified",
        email_verified=False,
    )
    fake_clerk.memberships[clerk_u] = [
        ClerkOrgMembership(clerk_org_id=org_a, org_name="Org A", role="org:member")
    ]
    token_u = make_token(sub=clerk_u, org_id=org_a, org_role="org:member")
    assert client.get("/v1/me", headers=_auth(token_u)).status_code == 200
    unverified = _local_user(db_session, clerk_u)
    assert unverified.email_verified is False
    org_id = _org_id(client, token)
    response = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
        json={
            "email_enabled": True,
            "email_min_priority": "medium",
            "recipient_user_ids": [str(unverified.id)],
        },
    )
    assert response.status_code == 400
    settings = client.get(
        f"/v1/organizations/{org_id}/notification-settings", headers=_auth(token)
    ).json()
    assert settings["recipients"] == []


def test_immutable_provider_payload_after_mutating_rebuild_sources(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    _delivery_settings(monkeypatch)
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _target_id, _host = _hsts_alert(
        client, token, dns_resolver, engine, "mail-freeze.example"
    )
    db_session.expire_all()
    rows = _email_rows(db_session)
    assert len(rows) == 1
    row = rows[0]
    snapshot = dict(row.delivery_snapshot or {})
    assert snapshot["recipient_email_snapshot"] == "alice@example.com"
    frozen_request = request_from_snapshot(row.id, snapshot)

    org = db_session.scalar(select(Organization).where(Organization.clerk_org_id == org_a))
    assert org is not None
    org.name = "Renamed Org"
    user.email = "Alice@Example.COM"
    db_session.commit()
    _delivery_settings(
        monkeypatch,
        EMAIL_FROM="other@example.test",
        FRONTEND_URL="https://other.example",
    )

    provider = FakeEmailProvider()
    processed = process_one_email_delivery(
        factory, provider=provider, settings=get_settings()
    )
    assert processed is not None
    assert len(provider.requests) == 1
    sent = provider.requests[0]
    assert sent == frozen_request
    assert sent.to_email == "alice@example.com"
    assert sent.from_email == "Scout Alerts <alerts@example.test>"
    assert "http://localhost:3000/dashboard" in sent.text_body
    assert "https://other.example" not in sent.text_body
    assert "Renamed Org" not in sent.subject
    listed = client.get("/v1/alerts", headers=_auth(token)).json()
    assert listed
    assert "recipient_email_snapshot" not in listed[0]
    assert listed[0]["deliveries"]
    for item in listed[0]["deliveries"]:
        assert "recipient_email" not in item
        assert "text_body" not in item


def test_recipient_identity_change_skips_without_sending(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-identity.example")
    db_session.expire_all()
    user = _local_user(db_session, clerk_a)
    user.email = "new-alice@example.com"
    db_session.commit()
    provider = FakeEmailProvider()
    process_one_email_delivery(factory, provider=provider, settings=settings)
    assert provider.requests == []
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "skipped"
    assert row.last_error_code == SKIP_RECIPIENT_IDENTITY_CHANGED


def test_lease_fencing_stale_worker_cannot_clobber(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-fence.example")
    t0 = datetime.now(timezone.utc)
    db_a = factory()
    try:
        claimed = claim_email_outbox(db_a, now=t0, lease_seconds=1)
        assert claimed is not None
        row, token_a = claimed
        outbox_id = row.id
    finally:
        db_a.close()

    provider = FakeEmailProvider()
    process_one_email_delivery(
        factory,
        provider=provider,
        settings=settings,
        now=t0 + timedelta(seconds=5),
    )
    assert len(provider.requests) == 1
    db_late = factory()
    try:
        owned = complete_claimed_outbox(
            db_late,
            outbox_id=outbox_id,
            processing_token=token_a,
            values={
                "status": "dead",
                "last_error_code": "stale_worker",
                "last_error": "stale_worker",
            },
        )
        assert owned is False
        current = db_late.get(NotificationOutbox, outbox_id)
        assert current is not None
        assert current.status == "delivered"
        assert current.last_error_code is None
        assert current.processing_token is None
    finally:
        db_late.close()


def test_delivery_pause_leaves_pending_then_reenable_delivers(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("EMAIL_FROM", "Scout Alerts <alerts@example.test>")
    monkeypatch.setenv("EMAIL_DELIVERY_ENABLED", "false")
    monkeypatch.setenv("EMAIL_PROVIDER", "fake")
    reset_settings_cache()
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-pause.example")
    provider = FakeEmailProvider()
    result = process_one_email_delivery(
        factory, provider=provider, settings=get_settings()
    )
    assert result is None
    assert provider.requests == []
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "pending"

    settings = _delivery_settings(monkeypatch)
    process_one_email_delivery(factory, provider=provider, settings=settings)
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "delivered"
    assert len(provider.requests) == 1


def test_invalid_provider_config_fails_readiness_without_dead_letter(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("EMAIL_FROM", "Scout Alerts <alerts@example.test>")
    reset_settings_cache()
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-config.example")
    settings = _delivery_settings(
        monkeypatch,
        EMAIL_DELIVERY_ENABLED="true",
        EMAIL_PROVIDER="resend",
        EMAIL_API_KEY="",
        EMAIL_FROM="",
    )
    provider = FakeEmailProvider()
    try:
        process_one_email_delivery(factory, provider=provider, settings=settings)
        raise AssertionError("expected NotificationWorkerNotReady")
    except NotificationWorkerNotReady:
        pass
    assert provider.requests == []
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "pending"
    assert row.last_error_code is None


def test_retry_reuses_idempotency_key_and_frozen_payload(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-retry.example")
    provider = FakeEmailProvider()
    provider.next_result = EmailSendResult(
        outcome="retryable", error_code="provider_retryable", error_message="provider_retryable"
    )
    process_one_email_delivery(factory, provider=provider, settings=settings)
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "failed"
    first = provider.requests[0]
    provider.next_result = None
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    process_one_email_delivery(
        factory, provider=provider, settings=settings, now=later
    )
    assert len(provider.requests) == 2
    assert provider.requests[1] == first
    assert provider.requests[1].idempotency_key == str(row.id)
    db_session.expire_all()
    assert _email_rows(db_session)[0].status == "delivered"


def test_unchanged_episode_creates_no_email_reopen_creates_one(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    domain = "mail-reopen.example"
    host = f"hsts.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    present = {domain: _https_html(domain), host: _https_html(host, hsts=True)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False)}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    db_session.expire_all()
    assert _email_rows(db_session) == []
    assert list(db_session.scalars(select(Alert)).all()) == []

    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    db_session.expire_all()
    assert len(_email_rows(db_session)) == 1

    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    db_session.expire_all()
    assert len(_email_rows(db_session)) == 1
    assert len(list(db_session.scalars(select(Alert)).all())) == 1

    _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    db_session.expire_all()
    assert len(list(db_session.scalars(select(Alert)).all())) == 2
    assert len(_email_rows(db_session)) == 2

    alerts = client.get("/v1/alerts", headers=_auth(token)).json()
    first_id = alerts[1]["id"] if alerts[0]["created_at"] > alerts[1]["created_at"] else alerts[0]["id"]
    before = [(row.status, row.attempt_count, row.available_at) for row in _email_rows(db_session)]
    assert client.post(f"/v1/alerts/{first_id}/read", headers=_auth(token)).status_code == 200
    assert client.post(f"/v1/alerts/{first_id}/dismiss", headers=_auth(token)).status_code == 200
    assert client.post(f"/v1/alerts/{first_id}/acknowledge", headers=_auth(token)).status_code == 200
    db_session.expire_all()
    after = [(row.status, row.attempt_count, row.available_at) for row in _email_rows(db_session)]
    assert after == before
    assert all(row.status == "pending" for row in _email_rows(db_session))

    provider = FakeEmailProvider()
    process_one_email_delivery(factory, provider=provider, settings=settings)
    process_one_email_delivery(factory, provider=provider, settings=settings)
    assert len(provider.requests) == 2
    assert isinstance(provider, FakeEmailProvider)


def test_staging_destination_not_allowed_skips_without_provider_call(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("EMAIL_FROM", "Scout Alerts <alerts@example.test>")
    reset_settings_cache()
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)])
    factory, _, _ = _hsts_alert(client, token, dns_resolver, engine, "mail-staging.example")
    from types import SimpleNamespace

    settings = SimpleNamespace(
        email_delivery_enabled=True,
        email_provider="resend",
        environment="staging",
        email_api_key="re_dummy",
        email_from="Scout Alerts <alerts@example.test>",
        staging_email_allowlist={"allowed@example.com"},
        notification_lease_seconds=300,
    )
    provider = FakeEmailProvider()
    process_one_email_delivery(factory, provider=provider, settings=settings)
    assert provider.requests == []
    db_session.expire_all()
    row = _email_rows(db_session)[0]
    assert row.status == "skipped"
    assert row.last_error_code == SKIP_STAGING_DESTINATION


def test_low_priority_not_enqueued_when_min_is_medium(
    client, make_token, seed_user_a, dns_resolver, engine, db_session, monkeypatch
):
    monkeypatch.setenv("EMAIL_FROM", "Scout Alerts <alerts@example.test>")
    reset_settings_cache()
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a)
    client.get("/v1/me", headers=_auth(token))
    user = _local_user(db_session, clerk_a)
    _enable_org_email(client, token, [str(user.id)], min_priority="medium")
    domain = "mail-low.example"
    extra = f"gap.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    first_tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, extra]},
        probes_by_host={
            domain: _https_html(domain, hsts=True),
            extra: _https_html(extra, hsts=True),
        },
    )
    second_tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, extra]},
        probes_by_host={
            domain: _https_html(domain, hsts=True),
            extra: ProbeResult(
                url=f"https://{extra}/",
                status_code=None,
                title=None,
                headers_observed=False,
                headers={},
                headers_present=(),
                content_type=None,
                scheme="https",
                redirected=False,
                requested_url=f"https://{extra}/",
                final_url=f"https://{extra}/",
                outcome="no_result",
            ),
        },
    )
    _queue(client, token, target_id)
    _run(factory, first_tools)
    _queue(client, token, target_id)
    _run(factory, second_tools)
    db_session.expire_all()
    alerts = list(db_session.scalars(select(Alert)).all())
    assert alerts
    assert all(row.priority != "medium" for row in alerts)
    assert _email_rows(db_session) == []
"""Milestone 34 — finding follow-up reminders."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings, reset_settings_cache
from app.models.finding import Finding
from app.models.finding_follow_up_reminder import FindingFollowUpReminderJob
from app.models.user import User
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.email_provider import EmailSendResult, FakeEmailProvider
from app.services.findings.follow_up_reminders import (
    SKIP_ASSIGNEE_NOT_MEMBER,
    SKIP_GENERATION_CHANGED,
    SKIP_NO_DELIVERABLE_EMAIL,
    SKIP_RECIPIENT_CHANGED,
    RETRY_IDENTITY_PROVIDER_UNAVAILABLE,
    discover_follow_up_reminder_jobs,
    process_one_follow_up_reminder,
    resolve_current_follow_up_generation,
)
from app.services.scheduler_runtime import (
    maybe_discover_follow_up_reminders,
    reset_follow_up_discovery_throttle_for_tests,
)
from tests.test_finding_follow_up import _finding


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _reset_settings_and_throttle(fake_clerk):
    reset_settings_cache()
    reset_follow_up_discovery_throttle_for_tests()
    fake_clerk.fail_get_user = False
    fake_clerk.fail_memberships = False
    yield
    reset_settings_cache()
    reset_follow_up_discovery_throttle_for_tests()
    fake_clerk.fail_get_user = False
    fake_clerk.fail_memberships = False


def _ensure_org(client, fake_clerk, make_token):
    """Create admin + org using the same pattern as M33 tests."""
    clerk_id = f"clerk_m34_{uuid4().hex[:8]}"
    org_clerk = f"org_m34_{uuid4().hex[:8]}"
    fake_clerk.users[clerk_id] = ClerkUserInfo(
        clerk_user_id=clerk_id,
        email=f"{clerk_id}@example.com",
        name="Admin",
        email_verified=True,
    )
    fake_clerk.memberships[clerk_id] = [
        ClerkOrgMembership(clerk_org_id=org_clerk, org_name="M34 Org", role="org:admin")
    ]
    token = make_token(sub=clerk_id, org_id=org_clerk, org_role="org:admin")
    me = client.get("/v1/me", headers=_auth(token))
    assert me.status_code == 200, me.text
    body = me.json()
    return token, clerk_id, UUID(body["id"]), UUID(body["active_organization_id"]), org_clerk


def _add_member(fake_clerk, *, clerk_id: str, org_clerk: str, email: str | None = None):
    fake_clerk.users[clerk_id] = ClerkUserInfo(
        clerk_user_id=clerk_id,
        email=email or f"{clerk_id}@example.com",
        name=clerk_id,
        email_verified=True,
    )
    fake_clerk.memberships[clerk_id] = [
        ClerkOrgMembership(clerk_org_id=org_clerk, org_name="M34 Org", role="org:member")
    ]


def _enable_reminders(client, token: str, org_id: UUID, *, enabled: bool = True):
    response = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
        json={
            "email_enabled": False,
            "email_min_priority": "medium",
            "finding_follow_up_reminders_enabled": enabled,
            "recipient_user_ids": [],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["finding_follow_up_reminders_enabled"] is enabled
    return response.json()


def _assign_follow_up(
    client,
    token: str,
    finding_id: UUID,
    *,
    assignee_user_id: UUID,
    due_at: datetime,
):
    response = client.put(
        f"/v1/findings/{finding_id}/follow-up",
        headers=_auth(token),
        json={
            "assigned_to_user_id": str(assignee_user_id),
            "follow_up_due_at": due_at.isoformat(),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _sync_member(client, make_token, fake_clerk, *, clerk_id: str, org_clerk: str):
    token = make_token(sub=clerk_id, org_id=org_clerk, org_role="org:member")
    assert client.get("/v1/me", headers=_auth(token)).status_code == 200
    return token


def _jobs(db) -> list[FindingFollowUpReminderJob]:
    return list(db.scalars(select(FindingFollowUpReminderJob)).all())


def _delivery_settings(monkeypatch, **env: str):
    for key, value in {
        "EMAIL_DELIVERY_ENABLED": "true",
        "EMAIL_PROVIDER": "fake",
        "EMAIL_FROM": "scout@example.com",
        "ENVIRONMENT": "test",
        **env,
    }.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()
    return get_settings()


def test_reminders_default_off(client, fake_clerk, make_token, db_session):
    token, _clerk, _uid, org_id, _org = _ensure_org(client, fake_clerk, make_token)
    got = client.get(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
    )
    assert got.status_code == 200
    assert got.json()["finding_follow_up_reminders_enabled"] is False
    assert discover_follow_up_reminder_jobs(db_session) == 0


def test_opt_in_and_disable_soft_wait(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, admin_clerk, admin_uid, org_id, org_clerk = _ensure_org(
        client, fake_clerk, make_token
    )
    assignee_clerk = f"clerk_assignee_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    assert assignee is not None

    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    db_session.expire_all()

    assert discover_follow_up_reminder_jobs(db_session) == 0
    _enable_reminders(client, token, org_id, enabled=True)
    db_session.expire_all()
    assert discover_follow_up_reminder_jobs(db_session) == 1
    jobs = _jobs(db_session)
    assert len(jobs) == 1
    assert jobs[0].status == "pending"

    provider = FakeEmailProvider()
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert (
        process_one_follow_up_reminder(
            factory, provider=provider, settings=settings, directory=fake_clerk
        )
        is not None
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "delivered"
    assert len(provider.requests) == 1

    # Disable: pending soft-wait (create new past-due generation)
    _enable_reminders(client, token, org_id, enabled=False)
    due2 = datetime.now(UTC) - timedelta(minutes=30)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due2
    )
    _enable_reminders(client, token, org_id, enabled=True)
    assert discover_follow_up_reminder_jobs(db_session) == 1
    _enable_reminders(client, token, org_id, enabled=False)
    # Claim should not pick disabled-org jobs
    assert (
        process_one_follow_up_reminder(
            factory, provider=provider, settings=settings, directory=fake_clerk
        )
        is None
    )
    pending = [j for j in _jobs(db_session) if j.status == "pending"]
    assert len(pending) == 1


def test_generation_identity_restore_same_owner_due(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_gen_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    assert assignee is not None
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)

    due_a = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due_a
    )
    # Force due into the past for discovery without rewriting history: update
    # available path by setting due in the past via another change... Use past dues.
    due_a = datetime.now(UTC) - timedelta(days=3)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due_a
    )
    db_session.expire_all()
    gen_a = resolve_current_follow_up_generation(db_session, db_session.get(Finding, finding.id))
    assert gen_a is not None
    assert discover_follow_up_reminder_jobs(db_session) == 1
    job_a_id = _jobs(db_session)[0].id
    assert _jobs(db_session)[0].follow_up_change_id == gen_a.id

    due_b = datetime.now(UTC) - timedelta(days=2)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due_b
    )
    db_session.expire_all()
    gen_b = resolve_current_follow_up_generation(db_session, db_session.get(Finding, finding.id))
    assert gen_b is not None and gen_b.id != gen_a.id
    assert discover_follow_up_reminder_jobs(db_session) == 1
    assert {j.follow_up_change_id for j in _jobs(db_session)} == {gen_a.id, gen_b.id}

    # Restore exact A values → new generation C
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due_a
    )
    db_session.expire_all()
    gen_c = resolve_current_follow_up_generation(db_session, db_session.get(Finding, finding.id))
    assert gen_c is not None and gen_c.id not in {gen_a.id, gen_b.id}
    assert discover_follow_up_reminder_jobs(db_session) == 1
    assert len(_jobs(db_session)) == 3
    assert any(j.follow_up_change_id == gen_c.id for j in _jobs(db_session))
    # A does not block C
    assert any(j.id == job_a_id for j in _jobs(db_session))

    # Stale job A suppressed on send after generation moved (then restored to C)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    # Process until jobs drain or a few iterations
    for _ in range(5):
        process_one_follow_up_reminder(
            factory, provider=provider, settings=settings, directory=fake_clerk
        )
    db_session.expire_all()
    by_gen = {j.follow_up_change_id: j for j in _jobs(db_session)}
    assert by_gen[gen_a.id].status == "skipped"
    assert by_gen[gen_a.id].last_error_code == SKIP_GENERATION_CHANGED
    assert by_gen[gen_b.id].status == "skipped"
    assert by_gen[gen_b.id].last_error_code == SKIP_GENERATION_CHANGED
    assert by_gen[gen_c.id].status == "delivered"
    assert len(provider.requests) == 1


def test_duplicate_discovery_same_generation(client, fake_clerk, make_token, db_session):
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_dup_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=2)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    assert discover_follow_up_reminder_jobs(db_session) == 0
    assert len(_jobs(db_session)) == 1


def test_authoritative_non_member_skipped(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_leave_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    # Depart
    fake_clerk.memberships[assignee_clerk] = []
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    job = _jobs(db_session)[0]
    assert job.status == "skipped"
    assert job.last_error_code == SKIP_ASSIGNEE_NOT_MEMBER
    assert provider.requests == []


def test_transient_membership_failure_retries(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_flaky_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1

    fake_clerk.fail_memberships = True
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    job = _jobs(db_session)[0]
    assert job.status == "failed"
    assert job.last_error_code == RETRY_IDENTITY_PROVIDER_UNAVAILABLE
    assert provider.requests == []

    fake_clerk.fail_memberships = False
    job.available_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "delivered"
    assert len(provider.requests) == 1


def test_no_verified_email_skipped(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_unver_{uuid4().hex[:6]}"
    fake_clerk.users[assignee_clerk] = ClerkUserInfo(
        clerk_user_id=assignee_clerk,
        email=f"{assignee_clerk}@example.com",
        name="Unverified",
        email_verified=False,
    )
    fake_clerk.memberships[assignee_clerk] = [
        ClerkOrgMembership(clerk_org_id=org_clerk, org_name="M34 Org", role="org:member")
    ]
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    # Local stale verified email must NOT be used when Clerk says unverified
    assignee.email_verified = True
    db_session.commit()
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "skipped"
    assert _jobs(db_session)[0].last_error_code == SKIP_NO_DELIVERABLE_EMAIL
    assert provider.requests == []


def test_transient_email_lookup_retries(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_emfail_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    fake_clerk.fail_get_user = True
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "failed"
    assert _jobs(db_session)[0].last_error_code == RETRY_IDENTITY_PROVIDER_UNAVAILABLE
    assert provider.requests == []
    fake_clerk.fail_get_user = False


def test_frozen_destination_recipient_changed(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_freeze_{uuid4().hex[:6]}"
    _add_member(
        fake_clerk,
        clerk_id=assignee_clerk,
        org_clerk=org_clerk,
        email="alice@example.com",
    )
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    provider.next_result = EmailSendResult(
        outcome="retryable", error_code="provider_unavailable"
    )
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    job = _jobs(db_session)[0]
    assert job.status == "failed"
    assert job.delivery_snapshot is not None
    frozen = job.delivery_snapshot["recipient_email_snapshot"]
    assert frozen == "alice@example.com"
    idem = str(job.id)
    assert len(provider.requests) == 1
    assert provider.requests[0].idempotency_key == idem

    # Change authoritative email before retry
    fake_clerk.users[assignee_clerk] = ClerkUserInfo(
        clerk_user_id=assignee_clerk,
        email="alice-new@example.com",
        name="Alice",
        email_verified=True,
    )
    provider.next_result = None
    job.available_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    job = _jobs(db_session)[0]
    assert job.status == "skipped"
    assert job.last_error_code == SKIP_RECIPIENT_CHANGED
    assert job.delivery_snapshot["recipient_email_snapshot"] == frozen
    assert len(provider.requests) == 1
    assert provider.requests[0].to_email == "alice@example.com"


def test_email_delivery_paused(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    monkeypatch.setenv("EMAIL_DELIVERY_ENABLED", "false")
    monkeypatch.setenv("EMAIL_PROVIDER", "fake")
    monkeypatch.setenv("EMAIL_FROM", "scout@example.com")
    monkeypatch.setenv("ENVIRONMENT", "test")
    reset_settings_cache()
    settings = get_settings()

    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_pause_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    assert (
        process_one_follow_up_reminder(
            factory, provider=provider, settings=settings, directory=fake_clerk
        )
        is None
    )
    assert _jobs(db_session)[0].status == "pending"
    assert provider.requests == []

    monkeypatch.setenv("EMAIL_DELIVERY_ENABLED", "true")
    reset_settings_cache()
    settings = get_settings()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "delivered"


def test_no_history_no_invented_generation(client, fake_clerk, make_token, db_session):
    token, _ac, admin_uid, org_id, _org = _ensure_org(client, fake_clerk, make_token)
    _enable_reminders(client, token, org_id)
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    finding.assigned_to_user_id = admin_uid
    finding.follow_up_due_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.commit()
    assert resolve_current_follow_up_generation(db_session, finding) is None
    assert discover_follow_up_reminder_jobs(db_session) == 0


def test_scheduler_throttle_discovery(client, fake_clerk, make_token, db_session, engine):
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_sched_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert maybe_discover_follow_up_reminders(factory, force=True) == 1
    assert maybe_discover_follow_up_reminders(factory, force=False) == 0


def test_resolved_finding_skipped(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_res_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    finding = db_session.get(Finding, finding.id)
    assert finding is not None
    finding.status = "resolved"
    finding.resolved_at = datetime.now(UTC)
    db_session.commit()
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    db_session.expire_all()
    assert _jobs(db_session)[0].status == "skipped"
    assert provider.requests == []


def test_reminder_content_has_required_framing_no_secrets(
    client, fake_clerk, make_token, db_session, engine, monkeypatch
):
    settings = _delivery_settings(monkeypatch)
    token, _ac, admin_uid, org_id, org_clerk = _ensure_org(client, fake_clerk, make_token)
    assignee_clerk = f"clerk_copy_{uuid4().hex[:6]}"
    _add_member(fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    _sync_member(client, make_token, fake_clerk, clerk_id=assignee_clerk, org_clerk=org_clerk)
    assignee = db_session.scalar(select(User).where(User.clerk_user_id == assignee_clerk))
    finding = _finding(db_session, organization_id=org_id, user_id=admin_uid)
    db_session.commit()
    _enable_reminders(client, token, org_id)
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign_follow_up(
        client, token, finding.id, assignee_user_id=assignee.id, due_at=due
    )
    assert discover_follow_up_reminder_jobs(db_session) == 1
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    provider = FakeEmailProvider()
    process_one_follow_up_reminder(
        factory, provider=provider, settings=settings, directory=fake_clerk
    )
    assert len(provider.requests) == 1
    body = provider.requests[0].text_body
    assert "follow-up date chosen by your organization" in body.lower()
    assert "passing retest is required" in body.lower()
    assert "remediation guidance" not in body.lower()
    assert "bearer" not in body.lower()
    assert "/share/" not in body

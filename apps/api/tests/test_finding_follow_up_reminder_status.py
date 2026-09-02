"""Milestone 35 — finding follow-up reminder delivery status (read-only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker

from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import (
    REMINDER_KIND_DUE,
    FindingFollowUpReminderJob,
)
from app.models.notification import OrganizationNotificationSettings
from app.services.findings.follow_up_reminder_status import (
    INVALID_HISTORY_CURSOR_DETAIL,
    list_finding_follow_up_reminders,
    project_safe_reason,
)
from app.services.findings.follow_up_reminders import resolve_current_follow_up_generation
from tests.test_finding_follow_up import (
    _add_clerk_member,
    _assert_no_email,
    _auth,
    _finding,
    _ids,
    _put_follow_up,
)


# --------------------------------------------------------------------------- helpers


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


def _status(client, token: str, finding_id: UUID):
    return client.get(
        f"/v1/findings/{finding_id}/follow-up-reminder",
        headers=_auth(token),
    )


def _history(client, token: str, finding_id: UUID, **params):
    return client.get(
        f"/v1/findings/{finding_id}/follow-up-reminders",
        headers=_auth(token),
        params=params or None,
    )


def _assign(
    client,
    token: str,
    finding_id: UUID,
    *,
    assignee_user_id: UUID,
    due_at: datetime,
):
    response = _put_follow_up(
        client,
        token,
        finding_id,
        {
            "assigned_to_user_id": str(assignee_user_id),
            "follow_up_due_at": due_at.isoformat(),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _current_change(db, finding_id: UUID) -> FindingFollowUpChange:
    change = db.scalar(
        select(FindingFollowUpChange)
        .where(FindingFollowUpChange.finding_id == finding_id)
        .order_by(
            FindingFollowUpChange.created_at.desc(),
            FindingFollowUpChange.id.desc(),
        )
        .limit(1)
    )
    assert change is not None
    return change


def _insert_job(
    db,
    *,
    organization_id: UUID,
    finding_id: UUID,
    follow_up_change_id: UUID,
    assigned_to_user_id: UUID,
    due_at: datetime,
    status: str = "pending",
    last_error_code: str | None = None,
    last_error: str | None = None,
    delivered_at: datetime | None = None,
    attempt_count: int = 0,
    created_at: datetime | None = None,
    available_at: datetime | None = None,
    processing_token=None,
    delivery_snapshot: dict | None = None,
) -> FindingFollowUpReminderJob:
    moment = available_at or datetime.now(UTC)
    job = FindingFollowUpReminderJob(
        organization_id=organization_id,
        finding_id=finding_id,
        follow_up_change_id=follow_up_change_id,
        assigned_to_user_id=assigned_to_user_id,
        due_at=due_at,
        reminder_kind=REMINDER_KIND_DUE,
        status=status,
        available_at=moment,
        attempt_count=attempt_count,
        last_error_code=last_error_code,
        last_error=last_error,
        delivered_at=delivered_at,
        processing_token=processing_token,
        delivery_snapshot=delivery_snapshot,
    )
    if created_at is not None:
        job.created_at = created_at
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _job_count(db) -> int:
    return int(db.scalar(select(func.count()).select_from(FindingFollowUpReminderJob)) or 0)


def _assert_privacy(payload) -> None:
    """Customer JSON must omit internal ids, secrets, emails, and membership flags."""
    _assert_no_email(payload)
    raw = str(payload)
    for forbidden in (
        "follow_up_change_id",
        "processing_token",
        "delivery_snapshot",
        "recipient_email",
        "clerk",
        "current_member",
    ):
        assert forbidden not in raw, forbidden
    # last_error as a key (not merely a substring of safe labels)
    if isinstance(payload, dict):
        assert "last_error" not in payload
        assert "id" not in payload  # no top-level job id
        for key, value in payload.items():
            assert "job" not in key.lower() or key in {"reminder_kind"}, key
            if isinstance(value, (dict, list)):
                _assert_privacy_keys(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_privacy_keys(item)


def _assert_privacy_keys(payload) -> None:
    _assert_no_email(payload)
    if isinstance(payload, dict):
        assert "email" not in payload
        assert "current_member" not in payload
        assert "follow_up_change_id" not in payload
        assert "processing_token" not in payload
        assert "delivery_snapshot" not in payload
        assert "last_error" not in payload
        assert "recipient_email" not in payload
        for key in payload:
            assert "clerk" not in key.lower()
            # history items must not expose job primary keys
            assert key not in {"id", "job_id", "reminder_job_id"}
        for value in payload.values():
            if isinstance(value, (dict, list)):
                _assert_privacy_keys(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_privacy_keys(item)


def _setup_org(client, make_token, seed_user_a, fake_clerk, db_session):
    admin_clerk, clerk_org = seed_user_a
    token = make_token(sub=admin_clerk, org_id=clerk_org, org_role="org:admin")
    admin_id, org_id = _ids(client, token)
    member_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=clerk_org, name="Assignee"
    )
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)
    finding = _finding(db_session, organization_id=org_id, user_id=admin_id)
    return {
        "admin_clerk": admin_clerk,
        "clerk_org": clerk_org,
        "token": token,
        "admin_id": admin_id,
        "org_id": org_id,
        "member_clerk": member_clerk,
        "member_token": member_token,
        "member_id": member_id,
        "finding": finding,
    }


# --------------------------------------------------------------------------- unit: project_safe_reason


def test_project_safe_reason_mappings():
    code, label = project_safe_reason(
        customer_state="retrying",
        last_error_code="identity_provider_unavailable",
    )
    assert code == "identity_provider_unavailable"
    assert label is not None
    assert "retri" in label.lower()  # retry / retried

    code, label = project_safe_reason(
        customer_state="retrying",
        last_error_code="provider_timeout",
    )
    assert code == "delivery_temporarily_unavailable"
    assert label is not None
    assert code != "provider_timeout"
    assert "provider_timeout" not in (label or "")

    code, label = project_safe_reason(
        customer_state="dead",
        last_error_code="provider_permanent_failure",
    )
    assert code == "delivery_issue"
    assert "provider_" not in (code or "")

    code, label = project_safe_reason(
        customer_state="dead",
        last_error_code="unknown_code_xyz",
    )
    assert code == "delivery_issue"

    code, label = project_safe_reason(
        customer_state="skipped",
        last_error_code="finding_resolved",
    )
    assert code == "finding_resolved"
    assert label is not None

    code, label = project_safe_reason(
        customer_state="skipped",
        last_error_code="owner_changed",
    )
    assert code == "owner_changed"

    # Quiet states never surface a reason
    for quiet in (
        "disabled",
        "not_applicable",
        "generation_unavailable",
        "scheduled_for_future",
        "awaiting_discovery",
        "pending",
        "processing",
        "delivered",
    ):
        assert project_safe_reason(
            customer_state=quiet, last_error_code="provider_timeout"
        ) == (None, None)


# --------------------------------------------------------------------------- current generation


def test_current_generation_maps_job_state(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=2)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    db_session.expire_all()
    change = _current_change(db_session, ctx["finding"].id)
    job = _insert_job(
        db_session,
        organization_id=ctx["org_id"],
        finding_id=ctx["finding"].id,
        follow_up_change_id=change.id,
        assigned_to_user_id=ctx["member_id"],
        due_at=due,
        status="pending",
    )

    response = _status(client, ctx["token"], ctx["finding"].id)
    assert response.status_code == 200, response.text
    body = response.json()
    _assert_privacy(body)
    assert body["state"] == "pending"
    assert body["reminders_enabled"] is True
    assert body["reminder"] is not None
    assert body["reminder"]["created_at"] is not None
    assert body["current_generation"]["owner"]["user_id"] == str(ctx["member_id"])
    assert body["current_generation"]["owner"]["display_name"] == "Assignee"
    assert UUID(body["finding_id"]) == ctx["finding"].id
    # Ensure mapped state tracks this job, not a phantom
    assert job.status == "pending"


def test_current_generation_ignores_older_delivered_job(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    due_old = datetime.now(UTC) - timedelta(days=2)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due_old,
    )
    db_session.expire_all()
    old_change = _current_change(db_session, ctx["finding"].id)
    _insert_job(
        db_session,
        organization_id=ctx["org_id"],
        finding_id=ctx["finding"].id,
        follow_up_change_id=old_change.id,
        assigned_to_user_id=ctx["member_id"],
        due_at=due_old,
        status="delivered",
        delivered_at=datetime.now(UTC) - timedelta(hours=1),
        created_at=datetime.now(UTC) - timedelta(days=1),
    )

    due_new = datetime.now(UTC) - timedelta(hours=3)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due_new,
    )
    db_session.expire_all()
    new_change = _current_change(db_session, ctx["finding"].id)
    assert new_change.id != old_change.id
    _insert_job(
        db_session,
        organization_id=ctx["org_id"],
        finding_id=ctx["finding"].id,
        follow_up_change_id=new_change.id,
        assigned_to_user_id=ctx["member_id"],
        due_at=due_new,
        status="pending",
    )

    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "pending"
    assert body["reminder"]["delivered_at"] is None


def test_owner_or_due_change_makes_old_job_not_current(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    due = datetime.now(UTC) - timedelta(hours=4)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    db_session.expire_all()
    old_change = _current_change(db_session, ctx["finding"].id)
    _insert_job(
        db_session,
        organization_id=ctx["org_id"],
        finding_id=ctx["finding"].id,
        follow_up_change_id=old_change.id,
        assigned_to_user_id=ctx["member_id"],
        due_at=due,
        status="delivered",
        delivered_at=datetime.now(UTC),
    )

    # Owner change → new generation; old delivered job must not surface as current
    other_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=ctx["clerk_org"], name="Other"
    )
    other_token = make_token(
        sub=other_clerk, org_id=ctx["clerk_org"], org_role="org:member"
    )
    other_id, _ = _ids(client, other_token)
    new_due = datetime.now(UTC) - timedelta(hours=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=other_id,
        due_at=new_due,
    )

    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "awaiting_discovery"
    assert body["reminder"] is None
    assert body["current_generation"]["owner"]["user_id"] == str(other_id)


def test_legacy_owner_due_without_matching_generation(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    finding = db_session.get(Finding, ctx["finding"].id)
    assert finding is not None
    finding.assigned_to_user_id = ctx["member_id"]
    finding.follow_up_due_at = datetime.now(UTC) - timedelta(hours=1)
    db_session.commit()

    assert (
        resolve_current_follow_up_generation(db_session, finding) is None
    )
    before = _job_count(db_session)

    response = _status(client, ctx["token"], ctx["finding"].id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "generation_unavailable"
    assert body["reminder"] is None
    assert body["current_generation"] is not None
    assert body["current_generation"]["owner"]["user_id"] == str(ctx["member_id"])
    _assert_privacy(body)

    assert _job_count(db_session) == before

    # Mismatching history row also yields generation_unavailable
    db_session.add(
        FindingFollowUpChange(
            organization_id=ctx["org_id"],
            finding_id=ctx["finding"].id,
            changed_by_user_id=ctx["admin_id"],
            previous_assigned_to_user_id=None,
            new_assigned_to_user_id=ctx["admin_id"],  # mismatch vs finding
            previous_due_at=None,
            new_due_at=datetime.now(UTC) - timedelta(days=5),
        )
    )
    db_session.commit()
    body2 = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body2["state"] == "generation_unavailable"
    assert body2["reminder"] is None
    assert _job_count(db_session) == before


# --------------------------------------------------------------------------- states


def test_state_disabled(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    # Default off; also set explicitly
    settings = db_session.scalar(
        select(OrganizationNotificationSettings).where(
            OrganizationNotificationSettings.organization_id == ctx["org_id"]
        )
    )
    if settings is not None:
        settings.finding_follow_up_reminders_enabled = False
        db_session.commit()

    due = datetime.now(UTC) + timedelta(days=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "disabled"
    assert body["reminders_enabled"] is False
    assert body["reminder"] is None


def test_state_resolved_not_applicable(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    finding = db_session.get(Finding, ctx["finding"].id)
    assert finding is not None
    finding.status = "resolved"
    finding.resolved_at = datetime.now(UTC)
    db_session.commit()

    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "not_applicable"
    assert body["reminder"] is None


def test_state_no_owner_not_applicable(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "not_applicable"
    assert body["current_generation"] is None
    assert body["reminder"] is None


def test_state_scheduled_for_future(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) + timedelta(days=3)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "scheduled_for_future"
    assert body["reminder"] is None
    assert body["current_generation"] is not None


def test_state_awaiting_discovery(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=2)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    assert _job_count(db_session) == 0
    body = _status(client, ctx["token"], ctx["finding"].id).json()
    assert body["state"] == "awaiting_discovery"
    assert body["reminder"] is None


def test_db_job_status_mappings(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    db_session.expire_all()
    change = _current_change(db_session, ctx["finding"].id)

    cases = [
        ("pending", "pending", None, None),
        ("processing", "processing", None, None),
        ("failed", "retrying", "provider_timeout", "delivery_temporarily_unavailable"),
        ("delivered", "delivered", None, None),
        ("skipped", "skipped", "owner_changed", "owner_changed"),
        ("dead", "dead", "provider_timeout", "delivery_issue"),
    ]
    for db_status, customer_state, err, safe in cases:
        # One job per generation: replace in place
        existing = db_session.scalar(
            select(FindingFollowUpReminderJob).where(
                FindingFollowUpReminderJob.follow_up_change_id == change.id
            )
        )
        if existing is None:
            _insert_job(
                db_session,
                organization_id=ctx["org_id"],
                finding_id=ctx["finding"].id,
                follow_up_change_id=change.id,
                assigned_to_user_id=ctx["member_id"],
                due_at=due,
                status=db_status,
                last_error_code=err,
                last_error="INTERNAL DO NOT LEAK" if err else None,
                delivered_at=datetime.now(UTC) if db_status == "delivered" else None,
                delivery_snapshot={"recipient_email": "secret@example.com"}
                if err
                else None,
                processing_token=uuid4() if db_status == "processing" else None,
            )
        else:
            existing.status = db_status
            existing.last_error_code = err
            existing.last_error = "INTERNAL DO NOT LEAK" if err else None
            existing.delivered_at = (
                datetime.now(UTC) if db_status == "delivered" else None
            )
            existing.delivery_snapshot = (
                {"recipient_email": "secret@example.com"} if err else None
            )
            existing.processing_token = (
                uuid4() if db_status == "processing" else None
            )
            db_session.commit()

        response = _status(client, ctx["token"], ctx["finding"].id)
        assert response.status_code == 200, response.text
        body = response.json()
        _assert_privacy(body)
        assert body["state"] == customer_state, (db_status, body)
        if safe is None:
            assert body["reminder"]["safe_reason_code"] is None
        else:
            assert body["reminder"]["safe_reason_code"] == safe
            assert body["reminder"]["safe_reason_label"] is not None
            assert "provider_timeout" not in body["reminder"]["safe_reason_code"]
            assert "INTERNAL" not in str(body)
            assert "last_error" not in body["reminder"]


def test_safe_reasons_via_status_endpoint(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    db_session.expire_all()
    change = _current_change(db_session, ctx["finding"].id)

    scenarios = [
        (
            "failed",
            "identity_provider_unavailable",
            "retrying",
            "identity_provider_unavailable",
            "retri",
        ),
        (
            "failed",
            "provider_timeout",
            "retrying",
            "delivery_temporarily_unavailable",
            None,
        ),
        (
            "dead",
            "provider_permanent_failure",
            "dead",
            "delivery_issue",
            None,
        ),
        ("dead", "unknown_code_xyz", "dead", "delivery_issue", None),
        (
            "skipped",
            "finding_resolved",
            "skipped",
            "finding_resolved",
            None,
        ),
    ]
    for db_status, err, state, safe, label_hint in scenarios:
        existing = db_session.scalar(
            select(FindingFollowUpReminderJob).where(
                FindingFollowUpReminderJob.follow_up_change_id == change.id
            )
        )
        if existing is None:
            _insert_job(
                db_session,
                organization_id=ctx["org_id"],
                finding_id=ctx["finding"].id,
                follow_up_change_id=change.id,
                assigned_to_user_id=ctx["member_id"],
                due_at=due,
                status=db_status,
                last_error_code=err,
                last_error=f"raw:{err}",
            )
        else:
            existing.status = db_status
            existing.last_error_code = err
            existing.last_error = f"raw:{err}"
            db_session.commit()

        body = _status(client, ctx["token"], ctx["finding"].id).json()
        _assert_privacy(body)
        assert body["state"] == state
        assert body["reminder"]["safe_reason_code"] == safe
        assert not str(body["reminder"]["safe_reason_code"]).startswith("provider_")
        assert "last_error" not in body["reminder"]
        assert f"raw:{err}" not in str(body)
        if label_hint:
            assert label_hint in body["reminder"]["safe_reason_label"].lower()


# --------------------------------------------------------------------------- history


def test_history_newest_first_across_generations(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    dues = [
        datetime.now(UTC) - timedelta(days=3),
        datetime.now(UTC) - timedelta(days=2),
        datetime.now(UTC) - timedelta(days=1),
    ]
    created = [
        datetime.now(UTC) - timedelta(hours=3),
        datetime.now(UTC) - timedelta(hours=2),
        datetime.now(UTC) - timedelta(hours=1),
    ]
    for due, created_at in zip(dues, created, strict=True):
        _assign(
            client,
            ctx["token"],
            ctx["finding"].id,
            assignee_user_id=ctx["member_id"],
            due_at=due,
        )
        db_session.expire_all()
        change = _current_change(db_session, ctx["finding"].id)
        _insert_job(
            db_session,
            organization_id=ctx["org_id"],
            finding_id=ctx["finding"].id,
            follow_up_change_id=change.id,
            assigned_to_user_id=ctx["member_id"],
            due_at=due,
            status="delivered" if due == dues[0] else "pending",
            delivered_at=created_at if due == dues[0] else None,
            created_at=created_at,
        )

    response = _history(client, ctx["token"], ctx["finding"].id, page_size=10)
    assert response.status_code == 200, response.text
    body = response.json()
    _assert_privacy(body)
    assert len(body["items"]) == 3
    times = [item["created_at"] for item in body["items"]]
    assert times == sorted(times, reverse=True)
    assert body["items"][0]["state"] == "pending"
    assert body["items"][-1]["state"] == "delivered"


def test_history_cursor_paging_without_dupes(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    for index in range(5):
        due = datetime.now(UTC) - timedelta(days=5 - index)
        _assign(
            client,
            ctx["token"],
            ctx["finding"].id,
            assignee_user_id=ctx["member_id"],
            due_at=due,
        )
        db_session.expire_all()
        change = _current_change(db_session, ctx["finding"].id)
        _insert_job(
            db_session,
            organization_id=ctx["org_id"],
            finding_id=ctx["finding"].id,
            follow_up_change_id=change.id,
            assigned_to_user_id=ctx["member_id"],
            due_at=due,
            status="pending",
            created_at=datetime.now(UTC) - timedelta(minutes=10 - index),
        )

    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params: dict = {"page_size": 2}
        if cursor:
            params["cursor"] = cursor
        response = _history(client, ctx["token"], ctx["finding"].id, **params)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["page_size"] == 2
        page_keys = [
            f"{item['created_at']}|{item['due_at']}|{item['state']}"
            for item in body["items"]
        ]
        assert len(page_keys) == len(set(page_keys))
        seen.extend(page_keys)
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert pages >= 3
    assert len(seen) == len(set(seen)) == 5


def test_history_malformed_cursor_and_page_size(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    bad = _history(
        client, ctx["token"], ctx["finding"].id, cursor="not-a-cursor"
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["message"] == INVALID_HISTORY_CURSOR_DETAIL

    oversized = _history(client, ctx["token"], ctx["finding"].id, page_size=101)
    assert oversized.status_code == 422


def test_history_cross_org_404(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    other_clerk, other_org = seed_user_b
    other_token = make_token(
        sub=other_clerk, org_id=other_org, org_role="org:admin"
    )
    _ids(client, other_token)

    assert (
        _status(client, other_token, ctx["finding"].id).status_code == 404
    )
    assert (
        _history(client, other_token, ctx["finding"].id).status_code == 404
    )


# --------------------------------------------------------------------------- read-only / query budget


def test_get_is_read_only(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) - timedelta(hours=2)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )
    db_session.expire_all()
    change = _current_change(db_session, ctx["finding"].id)
    job = _insert_job(
        db_session,
        organization_id=ctx["org_id"],
        finding_id=ctx["finding"].id,
        follow_up_change_id=change.id,
        assigned_to_user_id=ctx["member_id"],
        due_at=due,
        status="pending",
        attempt_count=2,
        last_error="keep",
        last_error_code="provider_timeout",
    )

    # Second finding in awaiting_discovery (no job) — GETs must not invent one
    finding2 = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"]
    )
    due2 = datetime.now(UTC) - timedelta(minutes=30)
    _assign(
        client,
        ctx["token"],
        finding2.id,
        assignee_user_id=ctx["member_id"],
        due_at=due2,
    )

    db_session.expire_all()
    finding = db_session.get(Finding, ctx["finding"].id)
    assert finding is not None
    finding_updated_at = finding.updated_at
    job_updated_at = job.updated_at
    job_status = job.status
    job_attempts = job.attempt_count
    jobs_before = _job_count(db_session)
    audit_before = int(
        db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0
    )

    assert _status(client, ctx["token"], ctx["finding"].id).status_code == 200
    assert _history(client, ctx["token"], ctx["finding"].id).status_code == 200
    assert _status(client, ctx["token"], finding2.id).json()["state"] == (
        "awaiting_discovery"
    )
    assert _history(client, ctx["token"], finding2.id).status_code == 200

    db_session.expire_all()
    job_after = db_session.get(FindingFollowUpReminderJob, job.id)
    assert job_after is not None
    assert job_after.status == job_status
    assert job_after.attempt_count == job_attempts
    assert job_after.updated_at == job_updated_at
    finding_after = db_session.get(Finding, ctx["finding"].id)
    assert finding_after is not None
    assert finding_after.updated_at == finding_updated_at
    assert _job_count(db_session) == jobs_before
    audit_after = int(
        db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0
    )
    assert audit_after == audit_before


def test_history_select_count_independent_of_page_size(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])

    for index in range(8):
        due = datetime.now(UTC) - timedelta(days=8 - index)
        _assign(
            client,
            ctx["token"],
            ctx["finding"].id,
            assignee_user_id=ctx["member_id"],
            due_at=due,
        )
        db_session.expire_all()
        change = _current_change(db_session, ctx["finding"].id)
        _insert_job(
            db_session,
            organization_id=ctx["org_id"],
            finding_id=ctx["finding"].id,
            follow_up_change_id=change.id,
            assigned_to_user_id=ctx["member_id"],
            due_at=due,
            status="pending",
            created_at=datetime.now(UTC) - timedelta(minutes=20 - index),
        )

    # Detach fixture session so engine listeners only see service queries.
    db_session.expire_all()
    db_session.commit()

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def _count_selects(page_size: int) -> tuple[int, list[str], object]:
        statements: list[str] = []

        def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        session = factory()
        event.listen(engine, "before_cursor_execute", capture)
        try:
            result = list_finding_follow_up_reminders(
                session,
                finding_id=ctx["finding"].id,
                user_id=ctx["admin_id"],
                organization_id=ctx["org_id"],
                page_size=page_size,
            )
            session.rollback()
        finally:
            event.remove(engine, "before_cursor_execute", capture)
            session.close()
        return len(statements), list(statements), result

    # Warm-up: first engine touch can include an extra Finding SELECT via the
    # shared TestClient db_session identity map / connection pool.
    _count_selects(1)

    count_one, stmts_one, one = _count_selects(1)
    count_fifty, stmts_fifty, fifty = _count_selects(50)

    assert one.items
    assert fifty.items
    assert count_one == count_fifty
    joined = " ".join(stmts_one + stmts_fifty).lower()
    assert "delivery_snapshot" not in joined
    assert "processing_token" not in joined
    assert "last_error," not in joined and "last_error from" not in joined


# --------------------------------------------------------------------------- RBAC


def test_member_ok_unauthenticated_401(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup_org(client, make_token, seed_user_a, fake_clerk, db_session)
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    due = datetime.now(UTC) + timedelta(days=1)
    _assign(
        client,
        ctx["token"],
        ctx["finding"].id,
        assignee_user_id=ctx["member_id"],
        due_at=due,
    )

    assert (
        _status(client, ctx["member_token"], ctx["finding"].id).status_code
        == 200
    )
    assert (
        _history(client, ctx["member_token"], ctx["finding"].id).status_code
        == 200
    )
    assert (
        client.get(
            f"/v1/findings/{ctx['finding'].id}/follow-up-reminder"
        ).status_code
        == 401
    )
    assert (
        client.get(
            f"/v1/findings/{ctx['finding'].id}/follow-up-reminders"
        ).status_code
        == 401
    )

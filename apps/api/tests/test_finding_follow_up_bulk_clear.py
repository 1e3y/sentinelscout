"""Milestone 53 — atomic bulk Finding follow-up owner/due clear."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, func, select, update

from app.api.routes.findings import bulk_clear_finding_follow_up_endpoint
from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import FindingFollowUpReminderJob
from app.models.organization import OrganizationMembership
from app.models.rate_limit import RateLimitCounter
from app.services.findings.follow_up_bulk_clear import (
    CHANGED_DETAIL,
    INACTIVE_DETAIL,
    bulk_clear_finding_follow_up,
)
from app.services.findings.follow_up_reminders import (
    SKIP_GENERATION_CHANGED,
    authorize_reminder_send,
    discover_follow_up_reminder_jobs,
    resolve_current_follow_up_generation,
)
from app.services.rate_limit import (
    ACTION_FINDING_FOLLOW_UP,
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_CLEAR,
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE,
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT,
    ACTION_ORGANIZATION_FINDING_OWNERSHIP_BULK_ASSIGN,
    _window_start,
)
from tests.test_finding_follow_up import _auth, _finding, _ids, _put_follow_up
from tests.test_organization_access import _setup

BULK = "/v1/findings/follow-up-review/bulk-clear"
OLD_DUE = "2026-09-01T15:00:00Z"
OLD_DUE_DT = datetime(2026, 9, 1, 15, 0, tzinfo=UTC)
PAST_DUE = datetime.now(UTC) - timedelta(hours=2)

CLERK_METHODS = (
    "get_user",
    "list_organization_memberships",
    "list_organization_members",
    "list_organization_memberships_raw",
    "list_organization_membership_presence",
    "get_organization_membership",
    "update_organization_membership_role",
    "delete_organization_membership",
    "list_organization_invitations",
    "create_organization_invitation",
    "get_organization_invitation",
    "revoke_organization_invitation",
    "list_organization_invitation_history",
)
AUTH_CLERK_METHODS = frozenset({"get_user", "list_organization_memberships"})


def _item(finding_id, *, owner_id=None, due_at=None) -> dict:
    return {
        "finding_id": str(finding_id),
        "expected_follow_up": {
            "assigned_to_user_id": str(owner_id) if owner_id is not None else None,
            "follow_up_due_at": due_at,
        },
    }


def _body(*items, clear_owner=True, clear_due=False) -> dict:
    payload: dict = {"items": list(items)}
    if clear_owner is not ...:
        payload["clear_owner"] = clear_owner
    if clear_due is not ...:
        payload["clear_due"] = clear_due
    return payload


def _bulk(client, token: str, body: dict, **params):
    return client.post(
        BULK,
        headers=_auth(token),
        json=body,
        params=params or None,
    )


def _row(db, finding_id: UUID) -> Finding:
    db.expire_all()
    row = db.get(Finding, finding_id)
    assert row is not None
    return row


def _set_follow_up(db, finding: Finding, *, owner_id=None, due_at=None) -> None:
    finding.assigned_to_user_id = owner_id
    finding.follow_up_due_at = due_at
    db.commit()
    db.refresh(finding)


def _history_count(db) -> int:
    return int(db.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0)


def _audit_count(db) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "finding.follow_up_changed")
        )
        or 0
    )


def _job_count(db) -> int:
    return int(db.scalar(select(func.count()).select_from(FindingFollowUpReminderJob)) or 0)


def _listen_sql(engine, sink: list[str]):
    def capture(conn, cursor, statement, parameters, context, executemany):
        sink.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    return capture


def _finding_locks(statements: list[str]) -> list[str]:
    return [
        sql
        for sql in statements
        if "for update" in sql.lower() and "from findings" in sql.lower()
    ]


def _membership_writes(statements: list[str]) -> list[str]:
    return [
        sql
        for sql in statements
        if (
            "insert into organization_memberships" in sql.lower()
            or "update organization_memberships" in sql.lower()
        )
    ]


def _watch_clerk(fake_clerk, monkeypatch) -> list[str]:
    calls: list[str] = []
    for name in CLERK_METHODS:
        if not hasattr(fake_clerk, name):
            continue
        original = getattr(fake_clerk, name)

        def wrapped(*args, __name=name, __original=original, **kwargs):
            calls.append(__name)
            return __original(*args, **kwargs)

        monkeypatch.setattr(fake_clerk, name, wrapped)
    return calls


def _assert_zero_clerk(calls: list[str], fake_clerk) -> None:
    assert all(name in AUTH_CLERK_METHODS for name in calls), calls
    assert fake_clerk.membership_presence_calls == 0
    assert fake_clerk.list_organization_members_calls == 0


def _enable_reminders(client, token: str, org_id: UUID) -> None:
    response = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
        json={
            "email_enabled": False,
            "email_min_priority": "medium",
            "finding_follow_up_reminders_enabled": True,
            "recipient_user_ids": [],
        },
    )
    assert response.status_code == 200, response.text


def test_required_flags_and_invalid_dto_shapes_are_rejected(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    item = _item(uuid4())
    cases = [
        {"items": [item]},
        {"clear_owner": True, "items": [item]},
        {"clear_due": True, "items": [item]},
        _body(item, clear_owner=False, clear_due=False),
        _body(*[_item(uuid4()) for _ in range(51)], clear_owner=True, clear_due=False),
        _body(clear_owner=True, clear_due=False),
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [_item(uuid4()), _item(uuid4())],
            "extra": True,
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [
                {
                    "finding_id": str(uuid4()),
                    "expected_follow_up": None,
                }
            ],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [{**item, "extra": True}],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [
                {
                    "finding_id": "not-a-uuid",
                    "expected_follow_up": {
                        "assigned_to_user_id": None,
                        "follow_up_due_at": None,
                    },
                }
            ],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [
                {
                    "finding_id": str(uuid4()),
                    "expected_follow_up": {"assigned_to_user_id": None},
                }
            ],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [
                {
                    "finding_id": str(uuid4()),
                    "expected_follow_up": {
                        "assigned_to_user_id": None,
                        "follow_up_due_at": "2026-09-01T15:00:00",
                    },
                }
            ],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "items": [
                {
                    "finding_id": str(uuid4()),
                    "expected_follow_up": {
                        "assigned_to_user_id": None,
                        "follow_up_due_at": None,
                        "extra": True,
                    },
                }
            ],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "assigned_to_user_id": str(ctx["member_id"]),
            "items": [item],
        },
        {
            "clear_owner": True,
            "clear_due": False,
            "follow_up_due_at": OLD_DUE,
            "items": [item],
        },
    ]
    for body in cases:
        assert _bulk(client, ctx["token"], body).status_code == 422, body


def test_duplicate_ids_rejected(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _bulk(
        client,
        ctx["token"],
        _body(_item(finding.id), _item(finding.id), clear_owner=True, clear_due=False),
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("clear_owner", "clear_due"),
    [(True, False), (False, True), (True, True)],
)
def test_one_and_fifty_items_are_allowed(
    client, make_token, seed_user_a, fake_clerk, db_session, clear_owner, clear_due
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, first, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    one = _bulk(
        client,
        ctx["token"],
        _body(
            _item(first.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            clear_owner=clear_owner,
            clear_due=clear_due,
        ),
    )
    assert one.status_code == 200, one.text
    assert one.json()["selected_count"] == 1

    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(50)
    ]
    for row in rows:
        _set_follow_up(db_session, row, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    fifty = _bulk(
        client,
        ctx["token"],
        _body(
            *[
                _item(row.id, owner_id=ctx["member_id"], due_at=OLD_DUE)
                for row in rows
            ],
            clear_owner=clear_owner,
            clear_due=clear_due,
        ),
    )
    assert fifty.status_code == 200, fifty.text
    assert fifty.json()["selected_count"] == 50


def test_auth_admin_and_org_privacy(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    local = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, local, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    body = _body(
        _item(local.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
        clear_owner=True,
        clear_due=False,
    )
    assert client.post(BULK, json=body).status_code == 401
    assert _bulk(client, ctx["member_token"], body).status_code == 403
    no_org = make_token(sub=seed_user_a[0], org_id=None)
    assert _bulk(client, no_org, body).status_code == 400

    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)
    mixed = _bulk(
        client,
        ctx["token"],
        _body(
            _item(local.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            _item(foreign.id),
            clear_owner=True,
            clear_due=False,
        ),
    )
    assert mixed.status_code == 404
    assert mixed.json()["error"]["message"] == "Finding not found"
    assert str(foreign.id) not in mixed.text
    assert str(local.id) not in mixed.text
    assert _row(db_session, local.id).assigned_to_user_id == ctx["member_id"]
    foreign_only = _bulk(
        client,
        ctx["token"],
        _body(_item(foreign.id), clear_owner=True, clear_due=False),
    )
    assert foreign_only.status_code == 404
    assert foreign_only.json()["error"]["message"] == "Finding not found"
    assert str(foreign.id) not in foreign_only.text

    missing = _bulk(
        client,
        ctx["token"],
        _body(_item(uuid4()), clear_owner=True, clear_due=False),
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["message"] == "Finding not found"

    ignored_query_org = _bulk(
        client,
        ctx["token"],
        body,
        organization_id=str(uuid4()),
    )
    assert ignored_query_org.status_code == 200, ignored_query_org.text


@pytest.mark.parametrize(
    ("clear_owner", "clear_due", "departed", "unassigned"),
    [
        (True, False, False, False),
        (True, False, True, False),
        (False, True, False, False),
        (False, True, True, False),
        (False, True, False, True),
        (True, True, False, False),
        (True, True, True, False),
    ],
)
def test_all_modes_are_provider_free(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    monkeypatch,
    clear_owner,
    clear_due,
    departed,
    unassigned,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    owner = None if unassigned else ctx["member_id"]
    _set_follow_up(db_session, finding, owner_id=owner, due_at=OLD_DUE_DT)
    if departed:
        fake_clerk.memberships[ctx["member_clerk"]] = []
    memberships_before = int(
        db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0
    )
    fake_clerk.get_user_calls = 0
    fake_clerk.list_organization_members_calls = 0
    fake_clerk.membership_presence_calls = 0
    calls = _watch_clerk(fake_clerk, monkeypatch)
    response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(finding.id, owner_id=owner, due_at=OLD_DUE),
            clear_owner=clear_owner,
            clear_due=clear_due,
        ),
    )
    assert response.status_code == 200, response.text
    _assert_zero_clerk(calls, fake_clerk)
    row = _row(db_session, finding.id)
    if clear_owner:
        assert row.assigned_to_user_id is None
    else:
        assert row.assigned_to_user_id == owner
    if clear_due:
        assert row.follow_up_due_at is None
    else:
        assert row.follow_up_due_at == OLD_DUE_DT
    assert (
        int(db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0)
        == memberships_before
    )


def test_service_and_route_have_no_provider_or_membership_authority(
    client, make_token, seed_user_a, fake_clerk
):
    _setup(client, make_token, seed_user_a, fake_clerk)
    service = inspect.getsource(bulk_clear_finding_follow_up)
    route = inspect.getsource(bulk_clear_finding_follow_up_endpoint)
    for source in (service, route):
        assert "ClerkDirectory" not in source
        assert "get_clerk_directory" not in source
        assert "verify_current_org_member_batch" not in source
        assert "verify_assignable_org_member" not in source
        assert "assert_assignable_org_member" not in source
        assert "warm_local_org_membership" not in source
        assert "list_organization_membership_presence" not in source
        assert "OrganizationMembership" not in source
        assert "update_finding_follow_up(" not in source
    assert service.count("Finding.organization_id == organization.id") == 2
    assert service.count(".order_by(Finding.id.asc())") == 2
    assert ".with_for_update()" in service
    assert ".execution_options(populate_existing=True)" in service
    assert service.count("db.commit()") == 1
    assert service.index("preflight_rows") < service.index(".with_for_update()")
    assert "directory" not in inspect.signature(bulk_clear_finding_follow_up).parameters


def test_stale_expected_owner_and_due(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    stale_owner = _bulk(
        client,
        ctx["token"],
        _body(
            _item(finding.id, owner_id=ctx["admin_id"], due_at=OLD_DUE),
            clear_owner=False,
            clear_due=True,
        ),
    )
    assert stale_owner.status_code == 409
    assert stale_owner.json()["error"]["message"] == CHANGED_DETAIL
    stale_due = _bulk(
        client,
        ctx["token"],
        _body(
            _item(finding.id, owner_id=ctx["member_id"], due_at="2026-10-01T15:00:00Z"),
            clear_owner=True,
            clear_due=False,
        ),
    )
    assert stale_due.status_code == 409
    assert stale_due.json()["error"]["message"] == CHANGED_DETAIL
    assert _row(db_session, finding.id).assigned_to_user_id == ctx["member_id"]
    assert _history_count(db_session) == 0


def test_equivalent_due_offset_is_accepted(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(
                finding.id,
                owner_id=ctx["member_id"],
                due_at="2026-09-01T16:00:00+01:00",
            ),
            clear_owner=False,
            clear_due=True,
        ),
    )
    assert response.status_code == 200, response.text
    assert _row(db_session, finding.id).follow_up_due_at is None


def test_inactive_conflict(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    active = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    inactive = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="resolved",
    )
    response = _bulk(
        client,
        ctx["token"],
        _body(_item(active.id), _item(inactive.id), clear_owner=True, clear_due=True),
    )
    assert response.status_code == 409
    assert response.json()["error"]["message"] == INACTIVE_DETAIL
    assert _row(db_session, active.id).assigned_to_user_id is None
    assert _history_count(db_session) == 0


def test_preflight_to_lock_competing_mutation_is_rechecked(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    session_factory,
    monkeypatch,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    from app.services.findings import follow_up_bulk_clear as bulk_mod

    original = bulk_mod._validate_rows
    calls = {"n": 0}

    def validate_then_race(*args, **kwargs):
        original(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == 1:
            other = session_factory()
            try:
                other.execute(
                    update(Finding)
                    .where(Finding.id == finding.id)
                    .values(assigned_to_user_id=None)
                )
                other.commit()
            finally:
                other.close()

    monkeypatch.setattr(bulk_mod, "_validate_rows", validate_then_race)
    response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            clear_owner=True,
            clear_due=False,
        ),
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["message"] == CHANGED_DETAIL
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_locks_are_org_scoped_sorted_and_populated(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(3)
    ]
    for row in findings:
        _set_follow_up(db_session, row, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(
                *[
                    _item(row.id, owner_id=ctx["member_id"], due_at=OLD_DUE)
                    for row in reversed(findings)
                ],
                clear_owner=True,
                clear_due=False,
            ),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    locks = _finding_locks(statements)
    assert len(locks) == 1
    assert "order by findings.id asc" in locks[0].lower()
    assert "for update" in locks[0].lower()
    assert "organization_id" in locks[0].lower()
    assert _membership_writes(statements) == []
    assert not any("finding_follow_up_reminder" in sql.lower() for sql in statements)


def test_owner_due_and_both_history_and_unchanged_mix(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    owner_clear = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    due_clear = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    both_clear = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    already = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, owner_clear, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    _set_follow_up(db_session, due_clear, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    _set_follow_up(db_session, both_clear, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    owner_updated = owner_clear.updated_at
    due_updated = due_clear.updated_at
    both_updated = both_clear.updated_at
    already_updated = already.updated_at

    owner_response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(owner_clear.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            clear_owner=True,
            clear_due=False,
        ),
    )
    assert owner_response.json() == {
        "selected_count": 1,
        "changed_count": 1,
        "unchanged_count": 0,
    }
    owner_row = _row(db_session, owner_clear.id)
    assert owner_row.assigned_to_user_id is None
    assert owner_row.follow_up_due_at == OLD_DUE_DT
    assert owner_row.updated_at == owner_updated

    due_response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(due_clear.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            clear_owner=False,
            clear_due=True,
        ),
    )
    assert due_response.status_code == 200
    due_row = _row(db_session, due_clear.id)
    assert due_row.assigned_to_user_id == ctx["member_id"]
    assert due_row.follow_up_due_at is None
    assert due_row.updated_at == due_updated

    both_response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(both_clear.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
            _item(already.id),
            clear_owner=True,
            clear_due=True,
        ),
    )
    assert both_response.json() == {
        "selected_count": 2,
        "changed_count": 1,
        "unchanged_count": 1,
    }
    both_row = _row(db_session, both_clear.id)
    already_row = _row(db_session, already.id)
    assert both_row.assigned_to_user_id is None
    assert both_row.follow_up_due_at is None
    assert both_row.updated_at == both_updated
    assert already_row.assigned_to_user_id is None
    assert already_row.follow_up_due_at is None
    assert already_row.updated_at == already_updated

    changes = list(db_session.scalars(select(FindingFollowUpChange)).all())
    assert len(changes) == 3
    by_finding = {change.finding_id: change for change in changes}
    owner_change = by_finding[owner_clear.id]
    assert owner_change.previous_assigned_to_user_id == ctx["member_id"]
    assert owner_change.new_assigned_to_user_id is None
    assert owner_change.previous_due_at == OLD_DUE_DT
    assert owner_change.new_due_at == OLD_DUE_DT
    due_change = by_finding[due_clear.id]
    assert due_change.previous_assigned_to_user_id == ctx["member_id"]
    assert due_change.new_assigned_to_user_id == ctx["member_id"]
    assert due_change.previous_due_at == OLD_DUE_DT
    assert due_change.new_due_at is None
    both_change = by_finding[both_clear.id]
    assert both_change.previous_assigned_to_user_id == ctx["member_id"]
    assert both_change.new_assigned_to_user_id is None
    assert both_change.previous_due_at == OLD_DUE_DT
    assert both_change.new_due_at is None
    assert already.id not in by_finding
    assert _audit_count(db_session) == 3


def test_all_unchanged_writes_no_history_or_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(2)
    ]
    response = _bulk(
        client,
        ctx["token"],
        _body(*[_item(row.id) for row in rows], clear_owner=True, clear_due=True),
    )
    assert response.json() == {
        "selected_count": 2,
        "changed_count": 0,
        "unchanged_count": 2,
    }
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_history_insert_failure_rolls_back_every_change(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(2)
    ]
    for row in rows:
        _set_follow_up(db_session, row, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)

    def fail_history_insert(mapper, connection, target):
        raise RuntimeError("history failure")

    event.listen(FindingFollowUpChange, "before_insert", fail_history_insert)
    try:
        with pytest.raises(RuntimeError, match="history failure"):
            _bulk(
                client,
                ctx["token"],
                _body(
                    *[
                        _item(row.id, owner_id=ctx["member_id"], due_at=OLD_DUE)
                        for row in rows
                    ],
                    clear_owner=True,
                    clear_due=False,
                ),
            )
    finally:
        event.remove(FindingFollowUpChange, "before_insert", fail_history_insert)

    assert all(
        _row(db_session, row.id).assigned_to_user_id == ctx["member_id"] for row in rows
    )
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_audit_failure_rolls_back_every_change(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(2)
    ]
    for row in rows:
        _set_follow_up(db_session, row, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    from app.services.findings import follow_up_bulk_clear as bulk_mod

    original = bulk_mod.record_audit
    calls = {"n": 0}

    def fail_second(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("audit failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(bulk_mod, "record_audit", fail_second)
    with pytest.raises(RuntimeError, match="audit failure"):
        _bulk(
            client,
            ctx["token"],
            _body(
                *[
                    _item(row.id, owner_id=ctx["member_id"], due_at=OLD_DUE)
                    for row in rows
                ],
                clear_owner=True,
                clear_due=True,
            ),
        )
    assert all(
        _row(db_session, row.id).assigned_to_user_id == ctx["member_id"] for row in rows
    )
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_dedicated_rate_action_is_independent_and_rejects_before_preflight(
    client, make_token, seed_user_a, fake_clerk, db_session, engine, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    settings = get_settings()
    assert settings.rate_limit_organization_finding_follow_up_bulk_clear == 20
    assert (
        ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_CLEAR
        == "organization.finding_follow_up.bulk_clear"
    )
    assert ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE.endswith("bulk_due")
    assert ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT.endswith("bulk_edit")
    assert ACTION_ORGANIZATION_FINDING_OWNERSHIP_BULK_ASSIGN.endswith("bulk_assign")
    assert ACTION_FINDING_FOLLOW_UP == "finding.follow_up"
    assert ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_CLEAR not in {
        ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE,
        ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT,
        ACTION_ORGANIZATION_FINDING_OWNERSHIP_BULK_ASSIGN,
        ACTION_FINDING_FOLLOW_UP,
    }
    db_session.add(
        RateLimitCounter(
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            action=ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_CLEAR,
            window_start=_window_start(
                datetime.now(UTC), settings.rate_limit_window_seconds
            ),
            count=settings.rate_limit_organization_finding_follow_up_bulk_clear,
        )
    )
    db_session.commit()
    fake_clerk.get_user_calls = 0
    fake_clerk.membership_presence_calls = 0
    calls = _watch_clerk(fake_clerk, monkeypatch)
    import app.api.routes.findings as findings_routes

    service_calls = {"n": 0}
    original_service = findings_routes.bulk_clear_finding_follow_up

    def wrapped_service(*args, **kwargs):
        service_calls["n"] += 1
        return original_service(*args, **kwargs)

    monkeypatch.setattr(
        findings_routes, "bulk_clear_finding_follow_up", wrapped_service
    )
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(
                _item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
                clear_owner=True,
                clear_due=False,
            ),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 429
    _assert_zero_clerk(calls, fake_clerk)
    assert service_calls["n"] == 0
    assert _finding_locks(statements) == []
    assert _row(db_session, finding.id).assigned_to_user_id == ctx["member_id"]


def test_static_route_is_reachable_and_registered_before_dynamic_route(client):
    response = client.post(
        BULK,
        json=_body(_item(uuid4()), clear_owner=True, clear_due=False),
    )
    assert response.status_code == 401
    paths = list(client.app.openapi()["paths"])
    assert BULK in paths
    assert paths.index(BULK) < paths.index("/v1/findings/{finding_id}")


@pytest.mark.parametrize(
    ("clear_owner", "clear_due"),
    [(True, False), (False, True), (True, True)],
)
def test_clear_has_no_current_generation_and_leaves_prior_job(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    clear_owner,
    clear_due,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assigned = _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {
            "assigned_to_user_id": str(ctx["member_id"]),
            "follow_up_due_at": PAST_DUE.isoformat(),
        },
    )
    assert assigned.status_code == 200, assigned.text
    _enable_reminders(client, ctx["token"], ctx["org_id"])
    db_session.expire_all()
    assert discover_follow_up_reminder_jobs(db_session) == 1
    jobs = list(db_session.scalars(select(FindingFollowUpReminderJob)).all())
    assert len(jobs) == 1
    prior = jobs[0]
    prior_id = prior.id
    prior_status = prior.status
    prior_generation = prior.follow_up_change_id
    assert prior.status == "pending"

    finding_row = _row(db_session, finding.id)
    response = _bulk(
        client,
        ctx["token"],
        _body(
            _item(
                finding.id,
                owner_id=finding_row.assigned_to_user_id,
                due_at=finding_row.follow_up_due_at.isoformat()
                if finding_row.follow_up_due_at is not None
                else None,
            ),
            clear_owner=clear_owner,
            clear_due=clear_due,
        ),
    )
    assert response.status_code == 200, response.text
    cleared = _row(db_session, finding.id)
    assert resolve_current_follow_up_generation(db_session, cleared) is None
    assert discover_follow_up_reminder_jobs(db_session) == 0
    leftover = db_session.get(FindingFollowUpReminderJob, prior_id)
    assert leftover is not None
    assert leftover.status == prior_status
    assert leftover.follow_up_change_id == prior_generation
    assert _job_count(db_session) == 1
    outcome = authorize_reminder_send(
        db_session,
        leftover,
        directory=fake_clerk,
        settings=get_settings(),
    )
    assert outcome.kind == "skip"
    assert outcome.code == SKIP_GENERATION_CHANGED
    leftover_after = db_session.get(FindingFollowUpReminderJob, prior_id)
    assert leftover_after is not None
    assert leftover_after.status == prior_status

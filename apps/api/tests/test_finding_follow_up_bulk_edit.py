"""Milestone 52 — atomic bulk Finding follow-up owner/due edit."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import event, func, select, update

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization, OrganizationMembership
from app.models.rate_limit import RateLimitCounter
from app.services.clerk import HttpClerkDirectory
from app.services.findings.follow_up_bulk_edit import (
    CHANGED_DETAIL,
    INACTIVE_DETAIL,
    MEMBERSHIP_FAILURE_DETAIL,
    _verify_assignee,
    bulk_edit_finding_follow_up,
)
from app.services.findings.follow_up_reminders import (
    resolve_current_follow_up_generation,
)
from app.services.rate_limit import (
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE,
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT,
    _window_start,
)
from tests.test_finding_follow_up import _auth, _finding, _ids
from tests.test_organization_access import _setup

BULK = "/v1/findings/follow-up-review/bulk-edit"
NEW_DUE = "2026-10-01T15:00:00Z"
NEW_DUE_DT = datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
OLD_DUE = "2026-09-01T15:00:00Z"
OLD_DUE_DT = datetime(2026, 9, 1, 15, 0, tzinfo=UTC)


def _item(finding_id, *, owner_id=None, due_at=None) -> dict:
    return {
        "finding_id": str(finding_id),
        "expected_follow_up": {
            "assigned_to_user_id": str(owner_id) if owner_id is not None else None,
            "follow_up_due_at": due_at,
        },
    }


def _body(assignee, *items, due_at=NEW_DUE) -> dict:
    return {
        "assigned_to_user_id": str(assignee) if assignee is not None else None,
        "follow_up_due_at": due_at,
        "items": list(items),
    }


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


def test_one_item_and_fifty_items_are_allowed(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(first.id)),
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "selected_count": 1,
        "changed_count": 1,
        "unchanged_count": 0,
    }

    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(50)
    ]
    fifty = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], *[_item(row.id) for row in rows]),
    )
    assert fifty.status_code == 200, fifty.text
    assert fifty.json()["selected_count"] == 50


def test_fifty_one_and_invalid_dto_shapes_are_rejected(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    items = [_item(uuid4()) for _ in range(51)]
    cases = [
        _body(ctx["member_id"], *items),
        _body(ctx["member_id"]),
        _body(None, _item(uuid4())),
        {"follow_up_due_at": NEW_DUE, "items": [_item(uuid4())]},
        _body(ctx["member_id"], _item(uuid4()), due_at=None),
        {"assigned_to_user_id": str(ctx["member_id"]), "items": [_item(uuid4())]},
        _body(ctx["member_id"], _item(uuid4()), due_at="2026-10-01T15:00:00"),
        {
            **_body(ctx["member_id"], _item(uuid4())),
            "extra": True,
        },
        _body(
            ctx["member_id"],
            {
                "finding_id": str(uuid4()),
                "expected_follow_up": None,
            },
        ),
        _body(
            ctx["member_id"],
            {
                **_item(uuid4()),
                "extra": True,
            },
        ),
        _body(
            ctx["member_id"],
            {
                "finding_id": "not-a-uuid",
                "expected_follow_up": {
                    "assigned_to_user_id": None,
                    "follow_up_due_at": None,
                },
            },
        ),
        _body("not-a-uuid", _item(uuid4())),
        _body(
            ctx["member_id"],
            {
                "finding_id": str(uuid4()),
                "expected_follow_up": {"assigned_to_user_id": None},
            },
        ),
        _body(
            ctx["member_id"],
            {
                "finding_id": str(uuid4()),
                "expected_follow_up": {
                    "follow_up_due_at": None,
                    "assigned_to_user_id": None,
                    "extra": True,
                },
            },
        ),
    ]
    for body in cases:
        assert _bulk(client, ctx["token"], body).status_code == 422


def test_duplicate_ids_rejected_but_nullable_complete_expected_is_valid(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    duplicate = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id), _item(finding.id)),
    )
    assert duplicate.status_code == 422
    valid = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id)),
    )
    assert valid.status_code == 200, valid.text


def test_auth_admin_and_org_privacy(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    local = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    body = _body(ctx["member_id"], _item(local.id))
    assert client.post(BULK, json=body).status_code == 401
    assert _bulk(client, ctx["member_token"], body).status_code == 403

    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)
    foreign_response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(local.id), _item(foreign.id)),
    )
    assert foreign_response.status_code == 404
    assert foreign_response.json()["error"]["message"] == "Finding not found"
    assert str(foreign.id) not in foreign_response.text
    assert _row(db_session, local.id).assigned_to_user_id is None

    ignored_query_org = _bulk(
        client,
        ctx["token"],
        body,
        organization_id=str(uuid4()),
    )
    assert ignored_query_org.status_code == 200, ignored_query_org.text


@pytest.mark.parametrize(
    ("expected", "status_code", "message"),
    [
        (
            {"assigned_to_user_id": uuid4(), "follow_up_due_at": None},
            409,
            CHANGED_DETAIL,
        ),
        (
            {"assigned_to_user_id": None, "follow_up_due_at": OLD_DUE},
            409,
            CHANGED_DETAIL,
        ),
    ],
)
def test_preflight_stale_expected_skips_provider_and_locks(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    engine,
    monkeypatch,
    expected,
    status_code,
    message,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    calls = {"n": 0}
    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id == ctx["member_clerk"]:
            calls["n"] += 1
        return original(user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(
                ctx["member_id"],
                _item(
                    finding.id,
                    owner_id=expected["assigned_to_user_id"],
                    due_at=expected["follow_up_due_at"],
                ),
            ),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == status_code
    assert response.json()["error"]["message"] == message
    assert calls["n"] == 0
    assert _finding_locks(statements) == []


def test_preflight_missing_inactive_and_unknown_assignee_make_no_provider_call(
    client, make_token, seed_user_a, fake_clerk, db_session, engine, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    active = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    inactive = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="resolved",
    )
    calls = {"n": 0}
    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id == ctx["member_clerk"]:
            calls["n"] += 1
        return original(user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)
    cases = [
        (_body(ctx["member_id"], _item(active.id), _item(uuid4())), 404, "Finding not found"),
        (
            _body(ctx["member_id"], _item(active.id), _item(inactive.id)),
            409,
            INACTIVE_DETAIL,
        ),
        (_body(uuid4(), _item(active.id)), 400, "Assignee must be a current organization member"),
    ]
    for body, status_code, message in cases:
        statements: list[str] = []
        capture = _listen_sql(engine, statements)
        try:
            response = _bulk(client, ctx["token"], body)
        finally:
            event.remove(engine, "before_cursor_execute", capture)
        assert response.status_code == status_code, response.text
        assert response.json()["error"]["message"] == message
        assert _finding_locks(statements) == []
    assert calls["n"] == 0


def test_current_and_stale_provider_membership(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    current = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    accepted = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(current.id)),
    )
    assert accepted.status_code == 200, accepted.text

    stale = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    fake_clerk.memberships[ctx["member_clerk"]] = []
    rejected = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(stale.id)),
    )
    assert rejected.status_code == 400
    assert (
        rejected.json()["error"]["message"]
        == "Assignee must be a current organization member"
    )


@pytest.mark.parametrize("provider_result", ["timeout", "status", "malformed"])
def test_provider_verification_failures_are_exact_m52_502(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    engine,
    monkeypatch,
    provider_result,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])

    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id != ctx["member_clerk"]:
            return original(user_id)
        if provider_result == "timeout":
            raise TimeoutError("provider timeout")
        if provider_result == "status":
            # HttpClerkDirectory uses this HTTPException for provider status failures.
            raise HTTPException(
                status_code=502,
                detail="Failed to fetch organization memberships from Clerk",
            )

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], _item(finding.id)),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 502, response.text
    assert response.json()["error"]["message"] == MEMBERSHIP_FAILURE_DETAIL
    assert _finding_locks(statements) == []


def test_http_clerk_directory_status_failure_is_normalized_at_m52_boundary(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503, json={"error": "provider unavailable"})

    directory = HttpClerkDirectory(
        get_settings(),
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://api.clerk.test",
        ),
    )
    organization = db_session.get(Organization, ctx["org_id"])
    assert organization is not None

    with pytest.raises(HTTPException) as exc_info:
        _verify_assignee(
            db_session,
            directory=directory,
            organization=organization,
            assigned_to_user_id=ctx["member_id"],
        )

    assert exc_info.value.status_code == 502
    assert exc_info.value.detail == MEMBERSHIP_FAILURE_DETAIL
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert (
        requests[0].url.path
        == f"/users/{ctx['member_clerk']}/organization_memberships"
    )
    assert dict(requests[0].url.params) == {"limit": "100"}


def test_unrelated_http_error_is_not_relabeled(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id != ctx["member_clerk"]:
            return original(user_id)
        raise HTTPException(status_code=418, detail="unrelated verifier HTTP error")

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id)),
    )
    assert response.status_code == 418
    assert response.json()["error"]["message"] == "unrelated verifier HTTP error"


def test_provider_precedes_sorted_populated_lock_and_membership_is_never_written(
    client, make_token, seed_user_a, fake_clerk, db_session, engine, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(3)
    ]
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert membership is not None
    db_session.delete(membership)
    db_session.commit()

    events: list[str] = []
    statements: list[str] = []
    lock_seen = {"value": False}
    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id == ctx["member_clerk"]:
            assert lock_seen["value"] is False
            events.append("provider")
        return original(user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
        lowered = statement.lower()
        if "for update" in lowered and "from findings" in lowered:
            lock_seen["value"] = True
            events.append("lock")
            assert "order by findings.id asc" in lowered

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], *[_item(row.id) for row in reversed(findings)]),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    assert events == ["provider", "lock"]
    assert len(_finding_locks(statements)) == 1
    assert _membership_writes(statements) == []
    assert (
        db_session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == ctx["org_id"],
                OrganizationMembership.user_id == ctx["member_id"],
            )
        )
        is None
    )

    source = inspect.getsource(bulk_edit_finding_follow_up)
    assert source.index("preflight_rows") < source.index("_verify_assignee(")
    assert source.index("_verify_assignee(") < source.index(".with_for_update()")
    assert source.count("Finding.organization_id == organization.id") == 2
    assert source.count(".order_by(Finding.id.asc())") == 2
    assert ".execution_options(populate_existing=True)" in source
    assert "warm_local_org_membership" not in source
    assert "assert_assignable_org_member" not in source
    assert "update_finding_follow_up(" not in source


@pytest.mark.parametrize(
    ("mutation", "status_code", "message"),
    [
        ({"assigned_to_user_id": None}, 409, CHANGED_DETAIL),
        (
            {"follow_up_due_at": datetime(2026, 9, 15, 15, 0, tzinfo=UTC)},
            409,
            CHANGED_DETAIL,
        ),
        ({"status": "resolved"}, 409, INACTIVE_DETAIL),
    ],
)
def test_lock_time_m47_m49_m50_m51_drift_is_rechecked(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    session_factory,
    monkeypatch,
    mutation,
    status_code,
    message,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(
        db_session,
        finding,
        owner_id=ctx["admin_id"],
        due_at=OLD_DUE_DT,
    )
    from app.services.findings import follow_up_bulk_edit as bulk_mod

    original = bulk_mod.verify_assignable_org_member

    def verify_then_race(*args, **kwargs):
        result = original(*args, **kwargs)
        other = session_factory()
        try:
            other.execute(
                update(Finding).where(Finding.id == finding.id).values(**mutation)
            )
            other.commit()
        finally:
            other.close()
        return result

    monkeypatch.setattr(bulk_mod, "verify_assignable_org_member", verify_then_race)
    response = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(finding.id, owner_id=ctx["admin_id"], due_at=OLD_DUE),
        ),
    )
    assert response.status_code == status_code, response.text
    assert response.json()["error"]["message"] == message
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_changed_noop_history_audit_generation_and_stable_updated_at(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    changed = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    unchanged = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(
        db_session,
        changed,
        owner_id=ctx["admin_id"],
        due_at=OLD_DUE_DT,
    )
    _set_follow_up(
        db_session,
        unchanged,
        owner_id=ctx["member_id"],
        due_at=NEW_DUE_DT,
    )
    changed_updated_at = changed.updated_at
    unchanged_updated_at = unchanged.updated_at
    response = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(changed.id, owner_id=ctx["admin_id"], due_at=OLD_DUE),
            _item(unchanged.id, owner_id=ctx["member_id"], due_at=NEW_DUE),
        ),
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "selected_count": 2,
        "changed_count": 1,
        "unchanged_count": 1,
    }
    changed_row = _row(db_session, changed.id)
    unchanged_row = _row(db_session, unchanged.id)
    assert changed_row.assigned_to_user_id == ctx["member_id"]
    assert changed_row.follow_up_due_at == NEW_DUE_DT
    assert changed_row.updated_at == changed_updated_at
    assert unchanged_row.updated_at == unchanged_updated_at

    changes = list(db_session.scalars(select(FindingFollowUpChange)).all())
    assert len(changes) == 1
    change = changes[0]
    assert change.finding_id == changed.id
    assert change.previous_assigned_to_user_id == ctx["admin_id"]
    assert change.new_assigned_to_user_id == ctx["member_id"]
    assert change.previous_due_at == OLD_DUE_DT
    assert change.new_due_at == NEW_DUE_DT
    audit = db_session.scalar(
        select(AuditEvent).where(AuditEvent.resource_id == change.id)
    )
    assert audit is not None
    assert audit.action == "finding.follow_up_changed"
    assert audit.resource_type == "finding_follow_up_change"
    generation = resolve_current_follow_up_generation(db_session, changed_row)
    assert generation is not None
    assert generation.id == change.id


@pytest.mark.parametrize("difference", ["owner", "due"])
def test_effective_single_field_difference_records_one_combined_generation(
    client, make_token, seed_user_a, fake_clerk, db_session, difference
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    initial_owner = ctx["admin_id"] if difference == "owner" else ctx["member_id"]
    initial_due = NEW_DUE_DT if difference == "owner" else OLD_DUE_DT
    _set_follow_up(
        db_session,
        finding,
        owner_id=initial_owner,
        due_at=initial_due,
    )

    response = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(finding.id, owner_id=initial_owner, due_at=initial_due.isoformat()),
        ),
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "selected_count": 1,
        "changed_count": 1,
        "unchanged_count": 0,
    }
    changes = list(db_session.scalars(select(FindingFollowUpChange)).all())
    assert len(changes) == 1
    change = changes[0]
    assert change.previous_assigned_to_user_id == initial_owner
    assert change.new_assigned_to_user_id == ctx["member_id"]
    assert change.previous_due_at == initial_due
    assert change.new_due_at == NEW_DUE_DT
    assert _audit_count(db_session) == 1


def test_all_unchanged_writes_no_history_or_audit(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(2)
    ]
    for row in rows:
        _set_follow_up(
            db_session,
            row,
            owner_id=ctx["member_id"],
            due_at=NEW_DUE_DT,
        )

    response = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            *[
                _item(row.id, owner_id=ctx["member_id"], due_at=NEW_DUE)
                for row in rows
            ],
        ),
    )

    assert response.status_code == 200, response.text
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

    def fail_history_insert(mapper, connection, target):
        raise RuntimeError("history failure")

    event.listen(FindingFollowUpChange, "before_insert", fail_history_insert)
    try:
        with pytest.raises(RuntimeError, match="history failure"):
            _bulk(
                client,
                ctx["token"],
                _body(ctx["member_id"], *[_item(row.id) for row in rows]),
            )
    finally:
        event.remove(FindingFollowUpChange, "before_insert", fail_history_insert)

    assert all(_row(db_session, row.id).assigned_to_user_id is None for row in rows)
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_mid_batch_failure_rolls_back_every_change(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    rows = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(2)
    ]
    from app.services.findings import follow_up_bulk_edit as bulk_mod

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
            _body(ctx["member_id"], *[_item(row.id) for row in rows]),
        )
    assert all(_row(db_session, row.id).assigned_to_user_id is None for row in rows)
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_dedicated_rate_action_and_m50_action_remain_independent(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    settings = get_settings()
    assert settings.rate_limit_organization_finding_follow_up_bulk_edit == 20
    assert (
        ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT
        == "organization.finding_follow_up.bulk_edit"
    )
    assert (
        ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE
        == "organization.finding_follow_up.bulk_due"
    )
    db_session.add(
        RateLimitCounter(
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            action=ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_EDIT,
            window_start=_window_start(
                datetime.now(UTC), settings.rate_limit_window_seconds
            ),
            count=settings.rate_limit_organization_finding_follow_up_bulk_edit,
        )
    )
    db_session.commit()
    provider_calls = {"n": 0}
    original = fake_clerk.list_organization_memberships

    def provider(user_id):
        if user_id == ctx["member_clerk"]:
            provider_calls["n"] += 1
        return original(user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", provider)
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id)),
    )
    assert response.status_code == 429
    assert provider_calls["n"] == 0
    m50 = client.post(
        "/v1/findings/follow-up-review/bulk-due",
        headers=_auth(ctx["token"]),
        json={"follow_up_due_at": NEW_DUE, "items": [_item(finding.id)]},
    )
    assert m50.status_code == 200, m50.text
    assert m50.json() == {
        "selected_count": 1,
        "changed_count": 1,
        "unchanged_count": 0,
    }


def test_static_route_is_reachable_and_registered_before_dynamic_route(client):
    response = client.post(
        BULK,
        json=_body(uuid4(), _item(uuid4())),
    )
    assert response.status_code == 401
    paths = list(client.app.openapi()["paths"])
    assert BULK in paths
    assert paths.index(BULK) < paths.index("/v1/findings/{finding_id}")

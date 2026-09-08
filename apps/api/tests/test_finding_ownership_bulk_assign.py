"""Milestone 49 — bulk Finding ownership assignment."""

from __future__ import annotations

import inspect
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import event, select, text
from sqlalchemy.exc import OperationalError

from app.core.config import get_settings
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization, OrganizationMembership
from app.models.rate_limit import RateLimitCounter
from app.models.user import User
from app.services.findings.ownership_bulk_assign import (
    CHANGED_DETAIL,
    INACTIVE_DETAIL,
    bulk_assign_finding_ownership,
)
from app.services.organization_members import (
    verify_assignable_org_member,
    warm_local_org_membership,
)
from app.services.rate_limit import (
    ACTION_ORGANIZATION_FINDING_OWNERSHIP_BULK_ASSIGN,
    _window_start,
)
from tests.test_finding_follow_up import (
    _auth,
    _finding,
    _follow_up_audit_count,
    _follow_up_history_count,
    _ids,
    _put_follow_up,
)
from tests.test_organization_access import _setup

BULK = "/v1/findings/ownership-review/bulk-assign"
WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
BULK_SCRIPT = WEB_ROOT / "scripts" / "assert-bulk-ownership-assign.mjs"
SERVICE_PATH = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "services"
    / "findings"
    / "ownership_bulk_assign.py"
)
DUE = "2026-10-01T15:00:00Z"
DUE_DT = datetime(2026, 10, 1, 15, 0, tzinfo=UTC)


def _bulk(client, token: str, body: dict, **params):
    return client.post(
        BULK,
        headers=_auth(token),
        json=body,
        params=params or None,
    )


def _item(finding_id, *, assigned_to_user_id=None, follow_up_due_at=None) -> dict:
    return {
        "finding_id": str(finding_id),
        "expected_follow_up": {
            "assigned_to_user_id": (
                str(assigned_to_user_id) if assigned_to_user_id is not None else None
            ),
            "follow_up_due_at": follow_up_due_at,
        },
    }


def _body(assignee, *items) -> dict:
    return {"assigned_to_user_id": str(assignee), "items": list(items)}


def _row(db, finding_id: UUID) -> Finding:
    db.expire_all()
    row = db.get(Finding, finding_id)
    assert row is not None
    return row


def _listen_sql(engine, sink: list[str]):
    def capture(conn, cursor, statement, parameters, context, executemany):
        sink.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    return capture


def _finding_for_update_sql(statements: list[str]) -> list[str]:
    return [
        sql
        for sql in statements
        if "for update" in sql.lower() and "from findings" in sql.lower()
    ]


def _membership_insert_sql(statements: list[str]) -> list[str]:
    return [
        sql
        for sql in statements
        if "insert into organization_memberships" in sql.lower()
    ]


def _membership(
    db, *, organization_id: UUID, user_id: UUID
) -> OrganizationMembership | None:
    return db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
    )


def _delete_membership(db, *, organization_id: UUID, user_id: UUID) -> None:
    row = _membership(db, organization_id=organization_id, user_id=user_id)
    assert row is not None
    db.delete(row)
    db.commit()
    db.expire_all()


# ---------------------------------------------------------------- request validation


def test_one_item_assigns(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id)),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {"selected_count": 1, "changed_count": 1, "unchanged_count": 0}
    row = _row(db_session, finding.id)
    assert row.assigned_to_user_id == ctx["member_id"]
    assert row.follow_up_due_at is None


def test_fifty_items_ok_fifty_one_rejected(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(50)
    ]
    ok = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], *[_item(row.id) for row in findings]),
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["selected_count"] == 50
    assert ok.json()["changed_count"] == 50
    extra_ids = [row.id for row in findings] + [uuid4()]
    rejected = _bulk(
        client,
        ctx["token"],
        _body(ctx["admin_id"], *[_item(finding_id) for finding_id in extra_ids]),
    )
    assert rejected.status_code == 422


def test_empty_items_duplicate_malformed_and_nulls_are_422(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    empty = _bulk(client, ctx["token"], {"assigned_to_user_id": str(ctx["member_id"]), "items": []})
    assert empty.status_code == 422
    duplicate = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id), _item(finding.id)),
    )
    assert duplicate.status_code == 422
    malformed = _bulk(
        client,
        ctx["token"],
        {
            "assigned_to_user_id": str(ctx["member_id"]),
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
    )
    assert malformed.status_code == 422
    null_assignee = _bulk(
        client,
        ctx["token"],
        {"assigned_to_user_id": None, "items": [_item(finding.id)]},
    )
    assert null_assignee.status_code == 422
    null_expected = _bulk(
        client,
        ctx["token"],
        {
            "assigned_to_user_id": str(ctx["member_id"]),
            "items": [{"finding_id": str(finding.id), "expected_follow_up": None}],
        },
    )
    assert null_expected.status_code == 422
    naive = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(finding.id, follow_up_due_at="2026-10-01T15:00:00"),
        ),
    )
    assert naive.status_code == 422
    extra_org = _bulk(
        client,
        ctx["token"],
        {**_body(ctx["member_id"], _item(finding.id)), "organization_id": str(ctx["org_id"])},
    )
    assert extra_org.status_code == 422
    row = _row(db_session, finding.id)
    assert row.assigned_to_user_id is None


# ---------------------------------------------------------------- RBAC


def test_unauthenticated_401(client):
    response = client.post(
        BULK,
        json=_body(uuid4(), _item(uuid4())),
    )
    assert response.status_code == 401


def test_member_403(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    response = _bulk(
        client,
        ctx["member_token"],
        _body(ctx["admin_id"], _item(finding.id)),
    )
    assert response.status_code == 403
    assert _row(db_session, finding.id).assigned_to_user_id is None


def test_stale_local_admin_cannot_elevate(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert membership is not None
    membership.role = "org:admin"
    db_session.commit()
    response = _bulk(
        client,
        ctx["member_token"],
        _body(ctx["admin_id"], _item(finding.id)),
    )
    assert response.status_code == 403
    assert _row(db_session, finding.id).assigned_to_user_id is None


def test_admin_allowed_and_query_org_id_cannot_override(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _ids(client, token_b)
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id)),
        organization_id=str(uuid4()),
    )
    assert response.status_code == 200, response.text
    assert _row(db_session, finding.id).assigned_to_user_id == ctx["member_id"]


# ---------------------------------------------------------------- rate limit


def test_already_exhausted_429_skips_assignee_and_locks(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    settings = get_settings()
    window = _window_start(datetime.now(UTC), settings.rate_limit_window_seconds)
    db_session.add(
        RateLimitCounter(
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            action=ACTION_ORGANIZATION_FINDING_OWNERSHIP_BULK_ASSIGN,
            window_start=window,
            count=settings.rate_limit_organization_finding_ownership_bulk_assign,
        )
    )
    db_session.commit()

    assign_calls = {"n": 0}
    from app.services.findings import ownership_bulk_assign as bulk_mod

    orig_assert = bulk_mod.verify_assignable_org_member

    def wrapped_assert(*args, **kwargs):
        assign_calls["n"] += 1
        return orig_assert(*args, **kwargs)

    monkeypatch.setattr(bulk_mod, "verify_assignable_org_member", wrapped_assert)
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
    assert response.status_code == 429, response.text
    assert assign_calls["n"] == 0
    assert _finding_for_update_sql(statements) == []
    assert _row(db_session, finding.id).assigned_to_user_id is None


def test_limiter_invoked_once_not_per_finding(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(3)
    ]
    import app.api.routes.findings as findings_routes

    calls = {"n": 0}
    orig = findings_routes.enforce_rate_limit

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return orig(*args, **kwargs)

    monkeypatch.setattr(findings_routes, "enforce_rate_limit", wrapped)
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], *[_item(row.id) for row in findings]),
    )
    assert response.status_code == 200, response.text
    assert calls["n"] == 1


# ---------------------------------------------------------------- provider / ordering


def test_assignee_verified_once_before_finding_locks(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(3)
    ]
    from app.services.findings import ownership_bulk_assign as bulk_mod

    events: list[str] = []
    orig_assert = bulk_mod.verify_assignable_org_member

    def wrapped_assert(*args, **kwargs):
        events.append("assignee")
        return orig_assert(*args, **kwargs)

    monkeypatch.setattr(bulk_mod, "verify_assignable_org_member", wrapped_assert)
    orig_memberships = fake_clerk.list_organization_memberships
    lock_seen = {"value": False}
    memberships_after_lock: list[str] = []

    def wrapped_memberships(clerk_user_id: str):
        if lock_seen["value"]:
            memberships_after_lock.append(clerk_user_id)
        return orig_memberships(clerk_user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", wrapped_memberships)

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "for update" in statement.lower() and "from findings" in statement.lower():
            lock_seen["value"] = True
            events.append("for_update")
            assert "order by findings.id asc" in statement.lower()

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], *[_item(row.id) for row in findings]),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    assert events.count("assignee") == 1
    assert events.index("assignee") < events.index("for_update")
    assert memberships_after_lock == []


def test_nonmember_and_provider_failure_happen_before_locks(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    fake_clerk.memberships[ctx["member_clerk"]] = []
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        missing = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], _item(finding.id)),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert missing.status_code == 400, missing.text
    assert missing.json()["error"]["message"] == "Assignee must be a current organization member"
    assert _finding_for_update_sql(statements) == []

    from app.services.findings import ownership_bulk_assign as bulk_mod

    def boom(*_args, **_kwargs):
        raise HTTPException(
            status_code=502,
            detail="Failed to verify organization membership",
        )

    monkeypatch.setattr(bulk_mod, "verify_assignable_org_member", boom)
    statements = []
    capture = _listen_sql(engine, statements)
    try:
        failed = _bulk(
            client,
            ctx["token"],
            _body(ctx["admin_id"], _item(finding.id)),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert failed.status_code == 502, failed.text
    assert failed.json()["error"]["message"] == "Failed to verify organization membership"
    assert _finding_for_update_sql(statements) == []
    assert _row(db_session, finding.id).assigned_to_user_id is None


def test_pre_lock_verify_does_not_write_membership(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _delete_membership(
        db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
    )
    assert _membership(
        db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
    ) is None

    from app.services.findings import ownership_bulk_assign as bulk_mod

    events: list[str] = []
    orig_verify = bulk_mod.verify_assignable_org_member
    orig_warm = bulk_mod.warm_local_org_membership

    def wrapped_verify(*args, **kwargs):
        events.append("assignee")
        return orig_verify(*args, **kwargs)

    def wrapped_warm(*args, **kwargs):
        events.append("warm")
        return orig_warm(*args, **kwargs)

    monkeypatch.setattr(bulk_mod, "verify_assignable_org_member", wrapped_verify)
    monkeypatch.setattr(bulk_mod, "warm_local_org_membership", wrapped_warm)
    orig_memberships = fake_clerk.list_organization_memberships
    lock_seen = {"value": False}
    assignee_clerk_calls: list[str] = []
    memberships_after_lock: list[str] = []

    def wrapped_memberships(clerk_user_id: str):
        if clerk_user_id == ctx["member_clerk"]:
            assignee_clerk_calls.append(clerk_user_id)
        if lock_seen["value"]:
            memberships_after_lock.append(clerk_user_id)
        return orig_memberships(clerk_user_id)

    monkeypatch.setattr(fake_clerk, "list_organization_memberships", wrapped_memberships)
    statements: list[str] = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
        if "for update" in statement.lower() and "from findings" in statement.lower():
            lock_seen["value"] = True
            events.append("for_update")

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], _item(finding.id)),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)

    assert response.status_code == 200, response.text
    assert events.count("assignee") == 1
    assert events.count("warm") == 1
    assert events.index("assignee") < events.index("for_update")
    assert events.index("for_update") < events.index("warm")
    assert memberships_after_lock == []
    assert assignee_clerk_calls == [ctx["member_clerk"]]
    fu = next(
        i
        for i, sql in enumerate(statements)
        if "for update" in sql.lower() and "from findings" in sql.lower()
    )
    assert _membership_insert_sql(statements[:fu]) == []
    assert _membership_insert_sql(statements[fu:])
    db_session.expire_all()
    warmed = _membership(
        db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
    )
    assert warmed is not None
    assert warmed.user_id == ctx["member_id"]


def test_failed_batch_does_not_warm_membership(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _delete_membership(
        db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
    )
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        missing = _bulk(
            client,
            ctx["token"],
            _body(ctx["member_id"], _item(finding.id), _item(uuid4())),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert missing.status_code == 404, missing.text
    assert _finding_for_update_sql(statements)
    assert _membership_insert_sql(statements) == []
    assert (
        _membership(
            db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
        )
        is None
    )


def test_m49_verify_does_not_hold_membership_write_ahead_of_finding_lock(
    client, make_token, seed_user_a, fake_clerk, db_session, session_factory
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _delete_membership(
        db_session, organization_id=ctx["org_id"], user_id=ctx["member_id"]
    )
    session_m33 = session_factory()
    session_m49 = session_factory()
    try:
        session_m33.execute(text("SET LOCAL lock_timeout = '2000ms'"))
        locked = session_m33.scalar(
            select(Finding).where(Finding.id == finding.id).with_for_update()
        )
        assert locked is not None
        org_m49 = session_m49.get(Organization, ctx["org_id"])
        assert org_m49 is not None
        verify_assignable_org_member(
            session_m49,
            directory=fake_clerk,
            organization=org_m49,
            user_id=ctx["member_id"],
        )
        assert (
            _membership(
                session_m49,
                organization_id=ctx["org_id"],
                user_id=ctx["member_id"],
            )
            is None
        )
        org_m33 = session_m33.get(Organization, ctx["org_id"])
        user_m33 = session_m33.get(User, ctx["member_id"])
        assert org_m33 is not None
        assert user_m33 is not None
        warm_local_org_membership(
            session_m33, organization=org_m33, user=user_m33
        )
        with pytest.raises(OperationalError):
            session_m49.scalar(
                select(Finding)
                .where(Finding.id == finding.id)
                .with_for_update(nowait=True)
            )
        session_m33.commit()
    finally:
        session_m33.rollback()
        session_m49.rollback()
        session_m33.close()
        session_m49.close()


# ---------------------------------------------------------------- atomicity / privacy


def test_missing_and_foreign_ids_are_identical_404_with_zero_changes(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    local = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    history_before = _follow_up_history_count(db_session)
    audit_before = _follow_up_audit_count(db_session)
    missing = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(local.id), _item(uuid4())),
    )
    assert missing.status_code == 404, missing.text
    assert missing.json()["error"]["message"] == "Finding not found"
    assert _row(db_session, local.id).assigned_to_user_id is None
    assert _follow_up_history_count(db_session) == history_before
    assert _follow_up_audit_count(db_session) == audit_before

    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)
    foreign_resp = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(local.id), _item(foreign.id)),
    )
    assert foreign_resp.status_code == 404
    assert foreign_resp.json()["error"]["message"] == "Finding not found"
    assert str(foreign.id) not in foreign_resp.text
    assert _row(db_session, local.id).assigned_to_user_id is None
    assert _row(db_session, foreign.id).assigned_to_user_id is None
    assert _follow_up_history_count(db_session) == history_before


def test_inactive_and_stale_expected_fail_the_whole_batch(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    active = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    inactive = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="resolved"
    )
    history_before = _follow_up_history_count(db_session)
    inactive_resp = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(active.id), _item(inactive.id)),
    )
    assert inactive_resp.status_code == 409
    assert inactive_resp.json()["error"]["message"] == INACTIVE_DETAIL
    assert _row(db_session, active.id).assigned_to_user_id is None
    assert _follow_up_history_count(db_session) == history_before

    other = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    stale_owner = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(active.id),
            _item(other.id, assigned_to_user_id=ctx["admin_id"]),
        ),
    )
    assert stale_owner.status_code == 409
    assert stale_owner.json()["error"]["message"] == CHANGED_DETAIL
    assert _row(db_session, active.id).assigned_to_user_id is None
    assert _row(db_session, other.id).assigned_to_user_id is None

    due_finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        due_finding.id,
        {"assigned_to_user_id": None, "follow_up_due_at": DUE},
    ).status_code == 200
    stale_due = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(due_finding.id, follow_up_due_at="2026-11-01T15:00:00Z"),
        ),
    )
    assert stale_due.status_code == 409
    assert stale_due.json()["error"]["message"] == CHANGED_DETAIL
    assert _row(db_session, due_finding.id).assigned_to_user_id is None
    assert _row(db_session, due_finding.id).follow_up_due_at == DUE_DT
    assert _follow_up_history_count(db_session) == history_before + 1


# ---------------------------------------------------------------- concurrency


def test_m45_m47_m33_changes_conflict_before_lock_applies(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    m45 = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    m47 = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    m33 = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        m45.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": DUE},
    ).status_code == 200
    assert _put_follow_up(
        client,
        ctx["token"],
        m47.id,
        {
            "assigned_to_user_id": None,
            "follow_up_due_at": DUE,
            "expected_follow_up": {
                "assigned_to_user_id": None,
                "follow_up_due_at": None,
            },
        },
    ).status_code == 200
    assert _put_follow_up(
        client,
        ctx["token"],
        m33.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200

    owner_conflict = _bulk(client, ctx["token"], _body(ctx["member_id"], _item(m45.id)))
    assert owner_conflict.status_code == 409
    due_conflict = _bulk(client, ctx["token"], _body(ctx["member_id"], _item(m47.id)))
    assert due_conflict.status_code == 409
    m33_conflict = _bulk(client, ctx["token"], _body(ctx["admin_id"], _item(m33.id)))
    assert m33_conflict.status_code == 409
    assert _row(db_session, m45.id).assigned_to_user_id == ctx["admin_id"]
    assert _row(db_session, m47.id).assigned_to_user_id is None
    assert _row(db_session, m33.id).assigned_to_user_id == ctx["member_id"]


def test_overlapping_m49_batches_never_split_state(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    second = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    payload = _body(ctx["member_id"], _item(first.id), _item(second.id))

    def post():
        return _bulk(client, ctx["token"], payload)

    first_ok = post()
    second_resp = post()
    assert first_ok.status_code == 200, first_ok.text
    assert second_resp.status_code == 409, second_resp.text
    assert first_ok.json() == {
        "selected_count": 2,
        "changed_count": 2,
        "unchanged_count": 0,
    }
    assert second_resp.json()["error"]["message"] == CHANGED_DETAIL
    assert _row(db_session, first.id).assigned_to_user_id == ctx["member_id"]
    assert _row(db_session, second.id).assigned_to_user_id == ctx["member_id"]
    assert _follow_up_history_count(db_session) == 2
    assert _follow_up_audit_count(db_session) == 2


def test_lock_query_is_org_scoped_ordered_for_update():
    source = inspect.getsource(bulk_assign_finding_ownership)
    assert "Finding.id.in_(finding_ids)" in source
    assert "Finding.organization_id == organization.id" in source
    assert ".order_by(Finding.id.asc())" in source
    assert ".with_for_update()" in source
    assert "update_finding_follow_up(" not in source
    assert "row.follow_up_due_at =" not in source
    assert "verify_assignable_org_member" in source
    assert "assert_assignable_org_member" not in source
    assert source.index("verify_assignable_org_member") < source.index(".with_for_update()")
    assert source.index(".with_for_update()") < source.index("warm_local_org_membership")
    assert source.index("warm_local_org_membership") < source.index(
        "row.assigned_to_user_id = assigned_to_user_id"
    )
    text = SERVICE_PATH.read_text()
    assert "update_finding_follow_up(" not in text
    assert "assert_assignable_org_member" not in text


# ---------------------------------------------------------------- preservation / history / no-op


def test_due_updated_at_and_identity_are_preserved(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": None, "follow_up_due_at": DUE},
    ).status_code == 200
    before = _row(db_session, finding.id)
    updated_at = before.updated_at
    severity = before.severity
    status_value = before.status
    asset = db_session.get(Asset, before.asset_id)
    assert asset is not None
    target_id = asset.target_id
    response = _bulk(
        client,
        ctx["token"],
        _body(ctx["member_id"], _item(finding.id, follow_up_due_at=DUE)),
    )
    assert response.status_code == 200, response.text
    after = _row(db_session, finding.id)
    assert after.assigned_to_user_id == ctx["member_id"]
    assert after.follow_up_due_at == DUE_DT
    assert after.updated_at == updated_at
    assert after.severity == severity
    assert after.status == status_value
    after_asset = db_session.get(Asset, after.asset_id)
    assert after_asset is not None
    assert after_asset.target_id == target_id
    change = db_session.scalar(
        select(FindingFollowUpChange).where(
            FindingFollowUpChange.new_assigned_to_user_id == ctx["member_id"]
        )
    )
    assert change is not None
    assert change.previous_due_at == change.new_due_at == DUE_DT
    assert change.previous_assigned_to_user_id is None
    assert change.new_assigned_to_user_id == ctx["member_id"]
    audit = db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "finding.follow_up_changed",
            AuditEvent.resource_id == change.id,
        )
    )
    assert audit is not None
    assert audit.resource_type == "finding_follow_up_change"
    assert audit.resource_id == change.id
    bulk_audits = list(
        db_session.scalars(
            select(AuditEvent).where(AuditEvent.action.contains("bulk"))
        )
    )
    assert bulk_audits == []


def test_noop_and_mixed_counts_skip_history_for_unchanged(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    already = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    pending = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        already.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": DUE},
    ).status_code == 200
    history_after_seed = _follow_up_history_count(db_session)
    audit_after_seed = _follow_up_audit_count(db_session)

    all_noop = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(already.id, assigned_to_user_id=ctx["member_id"], follow_up_due_at=DUE),
        ),
    )
    assert all_noop.status_code == 200, all_noop.text
    assert all_noop.json() == {
        "selected_count": 1,
        "changed_count": 0,
        "unchanged_count": 1,
    }
    assert _follow_up_history_count(db_session) == history_after_seed
    assert _follow_up_audit_count(db_session) == audit_after_seed

    mixed = _bulk(
        client,
        ctx["token"],
        _body(
            ctx["member_id"],
            _item(already.id, assigned_to_user_id=ctx["member_id"], follow_up_due_at=DUE),
            _item(pending.id),
        ),
    )
    assert mixed.status_code == 200, mixed.text
    assert mixed.json() == {
        "selected_count": 2,
        "changed_count": 1,
        "unchanged_count": 1,
    }
    assert _follow_up_history_count(db_session) == history_after_seed + 1
    assert _follow_up_audit_count(db_session) == audit_after_seed + 1
    assert _row(db_session, pending.id).assigned_to_user_id == ctx["member_id"]
    changes = list(
        db_session.scalars(
            select(FindingFollowUpChange).where(
                FindingFollowUpChange.finding_id == pending.id
            )
        )
    )
    assert len(changes) == 1


# ---------------------------------------------------------------- frontend pins


def test_m49_frontend_selection_and_transport_contract():
    assert BULK_SCRIPT.is_file(), BULK_SCRIPT
    result = subprocess.run(
        ["node", str(BULK_SCRIPT)],
        cwd=str(WEB_ROOT),
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    panel = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-ownership-review-panel.tsx"
    ).read_text()
    m46 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-follow-up-review-panel.tsx"
    ).read_text()
    helper = (WEB_ROOT / "lib" / "bulk-ownership-assign.ts").read_text()
    modal = (
        WEB_ROOT
        / "app"
        / "(app)"
        / "dashboard"
        / "finding-ownership-bulk-assign-modal.tsx"
    ).read_text()
    assert "Select visible" in panel
    assert "payload.items.map((item) => item.finding_id)" in panel
    assert "invalidateBulk" in panel
    assert "setSelectedIds([])" in panel
    assert "shouldApplyReviewResult" in panel
    assert "ownershipRefreshCursor" in panel
    assert "handleBulkTransportUncertain" in panel
    assert "isTransportAmbiguousError" in modal
    assert "postBulkOwnershipAssign" in modal
    assert modal.count("postBulkOwnershipAssign(") == 1
    assert "for (" not in helper
    assert "while (" not in helper
    assert "retry" not in helper.lower()
    assert 'type="checkbox"' not in m46
    assert "Select visible" not in m46
    assert "stale" not in panel.lower() or "shouldApplyReviewResult" in panel
    assert "setSelectedIds(next.items" not in panel
    assert "setSelectedIds(payload.items" not in panel


def test_m45_write_path_is_unchanged():
    m45 = (
        WEB_ROOT / "app" / "(app)" / "dashboard" / "finding-ownership-assign-modal.tsx"
    ).read_text()
    follow_up = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "services"
        / "findings"
        / "follow_up.py"
    ).read_text()
    assert "expected_follow_up" not in m45
    assert "def update_finding_follow_up(" in follow_up
    assert "db.commit()" in inspect.getsource(
        __import__(
            "app.services.findings.follow_up", fromlist=["update_finding_follow_up"]
        ).update_finding_follow_up
    )

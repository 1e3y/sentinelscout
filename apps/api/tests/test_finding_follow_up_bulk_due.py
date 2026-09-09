"""Milestone 50 — atomic bulk Finding follow-up due-date update."""

from __future__ import annotations

import inspect
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import event, func, select, update

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.finding import Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import OrganizationMembership
from app.models.rate_limit import RateLimitCounter
from app.models.user import User
from app.services.findings.follow_up_bulk_due import (
    CHANGED_DETAIL,
    INACTIVE_DETAIL,
    bulk_update_finding_follow_up_due,
)
from app.services.findings.follow_up_reminders import (
    resolve_current_follow_up_generation,
)
from app.services.organization_members import verify_current_org_member_batch
from app.services.rate_limit import (
    ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE,
    _window_start,
)
from tests.test_finding_follow_up import _auth, _finding, _ids
from tests.test_organization_access import _setup

BULK = "/v1/findings/follow-up-review/bulk-due"
NEW_DUE = "2026-10-01T15:00:00Z"
NEW_DUE_DT = datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
OLD_DUE = "2026-09-01T15:00:00Z"
OLD_DUE_DT = datetime(2026, 9, 1, 15, 0, tzinfo=UTC)
WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
M50_SCRIPT = WEB_ROOT / "scripts" / "assert-bulk-follow-up-due.mjs"
M49_SCRIPT = WEB_ROOT / "scripts" / "assert-bulk-ownership-assign.mjs"


def _item(finding_id, *, owner_id=None, due_at=None) -> dict:
    return {
        "finding_id": str(finding_id),
        "expected_follow_up": {
            "assigned_to_user_id": str(owner_id) if owner_id is not None else None,
            "follow_up_due_at": due_at,
        },
    }


def _body(*items, due_at=NEW_DUE) -> dict:
    return {"follow_up_due_at": due_at, "items": list(items)}


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


def test_one_item_and_all_noop_counts(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    original_updated_at = finding.updated_at

    changed = _bulk(client, ctx["token"], _body(_item(finding.id)))
    assert changed.status_code == 200, changed.text
    assert changed.json() == {
        "selected_count": 1,
        "changed_count": 1,
        "unchanged_count": 0,
    }
    row = _row(db_session, finding.id)
    assert row.follow_up_due_at == NEW_DUE_DT
    assert row.assigned_to_user_id is None
    assert row.updated_at == original_updated_at
    history_after_change = _history_count(db_session)
    audit_after_change = _audit_count(db_session)

    noop = _bulk(
        client,
        ctx["token"],
        _body(_item(finding.id, due_at=NEW_DUE)),
    )
    assert noop.status_code == 200, noop.text
    assert noop.json() == {
        "selected_count": 1,
        "changed_count": 0,
        "unchanged_count": 1,
    }
    assert _history_count(db_session) == history_after_change
    assert _audit_count(db_session) == audit_after_change


def test_fifty_allowed_and_fifty_one_rejected(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(50)
    ]
    ok = _bulk(client, ctx["token"], _body(*[_item(row.id) for row in findings]))
    assert ok.status_code == 200, ok.text
    assert ok.json()["selected_count"] == 50
    too_many = _body(*[_item(row.id, due_at=NEW_DUE) for row in findings], _item(uuid4()))
    assert _bulk(client, ctx["token"], too_many).status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"follow_up_due_at": NEW_DUE, "items": []},
        {"follow_up_due_at": None, "items": [_item(uuid4())]},
        {"follow_up_due_at": "2026-10-01T15:00:00", "items": [_item(uuid4())]},
        {
            "follow_up_due_at": NEW_DUE,
            "items": [{"finding_id": "bad", "expected_follow_up": {}}],
        },
        {
            "follow_up_due_at": NEW_DUE,
            "items": [{"finding_id": str(uuid4()), "expected_follow_up": None}],
        },
        {
            "follow_up_due_at": NEW_DUE,
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
        {"follow_up_due_at": NEW_DUE, "items": [_item(uuid4())], "extra": True},
    ],
)
def test_invalid_request_shapes_are_422(
    client, make_token, seed_user_a, fake_clerk, body
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _bulk(client, ctx["token"], body).status_code == 422


def test_duplicate_ids_are_422(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert (
        _bulk(client, ctx["token"], _body(_item(finding.id), _item(finding.id))).status_code
        == 422
    )


def test_rbac_and_query_org_override(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    body = _body(_item(finding.id))
    assert client.post(BULK, json=body).status_code == 401
    assert _bulk(client, ctx["member_token"], body).status_code == 403

    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert membership is not None
    membership.role = "org:admin"
    db_session.commit()
    assert _bulk(client, ctx["member_token"], body).status_code == 403

    allowed = _bulk(
        client,
        ctx["token"],
        body,
        organization_id=str(uuid4()),
    )
    assert allowed.status_code == 200, allowed.text


def test_exhausted_rate_limit_stops_before_preflight_provider_and_locks(
    client, make_token, seed_user_a, fake_clerk, db_session, engine, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    settings = get_settings()
    db_session.add(
        RateLimitCounter(
            organization_id=ctx["org_id"],
            user_id=ctx["admin_id"],
            action=ACTION_ORGANIZATION_FINDING_FOLLOW_UP_BULK_DUE,
            window_start=_window_start(datetime.now(UTC), settings.rate_limit_window_seconds),
            count=settings.rate_limit_organization_finding_follow_up_bulk_due,
        )
    )
    db_session.commit()
    before_presence = fake_clerk.membership_presence_calls
    import app.api.routes.findings as findings_routes

    service_calls = {"n": 0}
    original_service = findings_routes.bulk_update_finding_follow_up_due

    def wrapped_service(*args, **kwargs):
        service_calls["n"] += 1
        return original_service(*args, **kwargs)

    monkeypatch.setattr(
        findings_routes,
        "bulk_update_finding_follow_up_due",
        wrapped_service,
    )
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(client, ctx["token"], _body(_item(finding.id)))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 429
    assert fake_clerk.membership_presence_calls == before_presence
    assert service_calls["n"] == 0
    assert _finding_locks(statements) == []


def test_limiter_invoked_once_per_post(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    findings = [
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        for _ in range(3)
    ]
    import app.api.routes.findings as findings_routes

    calls = {"n": 0}
    original = findings_routes.enforce_rate_limit

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(findings_routes, "enforce_rate_limit", wrapped)
    response = _bulk(
        client,
        ctx["token"],
        _body(*[_item(row.id) for row in findings]),
    )
    assert response.status_code == 200, response.text
    assert calls["n"] == 1


def test_preflight_failures_skip_provider_and_finding_locks(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    active = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    inactive = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="resolved",
    )
    clerk_b, org_b = seed_user_b
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    admin_b, org_b_id = _ids(client, token_b)
    foreign = _finding(db_session, organization_id=org_b_id, user_id=admin_b)

    cases = [
        (_body(_item(active.id), _item(uuid4())), 404, "Finding not found"),
        (_body(_item(active.id), _item(foreign.id)), 404, "Finding not found"),
        (
            _body(_item(active.id), _item(inactive.id)),
            409,
            INACTIVE_DETAIL,
        ),
        (
            _body(_item(active.id, owner_id=ctx["member_id"])),
            409,
            CHANGED_DETAIL,
        ),
        (
            _body(_item(active.id, due_at=OLD_DUE)),
            409,
            CHANGED_DETAIL,
        ),
    ]
    for body, expected_status, expected_message in cases:
        before_presence = fake_clerk.membership_presence_calls
        statements: list[str] = []
        capture = _listen_sql(engine, statements)
        try:
            response = _bulk(client, ctx["token"], body)
        finally:
            event.remove(engine, "before_cursor_execute", capture)
        assert response.status_code == expected_status, response.text
        assert response.json()["error"]["message"] == expected_message
        assert fake_clerk.membership_presence_calls == before_presence
        assert _finding_locks(statements) == []


def test_actual_preflight_owners_drive_one_deduplicated_presence_call(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    second = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    third = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, first, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    _set_follow_up(db_session, second, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    _set_follow_up(db_session, third, owner_id=ctx["admin_id"], due_at=OLD_DUE_DT)

    before_presence = fake_clerk.membership_presence_calls
    statements: list[str] = []
    lock_seen = {"value": False}
    provider_after_lock = {"value": False}
    original_presence = fake_clerk.list_organization_membership_presence

    def presence(*args, **kwargs):
        provider_after_lock["value"] = lock_seen["value"]
        return original_presence(*args, **kwargs)

    fake_clerk.list_organization_membership_presence = presence

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
        if "for update" in statement.lower() and "from findings" in statement.lower():
            lock_seen["value"] = True

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(
                _item(first.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
                _item(second.id, owner_id=ctx["member_id"], due_at=OLD_DUE),
                _item(third.id, owner_id=ctx["admin_id"], due_at=OLD_DUE),
            ),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        fake_clerk.list_organization_membership_presence = original_presence

    assert response.status_code == 200, response.text
    assert fake_clerk.membership_presence_calls == before_presence + 1
    assert fake_clerk.last_presence_provider_user_ids == tuple(
        sorted((ctx["clerk_admin"], ctx["member_clerk"]))
    )
    assert provider_after_lock["value"] is False
    assert len(_finding_locks(statements)) == 1
    assert _membership_writes(statements) == []


def test_unassigned_batch_skips_presence_and_membership_writes(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    before_presence = fake_clerk.membership_presence_calls
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(client, ctx["token"], _body(_item(finding.id)))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    assert fake_clerk.membership_presence_calls == before_presence
    assert _membership_writes(statements) == []


def test_provider_absence_and_failure_are_exact_and_prelock(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    body = _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE))

    fake_clerk.memberships[ctx["member_clerk"]] = []
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        absent = _bulk(client, ctx["token"], body)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert absent.status_code == 400
    assert absent.json()["error"]["message"] == "Assignee must be a current organization member"
    assert _finding_locks(statements) == []

    fake_clerk.fail_membership_presence = True
    statements = []
    capture = _listen_sql(engine, statements)
    try:
        unavailable = _bulk(client, ctx["token"], body)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert unavailable.status_code == 502
    assert (
        unavailable.json()["error"]["message"]
        == "Failed to verify organization membership"
    )
    assert _finding_locks(statements) == []


def test_local_owner_cardinality_and_identity_fail_before_provider_or_lock(
    client, make_token, seed_user_a, fake_clerk, db_session, engine, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    body = _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE))

    from app.services.findings import follow_up_bulk_due as bulk_mod

    original_verify = bulk_mod.verify_current_org_member_batch

    def delete_owner_then_verify(db, **kwargs):
        owner = db.get(User, ctx["member_id"])
        assert owner is not None
        db.delete(owner)
        db.flush()
        return original_verify(db, **kwargs)

    monkeypatch.setattr(
        bulk_mod,
        "verify_current_org_member_batch",
        delete_owner_then_verify,
    )
    before_presence = fake_clerk.membership_presence_calls
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        missing_local = _bulk(client, ctx["token"], body)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert missing_local.status_code == 409, missing_local.text
    assert missing_local.json()["error"]["message"] == CHANGED_DETAIL
    assert fake_clerk.membership_presence_calls == before_presence
    assert _finding_locks(statements) == []
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_blank_local_provider_identity_is_502_before_provider_or_lock(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    db_session.execute(
        update(User).where(User.id == ctx["member_id"]).values(clerk_user_id=" ")
    )
    db_session.commit()
    before_presence = fake_clerk.membership_presence_calls
    statements: list[str] = []
    capture = _listen_sql(engine, statements)
    try:
        response = _bulk(
            client,
            ctx["token"],
            _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE)),
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 502
    assert response.json()["error"]["message"] == "Failed to verify organization membership"
    assert fake_clerk.membership_presence_calls == before_presence
    assert _finding_locks(statements) == []


def test_local_owner_projection_cardinality_and_duplicate_identity_fail_closed():
    class Scalars:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

    class FakeDb:
        def __init__(self, rows):
            self.rows = rows

        def scalars(self, statement):
            return Scalars(self.rows)

    class Directory:
        calls = 0

        def list_organization_membership_presence(self, *args, **kwargs):
            self.calls += 1
            return frozenset()

    first_id = uuid4()
    second_id = uuid4()
    organization = SimpleNamespace(clerk_org_id="org_test")

    directory = Directory()
    missing_db = FakeDb([SimpleNamespace(id=first_id, clerk_user_id="user_a")])
    with pytest.raises(HTTPException) as missing:
        verify_current_org_member_batch(
            missing_db,
            directory=directory,
            organization=organization,
            user_ids=[first_id, second_id],
        )
    assert missing.value.status_code == 409
    assert missing.value.detail == CHANGED_DETAIL
    assert directory.calls == 0

    duplicate_db = FakeDb(
        [
            SimpleNamespace(id=first_id, clerk_user_id="user_same"),
            SimpleNamespace(id=second_id, clerk_user_id="user_same"),
        ]
    )
    with pytest.raises(HTTPException) as duplicate:
        verify_current_org_member_batch(
            duplicate_db,
            directory=directory,
            organization=organization,
            user_ids=[first_id, second_id],
        )
    assert duplicate.value.status_code == 502
    assert duplicate.value.detail == "Failed to verify organization membership"
    assert directory.calls == 0


def test_due_change_after_provider_is_rejected_by_populated_locked_recheck(
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
    from app.services.findings import follow_up_bulk_due as bulk_mod

    original_verify = bulk_mod.verify_current_org_member_batch

    def verify_then_change(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        other = session_factory()
        try:
            other.execute(
                update(Finding)
                .where(Finding.id == finding.id)
                .values(follow_up_due_at=datetime(2026, 9, 15, 15, 0, tzinfo=UTC))
            )
            other.commit()
        finally:
            other.close()
        return result

    monkeypatch.setattr(
        bulk_mod,
        "verify_current_org_member_batch",
        verify_then_change,
    )
    response = _bulk(
        client,
        ctx["token"],
        _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE)),
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["message"] == CHANGED_DETAIL
    assert _row(db_session, finding.id).follow_up_due_at != NEW_DUE_DT
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"assigned_to_user_id": None}, CHANGED_DETAIL),
        ({"status": "resolved"}, INACTIVE_DETAIL),
    ],
)
def test_owner_or_status_change_after_provider_fails_locked_recheck(
    client,
    make_token,
    seed_user_a,
    fake_clerk,
    db_session,
    session_factory,
    monkeypatch,
    mutation,
    message,
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    from app.services.findings import follow_up_bulk_due as bulk_mod

    original_verify = bulk_mod.verify_current_org_member_batch

    def verify_then_change(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        other = session_factory()
        try:
            other.execute(
                update(Finding).where(Finding.id == finding.id).values(**mutation)
            )
            other.commit()
        finally:
            other.close()
        return result

    monkeypatch.setattr(
        bulk_mod,
        "verify_current_org_member_batch",
        verify_then_change,
    )
    response = _bulk(
        client,
        ctx["token"],
        _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE)),
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["message"] == message
    assert _history_count(db_session) == 0
    assert _audit_count(db_session) == 0


def test_changed_rows_preserve_owner_history_audit_and_generation(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_follow_up(db_session, finding, owner_id=ctx["member_id"], due_at=OLD_DUE_DT)
    original_updated_at = finding.updated_at
    response = _bulk(
        client,
        ctx["token"],
        _body(_item(finding.id, owner_id=ctx["member_id"], due_at=OLD_DUE)),
    )
    assert response.status_code == 200, response.text
    row = _row(db_session, finding.id)
    assert row.assigned_to_user_id == ctx["member_id"]
    assert row.follow_up_due_at == NEW_DUE_DT
    assert row.updated_at == original_updated_at
    change = db_session.scalar(
        select(FindingFollowUpChange).where(
            FindingFollowUpChange.finding_id == finding.id
        )
    )
    assert change is not None
    assert change.previous_assigned_to_user_id == ctx["member_id"]
    assert change.new_assigned_to_user_id == ctx["member_id"]
    assert change.previous_due_at == OLD_DUE_DT
    assert change.new_due_at == NEW_DUE_DT
    audit = db_session.scalar(
        select(AuditEvent).where(AuditEvent.resource_id == change.id)
    )
    assert audit is not None
    assert audit.action == "finding.follow_up_changed"
    generation = resolve_current_follow_up_generation(db_session, row)
    assert generation is not None
    assert generation.id == change.id


def test_service_structure_pins_preflight_provider_and_locked_recheck():
    source = inspect.getsource(bulk_update_finding_follow_up_due)
    first_select = source.index("preflight_rows")
    provider = source.index("verify_current_org_member_batch")
    lock = source.index(".with_for_update()")
    assert first_select < provider < lock
    assert source.count("Finding.organization_id == organization.id") == 2
    assert source.count(".order_by(Finding.id.asc())") == 2
    assert ".execution_options(populate_existing=True)" in source
    assert "row.assigned_to_user_id =" not in source
    assert "assert_assignable_org_member" not in source
    assert "warm_local_org_membership" not in source
    helper = inspect.getsource(verify_current_org_member_batch)
    assert "list_organization_membership_presence" in helper
    assert "OrganizationMembership" not in helper


def test_frontend_m50_and_m49_contract_scripts():
    env = {**os.environ, "NODE_ENV": "test"}
    for script in (M50_SCRIPT, M49_SCRIPT):
        assert script.is_file(), script
        result = subprocess.run(
            ["node", str(script)],
            cwd=str(WEB_ROOT),
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr

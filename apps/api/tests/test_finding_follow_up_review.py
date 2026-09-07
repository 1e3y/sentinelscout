"""Milestone 46 — finding follow-up due-date review (read-only, DB-only)."""

from __future__ import annotations

import inspect
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import event, func, select, text, update

from app.api.routes.findings import finding_follow_up_review_endpoint
from app.core.config import get_settings, reset_settings_cache
from app.models.alert import NotificationOutbox
from app.models.audit import AuditEvent
from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.finding_follow_up_reminder import FindingFollowUpReminderJob
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.services.findings.follow_up_review import (
    INVALID_CURSOR_DETAIL,
    UNAVAILABLE_DETAIL,
    classify_due_state,
    decode_follow_up_review_cursor,
    encode_follow_up_review_cursor,
    list_finding_follow_up_review,
    resolve_follow_up_review_cursor,
)
from tests.test_finding_follow_up import _auth, _finding, _ids, _put_follow_up
from tests.test_organization_access import _assert_no_secrets, _setup

REVIEW = "/v1/findings/follow-up-review"
FORBIDDEN_DTO = {
    "email",
    "clerk_user_id",
    "clerk_org_id",
    "assignment_state",
    "current_member",
    "not_current_member",
    "days_overdue",
    "hours_remaining",
    "due_soon",
    "provider_user_id",
    "membership_id",
    "permissions",
    "evidence",
    "remediation_guidance",
}


def _review(client, token: str, **params):
    return client.get(REVIEW, headers=_auth(token), params=params or None)


def _assert_no_forbidden(payload) -> None:
    _assert_no_secrets(payload)
    if isinstance(payload, dict):
        lowered = {str(k).lower() for k in payload}
        assert FORBIDDEN_DTO.isdisjoint(lowered), lowered & FORBIDDEN_DTO
        for value in payload.values():
            _assert_no_forbidden(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_no_forbidden(item)


def _cursor_payload(raw: str) -> str:
    padded = raw + ("=" * (-len(raw) % 4))
    return urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")


def _set_created_at(db, finding: Finding, when: datetime) -> None:
    finding.created_at = when
    db.add(finding)
    db.commit()
    db.refresh(finding)


def _set_due(db, finding: Finding, when: datetime | None) -> None:
    finding.follow_up_due_at = when
    db.add(finding)
    db.commit()
    db.refresh(finding)


def _m46_provider_counts(fake_clerk) -> tuple[int, int, int]:
    """M46 business-logic provider surface. Auth may still call get_user (M21)."""
    return (
        fake_clerk.membership_presence_calls,
        fake_clerk.memberships_raw_calls,
        fake_clerk.get_membership_calls,
    )


def test_service_and_route_have_no_provider_dependency():
    service = inspect.signature(list_finding_follow_up_review)
    route = inspect.signature(finding_follow_up_review_endpoint)
    assert "directory" not in service.parameters
    assert "clerk" not in " ".join(service.parameters)
    assert "directory" not in route.parameters
    assert OPEN_FINDING_STATUSES == frozenset({"open", "in_progress", "ready_for_retest"})


def test_classification_equality_is_overdue():
    moment = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    assert classify_due_state(None, moment) == "no_due_date"
    assert classify_due_state(moment - timedelta(seconds=1), moment) == "overdue"
    assert classify_due_state(moment, moment) == "overdue"
    assert classify_due_state(moment + timedelta(seconds=1), moment) == "upcoming"


# ---------------------------------------------------------------- RBAC


def test_unauthenticated_401_zero_provider(client, fake_clerk):
    before = _m46_provider_counts(fake_clerk)
    assert client.get(REVIEW).status_code == 401
    assert client.post(REVIEW).status_code in {404, 405}
    assert _m46_provider_counts(fake_clerk) == before


def test_member_403_zero_provider(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    before = _m46_provider_counts(fake_clerk)
    response = _review(client, ctx["member_token"])
    assert response.status_code == 403
    assert _m46_provider_counts(fake_clerk) == before


# ---------------------------------------------------------------- collection / classification


def test_active_statuses_included_resolved_excluded(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    included = {
        status: _finding(
            db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status=status
        )
        for status in ("open", "in_progress", "ready_for_retest")
    }
    resolved = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="resolved"
    )
    _set_due(db_session, resolved, datetime(2020, 1, 1, tzinfo=UTC))
    before = _m46_provider_counts(fake_clerk)
    fake_clerk.fail_membership_presence = True
    body = _review(client, ctx["token"]).json()
    _assert_no_forbidden(body)
    ids = {item["finding_id"] for item in body["items"]}
    assert {str(row.id) for row in included.values()} <= ids
    assert str(resolved.id) not in ids
    assert _m46_provider_counts(fake_clerk) == before


def test_http_classifies_against_returned_evaluation_time(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    none = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    past = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    future = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_due(db_session, past, datetime(2020, 1, 1, 0, 0, tzinfo=UTC))
    _set_due(db_session, future, datetime(2099, 1, 1, 0, 0, tzinfo=UTC))
    assert _put_follow_up(
        client,
        ctx["token"],
        future.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": "2099-01-01T00:00:00Z"},
    ).status_code == 200
    body = _review(client, ctx["token"]).json()
    evaluation = datetime.fromisoformat(body["evaluation_time"].replace("Z", "+00:00"))
    assert evaluation.tzinfo is not None
    by_id = {item["finding_id"]: item for item in body["items"]}
    assert by_id[str(none.id)]["due_state"] == "no_due_date"
    assert by_id[str(none.id)]["follow_up_due_at"] is None
    assert by_id[str(none.id)]["assignee"] is None
    assert by_id[str(past.id)]["due_state"] == "overdue"
    assert by_id[str(future.id)]["due_state"] == "upcoming"
    assert by_id[str(future.id)]["assignee"]["user_id"] == str(ctx["member_id"])
    assert by_id[str(future.id)]["assignee"]["display_name"] == "Member One"


def test_service_classifies_equal_due_as_overdue(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    moment = datetime(2026, 7, 1, 15, 0, tzinfo=UTC)
    equal = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_due(db_session, equal, moment)
    organization = db_session.get(Organization, ctx["org_id"])
    assert organization is not None
    result = list_finding_follow_up_review(
        db_session,
        organization=organization,
        due_filter="all",
        evaluation_time=moment,
    )
    item = next(row for row in result.items if row.finding_id == equal.id)
    assert item.due_state == "overdue"
    assert result.evaluation_time == moment


# ---------------------------------------------------------------- public filters


def test_omitted_and_explicit_filters_and_all_rejected(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    moment = datetime.now(UTC)
    none = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    overdue = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    upcoming = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_due(db_session, overdue, moment - timedelta(days=1))
    _set_due(db_session, upcoming, moment + timedelta(days=1))
    all_body = _review(client, ctx["token"]).json()
    ids = {item["finding_id"] for item in all_body["items"]}
    assert {str(none.id), str(overdue.id), str(upcoming.id)} <= ids
    nulls = _review(client, ctx["token"], due_state="no_due_date").json()
    assert {item["finding_id"] for item in nulls["items"]} == {str(none.id)}
    assert all(item["due_state"] == "no_due_date" for item in nulls["items"])
    late = _review(client, ctx["token"], due_state="overdue").json()
    assert {item["finding_id"] for item in late["items"]} == {str(overdue.id)}
    early = _review(client, ctx["token"], due_state="upcoming").json()
    assert {item["finding_id"] for item in early["items"]} == {str(upcoming.id)}
    rejected = _review(client, ctx["token"], due_state="all")
    assert rejected.status_code == 422


# ---------------------------------------------------------------- cursor time / binding


def test_continuation_reuses_evaluation_time_and_filter_binding(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    rows = []
    for index in range(3):
        finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        _set_created_at(db_session, finding, base + timedelta(minutes=index))
        _set_due(db_session, finding, datetime(2020, 1, 1, tzinfo=UTC))
        rows.append(finding)
    first = _review(client, ctx["token"], page_size=2, due_state="overdue")
    assert first.status_code == 200, first.text
    body = first.json()
    assert [item["finding_id"] for item in body["items"]] == [str(rows[2].id), str(rows[1].id)]
    evaluation = body["evaluation_time"]
    cursor = body["next_cursor"]
    assert cursor
    payload = _cursor_payload(cursor)
    assert payload.startswith("v1|overdue|")
    assert "follow_up" not in payload
    decoded = decode_follow_up_review_cursor(cursor)
    assert decoded.due_filter == "overdue"
    assert decoded.finding_id == rows[1].id
    assert decoded.created_at == rows[1].created_at

    later = _review(client, ctx["token"], page_size=2, due_state="overdue", cursor=cursor)
    assert later.status_code == 200
    assert later.json()["evaluation_time"] == evaluation
    assert [item["finding_id"] for item in later.json()["items"]] == [str(rows[0].id)]
    assert later.json()["next_cursor"] is None

    assert _review(client, ctx["token"], cursor=cursor).status_code == 400
    assert _review(client, ctx["token"], due_state="upcoming", cursor=cursor).status_code == 400
    all_first = _review(client, ctx["token"], page_size=2)
    all_cursor = all_first.json()["next_cursor"]
    assert _review(client, ctx["token"], cursor=all_cursor).status_code == 200
    assert _review(client, ctx["token"], due_state="overdue", cursor=all_cursor).status_code == 400


def test_cursor_lifetime_and_canonical_instants(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    now = datetime.now(UTC)
    fresh = encode_follow_up_review_cursor(
        due_filter="all",
        evaluation_time=now - timedelta(minutes=10),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    assert _review(client, ctx["token"], cursor=fresh).status_code == 200

    hour = encode_follow_up_review_cursor(
        due_filter="all",
        evaluation_time=now - timedelta(hours=1) + timedelta(seconds=5),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    assert _review(client, ctx["token"], cursor=hour).status_code == 200

    expired = encode_follow_up_review_cursor(
        due_filter="all",
        evaluation_time=now - timedelta(hours=1, minutes=1),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    expired_response = _review(client, ctx["token"], cursor=expired)
    assert expired_response.status_code == 400
    assert expired_response.json()["error"]["message"] == INVALID_CURSOR_DETAIL

    future = encode_follow_up_review_cursor(
        due_filter="all",
        evaluation_time=now + timedelta(minutes=1),
        created_at=finding.created_at,
        finding_id=finding.id,
    )
    assert _review(client, ctx["token"], cursor=future).status_code == 400

    naive = urlsafe_b64encode(
        f"v1|all|{now.replace(tzinfo=None).isoformat()}|{finding.created_at.isoformat()}|{finding.id}".encode()
    ).decode("ascii").rstrip("=")
    assert _review(client, ctx["token"], cursor=naive).status_code == 400
    assert _review(client, ctx["token"], cursor="%%%not-a-cursor").status_code == 400


def test_z_and_offset_cursor_instants_are_equivalent(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    moment = datetime.now(UTC).replace(microsecond=0)
    z_payload = f"v1|all|{moment.strftime('%Y-%m-%dT%H:%M:%SZ')}|{moment.strftime('%Y-%m-%dT%H:%M:%SZ')}|{finding.id}"
    offset_payload = (
        f"v1|all|{moment.isoformat()}|{moment.astimezone(UTC).isoformat()}|{finding.id}"
    )
    z_cursor = urlsafe_b64encode(z_payload.encode()).decode("ascii").rstrip("=")
    offset_cursor = urlsafe_b64encode(offset_payload.encode()).decode("ascii").rstrip("=")
    decoded_z = decode_follow_up_review_cursor(z_cursor)
    decoded_offset = decode_follow_up_review_cursor(offset_cursor)
    assert decoded_z.evaluation_time == decoded_offset.evaluation_time
    assert _review(client, ctx["token"], cursor=z_cursor).status_code == 200


def test_wall_clock_does_not_reclassify_inside_unexpired_walk(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    evaluation = datetime.now(UTC) - timedelta(minutes=30)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_due(db_session, finding, evaluation + timedelta(minutes=10))
    cursor = encode_follow_up_review_cursor(
        due_filter="upcoming",
        evaluation_time=evaluation,
        created_at=finding.created_at + timedelta(seconds=1),
        finding_id=finding.id,
    )
    continued = _review(client, ctx["token"], due_state="upcoming", cursor=cursor)
    assert continued.status_code == 200, continued.text
    ids = {item["finding_id"] for item in continued.json()["items"]}
    assert str(finding.id) in ids
    assert all(item["due_state"] == "upcoming" for item in continued.json()["items"])
    fresh_upcoming = _review(client, ctx["token"], due_state="upcoming").json()
    assert str(finding.id) not in {item["finding_id"] for item in fresh_upcoming["items"]}
    fresh_overdue = _review(client, ctx["token"], due_state="overdue").json()
    assert str(finding.id) in {item["finding_id"] for item in fresh_overdue["items"]}


def test_invalid_cursor_is_400_before_review_query(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    calls = {"n": 0}
    real = list_finding_follow_up_review

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr("app.api.routes.findings.list_finding_follow_up_review", wrapped)
    response = _review(client, ctx["token"], cursor="%%%not-a-cursor")
    assert response.status_code == 400
    assert response.json()["error"]["message"] == INVALID_CURSOR_DETAIL
    assert calls["n"] == 0


# ---------------------------------------------------------------- keyset / sentinel


def test_keyset_page_size_plus_one_and_sentinel_not_enriched(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
    visible = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    sentinel = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_created_at(db_session, visible, base + timedelta(hours=1))
    _set_created_at(db_session, sentinel, base)
    assert _put_follow_up(
        client,
        ctx["token"],
        sentinel.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    organization = db_session.get(Organization, ctx["org_id"])
    assert organization is not None
    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        result = list_finding_follow_up_review(
            db_session,
            organization=organization,
            due_filter="all",
            evaluation_time=datetime.now(UTC),
            page_size=1,
        )
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
    assert [item.finding_id for item in result.items] == [visible.id]
    assert result.next_cursor is not None
    decoded = decode_follow_up_review_cursor(result.next_cursor)
    assert decoded.finding_id == visible.id
    user_sql = [item for item in statements if "from users" in item.lower()]
    assert user_sql == []
    joined = " ".join(statements).lower()
    assert "organization_membership" not in joined
    assert "findings.evidence" not in joined


def test_sentinel_only_missing_user_does_not_fail_visible_page(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    visible = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    sentinel = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _set_created_at(db_session, visible, base + timedelta(hours=1))
    _set_created_at(db_session, sentinel, base)
    missing = uuid4()
    db_session.execute(text("SET session_replication_role = replica"))
    db_session.execute(
        update(Finding).where(Finding.id == sentinel.id).values(assigned_to_user_id=missing)
    )
    db_session.execute(text("SET session_replication_role = DEFAULT"))
    db_session.commit()
    response = _review(client, ctx["token"], page_size=1)
    assert response.status_code == 200, response.text
    assert [item["finding_id"] for item in response.json()["items"]] == [str(visible.id)]


def test_due_edit_does_not_move_keyset_but_can_leave_filter(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    findings = []
    for index in range(3):
        finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        _set_created_at(db_session, finding, base + timedelta(hours=index))
        _set_due(db_session, finding, datetime(2099, 1, 1, tzinfo=UTC))
        findings.append(finding)
    first = _review(client, ctx["token"], page_size=2, due_state="upcoming").json()
    cursor = first["next_cursor"]
    newest = db_session.get(Finding, findings[2].id)
    assert newest is not None
    newest.follow_up_due_at = datetime(2020, 1, 1, tzinfo=UTC)
    db_session.add(newest)
    db_session.commit()
    second = _review(client, ctx["token"], page_size=2, due_state="upcoming", cursor=cursor)
    assert [item["finding_id"] for item in second.json()["items"]] == [str(findings[0].id)]
    upcoming = _review(client, ctx["token"], due_state="upcoming").json()
    assert str(findings[2].id) not in {item["finding_id"] for item in upcoming["items"]}
    overdue = _review(client, ctx["token"], due_state="overdue").json()
    assert str(findings[2].id) in {item["finding_id"] for item in overdue["items"]}


def test_page_size_validation_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _review(client, ctx["token"], page_size=0).status_code == 422
    assert _review(client, ctx["token"], page_size=101).status_code == 422


# ---------------------------------------------------------------- assignee / privacy / provider


def test_local_user_sql_selects_id_and_name_only(
    client, make_token, seed_user_a, fake_clerk, db_session, engine
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    organization = db_session.get(Organization, ctx["org_id"])
    assert organization is not None
    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        result = list_finding_follow_up_review(
            db_session,
            organization=organization,
            due_filter="all",
            evaluation_time=datetime.now(UTC),
        )
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
    assert any(item.assignee and item.assignee.user_id == ctx["member_id"] for item in result.items)
    user_sql = [item for item in statements if "from users" in item.lower()]
    assert user_sql, statements
    for sql in user_sql:
        lowered = sql.lower()
        assert "users.id" in lowered or "users.id" in lowered.replace("\n", " ")
        assert "clerk_user_id" not in lowered
        assert "users.email" not in lowered
        assert "email_verified" not in lowered
    joined = " ".join(statements).lower()
    assert "organization_membership" not in joined


def test_missing_visible_assignee_user_is_503(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    missing = uuid4()
    db_session.execute(text("SET session_replication_role = replica"))
    db_session.execute(
        update(Finding).where(Finding.id == finding.id).values(assigned_to_user_id=missing)
    )
    db_session.execute(text("SET session_replication_role = DEFAULT"))
    db_session.commit()
    response = _review(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UNAVAILABLE_DETAIL
    assert "items" not in response.json()


def test_blank_display_name_is_not_fabricated_from_email(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    user = db_session.get(User, ctx["member_id"])
    assert user is not None
    user.name = None
    db_session.add(user)
    db_session.commit()
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    item = next(
        row
        for row in _review(client, ctx["token"]).json()["items"]
        if row["finding_id"] == str(finding.id)
    )
    assert item["assignee"]["display_name"] is None
    assert "email" not in item["assignee"]


def test_http_zero_provider_calls_even_when_assigned(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    before = _m46_provider_counts(fake_clerk)
    fake_clerk.fail_membership_presence = True
    response = _review(client, ctx["token"])
    assert response.status_code == 200, response.text
    assert _m46_provider_counts(fake_clerk) == before
    assert fake_clerk.update_role_calls == 0
    assert fake_clerk.create_invitation_calls == 0


def test_cross_org_rows_never_returned(
    client, make_token, seed_user_a, seed_user_b, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    other_clerk, other_org = seed_user_b
    other_token = make_token(sub=other_clerk, org_id=other_org, org_role="org:admin")
    other_id, other_org_id = _ids(client, other_token)
    foreign = _finding(db_session, organization_id=other_org_id, user_id=other_id)
    local = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    body = _review(client, ctx["token"]).json()
    ids = {item["finding_id"] for item in body["items"]}
    assert str(local.id) in ids
    assert str(foreign.id) not in ids


# ---------------------------------------------------------------- read-only / rate limit


def test_read_does_not_write(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": "2026-12-01T00:00:00Z"},
    ).status_code == 200
    db_session.refresh(finding)
    fingerprint = (
        finding.assigned_to_user_id,
        finding.follow_up_due_at,
        finding.status,
        finding.updated_at,
    )
    follow_ups = int(db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0)
    audits = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    reminders = int(
        db_session.scalar(select(func.count()).select_from(FindingFollowUpReminderJob)) or 0
    )
    notices = int(db_session.scalar(select(func.count()).select_from(NotificationOutbox)) or 0)
    memberships = int(
        db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0
    )
    assert _review(client, ctx["token"]).status_code == 200
    db_session.refresh(finding)
    assert (
        finding.assigned_to_user_id,
        finding.follow_up_due_at,
        finding.status,
        finding.updated_at,
    ) == fingerprint
    assert int(db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0) == follow_ups
    assert int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0) == audits
    assert (
        int(db_session.scalar(select(func.count()).select_from(FindingFollowUpReminderJob)) or 0)
        == reminders
    )
    assert int(db_session.scalar(select(func.count()).select_from(NotificationOutbox)) or 0) == notices
    assert (
        int(db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0)
        == memberships
    )


def test_rate_limit_429_before_review_query(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_FINDING_FOLLOW_UP_READ", "1")
    reset_settings_cache()
    try:
        ctx = _setup(client, make_token, seed_user_a, fake_clerk)
        _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        calls = {"n": 0}
        real = list_finding_follow_up_review

        def wrapped(*args, **kwargs):
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr("app.api.routes.findings.list_finding_follow_up_review", wrapped)
        first = _review(client, ctx["token"])
        assert first.status_code == 200, first.text
        assert calls["n"] == 1
        limited = _review(client, ctx["token"])
        assert limited.status_code == 429, limited.text
        assert limited.json()["error"]["code"] == "rate_limited"
        assert calls["n"] == 1
    finally:
        monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_FINDING_FOLLOW_UP_READ", "60")
        reset_settings_cache()


def test_rate_limit_default_and_no_post_route():
    settings = get_settings()
    assert settings.rate_limit_organization_finding_follow_up_read == 60
    assert settings.rate_limit_window_seconds == 3600


def test_cursor_resolve_rejects_mismatched_filter_without_service():
    now = datetime.now(UTC)
    cursor = encode_follow_up_review_cursor(
        due_filter="overdue",
        evaluation_time=now,
        created_at=now,
        finding_id=uuid4(),
    )
    try:
        resolve_follow_up_review_cursor(cursor, due_filter="all", request_now=now)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
        assert exc.detail == INVALID_CURSOR_DETAIL
    else:
        raise AssertionError("expected invalid cursor")

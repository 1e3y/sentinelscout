"""Milestone 44 — finding ownership review (read-only)."""

from __future__ import annotations

import logging
from base64 import urlsafe_b64decode
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import event, func, select, update

from app.core.config import get_settings, reset_settings_cache
from app.models.audit import AuditEvent
from app.models.finding import OPEN_FINDING_STATUSES, Finding
from app.models.finding_follow_up import FindingFollowUpChange
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.services.clerk import (
    ClerkUserInfo,
    FindingOwnershipPresenceUnavailable,
    HttpClerkDirectory,
)
from app.services.findings.ownership_review import (
    INVALID_CURSOR_DETAIL,
    decode_ownership_review_cursor,
    list_finding_ownership_review,
)
from app.services.reports.summary import OPEN_FINDING_STATUSES as REPORT_OPEN_STATUSES
from tests.test_finding_follow_up import (
    _add_clerk_member,
    _auth,
    _finding,
    _ids,
    _put_follow_up,
)
from tests.test_organization_access import _assert_no_secrets, _setup
from tests.test_organization_access_mutations import _delete_member

REVIEW = "/v1/findings/ownership-review"
UNAVAILABLE = "Finding ownership could not be verified."
FORBIDDEN_DTO = {
    "email",
    "clerk_user_id",
    "clerk_org_id",
    "departed_member",
    "due_state",
    "current_retest_state",
    "provider_user_id",
    "membership_id",
    "permissions",
    "evidence",
    "remediation_guidance",
    "external_role",
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


def _http_directory(handler) -> HttpClerkDirectory:
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url="https://api.clerk.test")
    return HttpClerkDirectory(get_settings(), client=client)


def test_open_finding_statuses_are_shared_domain_constant():
    assert OPEN_FINDING_STATUSES is REPORT_OPEN_STATUSES
    assert OPEN_FINDING_STATUSES == frozenset({"open", "in_progress", "ready_for_retest"})
    assert "resolved" not in OPEN_FINDING_STATUSES
    assert "departed_member" not in ("unassigned", "current_member", "not_current_member")


# ---------------------------------------------------------------- RBAC


def test_unauthenticated_401_zero_provider(client, fake_clerk):
    before = fake_clerk.membership_presence_calls
    get_before = fake_clerk.get_user_calls
    raw_before = fake_clerk.memberships_raw_calls
    assert client.get(REVIEW).status_code == 401
    assert fake_clerk.membership_presence_calls == before
    assert fake_clerk.get_user_calls == get_before
    assert fake_clerk.memberships_raw_calls == raw_before
    assert fake_clerk.get_membership_calls == 0


def test_member_403_zero_provider(client, make_token, seed_user_a, fake_clerk, db_session):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    before = fake_clerk.membership_presence_calls
    raw_before = fake_clerk.memberships_raw_calls
    single_before = fake_clerk.get_membership_calls
    response = _review(client, ctx["member_token"])
    assert response.status_code == 403
    assert fake_clerk.membership_presence_calls == before
    assert fake_clerk.get_membership_calls == single_before
    assert fake_clerk.memberships_raw_calls == raw_before


# ---------------------------------------------------------------- state vocabulary


def test_unassigned_current_and_not_current_member(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unassigned = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    current = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    departed = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    due = "2026-10-01T15:00:00Z"
    assert _put_follow_up(
        client,
        ctx["token"],
        current.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due},
    ).status_code == 200
    stale_clerk = _add_clerk_member(fake_clerk, clerk_org_id=ctx["clerk_org"], name="Stale Owner")
    stale_token = make_token(sub=stale_clerk, org_id=ctx["clerk_org"], org_role="org:member")
    stale_id, _ = _ids(client, stale_token)
    assert _put_follow_up(
        client,
        ctx["token"],
        departed.id,
        {"assigned_to_user_id": str(stale_id), "follow_up_due_at": due},
    ).status_code == 200
    fake_clerk.memberships[stale_clerk] = []

    before_raw = fake_clerk.memberships_raw_calls
    before_single = fake_clerk.get_membership_calls
    before_presence = fake_clerk.membership_presence_calls
    response = _review(client, ctx["token"])
    assert response.status_code == 200, response.text
    body = response.json()
    _assert_no_forbidden(body)
    by_id = {item["finding_id"]: item for item in body["items"]}
    assert by_id[str(unassigned.id)]["assignment_state"] == "unassigned"
    assert by_id[str(unassigned.id)]["assignee"] is None
    assert by_id[str(current.id)]["assignment_state"] == "current_member"
    assert by_id[str(current.id)]["assignee"]["user_id"] == str(ctx["member_id"])
    assert by_id[str(current.id)]["assignee"]["display_name"] == "Member One"
    assert by_id[str(departed.id)]["assignment_state"] == "not_current_member"
    assert by_id[str(departed.id)]["assignee"]["user_id"] == str(stale_id)
    assert "departed_member" not in str(body)
    assert fake_clerk.membership_presence_calls == before_presence + 1
    assert fake_clerk.last_presence_limit == 2
    assert fake_clerk.last_presence_offset == 0
    assert fake_clerk.memberships_raw_calls == before_raw
    assert fake_clerk.get_membership_calls == before_single


def test_unknown_provider_role_still_current_member(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    custom_clerk = _add_clerk_member(
        fake_clerk, clerk_org_id=ctx["clerk_org"], role="org:billing", name="Custom Role"
    )
    custom_token = make_token(sub=custom_clerk, org_id=ctx["clerk_org"], org_role="org:member")
    custom_id, _ = _ids(client, custom_token)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(custom_id), "follow_up_due_at": None},
    ).status_code == 200
    body = _review(client, ctx["token"]).json()
    item = next(row for row in body["items"] if row["finding_id"] == str(finding.id))
    assert item["assignment_state"] == "current_member"


def test_provider_uncertainty_never_not_current_member(
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
    fake_clerk.fail_membership_presence = True
    response = _review(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UNAVAILABLE
    assert "not_current_member" not in response.text
    assert "items" not in response.json() or "items" not in response.json().get("error", {})


def test_active_scope_excludes_resolved_includes_assigned_and_unassigned(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    open_f = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="open"
    )
    progress = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="in_progress"
    )
    retest = _finding(
        db_session,
        organization_id=ctx["org_id"],
        user_id=ctx["admin_id"],
        status="ready_for_retest",
    )
    resolved = _finding(
        db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"], status="resolved"
    )
    assert _put_follow_up(
        client,
        ctx["token"],
        progress.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    body = _review(client, ctx["token"]).json()
    ids = {item["finding_id"] for item in body["items"]}
    assert {str(open_f.id), str(progress.id), str(retest.id)} <= ids
    assert str(resolved.id) not in ids
    states = {item["finding_id"]: item["status"] for item in body["items"]}
    assert states[str(open_f.id)] == "open"
    assert states[str(progress.id)] == "in_progress"
    assert states[str(retest.id)] == "ready_for_retest"


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


# ---------------------------------------------------------------- pagination


def test_order_created_at_desc_id_desc_cursor_omits_due_date(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    rows = []
    for index in range(3):
        finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        _set_created_at(db_session, finding, base + timedelta(minutes=index))
        finding.follow_up_due_at = base + timedelta(days=10 - index)
        db_session.add(finding)
        db_session.commit()
        rows.append(finding)
    first = _review(client, ctx["token"], page_size=2)
    assert first.status_code == 200, first.text
    body = first.json()
    assert [item["finding_id"] for item in body["items"]] == [
        str(rows[2].id),
        str(rows[1].id),
    ]
    assert body["next_cursor"]
    payload = _cursor_payload(body["next_cursor"])
    assert payload.startswith("v1|")
    assert "follow_up" not in payload
    created_at, finding_id = decode_ownership_review_cursor(body["next_cursor"])
    assert finding_id == rows[1].id
    assert created_at == rows[1].created_at

    later = _review(client, ctx["token"], page_size=2, cursor=body["next_cursor"])
    assert [item["finding_id"] for item in later.json()["items"]] == [str(rows[0].id)]
    assert later.json()["next_cursor"] is None


def test_due_date_mutation_does_not_change_cursor_order(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
    findings = []
    for index in range(3):
        finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        _set_created_at(db_session, finding, base + timedelta(hours=index))
        findings.append(finding)
    first = _review(client, ctx["token"], page_size=2).json()
    cursor = first["next_cursor"]
    newest = db_session.get(Finding, findings[2].id)
    assert newest is not None
    newest.follow_up_due_at = datetime(2020, 1, 1, tzinfo=UTC)
    db_session.add(newest)
    db_session.commit()
    second = _review(client, ctx["token"], page_size=2, cursor=cursor)
    assert [item["finding_id"] for item in second.json()["items"]] == [str(findings[0].id)]
    full = _review(client, ctx["token"], page_size=50).json()
    by_id = {item["finding_id"]: item for item in full["items"]}
    assert by_id[str(findings[2].id)]["follow_up_due_at"] is not None


def test_malformed_cursor_400(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.membership_presence_calls
    response = _review(client, ctx["token"], cursor="%%%not-a-cursor")
    assert response.status_code == 400
    assert response.json()["error"]["message"] == INVALID_CURSOR_DETAIL
    assert fake_clerk.membership_presence_calls == before


def test_page_size_validation_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.membership_presence_calls
    assert _review(client, ctx["token"], page_size=0).status_code == 422
    assert _review(client, ctx["token"], page_size=101).status_code == 422
    assert _review(client, ctx["token"], page_size=-1).status_code == 422
    assert fake_clerk.membership_presence_calls == before


def test_default_page_size_and_rate_limit_default():
    settings = get_settings()
    assert settings.rate_limit_organization_finding_ownership_read == 60
    assert settings.rate_limit_window_seconds == 3600


# ---------------------------------------------------------------- batch request


def test_same_assignee_once_and_all_unassigned_zero_calls(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    empty_before = fake_clerk.membership_presence_calls
    empty = _review(client, ctx["token"])
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert fake_clerk.membership_presence_calls == empty_before

    first = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    second = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    unassigned = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    for finding in (first, second):
        assert _put_follow_up(
            client,
            ctx["token"],
            finding.id,
            {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
        ).status_code == 200
    before = fake_clerk.membership_presence_calls
    body = _review(client, ctx["token"]).json()
    assert fake_clerk.membership_presence_calls == before + 1
    assert fake_clerk.last_presence_limit == 1
    assert fake_clerk.last_presence_offset == 0
    assert fake_clerk.last_presence_provider_user_ids == (ctx["member_clerk"],)
    states = {item["finding_id"]: item["assignment_state"] for item in body["items"]}
    assert states[str(first.id)] == "current_member"
    assert states[str(second.id)] == "current_member"
    assert states[str(unassigned.id)] == "unassigned"


def test_all_unassigned_page_zero_provider_calls(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    before = fake_clerk.membership_presence_calls
    body = _review(client, ctx["token"]).json()
    assert all(item["assignment_state"] == "unassigned" for item in body["items"])
    assert fake_clerk.membership_presence_calls == before
    assert fake_clerk.get_membership_calls == 0
    assert fake_clerk.memberships_raw_calls == 0


# ---------------------------------------------------------------- clerk wire encoding / integrity


def test_http_presence_u1_and_u100_encoding_and_canonical_order():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["items"] = list(request.url.params.multi_items())
        return httpx.Response(200, json={"data": [], "total_count": 9999})

    directory = _http_directory(handler)
    one = directory.list_organization_membership_presence(
        "org_test",
        provider_user_ids=("user_z",),
    )
    assert one == frozenset()
    assert captured["path"].endswith("/organizations/org_test/memberships")
    items = captured["items"]
    assert ("limit", "1") in items or ("limit", 1) in items
    assert ("offset", "0") in items or ("offset", 0) in items
    assert [v for k, v in items if k == "user_id"] == ["user_z"]

    ids = [f"user_{i:03d}" for i in range(99, -1, -1)]
    hundred = directory.list_organization_membership_presence(
        "org_test",
        provider_user_ids=ids,
    )
    assert hundred == frozenset()
    items = captured["items"]
    assert ("limit", "100") in items or ("limit", 100) in items
    assert ("offset", "0") in items or ("offset", 0) in items
    user_values = [v for k, v in items if k == "user_id"]
    assert user_values == sorted(ids)
    assert ",".join(user_values) not in {v for _, v in items}
    directory.close()


def test_http_presence_valid_subset_and_ignores_total_count():
    requested = ("user_b", "user_a", "user_c")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "total_count": 400,
                "data": [
                    {
                        "id": "mem_1",
                        "role": "org:admin",
                        "permissions": ["org:sys"],
                        "public_user_data": {
                            "user_id": "user_a",
                            "identifier": "a@example.com",
                            "first_name": "Ada",
                            "last_name": "Lovelace",
                            "image_url": "https://img.example/a.png",
                        },
                    }
                ],
            },
        )

    directory = _http_directory(handler)
    present = directory.list_organization_membership_presence(
        "org_test",
        provider_user_ids=requested,
    )
    assert present == frozenset({"user_a"})
    assert isinstance(present, frozenset)
    directory.close()


def test_http_presence_unexpected_duplicate_missing_malformed():
    def unexpected(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"public_user_data": {"user_id": "user_other"}}]},
        )

    directory = _http_directory(unexpected)
    try:
        directory.list_organization_membership_presence(
            "org_test", provider_user_ids=("user_a",)
        )
        raise AssertionError("expected unavailable")
    except FindingOwnershipPresenceUnavailable:
        pass
    directory.close()

    def duplicate(_request: httpx.Request) -> httpx.Response:
        row = {"public_user_data": {"user_id": "user_a"}}
        return httpx.Response(200, json={"data": [row, row]})

    directory = _http_directory(duplicate)
    try:
        directory.list_organization_membership_presence(
            "org_test", provider_user_ids=("user_a",)
        )
        raise AssertionError("expected unavailable")
    except FindingOwnershipPresenceUnavailable:
        pass
    directory.close()

    def missing(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"public_user_data": {}}]})

    directory = _http_directory(missing)
    try:
        directory.list_organization_membership_presence(
            "org_test", provider_user_ids=("user_a",)
        )
        raise AssertionError("expected unavailable")
    except FindingOwnershipPresenceUnavailable:
        pass
    directory.close()

    def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    directory = _http_directory(malformed)
    try:
        directory.list_organization_membership_presence(
            "org_test", provider_user_ids=("user_a",)
        )
        raise AssertionError("expected unavailable")
    except FindingOwnershipPresenceUnavailable:
        pass
    directory.close()


def test_http_presence_provider_errors():
    for status_code in (429, 500, 503):

        def handler(_request: httpx.Request, code=status_code) -> httpx.Response:
            return httpx.Response(code, json={"errors": [{"message": "nope"}]})

        directory = _http_directory(handler)
        try:
            directory.list_organization_membership_presence(
                "org_test", provider_user_ids=("user_a",)
            )
            raise AssertionError(f"expected unavailable for {status_code}")
        except FindingOwnershipPresenceUnavailable:
            pass
        directory.close()


def test_integrity_failure_is_atomic_503(
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
    fake_clerk.fail_membership_presence = True
    response = _review(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UNAVAILABLE
    assert "items" not in response.json()


# ---------------------------------------------------------------- data minimization / logs


def test_local_user_sql_selects_only_needed_columns(
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
    db_session.expire_all()
    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        result = list_finding_ownership_review(
            db_session,
            organization=organization,
            directory=fake_clerk,
            page_size=50,
        )
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
    assert any(item.assignment_state == "current_member" for item in result.items)

    joined = " ".join(statements).lower()
    user_sql = [
        item
        for item in statements
        if "users" in item.lower() and "clerk_user_id" in item.lower()
    ]
    assert user_sql, statements
    for sql in user_sql:
        lowered = sql.lower()
        assert "clerk_user_id" in lowered
        assert "users.email" not in lowered
        assert "email_verified" not in lowered
    assert "findings.evidence" not in joined
    assert "business_impact" not in joined
    assert "remediation_guidance" not in joined


def test_blank_clerk_user_id_is_503_not_not_current_member(
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
    db_session.execute(
        update(User).where(User.id == ctx["member_id"]).values(clerk_user_id="   ")
    )
    db_session.commit()
    before = fake_clerk.membership_presence_calls
    response = _review(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == UNAVAILABLE
    assert fake_clerk.membership_presence_calls == before
    assert "not_current_member" not in response.text


def test_display_name_uses_local_user_name_only(
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
    existing = fake_clerk.users[ctx["member_clerk"]]
    fake_clerk.users[ctx["member_clerk"]] = ClerkUserInfo(
        clerk_user_id=existing.clerk_user_id,
        email=existing.email,
        name="Provider Name",
        email_verified=existing.email_verified,
    )
    item = next(
        row
        for row in _review(client, ctx["token"]).json()["items"]
        if row["finding_id"] == str(finding.id)
    )
    assert item["assignee"]["display_name"] is None


def test_provider_error_logs_omit_provider_identifiers(
    client, make_token, seed_user_a, fake_clerk, db_session, caplog
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
    ).status_code == 200
    fake_clerk.fail_membership_presence = True
    caplog.set_level(logging.DEBUG)
    _review(client, ctx["token"])
    dumped = "\n".join(
        f"{record.getMessage()} {record.__dict__}"
        for record in caplog.records
        if record.name.startswith("scout.")
    )
    assert ctx["member_clerk"] not in dumped
    assert ctx["clerk_org"] not in dumped
    assert "user_id=" not in dumped
    assert "/memberships?" not in dumped
    ownership_logs = [
        record
        for record in caplog.records
        if record.name == "scout.finding_ownership_review"
    ]
    assert ownership_logs
    for record in ownership_logs:
        assert getattr(record, "operation", None) == "finding_ownership_presence"
        assert getattr(record, "requested_count", None) == 1
        assert getattr(record, "organization_app_id", None) == str(ctx["org_id"])


def test_http_presence_logs_omit_url_and_provider_ids(caplog):
    captured_ids = ["user_secret_aaa", "user_secret_bbb"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"errors": []})

    caplog.set_level(logging.DEBUG)
    directory = _http_directory(handler)
    try:
        directory.list_organization_membership_presence(
            "org_secret",
            provider_user_ids=captured_ids,
        )
    except FindingOwnershipPresenceUnavailable:
        pass
    directory.close()
    dumped = "\n".join(
        f"{record.getMessage()} {record.__dict__}"
        for record in caplog.records
        if record.name.startswith("scout.")
    )
    for value in captured_ids:
        assert value not in dumped
    assert "org_secret" not in dumped
    assert "/memberships" not in dumped
    assert "user_id=" not in dumped


# ---------------------------------------------------------------- M39 integration / read-only


def test_m39_removal_surfaces_not_current_member_without_repair(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
    due = "2026-11-01T00:00:00Z"
    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": due},
    ).status_code == 200
    db_session.refresh(finding)
    assigned = finding.assigned_to_user_id
    due_at = finding.follow_up_due_at
    history_before = int(
        db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0
    )
    audit_before = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)

    removed = _delete_member(client, ctx["token"], ctx["member_id"])
    assert removed.status_code == 200, removed.text
    db_session.refresh(finding)
    assert finding.assigned_to_user_id == assigned
    assert finding.follow_up_due_at == due_at
    history_after_remove = int(
        db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0
    )
    assert history_after_remove == history_before

    body = _review(client, ctx["token"]).json()
    item = next(row for row in body["items"] if row["finding_id"] == str(finding.id))
    assert item["assignment_state"] == "not_current_member"
    db_session.refresh(finding)
    assert finding.assigned_to_user_id == assigned
    assert finding.follow_up_due_at == due_at
    assert (
        int(db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0)
        == history_after_remove
    )
    m44_audits = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert m44_audits == int(
        db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0
    )
    assert m44_audits >= audit_before

    assert _put_follow_up(
        client,
        ctx["token"],
        finding.id,
        {"assigned_to_user_id": str(ctx["admin_id"]), "follow_up_due_at": due},
    ).status_code == 200
    later = next(
        row
        for row in _review(client, ctx["token"]).json()["items"]
        if row["finding_id"] == str(finding.id)
    )
    assert later["assignment_state"] == "current_member"


def test_read_does_not_write_findings_or_memberships(
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
    follow_ups = int(
        db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0
    )
    memberships = int(
        db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0
    )
    audits = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert _review(client, ctx["token"]).status_code == 200
    db_session.refresh(finding)
    assert (
        finding.assigned_to_user_id,
        finding.follow_up_due_at,
        finding.status,
        finding.updated_at,
    ) == fingerprint
    assert (
        int(db_session.scalar(select(func.count()).select_from(FindingFollowUpChange)) or 0)
        == follow_ups
    )
    assert (
        int(db_session.scalar(select(func.count()).select_from(OrganizationMembership)) or 0)
        == memberships
    )
    assert int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0) == audits
    assert fake_clerk.update_role_calls == 0
    assert fake_clerk.delete_membership_calls == 0
    assert fake_clerk.create_invitation_calls == 0


def test_local_membership_never_authoritative(
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
    fake_clerk.memberships[ctx["member_clerk"]] = []
    local = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert local is not None
    item = next(
        row
        for row in _review(client, ctx["token"]).json()["items"]
        if row["finding_id"] == str(finding.id)
    )
    assert item["assignment_state"] == "not_current_member"


# ---------------------------------------------------------------- rate limit


def test_rate_limit_before_provider_zero_calls_when_exceeded(
    client, make_token, seed_user_a, fake_clerk, db_session, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_FINDING_OWNERSHIP_READ", "1")
    reset_settings_cache()
    try:
        ctx = _setup(client, make_token, seed_user_a, fake_clerk)
        finding = _finding(db_session, organization_id=ctx["org_id"], user_id=ctx["admin_id"])
        assert _put_follow_up(
            client,
            ctx["token"],
            finding.id,
            {"assigned_to_user_id": str(ctx["member_id"]), "follow_up_due_at": None},
        ).status_code == 200
        first = _review(client, ctx["token"])
        assert first.status_code == 200, first.text
        calls_after_ok = fake_clerk.membership_presence_calls
        limited = _review(client, ctx["token"])
        assert limited.status_code == 429, limited.text
        assert limited.json()["error"]["code"] == "rate_limited"
        assert fake_clerk.membership_presence_calls == calls_after_ok
        assert fake_clerk.get_membership_calls == 0
        assert fake_clerk.memberships_raw_calls == 0
    finally:
        monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_FINDING_OWNERSHIP_READ", "60")
        reset_settings_cache()

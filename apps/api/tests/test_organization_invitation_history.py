"""Milestone 43 — organization invitation terminal history (read-only)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
from sqlalchemy import func, select

from app.core.config import get_settings
from app.models.audit import AuditEvent
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.clerk import (
    ORGANIZATION_INVITATION_TERMINAL_STATUSES,
    ClerkInvitationHistoryView,
    HttpClerkDirectory,
)
from app.services.organization_invitations import (
    HISTORY_UNAVAILABLE_DETAIL,
    INVALID_HISTORY_CURSOR_DETAIL,
    decode_history_cursor,
    encode_history_cursor,
    normalize_history_filter_key,
)
from app.services.clerk import ClerkOrganizationInvitationRaw
from tests.test_finding_follow_up import _auth
from tests.test_organization_access import _assert_no_secrets, _setup
from tests.test_organization_invitations import _plant_pending


def _history(client, token: str, **params):
    return client.get(
        "/v1/organization-invitations/history",
        headers=_auth(token),
        params=params or None,
    )


def _plant_terminal(
    fake_clerk,
    *,
    clerk_org: str,
    email: str,
    status: str,
    role: str = "org:member",
    created_at_ms: int | None = None,
):
    now_ms = created_at_ms
    if now_ms is None:
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    fake_clerk.invitations.setdefault(clerk_org, []).append(
        ClerkOrganizationInvitationRaw(
            provider_invitation_id=f"inv_hist_{uuid4().hex[:8]}",
            email_address=email,
            external_role=role,
            status=status,
            inviter_user_id="user_planter",
            created_at_ms=now_ms,
            expires_at_ms=now_ms + 86_400_000,
        )
    )


# ---------------------------------------------------------------- filter / cursor


def test_normalize_history_filter_key():
    assert normalize_history_filter_key(None) == "terminal"
    assert normalize_history_filter_key("accepted") == "accepted"
    assert normalize_history_filter_key("revoked") == "revoked"
    assert normalize_history_filter_key("expired") == "expired"


def test_history_cursor_bound_to_filter():
    cur = encode_history_cursor(filter_key="accepted", offset=10)
    assert decode_history_cursor(cur, expected_filter_key="accepted") == 10
    try:
        decode_history_cursor(cur, expected_filter_key="revoked")
        assert False, "expected mismatch"
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400


def test_terminal_status_order_canonical():
    assert ORGANIZATION_INVITATION_TERMINAL_STATUSES == (
        "accepted",
        "revoked",
        "expired",
    )


def test_http_history_multi_status_query_encoding():
    """Pin repeated status= query params (not comma-joined, not three GETs)."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["items"] = list(request.url.params.multi_items())
        return httpx.Response(
            200,
            json={"data": [], "total_count": 0},
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(
        transport=transport,
        base_url="https://api.clerk.test",
    )
    directory = HttpClerkDirectory(get_settings(), client=client)
    rows, total = directory.list_organization_invitation_history(
        "org_test",
        statuses=ORGANIZATION_INVITATION_TERMINAL_STATUSES,
        limit=50,
        offset=0,
    )
    assert rows == []
    assert total == 0
    assert captured["path"].endswith("/organizations/org_test/invitations")
    items = captured["items"]
    assert ("limit", "50") in items or ("limit", 50) in items
    status_values = [v for k, v in items if k == "status"]
    assert status_values == ["accepted", "revoked", "expired"]
    assert ",".join(status_values) not in {v for _, v in items}
    directory.close()


# ---------------------------------------------------------------- RBAC


def test_history_unauth_zero_provider(client, fake_clerk):
    before = fake_clerk.list_invitation_history_calls
    assert client.get("/v1/organization-invitations/history").status_code == 401
    assert fake_clerk.list_invitation_history_calls == before


def test_history_member_403_zero_provider(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.list_invitation_history_calls
    assert _history(client, ctx["member_token"]).status_code == 403
    assert fake_clerk.list_invitation_history_calls == before


# ---------------------------------------------------------------- happy path / multi-status


def test_history_all_terminal_one_provider_call(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    users_before = db_session.scalar(select(func.count()).select_from(User))
    memberships_before = db_session.scalar(
        select(func.count()).select_from(OrganizationMembership)
    )
    audits_before = db_session.scalar(select(func.count()).select_from(AuditEvent))
    _plant_pending(
        fake_clerk, clerk_org=ctx["clerk_org"], email="still-pending@example.com"
    )
    _plant_terminal(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="Accepted.Person@Example.COM",
        status="accepted",
        role="org:member",
    )
    _plant_terminal(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="admin-out@example.com",
        status="revoked",
        role="org:admin",
    )
    _plant_terminal(
        fake_clerk,
        clerk_org=ctx["clerk_org"],
        email="billing@example.com",
        status="expired",
        role="org:billing",
    )

    before = fake_clerk.list_invitation_history_calls
    response = _history(client, ctx["token"])
    assert response.status_code == 200, response.text
    assert fake_clerk.list_invitation_history_calls == before + 1
    assert fake_clerk.last_history_list_statuses == (
        "accepted",
        "revoked",
        "expired",
    )
    assert fake_clerk.list_invitations_calls == 0
    assert fake_clerk.get_invitation_calls == 0

    body = response.json()
    _assert_no_secrets(body)
    assert body["total_invitations"] == 3
    assert len(body["items"]) == 3
    assert "invitation_ref" not in response.text
    assert "Accepted.Person@Example.COM" not in response.text
    assert "email_address" not in response.text
    assert "status_state" not in response.text
    by_hint = {item["recipient_hint"]: item for item in body["items"]}
    assert by_hint["A***@example.com"]["status"] == "accepted"
    assert by_hint["A***@example.com"]["role"] == "member"
    assert by_hint["A***@example.com"]["role_state"] == "recognized"
    assert by_hint["a***@example.com"]["status"] == "revoked"
    assert by_hint["a***@example.com"]["role"] == "admin"
    assert by_hint["b***@example.com"]["status"] == "expired"
    assert by_hint["b***@example.com"]["role"] is None
    assert by_hint["b***@example.com"]["role_state"] == "unrecognized"
    for item in body["items"]:
        assert set(item.keys()) == {
            "status",
            "role",
            "role_state",
            "recipient_hint",
            "created_at",
            "expires_at",
        }
        assert "completed_at" not in item
        assert "updated_at" not in item

    assert db_session.scalar(select(func.count()).select_from(User)) == users_before
    assert (
        db_session.scalar(select(func.count()).select_from(OrganizationMembership))
        == memberships_before
    )
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == audits_before


def test_history_single_status_filters(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="a@example.com", status="accepted"
    )
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="r@example.com", status="revoked"
    )
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="e@example.com", status="expired"
    )

    accepted = _history(client, ctx["token"], status="accepted")
    assert accepted.status_code == 200
    assert fake_clerk.last_history_list_statuses == ("accepted",)
    assert len(accepted.json()["items"]) == 1
    assert accepted.json()["items"][0]["status"] == "accepted"

    revoked = _history(client, ctx["token"], status="revoked")
    assert revoked.status_code == 200
    assert fake_clerk.last_history_list_statuses == ("revoked",)
    assert len(revoked.json()["items"]) == 1

    expired = _history(client, ctx["token"], status="expired")
    assert expired.status_code == 200
    assert fake_clerk.last_history_list_statuses == ("expired",)
    assert len(expired.json()["items"]) == 1


def test_status_all_rejected_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.list_invitation_history_calls
    response = _history(client, ctx["token"], status="all")
    assert response.status_code == 422
    assert fake_clerk.list_invitation_history_calls == before


# ---------------------------------------------------------------- cursor cross-filter


def test_cross_filter_cursor_400_zero_provider(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    accepted_cursor = encode_history_cursor(filter_key="accepted", offset=0)
    before = fake_clerk.list_invitation_history_calls
    response = _history(
        client, ctx["token"], status="revoked", cursor=accepted_cursor
    )
    assert response.status_code == 400
    assert response.json()["error"]["message"] == INVALID_HISTORY_CURSOR_DETAIL
    assert fake_clerk.list_invitation_history_calls == before


def test_history_pagination_same_filter(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    base = int(datetime.now(timezone.utc).timestamp() * 1000)
    for index in range(3):
        _plant_terminal(
            fake_clerk,
            clerk_org=ctx["clerk_org"],
            email=f"p{index}@example.com",
            status="accepted",
            created_at_ms=base - index * 1000,
        )
    first = _history(client, ctx["token"], status="accepted", page_size=2)
    assert first.status_code == 200
    body = first.json()
    assert len(body["items"]) == 2
    assert body["total_invitations"] == 3
    assert body["next_cursor"]
    # Cursor encodes accepted filter.
    assert decode_history_cursor(body["next_cursor"], expected_filter_key="accepted") == 2
    second = _history(
        client,
        ctx["token"],
        status="accepted",
        page_size=2,
        cursor=body["next_cursor"],
    )
    assert second.status_code == 200
    assert len(second.json()["items"]) == 1
    assert second.json()["next_cursor"] is None


# ---------------------------------------------------------------- contradictions / pagination validation


def test_pending_contradiction_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="x@example.com", status="accepted"
    )
    fake_clerk.history_list_corrupt = "pending_in_terminal"
    response = _history(client, ctx["token"])
    assert response.status_code == 503
    assert response.json()["error"]["message"] == HISTORY_UNAVAILABLE_DETAIL


def test_unknown_status_contradiction_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="x@example.com", status="accepted"
    )
    fake_clerk.history_list_corrupt = "unknown_status"
    response = _history(client, ctx["token"])
    assert response.status_code == 503


def test_bad_email_history_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="ok@example.com", status="accepted"
    )
    fake_clerk.history_list_corrupt = "bad_email"
    response = _history(client, ctx["token"])
    assert response.status_code == 503


def test_total_count_invariants_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="a@example.com", status="accepted"
    )
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="b@example.com", status="accepted"
    )
    # total smaller than offset+rows
    fake_clerk.history_list_total_override = 1
    response = _history(client, ctx["token"], status="accepted", page_size=50)
    assert response.status_code == 503
    assert response.json()["error"]["message"] == HISTORY_UNAVAILABLE_DETAIL


def test_negative_total_override_503(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    _plant_terminal(
        fake_clerk, clerk_org=ctx["clerk_org"], email="a@example.com", status="accepted"
    )
    fake_clerk.history_list_total_override = -1
    assert _history(client, ctx["token"], status="accepted").status_code == 503


def test_page_size_over_max_422(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.list_invitation_history_calls
    assert _history(client, ctx["token"], page_size=101).status_code == 422
    assert fake_clerk.list_invitation_history_calls == before


def test_malformed_cursor_400(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    before = fake_clerk.list_invitation_history_calls
    assert _history(client, ctx["token"], cursor="%%%").status_code == 400
    assert fake_clerk.list_invitation_history_calls == before


# ---------------------------------------------------------------- email boundary / no mutation surface


def test_history_view_has_no_email_field():
    view = ClerkInvitationHistoryView(
        status="accepted",
        external_role="org:member",
        recipient_hint="a***@example.com",
        created_at_ms=1,
        expires_at_ms=None,
    )
    assert not hasattr(view, "email_address")
    assert "email" not in view.__dataclass_fields__


def test_no_resend_route(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    response = client.post(
        "/v1/organization-invitations/resend",
        headers=_auth(ctx["token"]),
        json={"invitation_ref": "v1.abc"},
    )
    assert response.status_code in {404, 405}


def test_history_rate_limit_default():
    settings = get_settings()
    assert settings.rate_limit_organization_invitation_history_read == 60
    assert settings.rate_limit_window_seconds == 3600

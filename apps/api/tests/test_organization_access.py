"""Milestone 38 — organization access review."""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select

from app.core.config import reset_settings_cache
from app.models.audit import AuditEvent
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo, CurrentAccessUnavailable
from app.services.organization_access import (
    CURRENT_ACCESS_UNAVAILABLE_DETAIL,
    INVALID_CURSOR_DETAIL,
    classify_provider_role,
)
from tests.test_finding_follow_up import _add_clerk_member, _auth, _ids


def _access(client, token: str, **params):
    return client.get(
        "/v1/organization-access",
        headers=_auth(token),
        params=params or None,
    )


def _setup(client, make_token, seed_user_a, fake_clerk):
    clerk_admin, clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    admin_id, org_id = _ids(client, token)
    member_clerk = _add_clerk_member(fake_clerk, clerk_org_id=clerk_org, name="Member One")
    member_token = make_token(
        sub=member_clerk, org_id=clerk_org, org_role="org:member"
    )
    member_id, _ = _ids(client, member_token)
    return {
        "token": token,
        "member_token": member_token,
        "admin_id": admin_id,
        "member_id": member_id,
        "org_id": org_id,
        "clerk_org": clerk_org,
        "clerk_admin": clerk_admin,
        "member_clerk": member_clerk,
    }


def _assert_no_secrets(payload) -> None:
    forbidden = {
        "email",
        "phone",
        "clerk_user_id",
        "clerk_org_id",
        "external_role",
        "provider_user_id",
        "identifier",
        "profile_image",
        "image_url",
        "session",
        "device",
    }
    if isinstance(payload, dict):
        lowered = {str(k).lower() for k in payload}
        assert forbidden.isdisjoint(lowered), lowered & forbidden
        for value in payload.values():
            _assert_no_secrets(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_no_secrets(item)


def _fingerprint_listed(db, *, org_id: UUID, clerk_user_ids: list[str]):
    users = db.scalars(select(User).where(User.clerk_user_id.in_(clerk_user_ids))).all()
    user_fp = sorted(
        (str(u.id), u.clerk_user_id, u.email, u.name, u.email_verified) for u in users
    )
    user_ids = [u.id for u in users]
    memberships = []
    if user_ids:
        memberships = db.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == org_id,
                OrganizationMembership.user_id.in_(user_ids),
            )
        ).all()
    membership_fp = sorted(
        (str(m.id), str(m.user_id), m.role) for m in memberships
    )
    return user_fp, membership_fp


# --------------------------------------------------------------------------- RBAC


def test_unauthenticated_401(client):
    assert client.get("/v1/organization-access").status_code == 401


def test_member_403_admin_200(client, make_token, seed_user_a, fake_clerk):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    assert _access(client, ctx["member_token"]).status_code == 403
    response = _access(client, ctx["token"])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source"] == "authoritative_current_membership"
    assert body["organization"]["id"] == str(ctx["org_id"])
    assert body["organization"]["name"]
    _assert_no_secrets(body)
    assert len(body["items"]) >= 2


def test_stale_local_admin_role_does_not_elevate(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == ctx["member_id"],
        )
    )
    assert membership is not None
    membership.role = "org:admin"
    db_session.commit()

    # JWT still member — must not elevate via stale local role.
    assert _access(client, ctx["member_token"]).status_code == 403


def test_no_active_organization_keeps_existing_contract(client, make_token, seed_user_a):
    clerk_admin, _clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=None)
    response = _access(client, token)
    assert response.status_code == 400
    assert "active organization" in response.json()["error"]["message"].lower()


# ----------------------------------------------------------- unknown role integrity


def test_unknown_role_still_appears_unrecognized(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    unknown_clerk = f"user_{uuid4().hex}"
    fake_clerk.users[unknown_clerk] = ClerkUserInfo(
        clerk_user_id=unknown_clerk,
        email=f"{unknown_clerk}@example.com",
        name="Mystery Role",
        email_verified=True,
    )
    fake_clerk.memberships[unknown_clerk] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"],
            org_name="Org A",
            role="org:billing_manager",
        )
    ]

    before_calls = fake_clerk.memberships_raw_calls
    get_user_before = fake_clerk.get_user_calls
    response = _access(client, ctx["token"], page_size=100)
    assert response.status_code == 200, response.text
    assert fake_clerk.memberships_raw_calls == before_calls + 1
    # Viewer auth may call get_user once; M38 must not call get_user per member.
    assert fake_clerk.get_user_calls == get_user_before + 1

    body = response.json()
    mystery = next(
        item for item in body["items"] if item["display_name"] == "Mystery Role"
    )
    assert mystery["role"] is None
    assert mystery["role_state"] == "unrecognized"
    assert mystery["role"] != "admin"
    assert mystery["role"] != "member"
    # Page is not reduced by silent role filtering.
    assert len(body["items"]) == body["total_members"]
    _assert_no_secrets(body)


def test_classify_provider_role_mappings():
    assert classify_provider_role("org:admin") == ("admin", "recognized")
    assert classify_provider_role("admin") == ("admin", "recognized")
    assert classify_provider_role("org:member") == ("member", "recognized")
    assert classify_provider_role("member") == ("member", "recognized")
    assert classify_provider_role("org:billing_manager") == (None, "unrecognized")
    assert classify_provider_role(None) == (None, "unrecognized")
    assert classify_provider_role("") == (None, "unrecognized")


# ----------------------------------------------------------- local mirror semantics


def test_local_mirror_states(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)

    # Unlinked provider member → not_linked / not_applicable
    unlinked = f"user_{uuid4().hex}"
    fake_clerk.users[unlinked] = ClerkUserInfo(
        clerk_user_id=unlinked,
        email=f"{unlinked}@example.com",
        name="Unlinked Person",
        email_verified=True,
    )
    fake_clerk.memberships[unlinked] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]

    # Linked user, no local membership → missing
    linked_missing_clerk = f"user_{uuid4().hex}"
    fake_clerk.users[linked_missing_clerk] = ClerkUserInfo(
        clerk_user_id=linked_missing_clerk,
        email=f"{linked_missing_clerk}@example.com",
        name="Linked Missing",
        email_verified=True,
    )
    fake_clerk.memberships[linked_missing_clerk] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]
    linked_user = User(
        clerk_user_id=linked_missing_clerk,
        email=f"{linked_missing_clerk}@example.com",
        email_verified=True,
        name="Linked Missing",
    )
    db_session.add(linked_user)
    db_session.commit()

    # Linked + local role differs from provider
    differ_clerk = f"user_{uuid4().hex}"
    fake_clerk.users[differ_clerk] = ClerkUserInfo(
        clerk_user_id=differ_clerk,
        email=f"{differ_clerk}@example.com",
        name="Role Differ",
        email_verified=True,
    )
    fake_clerk.memberships[differ_clerk] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]
    differ_token = make_token(
        sub=differ_clerk, org_id=ctx["clerk_org"], org_role="org:admin"
    )
    differ_id, _ = _ids(client, differ_token)
    # Force local cache to admin while provider says member.
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == ctx["org_id"],
            OrganizationMembership.user_id == differ_id,
        )
    )
    assert membership is not None
    membership.role = "org:admin"
    db_session.commit()

    # Unrecognized provider role → local_mirror not_applicable even if linked
    unknown_clerk = f"user_{uuid4().hex}"
    fake_clerk.users[unknown_clerk] = ClerkUserInfo(
        clerk_user_id=unknown_clerk,
        email=f"{unknown_clerk}@example.com",
        name="Unknown Linked",
        email_verified=True,
    )
    fake_clerk.memberships[unknown_clerk] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"],
            org_name="Org A",
            role="custom:weird",
        )
    ]
    unknown_token = make_token(
        sub=unknown_clerk, org_id=ctx["clerk_org"], org_role="org:member"
    )
    _ids(client, unknown_token)

    response = _access(client, ctx["token"], page_size=100)
    assert response.status_code == 200, response.text
    by_name = {item["display_name"]: item for item in response.json()["items"]}

    unlinked_item = by_name["Unlinked Person"]
    assert unlinked_item["user_id"] is None
    assert unlinked_item["account_link_state"] == "not_linked"
    assert unlinked_item["local_mirror_state"] == "not_applicable"
    assert unlinked_item["role"] == "member"
    assert unlinked_item["role_state"] == "recognized"

    missing_item = by_name["Linked Missing"]
    assert missing_item["account_link_state"] == "linked"
    assert missing_item["local_mirror_state"] == "missing"
    assert missing_item["user_id"] == str(linked_user.id)

    differ_item = by_name["Role Differ"]
    assert differ_item["role"] == "member"  # provider authoritative, not local admin
    assert differ_item["local_mirror_state"] == "role_differs"

    member_item = by_name["Member One"]
    assert member_item["local_mirror_state"] == "role_matches"
    assert member_item["role"] == "member"

    unknown_item = by_name["Unknown Linked"]
    assert unknown_item["role_state"] == "unrecognized"
    assert unknown_item["local_mirror_state"] == "not_applicable"


# ----------------------------------------------------------- failure contract


def test_provider_failure_returns_fixed_503_no_local_fallback(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    fake_clerk.fail_org_memberships_raw = True
    before_raw = fake_clerk.memberships_raw_calls
    get_user_before = fake_clerk.get_user_calls
    audit_before = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)

    response = _access(client, ctx["token"])
    assert response.status_code == 503, response.text
    body = response.json()
    assert body["error"]["message"] == CURRENT_ACCESS_UNAVAILABLE_DETAIL
    assert "Clerk" not in body["error"]["message"]
    assert "CLERK" not in str(body)
    assert fake_clerk.memberships_raw_calls == before_raw + 1
    assert fake_clerk.get_user_calls == get_user_before + 1
    # No local OrganizationMembership fallback payload.
    assert "items" not in body
    audit_after = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert audit_after == audit_before


def test_current_access_unavailable_exception_maps_to_detail():
    assert issubclass(CurrentAccessUnavailable, Exception)


# ----------------------------------------------------------- read-only path


def test_read_only_no_mutations_one_memberships_list_call(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    extra = [
        _add_clerk_member(fake_clerk, clerk_org_id=ctx["clerk_org"], name=f"Extra {i}")
        for i in range(2)
    ]
    # Warm extras into DB via M33 path? No — keep them unlinked to prove M38 doesn't upsert.
    listed_clerk_ids = [ctx["clerk_admin"], ctx["member_clerk"], *extra]

    before_users, before_memberships = _fingerprint_listed(
        db_session, org_id=ctx["org_id"], clerk_user_ids=listed_clerk_ids
    )
    audit_before = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    get_user_before = fake_clerk.get_user_calls
    raw_before = fake_clerk.memberships_raw_calls
    members_before = fake_clerk.list_organization_members_calls

    response = _access(client, ctx["token"], page_size=100)
    assert response.status_code == 200, response.text

    assert fake_clerk.memberships_raw_calls == raw_before + 1
    # One get_user for the authenticated viewer only (pre-existing auth sync).
    assert fake_clerk.get_user_calls == get_user_before + 1
    assert fake_clerk.list_organization_members_calls == members_before

    after_users, after_memberships = _fingerprint_listed(
        db_session, org_id=ctx["org_id"], clerk_user_ids=listed_clerk_ids
    )
    assert after_users == before_users
    assert after_memberships == before_memberships
    audit_after = int(db_session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
    assert audit_after == audit_before

    body = response.json()
    unlinked = [
        item for item in body["items"] if item["account_link_state"] == "not_linked"
    ]
    assert len(unlinked) == 2
    _assert_no_secrets(body)


# ----------------------------------------------------------- rate limit


def test_rate_limit_before_provider_zero_calls_when_exceeded(
    client, make_token, seed_user_a, fake_clerk, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_ACCESS_READ", "1")
    reset_settings_cache()
    try:
        ctx = _setup(client, make_token, seed_user_a, fake_clerk)
        first = _access(client, ctx["token"])
        assert first.status_code == 200, first.text
        calls_after_ok = fake_clerk.memberships_raw_calls
        get_user_after_ok = fake_clerk.get_user_calls

        limited = _access(client, ctx["token"])
        assert limited.status_code == 429, limited.text
        assert limited.json()["error"]["code"] == "rate_limited"
        # Zero provider membership-list calls on rejected request.
        assert fake_clerk.memberships_raw_calls == calls_after_ok
        # Viewer auth may still sync; M38 must not add roster get_user calls.
        assert fake_clerk.get_user_calls == get_user_after_ok + 1
    finally:
        monkeypatch.setenv("RATE_LIMIT_ORGANIZATION_ACCESS_READ", "60")
        reset_settings_cache()


# ----------------------------------------------------------- pagination / privacy


def test_pagination_preserves_provider_order_and_cursor_rules(
    client, make_token, seed_user_a, fake_clerk
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    for i in range(5):
        _add_clerk_member(
            fake_clerk, clerk_org_id=ctx["clerk_org"], name=f"Page Member {i}"
        )

    first = _access(client, ctx["token"], page_size=3)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["page_size"] == 3
    assert body["next_cursor"]
    assert len(body["items"]) == 3
    first_names = [item["display_name"] for item in body["items"]]

    second = _access(client, ctx["token"], page_size=3, cursor=body["next_cursor"])
    assert second.status_code == 200, second.text
    second_body = second.json()
    second_names = [item["display_name"] for item in second_body["items"]]
    assert not set(first_names) & set(second_names)

    full = _access(client, ctx["token"], page_size=100).json()
    full_names = [item["display_name"] for item in full["items"]]
    assert full_names[:3] == first_names
    assert full_names[3 : 3 + len(second_names)] == second_names

    bad = _access(client, ctx["token"], cursor="%%%not-a-cursor")
    assert bad.status_code == 400
    assert bad.json()["error"]["message"] == INVALID_CURSOR_DETAIL

    oversized = _access(client, ctx["token"], page_size=101)
    assert oversized.status_code == 422


def test_display_name_priority(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    ctx = _setup(client, make_token, seed_user_a, fake_clerk)
    # Linked user with User.name wins over provider first/last.
    user = db_session.get(User, ctx["member_id"])
    assert user is not None
    user.name = "Local Preferred Name"
    db_session.commit()

    # Unlinked uses provider first+last already present on page.
    unlinked = f"user_{uuid4().hex}"
    fake_clerk.users[unlinked] = ClerkUserInfo(
        clerk_user_id=unlinked,
        email=f"{unlinked}@example.com",
        name="Provider First Last",
        email_verified=True,
    )
    fake_clerk.memberships[unlinked] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]

    # No names → null display_name
    nameless = f"user_{uuid4().hex}"
    fake_clerk.users[nameless] = ClerkUserInfo(
        clerk_user_id=nameless,
        email=f"{nameless}@example.com",
        name=None,
        email_verified=True,
    )
    fake_clerk.memberships[nameless] = [
        ClerkOrgMembership(
            clerk_org_id=ctx["clerk_org"], org_name="Org A", role="org:member"
        )
    ]

    body = _access(client, ctx["token"], page_size=100).json()
    by_link = {item["user_id"]: item for item in body["items"] if item["user_id"]}
    assert by_link[str(ctx["member_id"])]["display_name"] == "Local Preferred Name"
    unlinked_item = next(
        item for item in body["items"] if item["display_name"] == "Provider First Last"
    )
    assert unlinked_item["account_link_state"] == "not_linked"
    nameless_item = next(
        item
        for item in body["items"]
        if item["account_link_state"] == "not_linked" and item["display_name"] is None
    )
    assert nameless_item["user_id"] is None
    _assert_no_secrets(body)


# ----------------------------------------------------------- M33 parity pin


def test_m33_organization_members_still_upserts(
    client, make_token, seed_user_a, fake_clerk, db_session
):
    clerk_admin, clerk_org = seed_user_a
    token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    _ids(client, token)
    extra = _add_clerk_member(fake_clerk, clerk_org_id=clerk_org, name="Picker Extra")

    listed = client.get("/v1/organization-members", headers=_auth(token))
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert all(item["user_id"] for item in body["items"])
    user = db_session.scalar(select(User).where(User.clerk_user_id == extra))
    assert user is not None
    membership = db_session.scalar(
        select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
    )
    assert membership is not None

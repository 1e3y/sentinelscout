from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.models.operation import Operation
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.services.authorization import (
    effective_authorized_role,
    explicit_org_actor,
    may_stop_operation,
    normalize_org_role,
)
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.monitoring import upsert_monitoring
from app.services.targets import create_target, update_scope


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _me(client, token: str) -> dict:
    response = client.get("/v1/me", headers=_auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def _org_uuid(client, token: str) -> str:
    rows = client.get("/v1/organizations", headers=_auth(token)).json()
    assert rows
    return rows[0]["id"]


def _add_clerk_user(fake_clerk, *, clerk_org_id: str, role: str, email: str):
    clerk_id = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_id] = ClerkUserInfo(
        clerk_user_id=clerk_id,
        email=email,
        name=email.split("@")[0],
        email_verified=True,
    )
    fake_clerk.memberships[clerk_id] = [
        ClerkOrgMembership(clerk_org_id=clerk_org_id, org_name="Org A", role=role)
    ]
    return clerk_id


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()["verified"]
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    return target_id


def test_normalize_known_clerk_encodings():
    assert normalize_org_role("org:admin") == "admin"
    assert normalize_org_role("admin") == "admin"
    assert normalize_org_role("org:member") == "member"
    assert normalize_org_role("member") == "member"
    assert normalize_org_role("org:billing") is None
    assert normalize_org_role(None) is None
    assert normalize_org_role("") is None


def test_effective_role_jwt_grant_directory_veto():
    assert effective_authorized_role("org:admin", "org:admin") == "admin"
    assert effective_authorized_role("admin", "org:admin") == "admin"
    assert effective_authorized_role("org:member", "org:admin") == "member"
    assert effective_authorized_role("org:admin", "org:member") == "member"
    assert effective_authorized_role("org:admin", "mystery") is None
    assert effective_authorized_role(None, "org:admin") is None


def test_null_created_by_manual_operation_is_admin_only():
    org_id = uuid4()
    member = explicit_org_actor(
        user_id=uuid4(), organization_id=org_id, normalized_role="member"
    )
    admin = explicit_org_actor(
        user_id=uuid4(), organization_id=org_id, normalized_role="admin"
    )
    operation = SimpleNamespace(
        organization_id=org_id, source="manual", created_by_user_id=None
    )
    assert may_stop_operation(operation, member) is False
    assert may_stop_operation(operation, admin) is True


def test_admin_can_manage_targets_monitoring_and_notifications(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    me = _me(client, token)
    assert me["active_organization_role"] == "admin"
    target_id = _create_verified_target(client, token, "rbac-admin.example", dns_resolver)
    monitoring = client.put(
        f"/v1/targets/{target_id}/monitoring",
        headers=_auth(token),
        json={"enabled": True, "frequency": "weekly"},
    )
    assert monitoring.status_code == 200, monitoring.text
    org_id = _org_uuid(client, token)
    settings = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(token),
        json={
            "email_enabled": False,
            "email_min_priority": "medium",
            "recipient_user_ids": [],
        },
    )
    assert settings.status_code == 200, settings.text
    assert settings.json()["can_manage"] is True
    revoked = client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(token))
    assert revoked.status_code == 200, revoked.text


def test_member_denied_admin_mutations_and_allowed_reads(
    client, make_token, seed_user_a, fake_clerk, dns_resolver
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _me(client, admin_token)
    clerk_m = _add_clerk_user(
        fake_clerk, clerk_org_id=org_a, role="org:member", email="member@example.com"
    )
    member_token = make_token(sub=clerk_m, org_id=org_a, org_role="org:member")
    me = _me(client, member_token)
    assert me["active_organization_role"] == "member"

    created = client.post(
        "/v1/targets", headers=_auth(member_token), json={"domain": "nope.example"}
    )
    assert created.status_code == 403

    target_id = _create_verified_target(client, admin_token, "rbac-member.example", dns_resolver)
    assert (
        client.post(
            f"/v1/targets/{target_id}/verification", headers=_auth(member_token)
        ).status_code
        == 403
    )
    assert (
        client.post(f"/v1/targets/{target_id}/verify", headers=_auth(member_token)).status_code
        == 403
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(member_token),
            json={"include_subdomains": False, "exclusions": []},
        ).status_code
        == 403
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/monitoring",
            headers=_auth(member_token),
            json={"enabled": True, "frequency": "daily"},
        ).status_code
        == 403
    )
    assert (
        client.post(f"/v1/targets/{target_id}/revoke", headers=_auth(member_token)).status_code
        == 403
    )
    org_id = _org_uuid(client, admin_token)
    assert (
        client.put(
            f"/v1/organizations/{org_id}/notification-settings",
            headers=_auth(member_token),
            json={
                "email_enabled": True,
                "email_min_priority": "medium",
                "recipient_user_ids": [],
            },
        ).status_code
        == 403
    )

    listed = client.get("/v1/targets", headers=_auth(member_token))
    assert listed.status_code == 200
    assert any(row["id"] == target_id for row in listed.json())
    settings = client.get(
        f"/v1/organizations/{org_id}/notification-settings", headers=_auth(member_token)
    )
    assert settings.status_code == 200
    assert settings.json()["can_manage"] is False

    queued = client.post(
        "/v1/operations", headers=_auth(member_token), json={"target_id": target_id}
    )
    assert queued.status_code == 201, queued.text


def test_active_org_required_for_mutations_across_memberships(
    client, make_token, seed_user_a, fake_clerk, dns_resolver
):
    clerk_a, org_a = seed_user_a
    org_b = f"org_{uuid4().hex}"
    fake_clerk.memberships[clerk_a].append(
        ClerkOrgMembership(clerk_org_id=org_b, org_name="Org B", role="org:admin")
    )
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_a, org_id=org_b, org_role="org:admin")
    _me(client, token_a)
    _me(client, token_b)
    target_id = _create_verified_target(client, token_a, "rbac-active.example", dns_resolver)
    op = client.post("/v1/operations", headers=_auth(token_a), json={"target_id": target_id})
    assert op.status_code == 201, op.text
    operation_id = op.json()["id"]

    wrong = client.post(
        "/v1/operations", headers=_auth(token_b), json={"target_id": target_id}
    )
    assert wrong.status_code == 404
    stop = client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token_b))
    assert stop.status_code == 404

    allowed = client.post(f"/v1/operations/{operation_id}/stop", headers=_auth(token_a))
    assert allowed.status_code == 200, allowed.text


def test_stale_db_admin_does_not_grant_when_jwt_is_member(
    client, make_token, seed_user_a, db_session
):
    clerk_a, org_a = seed_user_a
    member_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:member")
    _me(client, member_token)
    org = db_session.scalar(select(Organization).where(Organization.clerk_org_id == org_a))
    user = db_session.scalar(select(User).where(User.clerk_user_id == clerk_a))
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    membership.role = "org:admin"
    db_session.commit()

    created = client.post(
        "/v1/targets", headers=_auth(member_token), json={"domain": "stale-admin.example"}
    )
    assert created.status_code == 403
    org_id = str(org.id)
    settings = client.put(
        f"/v1/organizations/{org_id}/notification-settings",
        headers=_auth(member_token),
        json={
            "email_enabled": True,
            "email_min_priority": "medium",
            "recipient_user_ids": [],
        },
    )
    assert settings.status_code == 403


def test_verified_admin_allowed_when_db_role_is_stale_member(
    client, make_token, seed_user_a, db_session
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _me(client, admin_token)
    org = db_session.scalar(select(Organization).where(Organization.clerk_org_id == org_a))
    user = db_session.scalar(select(User).where(User.clerk_user_id == clerk_a))
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    membership.role = "org:member"
    db_session.commit()

    created = client.post(
        "/v1/targets", headers=_auth(admin_token), json={"domain": "stale-member.example"}
    )
    assert created.status_code == 201, created.text
    db_session.expire_all()
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    assert membership.role == "org:admin"


def test_clerk_directory_member_vetoes_jwt_admin(
    client, make_token, seed_user_a, fake_clerk
):
    clerk_a, org_a = seed_user_a
    fake_clerk.memberships[clerk_a] = [
        ClerkOrgMembership(clerk_org_id=org_a, org_name="Org A", role="org:member")
    ]
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    me = _me(client, token)
    assert me["active_organization_role"] == "member"
    created = client.post(
        "/v1/targets", headers=_auth(token), json={"domain": "veto.example"}
    )
    assert created.status_code == 403


def test_unknown_role_allows_member_reads_and_denies_admin(
    client, make_token, seed_user_a, fake_clerk, dns_resolver
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, admin_token, "rbac-unknown.example", dns_resolver)
    clerk_m = _add_clerk_user(
        fake_clerk, clerk_org_id=org_a, role="org:member", email="unknown@example.com"
    )
    missing = make_token(sub=clerk_m, org_id=org_a, omit_org_role=True)
    mystery = make_token(sub=clerk_m, org_id=org_a, org_role="org:billing")
    for token in (missing, mystery):
        me = _me(client, token)
        assert me["active_organization_role"] is None
        listed = client.get("/v1/targets", headers=_auth(token))
        assert listed.status_code == 200
        created = client.post(
            "/v1/targets", headers=_auth(token), json={"domain": "unknown-role.example"}
        )
        assert created.status_code == 403
        queued = client.post(
            "/v1/operations", headers=_auth(token), json={"target_id": target_id}
        )
        assert queued.status_code == 201, queued.text


def test_stop_ownership_matrix(
    client, make_token, seed_user_a, fake_clerk, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    clerk_m = _add_clerk_user(
        fake_clerk, clerk_org_id=org_a, role="org:member", email="stopper@example.com"
    )
    member_token = make_token(sub=clerk_m, org_id=org_a, org_role="org:member")
    admin_me = _me(client, admin_token)
    member_me = _me(client, member_token)
    target_id = _create_verified_target(client, admin_token, "rbac-stop.example", dns_resolver)

    own = client.post(
        "/v1/operations", headers=_auth(member_token), json={"target_id": target_id}
    )
    assert own.status_code == 201, own.text
    assert (
        client.post(
            f"/v1/operations/{own.json()['id']}/stop", headers=_auth(member_token)
        ).status_code
        == 200
    )

    other = client.post(
        "/v1/operations", headers=_auth(admin_token), json={"target_id": target_id}
    )
    assert other.status_code == 201, other.text
    denied_other = client.post(
        f"/v1/operations/{other.json()['id']}/stop", headers=_auth(member_token)
    )
    assert denied_other.status_code == 403

    scheduled = Operation(
        organization_id=UUID(admin_me["active_organization_id"]),
        target_id=UUID(target_id),
        created_by_user_id=UUID(member_me["id"]),
        status="queued",
        source="scheduled",
    )
    db_session.add(scheduled)
    db_session.commit()
    denied_scheduled = client.post(
        f"/v1/operations/{scheduled.id}/stop", headers=_auth(member_token)
    )
    assert denied_scheduled.status_code == 403
    allowed_scheduled = client.post(
        f"/v1/operations/{scheduled.id}/stop", headers=_auth(admin_token)
    )
    assert allowed_scheduled.status_code == 200, allowed_scheduled.text

    admin_stop_other = client.post(
        "/v1/operations", headers=_auth(member_token), json={"target_id": target_id}
    )
    assert admin_stop_other.status_code == 201
    assert (
        client.post(
            f"/v1/operations/{admin_stop_other.json()['id']}/stop",
            headers=_auth(admin_token),
        ).status_code
        == 200
    )


def test_direct_service_refuses_member_and_wrong_org_actors(
    client, make_token, seed_user_a, seed_user_b, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    me_a = _me(client, token_a)
    me_b = _me(client, token_b)
    org_a_id = UUID(me_a["active_organization_id"])
    org_b_id = UUID(me_b["active_organization_id"])
    member_actor = explicit_org_actor(
        user_id=UUID(me_a["id"]), organization_id=org_a_id, normalized_role="member"
    )
    wrong_actor = explicit_org_actor(
        user_id=UUID(me_b["id"]), organization_id=org_b_id, normalized_role="admin"
    )
    with pytest.raises(HTTPException) as member_exc:
        create_target(
            db_session,
            actor=member_actor,
            organization_id=org_a_id,
            raw_domain="svc-member.example",
        )
    assert member_exc.value.status_code == 403

    with pytest.raises(HTTPException) as wrong_exc:
        create_target(
            db_session,
            actor=wrong_actor,
            organization_id=org_a_id,
            raw_domain="svc-wrong.example",
        )
    assert wrong_exc.value.status_code == 404

    admin_actor = explicit_org_actor(
        user_id=UUID(me_a["id"]), organization_id=org_a_id, normalized_role="admin"
    )
    target = create_target(
        db_session,
        actor=admin_actor,
        organization_id=org_a_id,
        raw_domain="svc-admin.example",
    )
    with pytest.raises(HTTPException) as scope_exc:
        update_scope(
            db_session,
            target,
            actor=member_actor,
            include_subdomains=True,
            exclusions=[],
        )
    assert scope_exc.value.status_code == 403
    with pytest.raises(HTTPException) as monitor_exc:
        upsert_monitoring(
            db_session,
            actor=member_actor,
            target_id=target.id,
            enabled=False,
            frequency="weekly",
        )
    assert monitor_exc.value.status_code == 403

    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_a_id,
            OrganizationMembership.user_id == UUID(me_a["id"]),
        )
    )
    membership.role = "org:admin"
    db_session.commit()
    stale_db_member = explicit_org_actor(
        user_id=UUID(me_a["id"]), organization_id=org_a_id, normalized_role="member"
    )
    with pytest.raises(HTTPException) as stale_exc:
        create_target(
            db_session,
            actor=stale_db_member,
            organization_id=org_a_id,
            raw_domain="svc-stale-db.example",
        )
    assert stale_exc.value.status_code == 403


def test_removed_member_cannot_access_org(client, make_token, seed_user_a, fake_clerk):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _me(client, token)
    fake_clerk.memberships[clerk_a] = []
    me = client.get("/v1/me", headers=_auth(token))
    assert me.status_code == 200
    assert me.json()["active_organization_id"] is None
    listed = client.get("/v1/organizations", headers=_auth(token))
    assert listed.status_code == 200
    assert listed.json() == []
    created = client.post(
        "/v1/targets", headers=_auth(token), json={"domain": "removed.example"}
    )
    assert created.status_code == 400


def test_short_clerk_admin_encoding_is_accepted(
    client, make_token, seed_user_a
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="admin")
    me = _me(client, token)
    assert me["active_organization_role"] == "admin"
    created = client.post(
        "/v1/targets", headers=_auth(token), json={"domain": "short-admin.example"}
    )
    assert created.status_code == 201, created.text

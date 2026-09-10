from dataclasses import asdict

import httpx
import pytest

from app.core.config import get_settings
from app.services.clerk import (
    ClerkOrganizationMember,
    ClerkOrganizationMembershipRaw,
    ClerkOrgMembership,
    CurrentAccessUnavailable,
    HttpClerkDirectory,
)


def _directory(handler) -> HttpClerkDirectory:
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api.clerk.test",
    )
    return HttpClerkDirectory(get_settings(), client=client)


def test_list_organization_members_uses_current_roster_path_and_projects_members():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "role": "org:admin",
                        "public_user_data": {
                            "user_id": "user_admin",
                            "identifier": "admin@example.com",
                            "first_name": "Ada",
                            "last_name": "Admin",
                        },
                    },
                    {
                        "role": "org:member",
                        "public_user_data": {
                            "user_id": "user_member",
                            "identifier": "member@example.com",
                            "first_name": "",
                            "last_name": "",
                        },
                    },
                ],
                "total_count": 7,
            },
        )

    directory = _directory(handler)
    members, total = directory.list_organization_members("org_x", limit=25, offset=50)

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/organizations/org_x/memberships"
    assert dict(requests[0].url.params) == {"limit": "25", "offset": "50"}
    assert members == [
        ClerkOrganizationMember(
            clerk_user_id="user_admin",
            email="admin@example.com",
            name="Ada Admin",
            email_verified=False,
        ),
        ClerkOrganizationMember(
            clerk_user_id="user_member",
            email="member@example.com",
            name=None,
            email_verified=False,
        ),
    ]
    assert total == 7


def test_list_organization_memberships_raw_uses_one_email_blind_provider_call():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "role": "org:member",
                        "public_user_data": {
                            "user_id": "user_member",
                            "identifier": "must-not-return@example.com",
                            "first_name": "  Current ",
                            "last_name": " Member  ",
                        },
                    }
                ],
                "total_count": 3,
            },
        )

    directory = _directory(handler)
    members, total = directory.list_organization_memberships_raw(
        "org_x",
        limit=20,
        offset=40,
    )

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/organizations/org_x/memberships"
    assert dict(requests[0].url.params) == {"limit": "20", "offset": "40"}
    assert members == [
        ClerkOrganizationMembershipRaw(
            provider_user_id="user_member",
            external_role="org:member",
            first_name="Current",
            last_name="Member",
        )
    ]
    assert total == 3
    assert "email" not in asdict(members[0])
    assert "must-not-return@example.com" not in repr(members)


@pytest.mark.parametrize(
    ("status_code", "payload"),
    [
        (503, {}),
        (200, []),
        (200, {"data": "not-a-list"}),
        (200, {"data": [{"role": "org:member"}]}),
    ],
)
def test_list_organization_memberships_raw_fails_closed(status_code, payload):
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status_code, json=payload)

    directory = _directory(handler)
    with pytest.raises(CurrentAccessUnavailable):
        directory.list_organization_memberships_raw("org_x", limit=20, offset=0)
    assert calls == 1


def test_list_user_organization_memberships_keeps_user_scoped_path():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "organization": {"id": "org_x", "name": "Example org"},
                        "role": "org:admin",
                    }
                ]
            },
        )

    directory = _directory(handler)
    memberships = directory.list_organization_memberships("user_x")

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/users/user_x/organization_memberships"
    assert dict(requests[0].url.params) == {"limit": "100"}
    assert memberships == [
        ClerkOrgMembership(
            clerk_org_id="org_x",
            org_name="Example org",
            role="org:admin",
        )
    ]


def test_list_organization_membership_presence_keeps_bounded_modern_path():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "data": [{"public_user_data": {"user_id": "user_b"}}],
                "total_count": 1,
            },
        )

    directory = _directory(handler)
    present = directory.list_organization_membership_presence(
        "org_x",
        provider_user_ids=["user_b", "user_a"],
    )

    assert present == frozenset({"user_b"})
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/organizations/org_x/memberships"
    assert list(requests[0].url.params.multi_items()) == [
        ("limit", "2"),
        ("offset", "0"),
        ("user_id", "user_a"),
        ("user_id", "user_b"),
    ]

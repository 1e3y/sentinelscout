from sqlalchemy import select

from app.models import Organization, OrganizationMembership, User


def test_list_organizations_persists_membership(
    client, make_token, seed_user_a, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    response = client.get("/v1/organizations", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["clerk_org_id"] == org_id
    assert body[0]["name"] == "Org A"
    assert body[0]["role"] == "org:admin"

    db_session.expire_all()
    org = db_session.scalar(select(Organization).where(Organization.clerk_org_id == org_id))
    user = db_session.scalar(select(User).where(User.clerk_user_id == user_id))
    assert org is not None
    assert user is not None
    membership = db_session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == user.id,
        )
    )
    assert membership is not None
    assert membership.role == "org:admin"


def test_get_own_organization(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    listed = client.get("/v1/organizations", headers={"Authorization": f"Bearer {token}"})
    org_uuid = listed.json()[0]["id"]

    response = client.get(
        f"/v1/organizations/{org_uuid}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["clerk_org_id"] == org_id


def test_cross_org_access_returns_404(
    client, make_token, seed_user_a, seed_user_b
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b

    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)

    # Persist both users/orgs via authenticated calls.
    assert (
        client.get("/v1/organizations", headers={"Authorization": f"Bearer {token_a}"}).status_code
        == 200
    )
    orgs_b = client.get("/v1/organizations", headers={"Authorization": f"Bearer {token_b}"})
    assert orgs_b.status_code == 200
    org_b_uuid = orgs_b.json()[0]["id"]

    # User A must not see User B's organization.
    denied = client.get(
        f"/v1/organizations/{org_b_uuid}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert denied.status_code == 404

    listed_a = client.get("/v1/organizations", headers={"Authorization": f"Bearer {token_a}"})
    assert listed_a.status_code == 200
    assert all(item["clerk_org_id"] != org_b for item in listed_a.json())


def test_unknown_organization_returns_404(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    response = client.get(
        "/v1/organizations/00000000-0000-0000-0000-000000000099",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_list_requires_auth(client):
    assert client.get("/v1/organizations").status_code == 401

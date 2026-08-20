from sqlalchemy import select

from app.models import User


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_me_missing_token_returns_401(client):
    response = client.get("/v1/me")
    assert response.status_code == 401


def test_me_invalid_token_returns_401(client):
    response = client.get("/v1/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_me_expired_token_returns_401(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, expired=True)
    response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_wrong_azp_returns_401(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id, azp="https://evil.example")
    response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_persists_user(client, make_token, seed_user_a, db_session):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["clerk_user_id"] == user_id
    assert body["email"] == "alice@example.com"
    assert body["name"] == "Alice"
    assert body["active_organization_id"] is not None
    assert body["active_organization_role"] == "admin"

    db_session.expire_all()
    user = db_session.scalar(select(User).where(User.clerk_user_id == user_id))
    assert user is not None
    assert user.email == "alice@example.com"

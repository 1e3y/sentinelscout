from datetime import datetime, timezone

from sqlalchemy import select

from app.models.target import AuthorizedTarget
from app.services.targets import is_effectively_verified


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_target(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    response = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "Example.COM"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "example.com"
    assert body["status"] == "unverified"
    assert body["authorization"] is None


def test_malformed_domain_rejected(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    for domain in [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "not a domain",
        "*.example.com",
        "localhost",
    ]:
        response = client.post(
            "/v1/targets",
            headers=_auth(token),
            json={"domain": domain},
        )
        assert response.status_code == 422, domain


def test_cross_org_target_access_blocked(
    client, make_token, seed_user_a, seed_user_b
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)

    created = client.post(
        "/v1/targets",
        headers=_auth(token_a),
        json={"domain": "acme.example"},
    )
    assert created.status_code == 201
    target_id = created.json()["id"]

    denied = client.get(f"/v1/targets/{target_id}", headers=_auth(token_b))
    assert denied.status_code == 404

    listed_b = client.get("/v1/targets", headers=_auth(token_b))
    assert listed_b.status_code == 200
    assert listed_b.json() == []


def test_fake_verification_rejected(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    created = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "verify-fail.example"},
    )
    target_id = created.json()["id"]

    started = client.post(
        f"/v1/targets/{target_id}/verification",
        headers=_auth(token),
    )
    assert started.status_code == 200
    assert started.json()["status"] == "verification_pending"
    txt_name = started.json()["authorization"]["txt_name"]
    txt_value = started.json()["authorization"]["txt_value"]

    # Wrong TXT value present.
    dns_resolver.set(txt_name, ["sentinelscout-verify=wrong-token"])
    failed = client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token))
    assert failed.status_code == 200
    assert failed.json()["verified"] is False
    assert failed.json()["status"] == "verification_pending"

    # Ensure expected value format is what we publish (not client-controlled status).
    assert txt_value.startswith("sentinelscout-verify=")
    assert txt_name == "_sentinelscout-challenge.verify-fail.example"


def test_successful_dns_verification(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    created = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "verify-ok.example"},
    )
    target_id = created.json()["id"]

    started = client.post(
        f"/v1/targets/{target_id}/verification",
        headers=_auth(token),
    )
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])

    verified = client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token))
    assert verified.status_code == 200
    body = verified.json()
    assert body["verified"] is True
    assert body["status"] == "verified"

    fetched = client.get(f"/v1/targets/{target_id}", headers=_auth(token))
    assert fetched.json()["status"] == "verified"
    assert fetched.json()["verified_at"] is not None


def test_revoked_target_not_treated_as_verified(
    client, make_token, seed_user_a, db_session, dns_resolver
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    created = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "revoked.example"},
    )
    target_id = created.json()["id"]
    started = client.post(
        f"/v1/targets/{target_id}/verification",
        headers=_auth(token),
    )
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()[
        "verified"
    ]

    target = db_session.scalar(
        select(AuthorizedTarget).where(AuthorizedTarget.id == target_id)
    )
    assert target is not None
    target.status = "revoked"
    target.revoked_at = datetime.now(timezone.utc)
    db_session.commit()

    db_session.refresh(target)
    assert is_effectively_verified(target) is False

    retry = client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token))
    assert retry.status_code == 400

    fetched = client.get(f"/v1/targets/{target_id}", headers=_auth(token))
    assert fetched.json()["status"] == "revoked"
    assert is_effectively_verified(
        type("T", (), {"status": fetched.json()["status"]})()
    ) is False


def test_scope_and_exclusions_persist(client, make_token, seed_user_a):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    created = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "scope.example"},
    )
    target_id = created.json()["id"]

    updated = client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={
            "include_subdomains": True,
            "exclusions": ["dev.scope.example", "staging.scope.example"],
        },
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["root_domain"] == "scope.example"
    assert body["include_subdomains"] is True
    assert body["exclusions"] == ["dev.scope.example", "staging.scope.example"]

    fetched = client.get(f"/v1/targets/{target_id}/scope", headers=_auth(token))
    assert fetched.status_code == 200
    assert fetched.json()["include_subdomains"] is True
    assert fetched.json()["exclusions"] == ["dev.scope.example", "staging.scope.example"]


def test_cross_org_scope_access_blocked(
    client, make_token, seed_user_a, seed_user_b
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)

    created = client.post(
        "/v1/targets",
        headers=_auth(token_a),
        json={"domain": "private-scope.example"},
    )
    target_id = created.json()["id"]

    assert (
        client.get(f"/v1/targets/{target_id}/scope", headers=_auth(token_b)).status_code
        == 404
    )
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token_b),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 404
    )

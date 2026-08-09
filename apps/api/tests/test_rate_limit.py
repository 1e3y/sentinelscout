from __future__ import annotations

from app.core.config import reset_settings_cache


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_rate_limits_enforced_on_target_create(
    client, make_token, seed_user_a, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_TARGET_CREATE", "2")
    reset_settings_cache()

    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)

    assert (
        client.post(
            "/v1/targets",
            headers=_auth(token),
            json={"domain": "rl-a.example"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/v1/targets",
            headers=_auth(token),
            json={"domain": "rl-b.example"},
        ).status_code
        == 201
    )
    limited = client.post(
        "/v1/targets",
        headers=_auth(token),
        json={"domain": "rl-c.example"},
    )
    assert limited.status_code == 429
    body = limited.json()
    assert body["error"]["code"] == "rate_limited"
    assert "Retry-After" in limited.headers


def test_rate_limits_isolated_by_user_org(
    client, make_token, seed_user_a, seed_user_b, monkeypatch
):
    monkeypatch.setenv("RATE_LIMIT_TARGET_CREATE", "1")
    reset_settings_cache()

    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)

    assert (
        client.post(
            "/v1/targets",
            headers=_auth(token_a),
            json={"domain": "rl-iso-a.example"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/v1/targets",
            headers=_auth(token_a),
            json={"domain": "rl-iso-a2.example"},
        ).status_code
        == 429
    )
    # Different org/user still allowed.
    assert (
        client.post(
            "/v1/targets",
            headers=_auth(token_b),
            json={"domain": "rl-iso-b.example"},
        ).status_code
        == 201
    )

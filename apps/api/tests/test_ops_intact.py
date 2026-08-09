"""Smoke: audit/operation functionality remains intact after readiness work."""

from __future__ import annotations


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()[
        "verified"
    ]
    return target_id


def test_operation_and_audit_still_work(client, make_token, seed_user_a, dns_resolver):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    target_id = _create_verified_target(
        client, token, "ops-intact.example", dns_resolver
    )
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["control_snapshot"] is not None
    assert body["testing_profile"] == "safe_production"

    events = client.get(
        "/v1/audit-events",
        headers=_auth(token),
        params={"action": "operation.created"},
    ).json()
    assert any(e["resource_id"] == body["id"] for e in events)

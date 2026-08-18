from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.models.candidate import SecurityCandidate
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.services.coverage import REASON_PROBE_NO_RESULT
from app.services.diff import (
    CHANGE_CANDIDATE_NEW,
    CHANGE_HOSTNAME_NEWLY_DISCOVERED,
    CHANGE_HTTP_OBSERVATION_LOST,
    COMPARABILITY_COMPARABLE,
    COMPARABILITY_NO_BASELINE,
    COMPARABILITY_NOT_COMPARABLE_SCOPE,
    COMPARABILITY_PARTIAL_CAPABILITY,
    diff_snapshots,
    freeze_operation_diff,
)
from app.services.discovery.runner import FakeDiscoveryTools, ProbeResult
from app.services.worker_runtime import process_one_operation


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


def _queue(client, token: str, target_id: str, source: str = "manual") -> str:
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_first_operation_has_no_baseline(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-first.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    operation_id = _queue(client, token, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    payload = client.get(
        f"/v1/operations/{operation_id}/diff", headers=_auth(token)
    ).json()
    assert payload["comparability"] == COMPARABILITY_NO_BASELINE
    assert payload["changes"] == []
    assert payload["comparison_snapshot"]["discovered"] == [domain]
    assert payload["comparison_snapshot"]["security_signals_complete"] is True


def test_probe_no_result_is_not_hostname_removal(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-silent.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": []},
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    op1 = _queue(client, token, target_id)
    tools1 = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"silent.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"silent.{domain}": ProbeResult(
                url=f"https://silent.{domain}", status_code=200, title="Silent"
            ),
        },
    )
    assert process_one_operation(factory, tools=tools1).status == "completed"
    op2 = _queue(client, token, target_id)
    tools2 = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"silent.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
        },
    )
    assert process_one_operation(factory, tools=tools2).status == "completed"
    payload = client.get(f"/v1/operations/{op2}/diff", headers=_auth(token)).json()
    by_type = {}
    for row in payload["changes"]:
        by_type.setdefault(row["change_type"], []).append(row)
    assert CHANGE_HOSTNAME_NEWLY_DISCOVERED not in by_type or all(
        item["match_key"] != f"silent.{domain}"
        for item in by_type.get(CHANGE_HOSTNAME_NEWLY_DISCOVERED, [])
    )
    assert "hostname_no_longer_discovered" not in by_type
    lost = by_type[CHANGE_HTTP_OBSERVATION_LOST]
    assert lost[0]["match_key"] == f"silent.{domain}"
    assert lost[0]["after"]["reason_code"] == REASON_PROBE_NO_RESULT
    assert lost[0]["after"]["reason_code"] != "host_not_reachable"


def test_scope_change_is_not_comparable(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-scope.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": []},
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    _queue(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain, f"www.{domain}"]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root"),
            f"www.{domain}": ProbeResult(
                url=f"https://www.{domain}", status_code=200, title="WWW"
            ),
        },
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": [f"www.{domain}"]},
    )
    op2 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    payload = client.get(f"/v1/operations/{op2}/diff", headers=_auth(token)).json()
    assert payload["comparability"] == COMPARABILITY_NOT_COMPARABLE_SCOPE
    types = {row["change_type"] for row in payload["changes"]}
    assert types == {"scope_changed"}


def test_capability_change_suppresses_security_signals():
    current = {
        "discovered": ["a.example"],
        "http_observed": ["a.example"],
        "http_evidence": {},
        "gaps": {},
        "emitted_candidates": [
            {"hostname": "a.example", "candidate_type": "exposed_admin_interface"}
        ],
        "contract": {
            "scope_root": "example",
            "include_subdomains": True,
            "exclusions": [],
            "testing_profile": "safe_production",
            "capability_manifest_version": 2,
            "discovery_truncated": False,
        },
    }
    baseline = {
        "discovered": ["a.example"],
        "http_observed": ["a.example"],
        "http_evidence": {},
        "gaps": {},
        "emitted_candidates": [],
        "contract": {
            "scope_root": "example",
            "include_subdomains": True,
            "exclusions": [],
            "testing_profile": "safe_production",
            "capability_manifest_version": 1,
            "discovery_truncated": False,
        },
    }
    changes = diff_snapshots(
        current=current,
        baseline=baseline,
        comparability=COMPARABILITY_PARTIAL_CAPABILITY,
        include_security_signals=False,
    )
    types = {row["change_type"] for row in changes}
    assert "capability_manifest_changed" in types
    assert CHANGE_CANDIDATE_NEW not in types
    assert "candidate_no_longer_emitted" not in types


def test_resolved_finding_regression_requires_resolved_before_start(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-regr.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    client.put(
        f"/v1/targets/{target_id}/scope",
        headers=_auth(token),
        json={"include_subdomains": True, "exclusions": []},
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    admin = f"admin.{domain}"
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [admin]},
        probes_by_host={
            admin: ProbeResult(
                url=f"https://{admin}/",
                status_code=200,
                title="Admin Dashboard",
                headers_observed=True,
                headers={"content-type": "text/html"},
                content_type="text/html",
                scheme="https",
            )
        },
    )
    op1 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    candidate = db_session.scalar(
        select(SecurityCandidate).where(SecurityCandidate.operation_id == UUID(op1))
    )
    assert candidate is not None
    too_late = datetime.now(timezone.utc) + timedelta(hours=1)
    finding = Finding(
        organization_id=candidate.organization_id,
        operation_id=candidate.operation_id,
        candidate_id=candidate.id,
        asset_id=candidate.asset_id,
        title="Resolved later",
        summary="not before start",
        severity="low",
        status="resolved",
        business_impact="n/a",
        remediation_guidance="n/a",
        resolved_at=too_late,
    )
    db_session.add(finding)
    db_session.commit()
    op2 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    payload = client.get(f"/v1/operations/{op2}/diff", headers=_auth(token)).json()
    types = {row["change_type"] for row in payload["changes"]}
    assert "regression_resolved_condition_reappeared" not in types

    finding.resolved_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()
    op3 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    later = client.get(f"/v1/operations/{op3}/diff", headers=_auth(token)).json()
    later_types = {row["change_type"] for row in later["changes"]}
    assert "regression_resolved_condition_reappeared" in later_types


def test_follow_up_findings_do_not_rewrite_frozen_changes(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-follow.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    op_id = _queue(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(
                url=f"https://{domain}/",
                status_code=200,
                title="Admin",
                headers_observed=True,
                headers={"content-type": "text/html"},
                content_type="text/html",
                scheme="https",
            )
        },
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    before = client.get(f"/v1/operations/{op_id}/diff", headers=_auth(token)).json()
    frozen_changes = before["changes"]
    candidate = db_session.scalar(
        select(SecurityCandidate).where(SecurityCandidate.operation_id == UUID(op_id))
    )
    assert candidate is not None
    db_session.add(
        Finding(
            organization_id=candidate.organization_id,
            operation_id=candidate.operation_id,
            candidate_id=candidate.id,
            asset_id=candidate.asset_id,
            title="Promoted later",
            summary="after freeze",
            severity="low",
            status="open",
            business_impact="n/a",
            remediation_guidance="n/a",
            created_at=datetime.now(timezone.utc) + timedelta(seconds=2),
        )
    )
    db_session.commit()
    after = client.get(f"/v1/operations/{op_id}/diff", headers=_auth(token)).json()
    assert after["changes"] == frozen_changes
    assert after["follow_up_findings"]
    assert after["follow_up_findings"][0]["change_type"] == "finding_promoted_after_snapshot"


def test_diff_freeze_is_idempotent_and_uses_snapshot(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-freeze.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    op_id = _queue(client, token, target_id)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    operation = process_one_operation(factory, tools=tools)
    assert operation is not None
    first = client.get(f"/v1/operations/{op_id}/diff", headers=_auth(token)).json()
    row = db_session.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == UUID(op_id)
        )
    )
    assert row is not None
    snapshot_id = row.id
    freeze_operation_diff(db_session, operation, source="frozen")
    freeze_operation_diff(db_session, operation, source="frozen")
    again = db_session.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == UUID(op_id)
        )
    )
    assert again is not None
    assert again.id == snapshot_id
    db_session.delete(again)
    db_session.commit()
    recovered = client.get(f"/v1/operations/{op_id}/diff", headers=_auth(token)).json()
    assert recovered["source"] == "recovered"
    assert recovered["comparison_snapshot"]["discovered"] == first["comparison_snapshot"][
        "discovered"
    ]
    assert recovered["comparison_snapshot"]["security_signals_complete"] is False
    assert recovered["comparison_snapshot"]["emitted_candidates"] == []


def test_diff_endpoint_is_org_scoped(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, engine
):
    user_a, org_a = seed_user_a
    user_b, org_b = seed_user_b
    token_a = make_token(sub=user_a, org_id=org_a)
    token_b = make_token(sub=user_b, org_id=org_b)
    domain = "private-diff.example"
    target_id = _create_verified_target(client, token_a, domain, dns_resolver)
    operation_id = _queue(client, token_a, target_id)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    assert process_one_operation(factory, tools=tools).status == "completed"
    assert (
        client.get(
            f"/v1/operations/{operation_id}/diff", headers=_auth(token_b)
        ).status_code
        == 404
    )


def test_pre_m18_baseline_marks_security_signals_unavailable(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "diff-prem18.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = FakeDiscoveryTools(
        hosts_by_domain={domain: [domain]},
        probes_by_host={
            domain: ProbeResult(url=f"https://{domain}", status_code=200, title="Root")
        },
    )
    op1 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    row = db_session.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == UUID(op1)
        )
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()
    op2 = _queue(client, token, target_id)
    assert process_one_operation(factory, tools=tools).status == "completed"
    payload = client.get(f"/v1/operations/{op2}/diff", headers=_auth(token)).json()
    assert payload["comparability"] == COMPARABILITY_COMPARABLE
    assert payload["security_signal_baseline_unavailable"] is True
    types = {row["change_type"] for row in payload["changes"]}
    assert "candidate_new" not in types
    assert "candidate_no_longer_emitted" not in types
    assert payload["changes"] == []

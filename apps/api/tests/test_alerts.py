from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.attributes import flag_modified

from app.models.alert import (
    AlertEpisode,
    AlertGenerationReceipt,
    AlertUserState,
    NotificationOutbox,
)
from app.models.candidate import SecurityCandidate
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.services.alerts import (
    ALERT_HEADER_EVIDENCE_LOST,
    ALERT_HSTS_LOST,
    STATE_ACTIVE,
    STATE_RESOLVED,
    STATE_UNKNOWN,
    evaluate_episode_state,
    freeze_operation_alerts,
)
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.diff import (
    COMPARABILITY_COMPARABLE,
    COMPARABILITY_NOT_COMPARABLE_SCOPE,
    COMPARABILITY_PARTIAL_CAPABILITY,
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
    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": []},
        ).status_code
        == 200
    )
    return target_id


def _queue(client, token: str, target_id: str) -> str:
    created = client.post(
        "/v1/operations",
        headers=_auth(token),
        json={"target_id": target_id},
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _https_html(
    host: str,
    *,
    title: str = "Home",
    hsts: bool = True,
    headers_observed: bool = True,
    outcome: str = "observed",
) -> ProbeResult:
    headers = {"content-type": "text/html"}
    present = ["content-type"]
    if hsts:
        headers["strict-transport-security"] = "max-age=31536000"
        present.append("strict-transport-security")
    return ProbeResult(
        url=f"https://{host}/",
        status_code=200 if outcome == "observed" else None,
        title=title,
        headers_observed=headers_observed,
        headers=headers if headers_observed else {},
        headers_present=tuple(present) if headers_observed else (),
        content_type="text/html",
        scheme="https",
        redirected=False,
        requested_url=f"https://{host}/",
        final_url=f"https://{host}/",
        outcome=outcome,
    )


def _tools(domain: str, probes: dict[str, ProbeResult], extra_hosts: list[str] | None = None):
    hosts = [domain, *list(probes), *(extra_hosts or [])]
    unique = list(dict.fromkeys(hosts))
    return FakeDiscoveryTools(
        hosts_by_domain={domain: unique},
        probes_by_host=probes,
    )


def _run(factory, tools):
    result = process_one_operation(factory, tools=tools)
    assert result is not None
    assert result.status == "completed", result.error_message
    return result


def _episode(alert_type: str, hostname: str = "", **evidence):
    payload = {"hostname": hostname, **evidence}
    return SimpleNamespace(alert_type=alert_type, opening_evidence=payload)


def test_evaluate_hsts_and_header_evidence_states():
    host = "hsts.example"
    snapshot_absent = {
        "http_observed": [host],
        "discovered": [host],
        "http_evidence": {
            host: {
                "headers_observed": True,
                "hsts_present": False,
                "hsts_applicable": True,
                "redirected": False,
            }
        },
        "gaps": {},
        "emitted_candidates": [],
        "contract": {"discovery_truncated": False},
    }
    snapshot_present = {
        **snapshot_absent,
        "http_evidence": {
            host: {
                "headers_observed": True,
                "hsts_present": True,
                "hsts_applicable": True,
                "redirected": False,
            }
        },
    }
    episode = _episode(ALERT_HSTS_LOST, host)
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=snapshot_absent,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_ACTIVE
    )
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=snapshot_present,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_RESOLVED
    )
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=snapshot_absent,
            comparability=COMPARABILITY_NOT_COMPARABLE_SCOPE,
            security_signals_comparable=False,
        )
        == STATE_UNKNOWN
    )
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=snapshot_absent,
            comparability=COMPARABILITY_PARTIAL_CAPABILITY,
            security_signals_comparable=False,
        )
        == STATE_UNKNOWN
    )
    header_ep = _episode(ALERT_HEADER_EVIDENCE_LOST, host)
    headers_false = {
        "http_observed": [host],
        "discovered": [host],
        "http_evidence": {host: {"headers_observed": False}},
        "gaps": {},
        "contract": {"discovery_truncated": False},
    }
    assert (
        evaluate_episode_state(
            episode=header_ep,
            snapshot=headers_false,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_ACTIVE
    )
    gone = {
        "http_observed": [],
        "discovered": [host],
        "http_evidence": {},
        "gaps": {host: {"reason_code": "probe_no_result"}},
        "contract": {"discovery_truncated": False},
    }
    assert (
        evaluate_episode_state(
            episode=header_ep,
            snapshot=gone,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_UNKNOWN
    )


def test_evaluate_coverage_does_not_close_on_partial_recovery():
    episode = _episode(
        "http_observation_coverage_degraded",
        reference_numerator=9,
        reference_denominator=10,
    )
    partial = {
        "http_observed": [f"h{i}" for i in range(8)],
        "discovered": [f"h{i}" for i in range(10)],
        "http_evidence": {},
        "gaps": {},
        "contract": {"discovery_truncated": False},
    }
    restored = {
        "http_observed": [f"h{i}" for i in range(9)],
        "discovered": [f"h{i}" for i in range(10)],
        "http_evidence": {},
        "gaps": {},
        "contract": {"discovery_truncated": False},
    }
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=partial,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_ACTIVE
    )
    assert (
        evaluate_episode_state(
            episode=episode,
            snapshot=restored,
            comparability=COMPARABILITY_COMPARABLE,
            security_signals_comparable=True,
        )
        == STATE_RESOLVED
    )


def test_hsts_episode_lifecycle_and_no_duplicate_on_unchanged_run(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-hsts.example"
    host = f"hsts.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    present = {domain: _https_html(domain), host: _https_html(host, hsts=True)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False)}

    op1 = _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    assert client.get("/v1/alerts", headers=_auth(token)).json() == []

    op2 = _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    alerts = client.get("/v1/alerts", headers=_auth(token)).json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "hsts_lost"
    assert alerts[0]["category"] == "security_regression"
    assert alerts[0]["priority"] == "medium"
    assert "vulnerabilit" not in alerts[0]["title"].lower()
    assert "vulnerabilit" not in alerts[0]["summary"].lower()
    episode_id = alerts[0]["episode_id"]
    assert alerts[0]["episode_status"] == "open"
    assert alerts[0]["reopened_from_episode_id"] is None
    assert alerts[0]["last_seen_operation_id"] == op2

    op3 = _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    later = client.get("/v1/alerts", headers=_auth(token)).json()
    assert len(later) == 1
    assert later[0]["id"] == alerts[0]["id"]
    assert later[0]["episode_id"] == episode_id
    assert later[0]["last_seen_operation_id"] == op3
    assert later[0]["operation_id"] == op2

    op4 = _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    restored = client.get("/v1/alerts", headers=_auth(token)).json()
    assert len(restored) == 1
    assert restored[0]["episode_status"] == "closed"
    assert restored[0]["last_seen_operation_id"] == op4

    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    reopened = client.get("/v1/alerts", headers=_auth(token)).json()
    assert len(reopened) == 2
    newest = reopened[0]
    assert newest["alert_type"] == "hsts_lost"
    assert newest["episode_id"] != episode_id
    assert newest["reopened_from_episode_id"] == episode_id
    assert newest["episode_status"] == "open"

    db_session.expire_all()
    outbox = list(db_session.scalars(select(NotificationOutbox)).all())
    assert len(outbox) == 2
    assert all(row.channel == "in_app" and row.destination_key == "org" for row in outbox)
    receipts = list(db_session.scalars(select(AlertGenerationReceipt)).all())
    assert {row.alert_count for row in receipts} <= {0, 1}
    assert any(row.alert_count == 0 for row in receipts)


def test_header_evidence_lost_is_not_security_regression(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-headers.example"
    host = f"hdr.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    captured = {
        domain: _https_html(domain),
        host: _https_html(host, headers_observed=True),
    }
    missing = {
        domain: _https_html(domain),
        host: _https_html(host, headers_observed=False),
    }
    _queue(client, token, target_id)
    _run(factory, _tools(domain, captured))
    _queue(client, token, target_id)
    _run(factory, _tools(domain, missing))
    alerts = client.get("/v1/alerts", headers=_auth(token)).json()
    header_alerts = [row for row in alerts if row["alert_type"] == "header_evidence_lost"]
    assert len(header_alerts) == 1
    assert header_alerts[0]["category"] == "coverage_degradation"
    assert header_alerts[0]["priority"] == "low"
    assert header_alerts[0]["category"] != "security_regression"
    assert "Scout could not capture response-header evidence" in header_alerts[0]["summary"]
    episode_id = header_alerts[0]["episode_id"]
    last_seen = header_alerts[0]["last_seen_operation_id"]

    op3 = _queue(client, token, target_id)
    _run(factory, _tools(domain, missing))
    still = client.get("/v1/alerts", headers=_auth(token)).json()
    header_still = [row for row in still if row["alert_type"] == "header_evidence_lost"]
    assert len(header_still) == 1
    assert header_still[0]["episode_id"] == episode_id
    assert header_still[0]["last_seen_operation_id"] == op3
    assert header_still[0]["last_seen_operation_id"] != last_seen
    assert header_still[0]["episode_status"] == "open"

    _queue(client, token, target_id)
    gone = {domain: _https_html(domain)}
    _run(factory, _tools(domain, gone, extra_hosts=[host]))
    after = client.get("/v1/alerts", headers=_auth(token)).json()
    header_after = [row for row in after if row["alert_type"] == "header_evidence_lost"]
    assert len(header_after) == 1
    assert header_after[0]["episode_status"] == "open"
    assert header_after[0]["last_seen_operation_id"] == op3


def test_coverage_episode_stays_open_on_partial_recovery(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-cov.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    hosts = [domain, *[f"c{i:02d}.{domain}" for i in range(19)]]

    def probes_for(observed: list[str]) -> dict[str, ProbeResult]:
        return {host: _https_html(host) for host in observed}

    all_but_two = hosts[:18]
    fourteen = hosts[:14]
    fifteen = hosts[:15]

    _queue(client, token, target_id)
    _run(factory, _tools(domain, probes_for(all_but_two), extra_hosts=hosts))
    _queue(client, token, target_id)
    _run(factory, _tools(domain, probes_for(fourteen), extra_hosts=hosts))
    opened = [
        row
        for row in client.get("/v1/alerts", headers=_auth(token)).json()
        if row["alert_type"] == "http_observation_coverage_degraded"
    ]
    assert len(opened) == 1
    episode_id = opened[0]["episode_id"]
    assert opened[0]["priority"] == "low"
    assert opened[0]["category"] == "coverage_degradation"

    _queue(client, token, target_id)
    _run(factory, _tools(domain, probes_for(fifteen), extra_hosts=hosts))
    partial = [
        row
        for row in client.get("/v1/alerts", headers=_auth(token)).json()
        if row["alert_type"] == "http_observation_coverage_degraded"
    ]
    assert len(partial) == 1
    assert partial[0]["episode_id"] == episode_id
    assert partial[0]["episode_status"] == "open"

    _queue(client, token, target_id)
    _run(factory, _tools(domain, probes_for(all_but_two), extra_hosts=hosts))
    restored = [
        row
        for row in client.get("/v1/alerts", headers=_auth(token)).json()
        if row["alert_type"] == "http_observation_coverage_degraded"
    ]
    assert len(restored) == 1
    assert restored[0]["episode_status"] == "closed"


def test_silent_and_info_changes(
    client, make_token, seed_user_a, dns_resolver, engine
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-silent.example"
    silent = f"silent.{domain}"
    down = f"down.{domain}"
    added = f"admin.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    base = {
        domain: _https_html(domain, title="Alpha"),
        silent: _https_html(silent),
        down: _https_html(down),
    }
    _queue(client, token, target_id)
    _run(factory, _tools(domain, base))

    title_only = {
        domain: _https_html(domain, title="Beta"),
        silent: _https_html(silent),
        down: _https_html(down),
    }
    _queue(client, token, target_id)
    _run(factory, _tools(domain, title_only))
    assert client.get("/v1/alerts", headers=_auth(token)).json() == []

    with_new = {**title_only, added: _https_html(added, title="Admin Dashboard")}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, with_new))
    types = {row["alert_type"] for row in client.get("/v1/alerts", headers=_auth(token)).json()}
    assert "resolved_condition_reappeared" not in types

    no_result = {domain: _https_html(domain, title="Beta"), down: _https_html(down)}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, no_result, extra_hosts=[silent]))
    after_silent = client.get("/v1/alerts", headers=_auth(token)).json()
    assert all(row["alert_type"] != "http_observation_lost_explicit" for row in after_silent)

    unreachable = {
        domain: _https_html(domain, title="Beta"),
        down: ProbeResult(
            url=f"https://{down}/",
            status_code=None,
            title="",
            outcome="host_not_reachable",
        ),
    }
    _queue(client, token, target_id)
    _run(factory, _tools(domain, unreachable, extra_hosts=[silent, down]))
    explicit = [
        row
        for row in client.get("/v1/alerts", headers=_auth(token)).json()
        if row["alert_type"] == "http_observation_lost_explicit"
    ]
    assert len(explicit) == 1
    assert explicit[0]["priority"] == "info"


def test_scope_and_capability_leave_security_episodes_unknown(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-scope.example"
    host = f"hsts.{domain}"
    extra = f"www.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    present = {domain: _https_html(domain), host: _https_html(host, hsts=True), extra: _https_html(extra)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False), extra: _https_html(extra)}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    _queue(client, token, target_id)
    _run(factory, _tools(domain, absent))
    alerts = client.get("/v1/alerts", headers=_auth(token)).json()
    hsts = next(row for row in alerts if row["alert_type"] == "hsts_lost")
    last_seen = hsts["last_seen_operation_id"]

    assert (
        client.put(
            f"/v1/targets/{target_id}/scope",
            headers=_auth(token),
            json={"include_subdomains": True, "exclusions": [extra]},
        ).status_code
        == 200
    )
    _queue(client, token, target_id)
    scoped_op = _run(
        factory,
        _tools(domain, {domain: _https_html(domain), host: _https_html(host, hsts=False)}),
    )
    scoped = client.get("/v1/alerts", headers=_auth(token)).json()
    scope_alerts = [row for row in scoped if row["alert_type"] == "scope_not_comparable"]
    assert len(scope_alerts) == 1
    assert scope_alerts[0]["priority"] == "info"
    hsts_after = next(row for row in scoped if row["alert_type"] == "hsts_lost")
    assert hsts_after["episode_status"] == "open"
    assert hsts_after["last_seen_operation_id"] == last_seen

    db_session.expire_all()
    baseline = db_session.scalar(
        select(OperationDiffSummary).where(OperationDiffSummary.operation_id == scoped_op.id)
    )
    assert baseline is not None
    snapshot = dict(baseline.comparison_snapshot or {})
    contract = dict(snapshot.get("contract") or {})
    contract["capability_manifest_version"] = int(contract.get("capability_manifest_version") or 1) + 1
    snapshot["contract"] = contract
    baseline.comparison_snapshot = snapshot
    flag_modified(baseline, "comparison_snapshot")
    db_session.commit()

    _queue(client, token, target_id)
    _run(factory, _tools(domain, {domain: _https_html(domain), host: _https_html(host, hsts=False)}))
    cap = client.get("/v1/alerts", headers=_auth(token)).json()
    cap_alerts = [row for row in cap if row["alert_type"] == "capability_comparison_suppressed"]
    assert cap_alerts
    assert cap_alerts[0]["priority"] == "info"
    hsts_cap = next(row for row in cap if row["alert_type"] == "hsts_lost")
    assert hsts_cap["episode_status"] == "open"


def test_legacy_baseline_does_not_invent_security_signal_alert(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-legacy.example"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = _tools(domain, {domain: _https_html(domain)})
    op1 = _queue(client, token, target_id)
    _run(factory, tools)
    db_session.expire_all()
    row = db_session.scalar(
        select(OperationDiffSummary).where(OperationDiffSummary.operation_id == UUID(op1))
    )
    assert row is not None
    db_session.delete(row)
    db_session.commit()
    _queue(client, token, target_id)
    _run(factory, tools)
    types = {row["alert_type"] for row in client.get("/v1/alerts", headers=_auth(token)).json()}
    assert "resolved_condition_reappeared" not in types


def test_resolved_condition_reappeared_alert(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-reappear.example"
    admin = f"admin.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    tools = _tools(
        domain,
        {
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
    _run(factory, tools)
    candidate = db_session.scalar(
        select(SecurityCandidate).where(SecurityCandidate.operation_id == UUID(op1))
    )
    assert candidate is not None
    db_session.add(
        Finding(
            organization_id=candidate.organization_id,
            operation_id=candidate.operation_id,
            candidate_id=candidate.id,
            asset_id=candidate.asset_id,
            title="Resolved earlier",
            summary="before next start",
            severity="low",
            status="resolved",
            business_impact="n/a",
            remediation_guidance="n/a",
            resolved_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    db_session.commit()
    _queue(client, token, target_id)
    _run(factory, tools)
    alerts = [
        row
        for row in client.get("/v1/alerts", headers=_auth(token)).json()
        if row["alert_type"] == "resolved_condition_reappeared"
    ]
    assert len(alerts) == 1
    assert alerts[0]["category"] == "security_regression"
    assert alerts[0]["priority"] == "medium"


def test_read_dismiss_is_per_user_and_ack_does_not_close_episode(
    client, make_token, seed_user_a, fake_clerk, dns_resolver, engine, db_session
):
    clerk_a, clerk_org = seed_user_a
    token_a = make_token(sub=clerk_a, org_id=clerk_org)
    client.get("/v1/me", headers=_auth(token_a))
    clerk_b = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_b] = ClerkUserInfo(
        clerk_user_id=clerk_b,
        email="bob-alerts@example.com",
        name="Bob",
    )
    fake_clerk.memberships[clerk_b] = [
        ClerkOrgMembership(clerk_org_id=clerk_org, org_name="Org A", role="org:member")
    ]
    token_b = make_token(sub=clerk_b, org_id=clerk_org, org_role="org:member")
    me_b = client.get("/v1/me", headers=_auth(token_b))
    assert me_b.status_code == 200, me_b.text

    domain = "alert-users.example"
    host = f"hsts.{domain}"
    target_id = _create_verified_target(client, token_a, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    present = {domain: _https_html(domain), host: _https_html(host, hsts=True)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False)}
    _queue(client, token_a, target_id)
    _run(factory, _tools(domain, present))
    _queue(client, token_a, target_id)
    _run(factory, _tools(domain, absent))

    listed_a = client.get("/v1/alerts", headers=_auth(token_a)).json()
    listed_b = client.get("/v1/alerts", headers=_auth(token_b)).json()
    assert len(listed_a) == 1 and len(listed_b) == 1
    alert_id = listed_a[0]["id"]
    assert listed_a[0]["read_at"] is None
    assert listed_b[0]["read_at"] is None

    assert (
        client.post(f"/v1/alerts/{alert_id}/read", headers=_auth(token_a)).status_code
        == 200
    )
    assert (
        client.post(f"/v1/alerts/{alert_id}/dismiss", headers=_auth(token_a)).status_code
        == 200
    )
    after_a = client.get("/v1/alerts", headers=_auth(token_a)).json()
    after_b = client.get("/v1/alerts", headers=_auth(token_b)).json()
    assert after_a == []
    assert len(after_b) == 1
    assert after_b[0]["read_at"] is None
    assert after_b[0]["dismissed_at"] is None
    still_a = client.get(
        "/v1/alerts?include_dismissed=true", headers=_auth(token_a)
    ).json()
    assert len(still_a) == 1
    assert still_a[0]["dismissed_at"] is not None

    ack = client.post(f"/v1/alerts/{alert_id}/acknowledge", headers=_auth(token_a))
    assert ack.status_code == 200, ack.text
    body = ack.json()
    assert body["acknowledged_at"] is not None
    assert body["acknowledged_by_user_id"] is not None
    assert body["episode_status"] == "open"
    seen_b = client.get("/v1/alerts", headers=_auth(token_b)).json()
    assert len(seen_b) == 1
    assert seen_b[0]["acknowledged_at"] is not None
    assert seen_b[0]["episode_status"] == "open"
    summary_b = client.get("/v1/alerts/summary", headers=_auth(token_b)).json()
    assert summary_b["unread_count"] == 1
    summary_a = client.get("/v1/alerts/summary", headers=_auth(token_a)).json()
    assert summary_a["unread_count"] == 0

    db_session.expire_all()
    states = list(db_session.scalars(select(AlertUserState)).all())
    assert len(states) >= 1
    episode = db_session.get(AlertEpisode, UUID(listed_a[0]["episode_id"]))
    assert episode is not None
    assert episode.status == "open"


def test_alert_freeze_is_idempotent(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    user_id, org_id = seed_user_a
    token = make_token(sub=user_id, org_id=org_id)
    domain = "alert-idemp.example"
    host = f"hsts.{domain}"
    target_id = _create_verified_target(client, token, domain, dns_resolver)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    present = {domain: _https_html(domain), host: _https_html(host, hsts=True)}
    absent = {domain: _https_html(domain), host: _https_html(host, hsts=False)}
    _queue(client, token, target_id)
    _run(factory, _tools(domain, present))
    op2 = _queue(client, token, target_id)
    operation = _run(factory, _tools(domain, absent))
    first = client.get("/v1/alerts", headers=_auth(token)).json()
    assert len(first) == 1
    db_session.expire_all()
    again = freeze_operation_alerts(db_session, operation, source="recovered")
    db_session.commit()
    second = client.get("/v1/alerts", headers=_auth(token)).json()
    assert [row["id"] for row in second] == [row["id"] for row in first]
    receipts = list(
        db_session.scalars(
            select(AlertGenerationReceipt).where(
                AlertGenerationReceipt.operation_id == UUID(op2)
            )
        ).all()
    )
    assert len(receipts) == 1
    assert again is not None
    assert again.id == receipts[0].id
    recovered = client.get(f"/v1/operations/{op2}/diff", headers=_auth(token))
    assert recovered.status_code == 200
    third = client.get("/v1/alerts", headers=_auth(token)).json()
    assert [row["id"] for row in third] == [row["id"] for row in first]
    outbox = list(db_session.scalars(select(NotificationOutbox)).all())
    assert len(outbox) == 1
    episodes = list(db_session.scalars(select(AlertEpisode)).all())
    assert len([row for row in episodes if row.status == "open"]) == 1

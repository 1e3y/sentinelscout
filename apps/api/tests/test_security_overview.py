from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker

from app.models.alert import Alert, AlertEpisode
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.models.monitoring import (
    MonitoringConfiguration,
    MonitoringReportDeliveryRecipient,
)
from app.models.operation import Operation
from app.models.organization import Organization
from app.models.report import AssessmentReport
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.coverage import coverage_payload_from_snapshot
from app.services.security_overview import (
    MAX_PAGE_SIZE,
    REASON_ACTIVE_ALERT_EPISODE,
    REASON_ASSESSMENT_STALE,
    REASON_COMPARISON_UNAVAILABLE,
    REASON_COVERAGE_LIMITED,
    REASON_COVERAGE_UNAVAILABLE,
    REASON_FROZEN_REGRESSION_PRESENT,
    REASON_LATEST_ASSESSMENT_INCOMPLETE,
    REASON_NO_COMPLETED_ASSESSMENT,
    encode_overview_cursor,
    list_security_overview,
)

OVERVIEW = "/v1/security-overview"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _overview(client, token: str, **params):
    return client.get(OVERVIEW, headers=_auth(token), params=params or None)


def _rows(client, token: str, **params) -> list[dict]:
    response = _overview(client, token, **params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _row_for(client, token: str, domain: str) -> dict:
    for row in _rows(client, token):
        if row["domain"] == domain:
            return row
    raise AssertionError(f"{domain} not present in overview")


def _codes(row: dict) -> set[str]:
    return {reason["code"] for reason in row["attention_reasons"]}


def _create_target(client, token: str, domain: str) -> str:
    created = client.post("/v1/targets", headers=_auth(token), json={"domain": domain})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _create_verified_target(client, token: str, domain: str, dns_resolver) -> str:
    target_id = _create_target(client, token, domain)
    started = client.post(f"/v1/targets/{target_id}/verification", headers=_auth(token))
    authz = started.json()["authorization"]
    dns_resolver.set(authz["txt_name"], [authz["txt_value"]])
    assert client.post(f"/v1/targets/{target_id}/verify", headers=_auth(token)).json()[
        "verified"
    ]
    return target_id


def _ids(client, token: str) -> tuple[UUID, UUID]:
    me = client.get("/v1/me", headers=_auth(token)).json()
    return UUID(me["id"]), UUID(me["active_organization_id"])


def _add_member(fake_clerk, make_token, clerk_org: str, email: str) -> str:
    clerk_member = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_member] = ClerkUserInfo(
        clerk_user_id=clerk_member,
        email=email,
        name="Member",
        email_verified=True,
    )
    fake_clerk.memberships[clerk_member] = [
        ClerkOrgMembership(clerk_org_id=clerk_org, org_name="Org A", role="org:member")
    ]
    return make_token(sub=clerk_member, org_id=clerk_org, org_role="org:member")


def _surface(
    *,
    obtained: int = 3,
    discovered: int = 3,
    incomplete: int = 0,
    not_obtained: int | None = None,
) -> dict:
    ratio = None
    if discovered > 0:
        ratio = {
            "numerator": obtained,
            "denominator": discovered,
            "value": round(obtained / discovered, 4),
        }
    return {
        "unit": "in_scope_hostname",
        "in_scope_discovered": discovered,
        "submitted_for_http_observation": discovered,
        "http_observation_obtained": obtained,
        "http_observation_not_obtained": (
            not_obtained
            if not_obtained is not None
            else max(discovered - obtained - incomplete, 0)
        ),
        "incomplete": incomplete,
        "ratios": {
            "http_observation_obtained_of_in_scope_discovered": ratio,
            "http_observation_obtained_of_submitted": ratio,
        },
    }


def _insert_operation(
    db,
    *,
    organization_id: UUID,
    target_id: UUID,
    user_id: UUID,
    status: str = "completed",
    source: str = "manual",
    ended_at: datetime | None = None,
) -> Operation:
    ended = ended_at or datetime.now(UTC)
    operation = Operation(
        organization_id=organization_id,
        target_id=target_id,
        created_by_user_id=user_id,
        status=status,
        source=source,
        testing_profile="safe_production",
        created_at=ended - timedelta(minutes=5),
        started_at=ended - timedelta(minutes=4),
        completed_at=ended if status == "completed" else None,
        failed_at=ended if status == "failed" else None,
        stopped_at=ended if status == "stopped" else None,
    )
    db.add(operation)
    db.flush()
    return operation


def _insert_coverage(
    db,
    operation: Operation,
    *,
    headline: str = "Frozen coverage headline.",
    surface: dict | None = None,
    header_evidence_unavailable: int = 0,
    discovery_truncated: bool = False,
    source: str = "frozen",
) -> OperationCoverageSummary:
    row = OperationCoverageSummary(
        operation_id=operation.id,
        organization_id=operation.organization_id,
        schema_version=1,
        capability_manifest_version=1,
        capability_snapshot={"version": 1},
        surface=surface or _surface(),
        http_evidence={
            "unit": "http_observation",
            "http_observations": 3,
            "headers_captured": 3,
            "header_evidence_unavailable": header_evidence_unavailable,
            "redirect_header_evidence_unusable": 0,
        },
        scope_boundaries={
            "configured_exclusions": [],
            "include_subdomains": True,
            "discovered_results_discarded": 0,
            "discovery_truncated": discovery_truncated,
            "truncated_from": None,
            "truncated_to": None,
            "gaps": [],
        },
        freshness={},
        headline=headline,
        operation_status_at_freeze=operation.status,
        source=source,
    )
    db.add(row)
    db.flush()
    return row


def _insert_diff(
    db,
    operation: Operation,
    *,
    comparability: str = "comparable",
    headline: str = "Frozen comparison headline.",
    baseline_operation_id: UUID | None = None,
    counts: dict | None = None,
    suppressed: bool = False,
    baseline_unavailable: bool = False,
    suppression_reason: str | None = None,
) -> OperationDiffSummary:
    row = OperationDiffSummary(
        operation_id=operation.id,
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        baseline_operation_id=baseline_operation_id,
        schema_version=1,
        comparability=comparability,
        comparison_snapshot={"schema_version": 1},
        changes=[],
        counts=counts or {},
        headline=headline,
        security_signal_baseline_unavailable=baseline_unavailable,
        security_signal_comparison_suppressed=suppressed,
        security_signal_suppression_reason=suppression_reason,
        operation_status_at_freeze=operation.status,
        source="frozen",
    )
    db.add(row)
    db.flush()
    return row


def _insert_report(
    db,
    operation: Operation,
    *,
    version: int = 1,
    origin: str = "manual",
    created_by_user_id: UUID | None = None,
    headline_status: str = "no_open_supported_findings",
    completeness: str = "complete",
) -> AssessmentReport:
    report = AssessmentReport(
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        operation_id=operation.id,
        created_by_user_id=created_by_user_id,
        generation_origin=origin,
        target_domain="overview.example",
        report_version=version,
        schema_version=1,
        snapshot_digest=f"{version:02x}" * 32,
        snapshot_json={"must_not_load": True, "content": {"huge": "nope"}},
        operation_status_at_generation=operation.status,
        assessment_completeness=completeness,
        headline_status=headline_status,
        findings_total=0,
        findings_open=0,
        findings_resolved=0,
        regression_count=0,
        coverage_limitation_count=0,
        severity_counts={},
    )
    db.add(report)
    db.flush()
    return report


def _insert_monitoring(
    db,
    *,
    organization_id: UUID,
    target_id: UUID,
    enabled: bool = True,
    frequency: str = "weekly",
    auto_generate_reports: bool = False,
    auto_deliver_reports: bool = False,
    auto_deliver_expires_in: str = "7d",
    recipients: tuple[str, ...] = (),
) -> MonitoringConfiguration:
    config = MonitoringConfiguration(
        organization_id=organization_id,
        target_id=target_id,
        enabled=enabled,
        frequency=frequency,
        auto_generate_reports=auto_generate_reports,
        auto_deliver_reports=auto_deliver_reports,
        auto_deliver_expires_in=auto_deliver_expires_in,
        next_run_at=datetime.now(UTC) + timedelta(days=1) if enabled else None,
    )
    db.add(config)
    db.flush()
    for email in recipients:
        db.add(
            MonitoringReportDeliveryRecipient(
                organization_id=organization_id,
                monitoring_configuration_id=config.id,
                target_id=target_id,
                email_normalized=email,
            )
        )
    db.flush()
    return config


def _insert_episode(
    db,
    *,
    operation: Operation,
    diff: OperationDiffSummary,
    semantic_key: str,
    episode_status: str = "open",
    alert_acknowledged: bool = False,
    with_alert: bool = True,
) -> AlertEpisode:
    episode = AlertEpisode(
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        semantic_key=semantic_key,
        alert_type="hsts_lost",
        category="security_regression",
        priority="medium",
        status=episode_status,
        closed_at=datetime.now(UTC) if episode_status == "closed" else None,
        opening_operation_id=operation.id,
        opening_diff_summary_id=diff.id,
        last_seen_operation_id=operation.id,
        last_seen_diff_summary_id=diff.id,
        opening_evidence={"hostname": "example"},
    )
    db.add(episode)
    db.flush()
    if with_alert:
        db.add(
            Alert(
                organization_id=operation.organization_id,
                target_id=operation.target_id,
                episode_id=episode.id,
                operation_id=operation.id,
                diff_summary_id=diff.id,
                alert_type="hsts_lost",
                category="security_regression",
                priority="medium",
                semantic_key=semantic_key,
                title="HSTS no longer observed",
                summary="Secret alert body that must not appear in the overview.",
                evidence={"leak_probe": "alert-evidence-should-not-appear"},
                acknowledged_at=datetime.now(UTC) if alert_acknowledged else None,
            )
        )
        db.flush()
    return episode


# --------------------------------------------------------------------------- RBAC


def test_member_and_admin_see_identical_active_org_overview(
    client, make_token, seed_user_a, dns_resolver, db_session, fake_clerk
):
    clerk_admin, clerk_org = seed_user_a
    admin_token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    target_id = _create_verified_target(client, admin_token, "rbac.example", dns_resolver)
    user_id, org_id = _ids(client, admin_token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    _insert_coverage(db_session, operation)
    db_session.flush()

    admin = _overview(client, admin_token)
    assert admin.status_code == 200, admin.text
    assert admin.json()["organization_id"] == str(org_id)
    assert admin.json()["sort"] == "domain_asc"

    member_token = _add_member(fake_clerk, make_token, clerk_org, "m@example.com")
    member = _overview(client, member_token)
    assert member.status_code == 200, member.text
    assert member.json()["items"] == admin.json()["items"]
    assert member.json()["summary"] == admin.json()["summary"]


def test_other_org_targets_never_appear(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _create_verified_target(client, token_a, "org-a-only.example", dns_resolver)
    _create_verified_target(client, token_b, "org-b-only.example", dns_resolver)

    domains_a = {row["domain"] for row in _rows(client, token_a)}
    domains_b = {row["domain"] for row in _rows(client, token_b)}
    assert domains_a == {"org-a-only.example"}
    assert domains_b == {"org-b-only.example"}
    assert _overview(client, token_a).json()["summary"]["target_count"] == 1
    assert _overview(client, token_b).json()["summary"]["target_count"] == 1


def test_unauthenticated_and_orgless_requests_are_rejected(
    client, make_token, seed_user_a
):
    clerk_a, _ = seed_user_a
    assert client.get(OVERVIEW).status_code == 401
    orgless = make_token(sub=clerk_a)
    assert _overview(client, orgless).status_code == 400


# ------------------------------------------------------------------- latest run


def test_latest_terminal_and_latest_completed_are_selected_independently(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    base = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    ok = _create_verified_target(client, token, "a-completed.example", dns_resolver)
    failed = _create_verified_target(client, token, "b-failed.example", dns_resolver)
    stopped = _create_verified_target(client, token, "c-stopped.example", dns_resolver)
    never = _create_verified_target(client, token, "d-never.example", dns_resolver)
    user_id, org_id = _ids(client, token)

    good = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(ok),
        user_id=user_id,
        ended_at=base,
    )
    older_a = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(failed),
        user_id=user_id,
        ended_at=base - timedelta(days=7),
    )
    late_failure = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(failed),
        user_id=user_id,
        status="failed",
        ended_at=base,
    )
    older_b = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(stopped),
        user_id=user_id,
        ended_at=base - timedelta(days=7),
    )
    late_stop = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(stopped),
        user_id=user_id,
        status="stopped",
        ended_at=base,
    )
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(never),
        user_id=user_id,
        status="queued",
        ended_at=base,
    )
    # Frozen evidence belongs to the older completed runs, not the later failures.
    _insert_coverage(db_session, older_a, headline="Older completed coverage A.")
    _insert_coverage(db_session, older_b, headline="Older completed coverage B.")
    db_session.flush()

    completed_row = _row_for(client, token, "a-completed.example")
    assert completed_row["latest_terminal"]["operation_id"] == str(good.id)
    assert completed_row["latest_terminal"]["status"] == "completed"
    assert completed_row["latest_completed"]["operation_id"] == str(good.id)
    assert REASON_LATEST_ASSESSMENT_INCOMPLETE not in _codes(completed_row)

    failed_row = _row_for(client, token, "b-failed.example")
    assert failed_row["latest_terminal"]["operation_id"] == str(late_failure.id)
    assert failed_row["latest_terminal"]["status"] == "failed"
    assert failed_row["latest_completed"]["operation_id"] == str(older_a.id)
    assert failed_row["coverage"]["headline"] == "Older completed coverage A."
    assert REASON_LATEST_ASSESSMENT_INCOMPLETE in _codes(failed_row)
    assert REASON_NO_COMPLETED_ASSESSMENT not in _codes(failed_row)

    stopped_row = _row_for(client, token, "c-stopped.example")
    assert stopped_row["latest_terminal"]["operation_id"] == str(late_stop.id)
    assert stopped_row["latest_terminal"]["status"] == "stopped"
    assert stopped_row["latest_completed"]["operation_id"] == str(older_b.id)
    assert stopped_row["coverage"]["headline"] == "Older completed coverage B."

    never_row = _row_for(client, token, "d-never.example")
    assert never_row["latest_terminal"] is None
    assert never_row["latest_completed"] is None
    assert never_row["coverage"] is None
    assert never_row["comparison"] is None
    assert never_row["signals"] is None
    assert never_row["latest_report"] is None
    assert REASON_NO_COMPLETED_ASSESSMENT in _codes(never_row)


# ------------------------------------------------------------------ frozen data


def test_frozen_evidence_is_immune_to_later_live_mutation(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, token, "frozen.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    baseline = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime(2026, 7, 1, tzinfo=UTC),
    )
    operation = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    coverage = _insert_coverage(db_session, operation, headline="Frozen at capture.")
    _insert_diff(
        db_session,
        operation,
        baseline_operation_id=baseline.id,
        counts={"candidate_new": 2, "candidate_no_longer_emitted": 1, "regressions": 1},
    )
    db_session.flush()

    before = _row_for(client, token, "frozen.example")
    assert before["signals"]["candidates_newly_emitted"] == 2
    assert before["signals"]["conservative_regressions"] == 1
    assert before["comparison"]["baseline_operation_id"] == str(baseline.id)
    assert before["comparison"]["baseline_completed_at"] is not None

    asset = Asset(
        organization_id=org_id,
        target_id=UUID(target_id),
        hostname="frozen.example",
        url="https://frozen.example",
    )
    db_session.add(asset)
    db_session.flush()
    candidate = SecurityCandidate(
        organization_id=org_id,
        operation_id=operation.id,
        asset_id=asset.id,
        candidate_type="missing_security_header",
        title="Live candidate",
        summary="Created after freeze",
        status="supported",
    )
    db_session.add(candidate)
    db_session.flush()
    db_session.add(
        Finding(
            organization_id=org_id,
            operation_id=operation.id,
            candidate_id=candidate.id,
            asset_id=asset.id,
            title="Live finding",
            summary="Must not rewrite the overview",
            severity="high",
            status="resolved",
            business_impact="n/a",
            remediation_guidance="n/a",
            resolved_at=datetime.now(UTC),
        )
    )
    db_session.flush()

    rebuilt = coverage_payload_from_snapshot(db_session, operation, coverage)
    assert rebuilt["headline"] != coverage.headline

    after = _row_for(client, token, "frozen.example")
    assert after["coverage"]["headline"] == "Frozen at capture."
    assert after["signals"] == before["signals"]
    assert after["comparison"] == before["comparison"]


def test_missing_coverage_is_null_and_unavailable_comparison_is_not_zero(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    bare = _create_verified_target(client, token, "a-bare.example", dns_resolver)
    scoped = _create_verified_target(client, token, "b-scope.example", dns_resolver)
    suppressed = _create_verified_target(client, token, "c-suppress.example", dns_resolver)
    user_id, org_id = _ids(client, token)

    _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(bare), user_id=user_id
    )
    scoped_op = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(scoped), user_id=user_id
    )
    _insert_coverage(db_session, scoped_op)
    _insert_diff(
        db_session,
        scoped_op,
        comparability="not_comparable_scope",
        headline="Scope changed; comparison not possible.",
        counts={"regressions": 99},
    )
    suppressed_op = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(suppressed), user_id=user_id
    )
    _insert_coverage(db_session, suppressed_op)
    _insert_diff(
        db_session,
        suppressed_op,
        comparability="comparable",
        suppressed=True,
        suppression_reason="Baseline capability manifest differs.",
        counts={"regressions": 5},
    )
    db_session.flush()

    bare_row = _row_for(client, token, "a-bare.example")
    assert bare_row["coverage"] is None
    assert bare_row["comparison"] is None
    assert bare_row["signals"] is None
    assert REASON_COVERAGE_UNAVAILABLE in _codes(bare_row)
    assert REASON_COMPARISON_UNAVAILABLE in _codes(bare_row)

    scope_row = _row_for(client, token, "b-scope.example")
    assert scope_row["comparison"]["comparability"] == "not_comparable_scope"
    assert scope_row["signals"] is None
    assert REASON_COMPARISON_UNAVAILABLE in _codes(scope_row)
    assert REASON_FROZEN_REGRESSION_PRESENT not in _codes(scope_row)

    suppressed_row = _row_for(client, token, "c-suppress.example")
    assert suppressed_row["comparison"]["security_signal_comparison_suppressed"] is True
    assert suppressed_row["signals"] is None
    assert REASON_COMPARISON_UNAVAILABLE in _codes(suppressed_row)
    assert REASON_FROZEN_REGRESSION_PRESENT not in _codes(suppressed_row)


# ------------------------------------------------------- attention + provenance


def test_attention_reason_provenance_is_explicit_and_correct(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, token, "prov.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    baseline = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime.now(UTC) - timedelta(days=60),
    )
    operation = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime.now(UTC) - timedelta(days=30),
    )
    _insert_coverage(
        db_session, operation, surface=_surface(obtained=1, discovered=3, incomplete=1)
    )
    diff = _insert_diff(
        db_session,
        operation,
        baseline_operation_id=baseline.id,
        counts={"regressions": 2},
    )
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        status="failed",
        ended_at=datetime.now(UTC) - timedelta(days=1),
    )
    _insert_monitoring(
        db_session, organization_id=org_id, target_id=UUID(target_id), frequency="daily"
    )
    _insert_episode(db_session, operation=operation, diff=diff, semantic_key="k1")
    db_session.flush()

    row = _row_for(client, token, "prov.example")
    provenance = {
        reason["code"]: reason["provenance"] for reason in row["attention_reasons"]
    }
    assert provenance[REASON_LATEST_ASSESSMENT_INCOMPLETE] == "operation_history"
    assert provenance[REASON_FROZEN_REGRESSION_PRESENT] == "frozen_assessment"
    assert provenance[REASON_COVERAGE_LIMITED] == "frozen_assessment"
    assert provenance[REASON_ACTIVE_ALERT_EPISODE] == "current_state"
    assert provenance[REASON_ASSESSMENT_STALE] == "current_state"
    assert all(
        value in {"operation_history", "frozen_assessment", "current_state"}
        for value in provenance.values()
    )
    assert all(reason["label"] for reason in row["attention_reasons"])
    assert len(provenance) >= 5


def test_no_completed_assessment_provenance_is_operation_history(
    client, make_token, seed_user_a, dns_resolver
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _create_verified_target(client, token, "empty.example", dns_resolver)
    row = _row_for(client, token, "empty.example")
    assert [
        (reason["code"], reason["provenance"]) for reason in row["attention_reasons"]
    ] == [(REASON_NO_COMPLETED_ASSESSMENT, "operation_history")]


def test_clean_target_has_no_reasons_and_response_carries_no_score(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, token, "clean.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    baseline = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime.now(UTC) - timedelta(days=2),
    )
    operation = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime.now(UTC),
    )
    _insert_coverage(db_session, operation, surface=_surface(obtained=3, discovered=3))
    _insert_diff(
        db_session,
        operation,
        baseline_operation_id=baseline.id,
        counts={"regressions": 0},
    )
    db_session.flush()

    response = _overview(client, token)
    row = response.json()["items"][0]
    assert row["attention_reasons"] == []
    assert row["signals"]["conservative_regressions"] == 0

    body = response.text.lower()
    for banned in (
        "risk_score",
        "posture_score",
        "security_score",
        "criticality",
        "grade",
        "severity_rank",
        "weight",
        "priority",
    ):
        assert banned not in body, banned


def test_assessment_prompts_are_suppressed_for_unverified_and_revoked_targets(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _create_target(client, token, "a-unverified.example")
    revoked = _create_verified_target(client, token, "b-revoked.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    _insert_monitoring(
        db_session, organization_id=org_id, target_id=UUID(revoked), frequency="daily"
    )
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(revoked),
        user_id=user_id,
        ended_at=datetime.now(UTC) - timedelta(days=90),
    )
    db_session.flush()
    assert (
        client.post(f"/v1/targets/{revoked}/revoke", headers=_auth(token)).status_code
        == 200
    )

    unverified_row = _row_for(client, token, "a-unverified.example")
    assert unverified_row["authorization_status"] == "unverified"
    assert REASON_NO_COMPLETED_ASSESSMENT not in _codes(unverified_row)
    assert unverified_row["attention_reasons"] == []

    revoked_row = _row_for(client, token, "b-revoked.example")
    assert revoked_row["authorization_status"] == "revoked"
    assert revoked_row["revoked_at"] is not None
    assert REASON_ASSESSMENT_STALE not in _codes(revoked_row)
    assert revoked_row["staleness"]["is_stale"] is None
    assert revoked_row["staleness"]["threshold_basis"] == "not_applicable"
    assert revoked_row["staleness"]["days_since_last_completed"] >= 89


# ---------------------------------------------------------------------- sorting


def test_server_orders_by_domain_asc_and_does_not_rank_by_attention(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    for domain in ("zebra.example", "alpha.example", "middle.example"):
        _create_verified_target(client, token, domain, dns_resolver)
    user_id, org_id = _ids(client, token)
    # alpha is clean; zebra has the most attention reasons. Order must ignore that.
    alpha = _row_for(client, token, "alpha.example")
    zebra_id = _row_for(client, token, "zebra.example")["target_id"]
    operation = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(alpha["target_id"]),
        user_id=user_id,
    )
    _insert_coverage(db_session, operation, surface=_surface(obtained=3, discovered=3))
    _insert_diff(db_session, operation, counts={"regressions": 0})
    zebra_op = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(zebra_id),
        user_id=user_id,
        status="failed",
    )
    _insert_episode(
        db_session,
        operation=zebra_op,
        diff=_insert_diff(db_session, zebra_op, counts={"regressions": 3}),
        semantic_key="zebra",
    )
    db_session.flush()

    domains = [row["domain"] for row in _rows(client, token)]
    assert domains == ["alpha.example", "middle.example", "zebra.example"]
    assert domains == sorted(domains)


# -------------------------------------------------------------------- staleness


def test_staleness_is_cadence_derived_only(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    daily_stale = _create_verified_target(client, token, "a-daily.example", dns_resolver)
    daily_fresh = _create_verified_target(client, token, "b-daily.example", dns_resolver)
    weekly_stale = _create_verified_target(client, token, "c-weekly.example", dns_resolver)
    weekly_fresh = _create_verified_target(client, token, "d-weekly.example", dns_resolver)
    disabled = _create_verified_target(client, token, "e-disabled.example", dns_resolver)
    unconfigured = _create_verified_target(client, token, "f-none.example", dns_resolver)
    _create_verified_target(client, token, "g-never.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    now = datetime.now(UTC)

    for target, frequency, enabled, age_days in (
        (daily_stale, "daily", True, 3),
        (daily_fresh, "daily", True, 1),
        (weekly_stale, "weekly", True, 20),
        (weekly_fresh, "weekly", True, 10),
        (disabled, "weekly", False, 40),
    ):
        _insert_monitoring(
            db_session,
            organization_id=org_id,
            target_id=UUID(target),
            enabled=enabled,
            frequency=frequency,
        )
        _insert_operation(
            db_session,
            organization_id=org_id,
            target_id=UUID(target),
            user_id=user_id,
            ended_at=now - timedelta(days=age_days),
        )
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(unconfigured),
        user_id=user_id,
        ended_at=now - timedelta(days=37),
    )
    db_session.flush()

    stale_daily = _row_for(client, token, "a-daily.example")["staleness"]
    assert stale_daily["is_stale"] is True
    assert stale_daily["threshold_days"] == 2
    assert stale_daily["threshold_basis"] == "monitoring_cadence"
    assert stale_daily["days_since_last_completed"] == 3
    assert REASON_ASSESSMENT_STALE in _codes(_row_for(client, token, "a-daily.example"))

    fresh_daily = _row_for(client, token, "b-daily.example")["staleness"]
    assert fresh_daily["is_stale"] is False
    assert fresh_daily["threshold_days"] == 2
    assert REASON_ASSESSMENT_STALE not in _codes(_row_for(client, token, "b-daily.example"))

    stale_weekly = _row_for(client, token, "c-weekly.example")["staleness"]
    assert stale_weekly["is_stale"] is True
    assert stale_weekly["threshold_days"] == 14

    fresh_weekly = _row_for(client, token, "d-weekly.example")["staleness"]
    assert fresh_weekly["is_stale"] is False
    assert fresh_weekly["threshold_days"] == 14

    # Monitoring disabled: no cadence defines expected freshness, so is_stale is unknown.
    off = _row_for(client, token, "e-disabled.example")
    assert off["staleness"]["is_stale"] is None
    assert off["staleness"]["threshold_days"] is None
    assert off["staleness"]["threshold_basis"] == "not_applicable"
    assert off["staleness"]["days_since_last_completed"] == 40
    assert REASON_ASSESSMENT_STALE not in _codes(off)

    none_configured = _row_for(client, token, "f-none.example")
    assert none_configured["staleness"]["is_stale"] is None
    assert none_configured["staleness"]["threshold_days"] is None
    assert none_configured["staleness"]["threshold_basis"] == "not_applicable"
    assert none_configured["staleness"]["days_since_last_completed"] == 37
    assert REASON_ASSESSMENT_STALE not in _codes(none_configured)

    unassessed = _row_for(client, token, "g-never.example")["staleness"]
    assert unassessed["is_stale"] is None
    assert unassessed["threshold_days"] is None
    assert unassessed["threshold_basis"] == "not_applicable"
    assert unassessed["days_since_last_completed"] is None


# ----------------------------------------------------------------------- alerts


def test_alert_episode_counts_and_acknowledgement_semantics(
    client, make_token, seed_user_a, dns_resolver, db_session, fake_clerk
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, token, "alerts.example", dns_resolver)
    quiet = _create_verified_target(client, token, "quiet.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    diff = _insert_diff(db_session, operation, counts={"regressions": 1})
    _insert_episode(db_session, operation=operation, diff=diff, semantic_key="open-1")
    _insert_episode(
        db_session,
        operation=operation,
        diff=diff,
        semantic_key="open-2",
        alert_acknowledged=True,
    )
    _insert_episode(
        db_session,
        operation=operation,
        diff=diff,
        semantic_key="closed-1",
        episode_status="closed",
    )
    _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(quiet), user_id=user_id
    )
    db_session.flush()

    noisy = _row_for(client, token, "alerts.example")
    assert noisy["alerts"]["active_episode_count"] == 2
    assert noisy["alerts"]["unacknowledged_active_episode_count"] == 1
    assert REASON_ACTIVE_ALERT_EPISODE in _codes(noisy)

    # Zero is a truthful current-state count, unlike absent frozen evidence.
    silent = _row_for(client, token, "quiet.example")
    assert silent["alerts"]["active_episode_count"] == 0
    assert silent["alerts"]["unacknowledged_active_episode_count"] == 0
    assert REASON_ACTIVE_ALERT_EPISODE not in _codes(silent)

    member_token = _add_member(fake_clerk, make_token, org_a, "reader@example.com")
    response = _overview(client, member_token)
    body = response.text
    assert "alert-evidence-should-not-appear" not in body
    assert "Secret alert body" not in body
    assert "HSTS no longer observed" not in body
    assert "episode_id" not in body
    assert "semantic_key" not in body


def test_summary_counts_active_alert_targets_org_wide(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    first = _create_verified_target(client, token, "alert-a.example", dns_resolver)
    second = _create_verified_target(client, token, "alert-b.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    for target in (first, second):
        operation = _insert_operation(
            db_session, organization_id=org_id, target_id=UUID(target), user_id=user_id
        )
        diff = _insert_diff(db_session, operation)
        _insert_episode(
            db_session, operation=operation, diff=diff, semantic_key=f"k-{target}"
        )
    db_session.flush()
    summary = _overview(client, token, page_size=1).json()["summary"]
    assert summary["targets_with_active_alert_episode"] == 2
    assert summary["scope"] == "organization"


# ---------------------------------------------------------------------- reports


def test_report_metadata_versions_and_origins(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    manual = _create_verified_target(client, token, "a-manual.example", dns_resolver)
    auto = _create_verified_target(client, token, "b-auto.example", dns_resolver)
    none = _create_verified_target(client, token, "c-noreport.example", dns_resolver)
    user_id, org_id = _ids(client, token)

    manual_op = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(manual), user_id=user_id
    )
    _insert_report(db_session, manual_op, version=1, created_by_user_id=user_id)
    _insert_report(db_session, manual_op, version=2, created_by_user_id=user_id)
    _insert_report(
        db_session,
        manual_op,
        version=3,
        created_by_user_id=user_id,
        headline_status="action_required",
    )
    auto_op = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(auto), user_id=user_id
    )
    _insert_report(
        db_session,
        auto_op,
        version=1,
        origin="scheduled_automatic",
        created_by_user_id=None,
        headline_status="assessment_incomplete",
        completeness="incomplete",
    )
    _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(none), user_id=user_id
    )
    db_session.flush()

    manual_row = _row_for(client, token, "a-manual.example")["latest_report"]
    assert manual_row["report_version"] == 3
    assert manual_row["version_count"] == 3
    assert manual_row["generation_origin"] == "manual"
    assert manual_row["headline_status"] == "action_required"
    assert manual_row["headline_label"] == "Action Required"
    assert "findings_open" not in manual_row
    assert "severity_counts" not in manual_row

    auto_row = _row_for(client, token, "b-auto.example")["latest_report"]
    assert auto_row["generation_origin"] == "scheduled_automatic"
    assert auto_row["headline_label"] == "Assessment Incomplete"
    assert auto_row["assessment_completeness"] == "incomplete"

    assert _row_for(client, token, "c-noreport.example")["latest_report"] is None


# ------------------------------------------------------------ automation privacy


def test_recipient_addresses_are_never_returned_to_members_or_admins(
    client, make_token, seed_user_a, dns_resolver, db_session, fake_clerk
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(client, admin_token, "auto.example", dns_resolver)
    _, org_id = _ids(client, admin_token)
    _insert_monitoring(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        frequency="daily",
        auto_generate_reports=True,
        auto_deliver_reports=True,
        auto_deliver_expires_in="24h",
        recipients=("secops@customer.example", "ciso@customer.example"),
    )
    db_session.flush()

    member_token = _add_member(fake_clerk, make_token, org_a, "member@example.com")
    for token in (admin_token, member_token):
        response = _overview(client, token)
        assert response.status_code == 200, response.text
        automation = response.json()["items"][0]["automation"]
        assert automation["monitoring_enabled"] is True
        assert automation["frequency"] == "daily"
        assert automation["auto_generate_reports"] is True
        assert automation["auto_deliver_reports"] is True
        assert automation["auto_deliver_expires_in"] == "24h"
        assert automation["delivery_recipient_count"] == 2
        assert "recipients" not in automation
        body = response.text
        assert "secops@customer.example" not in body
        assert "ciso@customer.example" not in body
        assert "email_normalized" not in body


def test_unconfigured_monitoring_reports_defaults_without_inventing_a_cadence(
    client, make_token, seed_user_a, dns_resolver
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _create_verified_target(client, token, "nomon.example", dns_resolver)
    automation = _row_for(client, token, "nomon.example")["automation"]
    assert automation["monitoring_enabled"] is False
    assert automation["frequency"] is None
    assert automation["auto_generate_reports"] is False
    assert automation["auto_deliver_reports"] is False
    assert automation["auto_deliver_expires_in"] is None
    assert automation["delivery_recipient_count"] == 0


# ------------------------------------------------------------------- pagination


def test_pagination_is_deterministic_with_no_duplicates_or_gaps(
    client, make_token, seed_user_a, dns_resolver
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    domains = [f"page-{index:02d}.example" for index in range(7)]
    for domain in reversed(domains):
        _create_verified_target(client, token, domain, dns_resolver)

    collected: list[str] = []
    cursor = None
    pages = 0
    while True:
        params = {"page_size": 3}
        if cursor:
            params["cursor"] = cursor
        body = _overview(client, token, **params).json()
        collected.extend(row["domain"] for row in body["items"])
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            break
        assert pages < 10

    assert collected == domains
    assert len(collected) == len(set(collected))
    assert pages == 3


def test_malformed_cursor_is_400_and_page_size_is_capped(
    client, make_token, seed_user_a, dns_resolver
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _create_verified_target(client, token, "cursor.example", dns_resolver)

    for bad in ("!!!not-base64!!!", "Zm9vYmFy", "djJ8YXxi"):
        response = _overview(client, token, cursor=bad)
        assert response.status_code == 400, (bad, response.text)
        assert response.json()["error"]["message"] == "Invalid security overview cursor"

    assert _overview(client, token, cursor="").status_code == 200
    assert _overview(client, token, page_size=MAX_PAGE_SIZE).status_code == 200
    assert _overview(client, token, page_size=MAX_PAGE_SIZE + 1).status_code == 422
    assert _overview(client, token, page_size=0).status_code == 422


def test_cursor_minted_in_another_org_cannot_widen_visibility(
    client, make_token, seed_user_a, seed_user_b, dns_resolver
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _create_verified_target(client, token_a, "aaa-secret.example", dns_resolver)
    target_b = _create_verified_target(client, token_b, "zzz-other.example", dns_resolver)

    foreign = encode_overview_cursor(
        domain="aaa-secret.example", target_id=UUID(target_b)
    )
    response = _overview(client, token_b, cursor=foreign)
    assert response.status_code == 200, response.text
    assert {row["domain"] for row in response.json()["items"]} == {"zzz-other.example"}
    assert response.json()["summary"]["target_count"] == 1


# ---------------------------------------------------------------------- summary


def test_organization_summary_counts_only_verified_targets_without_completed_runs(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    verified_empty = _create_verified_target(
        client, token, "a-verified-empty.example", dns_resolver
    )
    verified_done = _create_verified_target(
        client, token, "b-verified-done.example", dns_resolver
    )
    _create_target(client, token, "c-unverified.example")
    revoked = _create_verified_target(client, token, "d-revoked.example", dns_resolver)
    user_id, org_id = _ids(client, token)
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(verified_done),
        user_id=user_id,
    )
    # An incomplete run does not satisfy "has a completed assessment".
    _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(verified_empty),
        user_id=user_id,
        status="failed",
    )
    db_session.flush()
    assert (
        client.post(f"/v1/targets/{revoked}/revoke", headers=_auth(token)).status_code
        == 200
    )

    summary = _overview(client, token, page_size=1).json()["summary"]
    assert summary["target_count"] == 4
    assert summary["verified_targets_without_completed_assessment"] == 1
    assert "targets_with_attention" not in summary
    assert "targets_with_frozen_regressions" not in summary
    assert "targets_without_completed_assessment" not in summary


def test_empty_organization_returns_empty_page_and_zero_summary(
    client, make_token, seed_user_a
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    body = _overview(client, token).json()
    assert body["items"] == []
    assert body["next_cursor"] is None
    assert body["summary"] == {
        "scope": "organization",
        "target_count": 0,
        "verified_targets_without_completed_assessment": 0,
        "targets_with_active_alert_episode": 0,
    }


# ------------------------------------------------------------------ performance


def test_query_count_is_bounded_and_heavy_columns_are_never_selected(
    client, make_token, seed_user_a, dns_resolver, db_session, engine
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    user_id, org_id = _ids(client, token)
    target_ids: list[str] = []
    for index in range(12):
        target_id = _create_verified_target(
            client, token, f"perf-{index:02d}.example", dns_resolver
        )
        target_ids.append(target_id)
        baseline = _insert_operation(
            db_session,
            organization_id=org_id,
            target_id=UUID(target_id),
            user_id=user_id,
            ended_at=datetime.now(UTC) - timedelta(days=10),
        )
        operation = _insert_operation(
            db_session,
            organization_id=org_id,
            target_id=UUID(target_id),
            user_id=user_id,
            ended_at=datetime.now(UTC) - timedelta(days=1),
        )
        _insert_coverage(db_session, operation)
        diff = _insert_diff(
            db_session,
            operation,
            baseline_operation_id=baseline.id,
            counts={"regressions": 1},
        )
        _insert_report(db_session, operation, version=1, created_by_user_id=user_id)
        _insert_monitoring(
            db_session,
            organization_id=org_id,
            target_id=UUID(target_id),
            recipients=(f"r{index}@customer.example",),
        )
        _insert_episode(
            db_session, operation=operation, diff=diff, semantic_key=f"perf-{index}"
        )
    db_session.flush()

    def _count(page_size: int) -> tuple[int, str]:
        statements: list[str] = []

        def _capture(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", _capture)
        try:
            response = _overview(client, token, page_size=page_size)
        finally:
            event.remove(engine, "before_cursor_execute", _capture)
        assert response.status_code == 200, response.text
        assert len(response.json()["items"]) == page_size
        selects = [
            item for item in statements if item.lstrip().lower().startswith("select")
        ]
        return len(selects), " ".join(statements).lower()

    one, _ = _count(1)
    twelve, joined = _count(12)

    # Constant across page sizes proves no per-target query. The fixed remainder above
    # the service budget is the shared authentication dependency path.
    assert twelve == one, (one, twelve)
    assert twelve <= 20, twelve
    assert "snapshot_json" not in joined
    assert "capability_snapshot" not in joined
    assert "comparison_snapshot" not in joined
    assert "email_normalized" not in joined
    for table in (
        "findings",
        "retest_attempts",
        "validation_attempts",
        "security_candidates",
        "discovery_observations",
        "assessment_report_shares",
        "audit_events",
    ):
        assert re.search(rf"\b(from|join)\s+{table}\b", joined) is None, table

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    try:
        organization = session.get(Organization, org_id)
        service_statements: list[str] = []

        def _capture_service(conn, cursor, statement, parameters, context, executemany):
            service_statements.append(statement)

        event.listen(engine, "before_cursor_execute", _capture_service)
        try:
            payload = list_security_overview(
                session,
                organization=organization,
                email_delivery_enabled=False,
                page_size=12,
            )
        finally:
            event.remove(engine, "before_cursor_execute", _capture_service)
        assert len(payload.items) == 12
        service_selects = [
            item
            for item in service_statements
            if item.lstrip().lower().startswith("select")
        ]
        # 1 target page + 3 organization summary + 2 latest-operation + 4 frozen
        # (coverage, diff, reports, baseline) + 2 monitoring + 1 alert aggregate.
        assert len(service_selects) == 13, len(service_selects)
        service_sql = " ".join(service_statements).lower()
        assert "snapshot_json" not in service_sql
        assert "email_normalized" not in service_sql
    finally:
        session.close()


def test_overview_read_creates_no_audit_event(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _create_verified_target(client, token, "audit.example", dns_resolver)
    before = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert _overview(client, token).status_code == 200
    after = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert after == before

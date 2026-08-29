from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker

from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.report import AssessmentReport
from app.services.assessment_history import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    encode_history_cursor,
)
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.coverage import coverage_payload_from_snapshot


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


def _ids(client, token: str) -> tuple[UUID, UUID]:
    me = client.get("/v1/me", headers=_auth(token)).json()
    return UUID(me["id"]), UUID(me["active_organization_id"])


def _surface(*, obtained: int = 2, discovered: int = 3, incomplete: int = 0) -> dict:
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
        "http_observation_not_obtained": max(discovered - obtained - incomplete, 0),
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
    error_code: str | None = None,
    error_message: str | None = None,
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
        error_code=error_code,
        error_message=error_message,
    )
    db.add(operation)
    db.flush()
    return operation


def _insert_coverage(
    db,
    operation: Operation,
    *,
    headline: str,
    surface: dict | None = None,
    capability_manifest_version: int = 1,
    source: str = "frozen",
) -> OperationCoverageSummary:
    row = OperationCoverageSummary(
        operation_id=operation.id,
        organization_id=operation.organization_id,
        schema_version=1,
        capability_manifest_version=capability_manifest_version,
        capability_snapshot={"version": capability_manifest_version},
        surface=surface or _surface(),
        http_evidence={
            "unit": "http_observation",
            "http_observations": 2,
            "headers_captured": 2,
            "header_evidence_unavailable": 0,
            "redirect_header_evidence_unusable": 0,
        },
        scope_boundaries={
            "configured_exclusions": [],
            "include_subdomains": True,
            "discovered_results_discarded": 0,
            "discovery_truncated": False,
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
    comparability: str,
    headline: str,
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
    version: int,
    origin: str,
    created_by_user_id: UUID | None,
    findings_open: int = 0,
    headline_status: str = "no_open_supported_findings",
    completeness: str = "complete",
) -> AssessmentReport:
    report = AssessmentReport(
        organization_id=operation.organization_id,
        target_id=operation.target_id,
        operation_id=operation.id,
        created_by_user_id=created_by_user_id,
        generation_origin=origin,
        target_domain="history.example",
        report_version=version,
        schema_version=1,
        snapshot_digest=f"{version:02x}" * 32,
        snapshot_json={"must_not_load": True, "content": {"huge": "nope"}},
        operation_status_at_generation=operation.status,
        assessment_completeness=completeness,
        headline_status=headline_status,
        findings_total=findings_open,
        findings_open=findings_open,
        findings_resolved=0,
        regression_count=0,
        coverage_limitation_count=0,
        severity_counts={"medium": findings_open} if findings_open else {},
    )
    db.add(report)
    db.flush()
    return report


def _history(client, token: str, target_id: str, **params):
    return client.get(
        f"/v1/targets/{target_id}/assessment-history",
        headers=_auth(token),
        params=params or None,
    )


def test_member_and_admin_can_read_own_org_history(
    client, make_token, seed_user_a, dns_resolver, db_session, fake_clerk
):
    clerk_admin, clerk_org = seed_user_a
    admin_token = make_token(sub=clerk_admin, org_id=clerk_org, org_role="org:admin")
    target_id = _create_verified_target(
        client, admin_token, "hist-rbac.example", dns_resolver
    )
    user_id, org_id = _ids(client, admin_token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    _insert_coverage(db_session, operation, headline="Frozen coverage")
    db_session.flush()

    admin = _history(client, admin_token, target_id)
    assert admin.status_code == 200, admin.text
    assert admin.json()["target_id"] == target_id
    assert len(admin.json()["items"]) == 1

    clerk_member = f"user_{uuid4().hex}"
    fake_clerk.users[clerk_member] = ClerkUserInfo(
        clerk_user_id=clerk_member,
        email="member-hist@example.com",
        name="Member",
        email_verified=True,
    )
    fake_clerk.memberships[clerk_member] = [
        ClerkOrgMembership(clerk_org_id=clerk_org, org_name="Org A", role="org:member")
    ]
    member_token = make_token(sub=clerk_member, org_id=clerk_org, org_role="org:member")
    member = _history(client, member_token, target_id)
    assert member.status_code == 200, member.text
    assert [row["operation_id"] for row in member.json()["items"]] == [
        str(operation.id)
    ]


def test_cross_org_history_is_404(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    target_id = _create_verified_target(
        client, token_a, "hist-xorg.example", dns_resolver
    )
    user_id, org_id = _ids(client, token_a)
    _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    db_session.flush()
    missing = _history(client, token_b, target_id)
    assert missing.status_code == 404
    assert missing.json()["error"]["message"] == "Target not found"


def test_unauthenticated_history_rejected(client, make_token, seed_user_a, dns_resolver):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-unauth.example", dns_resolver
    )
    response = client.get(f"/v1/targets/{target_id}/assessment-history")
    assert response.status_code == 401


def test_pagination_newest_first_stable_cursor_and_tie_break(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-page.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    base = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
    same_time = base + timedelta(days=3)
    operations: list[Operation] = []
    for index, status in enumerate(
        ("completed", "failed", "stopped", "completed", "completed")
    ):
        ended = same_time if index >= 3 else base + timedelta(days=index)
        operations.append(
            _insert_operation(
                db_session,
                organization_id=org_id,
                target_id=UUID(target_id),
                user_id=user_id,
                status=status,
                ended_at=ended,
                error_code="discovery_failed" if status == "failed" else None,
            )
        )
    queued = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        status="queued",
        ended_at=base + timedelta(days=10),
    )
    queued.status = "queued"
    queued.completed_at = None
    queued.failed_at = None
    queued.stopped_at = None
    db_session.flush()

    first = _history(client, token, target_id, page_size=2)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["page_size"] == 2
    assert body["next_cursor"]
    page1 = [row["operation_id"] for row in body["items"]]
    assert len(page1) == 2

    second = _history(
        client, token, target_id, page_size=2, cursor=body["next_cursor"]
    )
    page2 = [row["operation_id"] for row in second.json()["items"]]
    third = _history(
        client, token, target_id, page_size=2, cursor=second.json()["next_cursor"]
    )
    page3 = [row["operation_id"] for row in third.json()["items"]]
    assert third.json()["next_cursor"] is None

    combined = page1 + page2 + page3
    assert len(combined) == 5
    assert len(set(combined)) == 5
    assert str(queued.id) not in combined

    expected = sorted(
        operations,
        key=lambda row: (
            row.completed_at or row.failed_at or row.stopped_at or row.created_at,
            row.id,
        ),
        reverse=True,
    )
    assert combined == [str(row.id) for row in expected]
    same_time_ids = [str(row.id) for row in operations[3:]]
    same_time_order = [item for item in combined if item in same_time_ids]
    assert same_time_order == sorted(same_time_ids, reverse=True)


def test_malformed_cursor_and_page_size_limits(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-cursor.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    db_session.flush()

    defaulted = _history(client, token, target_id)
    assert defaulted.json()["page_size"] == DEFAULT_PAGE_SIZE

    oversized = _history(client, token, target_id, page_size=MAX_PAGE_SIZE + 1)
    assert oversized.status_code == 422

    empty = _history(client, token, target_id, cursor="")
    assert empty.status_code == 200
    for raw in ("%%%", "not-a-cursor", "YQ", "djJ8YmFk"):
        response = _history(client, token, target_id, cursor=raw)
        assert response.status_code == 400, raw
        assert response.json()["error"]["message"] == "Invalid assessment history cursor"

    listed = _history(client, token, target_id).json()["items"]
    last = listed[-1]
    past_last = encode_history_cursor(
        ended_at=datetime.fromisoformat(last["ended_at"]),
        operation_id=UUID(last["operation_id"]),
    )
    exhausted = _history(client, token, target_id, cursor=past_last)
    assert exhausted.status_code == 200
    assert exhausted.json()["items"] == []
    assert exhausted.json()["next_cursor"] is None


def test_frozen_history_ignores_later_live_mutations(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-frozen.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    coverage = _insert_coverage(
        db_session,
        operation,
        headline="Frozen coverage headline must survive live follow-up.",
    )
    _insert_diff(
        db_session,
        operation,
        comparability="comparable",
        headline="Frozen comparable headline.",
        counts={
            "candidate_new": 2,
            "candidate_no_longer_emitted": 1,
            "regressions": 1,
            "regression_hsts_lost": 1,
        },
    )
    db_session.flush()

    before = _history(client, token, target_id).json()["items"][0]
    assert before["coverage"]["headline"] == coverage.headline
    assert before["signals"]["candidates_newly_emitted"] == 2
    assert before["signals"]["conservative_regressions"] == 1

    asset = Asset(
        organization_id=org_id,
        target_id=UUID(target_id),
        hostname="hist-frozen.example",
        url="https://hist-frozen.example",
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
    finding = Finding(
        organization_id=org_id,
        operation_id=operation.id,
        candidate_id=candidate.id,
        asset_id=asset.id,
        title="Live finding",
        summary="Must not rewrite timeline",
        severity="high",
        status="resolved",
        business_impact="n/a",
        remediation_guidance="n/a",
        resolved_at=datetime.now(UTC),
    )
    db_session.add(finding)
    db_session.flush()

    rebuilt = coverage_payload_from_snapshot(db_session, operation, coverage)
    assert rebuilt["headline"] != coverage.headline
    assert rebuilt["follow_up"]["findings"] == 1

    after = _history(client, token, target_id).json()["items"][0]
    assert after["coverage"]["headline"] == coverage.headline
    assert after["comparison"]["headline"] == "Frozen comparable headline."
    assert after["signals"] == before["signals"]
    assert after["coverage"]["http_observation_obtained"] == 2


def test_missing_comparison_is_unavailable_not_zero(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-nodiff.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    _insert_coverage(db_session, operation, headline="Coverage only")
    db_session.flush()
    row = _history(client, token, target_id).json()["items"][0]
    assert row["comparison"] is None
    assert row["signals"] is None
    assert row["surface_changes"] is None
    assert row["coverage"] is not None


def test_baseline_states_are_frozen_and_explicit(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-base.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    t0 = datetime(2026, 7, 1, tzinfo=UTC)
    first = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=t0,
    )
    later = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=t0 + timedelta(days=2),
    )
    _insert_diff(
        db_session,
        first,
        comparability="no_baseline",
        headline="No previous comparable completed operation.",
    )
    _insert_diff(
        db_session,
        later,
        comparability="comparable",
        headline="Compared to frozen baseline.",
        baseline_operation_id=first.id,
        counts={
            "candidate_new": 3,
            "hostname_newly_discovered": 1,
            "regressions": 0,
        },
    )
    inserted_after_freeze = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=t0 + timedelta(days=1),
    )
    _insert_diff(
        db_session,
        inserted_after_freeze,
        comparability="no_baseline",
        headline="Inserted later; must not become later's baseline.",
    )
    db_session.flush()

    items = {row["operation_id"]: row for row in _history(client, token, target_id).json()["items"]}
    assert items[str(first.id)]["comparison"]["comparability"] == "no_baseline"
    assert items[str(first.id)]["signals"] is None
    assert items[str(first.id)]["surface_changes"] is None
    compared = items[str(later.id)]
    assert compared["comparison"]["baseline_operation_id"] == str(first.id)
    assert compared["comparison"]["baseline_completed_at"] is not None
    assert compared["signals"]["candidates_newly_emitted"] == 3
    assert compared["surface_changes"]["hostnames_newly_discovered"] == 1


def test_capability_change_and_suppression_null_signals(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-cap.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    _insert_coverage(
        db_session,
        operation,
        headline="Capability changed",
        capability_manifest_version=2,
    )
    _insert_diff(
        db_session,
        operation,
        comparability="partial_capability",
        headline="Capability manifest version changed.",
        counts={
            "candidate_new": 9,
            "regressions": 4,
            "hostname_newly_discovered": 1,
            "http_observation_lost": 1,
        },
        suppressed=True,
        suppression_reason="Capability manifest version differs.",
    )
    db_session.flush()
    row = _history(client, token, target_id).json()["items"][0]
    assert row["comparison"]["comparability"] == "partial_capability"
    assert row["comparison"]["security_signal_comparison_suppressed"] is True
    assert row["signals"] is None
    assert row["surface_changes"]["http_observation_lost"] == 1
    assert "0 regressions" not in row["comparison"]["headline"]


def test_incomplete_operations_stay_explicit(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-inc.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    _failed = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        status="failed",
        error_code="discovery_failed",
        error_message="probe failed",
    )
    stopped = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        status="stopped",
        ended_at=datetime.now(UTC) - timedelta(hours=1),
    )
    _insert_coverage(
        db_session,
        stopped,
        headline="Partial coverage after stop",
        surface=_surface(obtained=1, discovered=4, incomplete=3),
    )
    _insert_diff(
        db_session,
        stopped,
        comparability="current_incomplete",
        headline="This run did not complete.",
        counts={"regressions": 0, "candidate_new": 0},
    )
    db_session.flush()

    items = {row["status"]: row for row in _history(client, token, target_id).json()["items"]}
    assert items["failed"]["completeness"] == "incomplete"
    assert items["failed"]["coverage"] is None
    assert items["failed"]["comparison"] is None
    assert items["failed"]["signals"] is None
    assert items["failed"]["error_code"] == "discovery_failed"
    assert items["stopped"]["completeness"] == "incomplete"
    assert items["stopped"]["coverage"]["incomplete_hostnames"] == 3
    assert items["stopped"]["signals"] is None
    blob = str(items)
    assert "no findings" not in blob.lower()
    assert "no vulnerabilities" not in blob.lower()


def test_report_latest_version_count_and_origins(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-rep.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    none = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        ended_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    one = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        source="scheduled",
        ended_at=datetime(2026, 8, 2, tzinfo=UTC),
    )
    many = _insert_operation(
        db_session,
        organization_id=org_id,
        target_id=UUID(target_id),
        user_id=user_id,
        source="scheduled",
        ended_at=datetime(2026, 8, 3, tzinfo=UTC),
    )
    _insert_report(
        db_session, one, version=1, origin="manual", created_by_user_id=user_id
    )
    _insert_report(
        db_session,
        many,
        version=1,
        origin="scheduled_automatic",
        created_by_user_id=None,
        findings_open=1,
        headline_status="action_required",
    )
    latest = _insert_report(
        db_session,
        many,
        version=3,
        origin="scheduled_automatic",
        created_by_user_id=None,
        findings_open=2,
        headline_status="action_required",
    )
    _insert_report(
        db_session,
        many,
        version=2,
        origin="manual",
        created_by_user_id=user_id,
        findings_open=1,
        headline_status="attention_recommended",
    )
    db_session.flush()

    items = {
        row["operation_id"]: row for row in _history(client, token, target_id).json()["items"]
    }
    assert items[str(none.id)]["latest_report"] is None
    assert items[str(one.id)]["source"] == "scheduled"
    assert items[str(one.id)]["latest_report"]["generation_origin"] == "manual"
    assert items[str(one.id)]["latest_report"]["report_version"] == 1
    assert items[str(one.id)]["latest_report"]["version_count"] == 1
    many_report = items[str(many.id)]["latest_report"]
    assert many_report["id"] == str(latest.id)
    assert many_report["report_version"] == 3
    assert many_report["version_count"] == 3
    assert many_report["generation_origin"] == "scheduled_automatic"
    assert many_report["headline_label"] == "Action Required"
    assert many_report["findings_open"] == 2


def test_history_query_count_is_bounded_and_skips_snapshot_json(
    client, make_token, seed_user_a, dns_resolver, engine, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-perf.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    first = None
    for index in range(8):
        operation = _insert_operation(
            db_session,
            organization_id=org_id,
            target_id=UUID(target_id),
            user_id=user_id,
            ended_at=datetime(2026, 8, 1, tzinfo=UTC) + timedelta(days=index),
        )
        if first is None:
            first = operation
        _insert_coverage(db_session, operation, headline=f"Coverage {index}")
        _insert_diff(
            db_session,
            operation,
            comparability="comparable" if index else "no_baseline",
            headline="diff",
            baseline_operation_id=first.id if index else None,
            counts={"candidate_new": index, "regressions": 0},
        )
        _insert_report(
            db_session,
            operation,
            version=1,
            origin="manual",
            created_by_user_id=user_id,
        )
        _insert_report(
            db_session,
            operation,
            version=2,
            origin="manual",
            created_by_user_id=user_id,
        )
    db_session.flush()

    statements: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        response = _history(client, token, target_id, page_size=8)
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert response.status_code == 200, response.text
    joined = " ".join(statements).lower()
    assert "snapshot_json" not in joined
    for table in (
        "findings",
        "retest_attempts",
        "validation_attempts",
        "security_candidates",
        "discovery_observations",
    ):
        assert re.search(rf"\b(from|join)\s+{table}\b", joined) is None, table
    selects = [item for item in statements if item.lstrip().lower().startswith("select")]
    assert len(selects) <= 16

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    try:
        from app.models.target import AuthorizedTarget
        from app.services.assessment_history import list_assessment_history

        target = session.get(AuthorizedTarget, UUID(target_id))
        service_statements: list[str] = []

        def _capture_service(conn, cursor, statement, parameters, context, executemany):
            service_statements.append(statement)

        event.listen(engine, "before_cursor_execute", _capture_service)
        try:
            payload = list_assessment_history(session, target=target, page_size=8)
        finally:
            event.remove(engine, "before_cursor_execute", _capture_service)
        assert len(payload.items) == 8
        service_selects = [
            item
            for item in service_statements
            if item.lstrip().lower().startswith("select")
        ]
        assert 3 <= len(service_selects) <= 5
        assert "snapshot_json" not in " ".join(service_statements).lower()
    finally:
        session.close()


def test_history_read_creates_no_audit_event(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-audit.example", dns_resolver
    )
    before = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert _history(client, token, target_id).status_code == 200
    after = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert after == before


def test_empty_target_history(client, make_token, seed_user_a, dns_resolver):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-empty.example", dns_resolver
    )
    body = _history(client, token, target_id).json()
    assert body["items"] == []
    assert body["next_cursor"] is None


def test_recovered_snapshot_and_probe_language_are_preserved(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    target_id = _create_verified_target(
        client, token, "hist-probe.example", dns_resolver
    )
    user_id, org_id = _ids(client, token)
    operation = _insert_operation(
        db_session, organization_id=org_id, target_id=UUID(target_id), user_id=user_id
    )
    _insert_coverage(
        db_session,
        operation,
        headline="One hostname produced probe_no_result; cause is not distinguished.",
        source="recovered",
    )
    db_session.flush()
    row = _history(client, token, target_id).json()["items"][0]
    assert row["coverage"]["source"] == "recovered"
    assert "probe_no_result" in row["coverage"]["headline"]
    assert "unreachable" not in row["coverage"]["headline"]

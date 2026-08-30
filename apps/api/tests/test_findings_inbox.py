from __future__ import annotations

import pathlib
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import event, func, select
from sqlalchemy.orm import sessionmaker

from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.candidate import SecurityCandidate
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.organization import Organization
from app.models.retest import RetestAttempt
from app.models.target import AuthorizedTarget
from app.models.validation import ValidationAttempt
from app.schemas.findings_inbox import TARGET_AUTHORIZATION_STATUSES
from app.services.clerk import ClerkOrgMembership, ClerkUserInfo
from app.services.findings_inbox import (
    MAX_PAGE_SIZE,
    REASON_AWAITING_RETEST,
    REASON_LATEST_RETEST_ERROR,
    REASON_LATEST_RETEST_FAILED,
    REASON_LATEST_RETEST_INCONCLUSIVE,
    REASON_REMEDIATION_NOT_STARTED,
    REASON_TARGET_NOT_VERIFIED,
    encode_inbox_cursor,
    list_findings_inbox,
)

INBOX = "/v1/findings/inbox"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _inbox(client, token: str, **params):
    return client.get(INBOX, headers=_auth(token), params=params or None)


def _rows(client, token: str, **params) -> list[dict]:
    response = _inbox(client, token, **params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _row_for(client, token: str, finding_id, **params) -> dict:
    wanted = str(finding_id)
    for row in _rows(client, token, **params):
        if row["finding_id"] == wanted:
            return row
    raise AssertionError(f"{wanted} not present in inbox")


def _codes(row: dict) -> set[str]:
    return {reason["code"] for reason in row["attention_reasons"]}


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


def _insert_operation(
    db, *, organization_id: UUID, target_id: UUID, user_id: UUID
) -> Operation:
    operation = Operation(
        organization_id=organization_id,
        target_id=target_id,
        created_by_user_id=user_id,
        status="completed",
        source="manual",
        created_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )
    db.add(operation)
    db.flush()
    return operation


def _insert_asset(db, *, organization_id: UUID, target_id: UUID, hostname: str) -> Asset:
    asset = Asset(
        organization_id=organization_id,
        target_id=target_id,
        hostname=hostname,
        url=f"https://{hostname}",
    )
    db.add(asset)
    db.flush()
    return asset


def _insert_candidate(
    db,
    *,
    organization_id: UUID,
    operation: Operation,
    asset: Asset,
    candidate_type: str = "staging_dev_exposed",
    status: str = "supported",
) -> SecurityCandidate:
    candidate = SecurityCandidate(
        organization_id=organization_id,
        operation_id=operation.id,
        asset_id=asset.id,
        candidate_type=candidate_type,
        title=f"{candidate_type} on {asset.hostname}",
        summary="Deterministic rule matched.",
        status=status,
        evidence={"reasons": ["hostname_marker"], "observation_ids": []},
    )
    db.add(candidate)
    db.flush()
    return candidate


def _insert_finding(
    db,
    *,
    organization_id: UUID,
    operation: Operation,
    asset: Asset,
    candidate: SecurityCandidate,
    severity: str = "medium",
    status: str = "open",
    created_at: datetime | None = None,
    resolved_at: datetime | None = None,
) -> Finding:
    moment = created_at or datetime.now(UTC)
    finding = Finding(
        organization_id=organization_id,
        operation_id=operation.id,
        candidate_id=candidate.id,
        asset_id=asset.id,
        title=candidate.title,
        summary=candidate.summary,
        severity=severity,
        status=status,
        business_impact="Static catalog impact text.",
        remediation_guidance="Static catalog guidance text.",
        evidence={
            "provenance": {"candidate_id": str(candidate.id)},
            "candidate_type": candidate.candidate_type,
            "validation": {"evidence": {"authorization": "Bearer super-secret-token"}},
        },
        created_at=moment,
        updated_at=moment,
        resolved_at=resolved_at,
    )
    db.add(finding)
    db.flush()
    return finding


def _insert_validation(
    db, *, organization_id: UUID, operation: Operation, candidate: SecurityCandidate,
    asset: Asset, status: str = "supported",
) -> ValidationAttempt:
    attempt = ValidationAttempt(
        organization_id=organization_id,
        operation_id=operation.id,
        candidate_id=candidate.id,
        asset_id=asset.id,
        status=status,
        validation_method="http_recheck",
        summary="Observed.",
        evidence={"method": "http_recheck", "reachable": True, "status_code": 200},
        completed_at=datetime.now(UTC),
    )
    db.add(attempt)
    db.flush()
    return attempt


def _insert_retest(
    db,
    *,
    organization_id: UUID,
    finding: Finding,
    validation: ValidationAttempt,
    status: str,
    created_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> RetestAttempt:
    moment = created_at or datetime.now(UTC)
    attempt = RetestAttempt(
        organization_id=organization_id,
        finding_id=finding.id,
        candidate_id=finding.candidate_id,
        asset_id=finding.asset_id,
        original_validation_attempt_id=validation.id,
        status=status,
        method="http_recheck",
        summary="Recheck performed.",
        evidence={"recheck": {"reachable": True, "status_code": 200}},
        created_at=moment,
        completed_at=completed_at,
    )
    db.add(attempt)
    db.flush()
    return attempt


class Scenario:
    """One verified target with an operation and a per-finding asset.

    uq_candidate_org_asset_type allows one candidate per (org, asset, type), so
    every finding gets its own asset, which is also how discovery produces them.
    """

    def __init__(self, db, *, organization_id, user_id, target_id, hostname):
        self.db = db
        self.organization_id = organization_id
        self.target_id = target_id
        self.hostname_suffix = hostname
        self._asset_seq = 0
        self.operation = _insert_operation(
            db, organization_id=organization_id, target_id=target_id, user_id=user_id
        )
        self.asset = self.new_asset()
        self.last_asset = self.asset

    def new_asset(self) -> Asset:
        self._asset_seq += 1
        return _insert_asset(
            self.db,
            organization_id=self.organization_id,
            target_id=self.target_id,
            hostname=f"h{self._asset_seq}.{self.hostname_suffix}",
        )

    def finding(
        self,
        *,
        candidate_type: str = "staging_dev_exposed",
        severity: str = "medium",
        status: str = "open",
        created_at: datetime | None = None,
        resolved_at: datetime | None = None,
    ) -> Finding:
        asset = self.new_asset()
        self.last_asset = asset
        candidate = _insert_candidate(
            self.db,
            organization_id=self.organization_id,
            operation=self.operation,
            asset=asset,
            candidate_type=candidate_type,
        )
        # A supported ValidationAttempt is what promotion requires; retests
        # reference it, so every fixture finding carries one.
        self.validation = _insert_validation(
            self.db,
            organization_id=self.organization_id,
            operation=self.operation,
            candidate=candidate,
            asset=asset,
        )
        return _insert_finding(
            self.db,
            organization_id=self.organization_id,
            operation=self.operation,
            asset=asset,
            candidate=candidate,
            severity=severity,
            status=status,
            created_at=created_at,
            resolved_at=resolved_at,
        )

    def retest(self, finding: Finding, status: str, **kwargs) -> RetestAttempt:
        return _insert_retest(
            self.db,
            organization_id=self.organization_id,
            finding=finding,
            validation=self.validation,
            status=status,
            **kwargs,
        )


def _scenario(client, token, dns_resolver, db, *, hostname="app.example") -> Scenario:
    user_id, org_id = _ids(client, token)
    target_id = _create_verified_target(client, token, hostname, dns_resolver)
    return Scenario(
        db,
        organization_id=org_id,
        user_id=user_id,
        target_id=UUID(target_id),
        hostname=f"www.{hostname}",
    )


# ----------------------------------------------------------------- RBAC


def test_member_and_admin_read_the_same_active_org_inbox(
    client, make_token, seed_user_a, fake_clerk, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    admin_token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, admin_token, dns_resolver, db_session)
    finding = scenario.finding()
    db_session.commit()

    member_token = _add_member(fake_clerk, make_token, org_a, "member@example.com")
    admin_rows = _rows(client, admin_token)
    member_rows = _rows(client, member_token)
    assert [row["finding_id"] for row in admin_rows] == [str(finding.id)]
    assert admin_rows == member_rows


def test_other_organization_findings_never_appear(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")

    scenario_a = _scenario(client, token_a, dns_resolver, db_session, hostname="a.example")
    finding_a = scenario_a.finding()
    scenario_b = _scenario(client, token_b, dns_resolver, db_session, hostname="b.example")
    finding_b = scenario_b.finding()
    db_session.commit()

    assert [row["finding_id"] for row in _rows(client, token_a)] == [str(finding_a.id)]
    assert [row["finding_id"] for row in _rows(client, token_b)] == [str(finding_b.id)]


def test_unauthenticated_is_rejected(client):
    assert client.get(INBOX).status_code == 401


def test_no_active_organization_is_rejected(client, make_token, seed_user_a):
    clerk_a, _ = seed_user_a
    response = client.get(INBOX, headers=_auth(make_token(sub=clerk_a)))
    assert response.status_code == 400


def test_client_supplied_organization_id_is_ignored(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    scenario_b = _scenario(client, token_b, dns_resolver, db_session, hostname="b.example")
    scenario_b.finding()
    db_session.commit()
    _, org_b_id = _ids(client, token_b)

    response = _inbox(client, token_a, organization_id=str(org_b_id))
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_inbox_path_is_not_shadowed_by_the_finding_id_route(
    client, make_token, seed_user_a
):
    """Guards the declaration order: /{finding_id} parses as UUID and would 422."""
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    response = _inbox(client, token)
    assert response.status_code == 200, response.text
    assert response.json()["organization_id"]


# --------------------------------------------------------- finding identity


def test_candidate_without_a_finding_never_appears(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    for candidate_status in ("candidate", "needs_review", "dismissed", "supported"):
        _insert_candidate(
            db_session,
            organization_id=scenario.organization_id,
            operation=scenario.operation,
            asset=scenario.new_asset(),
            candidate_type="staging_dev_exposed",
            status=candidate_status,
        )
    db_session.commit()

    response = _inbox(client, token)
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["summary"]["finding_count"] == 0


def test_promotion_path_produces_a_visible_inbox_row(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    candidate = _insert_candidate(
        db_session,
        organization_id=scenario.organization_id,
        operation=scenario.operation,
        asset=scenario.asset,
    )
    _insert_validation(
        db_session,
        organization_id=scenario.organization_id,
        operation=scenario.operation,
        candidate=candidate,
        asset=scenario.asset,
    )
    db_session.commit()

    promoted = client.post(
        f"/v1/candidates/{candidate.id}/promote", headers=_auth(token)
    )
    assert promoted.status_code in (200, 201), promoted.text
    finding_id = promoted.json()["id"]

    row = _row_for(client, token, finding_id)
    assert row["finding_type"] == "staging_dev_exposed"
    assert row["severity"] == "medium"
    assert row["status"] == "open"


# ------------------------------------------------------------ current state


def test_response_declares_current_state_provenance(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    scenario.finding()
    db_session.commit()

    payload = _inbox(client, token).json()
    assert payload["state"] == "current"
    assert payload["sort"] == "promoted_at_desc"


def test_live_workflow_and_retest_changes_are_reflected(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding()
    db_session.commit()

    assert _row_for(client, token, finding.id)["workflow"]["state"] == "not_started"

    started = client.post(
        f"/v1/findings/{finding.id}/start-remediation", headers=_auth(token)
    )
    assert started.status_code == 200, started.text
    assert _row_for(client, token, finding.id)["workflow"]["state"] == "in_progress"

    recorded = client.post(
        f"/v1/findings/{finding.id}/remediation",
        headers=_auth(token),
        json={"summary": "Updated the application configuration."},
    )
    assert recorded.status_code == 201, recorded.text
    remediation = _row_for(client, token, finding.id)["remediation"]
    assert remediation["revision_count"] == 1
    assert remediation["latest_recorded_at"] is not None

    ready = client.post(
        f"/v1/findings/{finding.id}/ready-for-retest", headers=_auth(token)
    )
    assert ready.status_code == 200, ready.text
    row = _row_for(client, token, finding.id)
    assert row["workflow"]["state"] == "ready_for_retest"
    assert row["retests"]["current_state"] == "none"

    scenario.retest(finding, "failed", completed_at=datetime.now(UTC))
    db_session.commit()
    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "failed"
    assert row["retests"]["latest_terminal"]["status"] == "failed"


# ------------------------------------------------------ workflow truthfulness


def test_workflow_maps_every_finding_status_separately_from_remediation(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    expected = {
        "open": "not_started",
        "in_progress": "in_progress",
        "ready_for_retest": "ready_for_retest",
        "resolved": "resolved_by_retest",
    }
    resolved_moment = datetime.now(UTC)
    findings = {}
    for index, finding_status in enumerate(expected):
        findings[finding_status] = scenario.finding(
            status=finding_status,
            created_at=datetime.now(UTC) - timedelta(minutes=index),
            resolved_at=resolved_moment if finding_status == "resolved" else None,
        )
    db_session.commit()

    body = _inbox(client, token).text
    for finding_status, workflow_state in expected.items():
        row = _row_for(client, token, findings[finding_status].id)
        assert row["status"] == finding_status
        assert row["workflow"]["state"] == workflow_state
        assert set(row["workflow"]) == {"state", "resolved_at"}
        assert row["remediation"] == {
            "revision_count": 0,
            "latest_recorded_at": None,
        }
        if finding_status == "resolved":
            assert row["workflow"]["resolved_at"] is not None
        else:
            assert row["workflow"]["resolved_at"] is None

    # The compact resource is real, but no body or static catalog signal leaks.
    for absent in (
        "remediation_present",
        "remediation_recorded",
        "remediation_updated_at",
        "remediation_guidance",
        "guidance_available",
        "business_impact",
    ):
        assert absent not in body, absent


def test_static_guidance_text_is_never_a_remediation_signal(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="open")
    db_session.commit()

    stored = db_session.get(Finding, finding.id)
    assert stored.remediation_guidance  # always non-empty catalog text
    row = _row_for(client, token, finding.id)
    assert row["workflow"]["state"] == "not_started"
    assert row["remediation"]["revision_count"] == 0
    assert row["remediation"]["latest_recorded_at"] is None
    assert REASON_REMEDIATION_NOT_STARTED in _codes(row)


# ------------------------------------------------------- current retest state


def test_no_attempts_is_state_none(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"] == {
        "current_state": "none",
        "attempt_count": 0,
        "latest_terminal": None,
    }
    assert REASON_AWAITING_RETEST in _codes(row)


def test_prior_failure_without_active_attempt_is_state_failed(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    scenario.retest(finding, "failed", completed_at=datetime.now(UTC))
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "failed"
    assert row["retests"]["latest_terminal"]["status"] == "failed"
    assert row["retests"]["attempt_count"] == 1
    assert REASON_LATEST_RETEST_FAILED in _codes(row)


def test_new_run_after_failure_reports_in_progress_and_keeps_latest_terminal(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    scenario.retest(
        finding,
        "failed",
        created_at=datetime.now(UTC) - timedelta(hours=2),
        completed_at=datetime.now(UTC) - timedelta(hours=2),
    )
    scenario.retest(finding, "running")
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "in_progress"
    assert row["retests"]["latest_terminal"]["status"] == "failed"
    assert row["retests"]["attempt_count"] == 2
    # The row already says "retest in progress"; the old failure is not the
    # current follow-up reason.
    assert REASON_LATEST_RETEST_FAILED not in _codes(row)
    assert REASON_AWAITING_RETEST not in _codes(row)


def test_running_only_is_in_progress_with_no_latest_terminal(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    scenario.retest(finding, "pending")
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "in_progress"
    assert row["retests"]["latest_terminal"] is None
    assert REASON_AWAITING_RETEST not in _codes(row)


def test_completed_pass_becomes_the_current_state(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    attempt = scenario.retest(finding, "running")
    db_session.commit()
    assert _row_for(client, token, finding.id)["retests"]["current_state"] == "in_progress"

    attempt.status = "passed"
    attempt.completed_at = datetime.now(UTC)
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "passed"
    assert row["retests"]["latest_terminal"]["status"] == "passed"


def test_inconclusive_and_error_states_produce_their_own_reasons(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    inconclusive = scenario.finding(
        status="ready_for_retest", created_at=datetime.now(UTC) - timedelta(minutes=1)
    )
    scenario.retest(inconclusive, "inconclusive", completed_at=datetime.now(UTC))
    errored = scenario.finding(
        status="ready_for_retest", created_at=datetime.now(UTC) - timedelta(minutes=2)
    )
    scenario.retest(errored, "error", completed_at=datetime.now(UTC))
    db_session.commit()

    assert REASON_LATEST_RETEST_INCONCLUSIVE in _codes(
        _row_for(client, token, inconclusive.id)
    )
    assert REASON_LATEST_RETEST_ERROR in _codes(_row_for(client, token, errored.id))


def test_latest_terminal_tie_breaks_deterministically(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    moment = datetime.now(UTC)
    first = scenario.retest(finding, "failed", created_at=moment, completed_at=moment)
    second = scenario.retest(finding, "passed", created_at=moment, completed_at=moment)
    db_session.commit()

    expected = max(first.id, second.id)
    expected_status = first.status if expected == first.id else second.status
    for _ in range(3):
        row = _row_for(client, token, finding.id)
        assert row["retests"]["latest_terminal"]["retest_attempt_id"] == str(expected)
        assert row["retests"]["current_state"] == expected_status


def test_resolved_finding_reports_no_retest_follow_up(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="resolved", resolved_at=datetime.now(UTC))
    scenario.retest(finding, "failed", completed_at=datetime.now(UTC))
    db_session.commit()

    row = _row_for(client, token, finding.id)
    assert row["retests"]["current_state"] == "failed"
    assert REASON_LATEST_RETEST_FAILED not in _codes(row)


def test_inbox_read_does_not_mutate_finding_status(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    scenario.retest(finding, "passed", completed_at=datetime.now(UTC))
    db_session.commit()
    before = (finding.status, finding.updated_at, finding.resolved_at)

    assert _inbox(client, token).status_code == 200

    db_session.expire_all()
    stored = db_session.get(Finding, finding.id)
    assert (stored.status, stored.updated_at, stored.resolved_at) == before
    assert stored.status == "ready_for_retest"


# ------------------------------------------------------------------ filters


def test_status_and_severity_filters(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    low_open = scenario.finding(
        candidate_type="security_header_observation",
        severity="low",
        status="open",
        created_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    medium_resolved = scenario.finding(
        severity="medium",
        status="resolved",
        created_at=datetime.now(UTC) - timedelta(minutes=2),
        resolved_at=datetime.now(UTC),
    )
    db_session.commit()

    assert [row["finding_id"] for row in _rows(client, token, status="open")] == [
        str(low_open.id)
    ]
    assert [row["finding_id"] for row in _rows(client, token, severity="medium")] == [
        str(medium_resolved.id)
    ]
    assert _rows(client, token, status="open", severity="medium") == []


def test_target_filter_scopes_to_one_target(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    first = _scenario(client, token, dns_resolver, db_session, hostname="one.example")
    second = _scenario(client, token, dns_resolver, db_session, hostname="two.example")
    finding_one = first.finding(created_at=datetime.now(UTC) - timedelta(minutes=1))
    second.finding(created_at=datetime.now(UTC) - timedelta(minutes=2))
    db_session.commit()

    rows = _rows(client, token, target_id=str(first.target_id))
    assert [row["finding_id"] for row in rows] == [str(finding_one.id)]
    assert rows[0]["target"]["target_id"] == str(first.target_id)


def test_target_filter_cannot_cross_the_org_boundary(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _scenario(client, token_a, dns_resolver, db_session, hostname="a.example").finding()
    scenario_b = _scenario(client, token_b, dns_resolver, db_session, hostname="b.example")
    scenario_b.finding()
    db_session.commit()

    assert _rows(client, token_a, target_id=str(scenario_b.target_id)) == []


def test_every_retest_state_filter_partitions_the_inbox(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    moment = datetime.now(UTC)
    expected: dict[str, str] = {}

    no_retest = scenario.finding(created_at=moment - timedelta(minutes=1))
    expected[str(no_retest.id)] = "none"

    running = scenario.finding(
        status="ready_for_retest", created_at=moment - timedelta(minutes=2)
    )
    scenario.retest(running, "running")
    expected[str(running.id)] = "in_progress"

    after_failure = scenario.finding(
        status="ready_for_retest", created_at=moment - timedelta(minutes=3)
    )
    scenario.retest(
        after_failure,
        "failed",
        created_at=moment - timedelta(hours=1),
        completed_at=moment - timedelta(hours=1),
    )
    scenario.retest(after_failure, "pending")
    expected[str(after_failure.id)] = "in_progress"

    for index, terminal in enumerate(("passed", "failed", "inconclusive", "error")):
        finding = scenario.finding(
            status="ready_for_retest",
            created_at=moment - timedelta(minutes=10 + index),
        )
        scenario.retest(finding, terminal, completed_at=moment)
        expected[str(finding.id)] = terminal
    db_session.commit()

    unfiltered = {row["finding_id"]: row["retests"]["current_state"] for row in _rows(client, token)}
    assert unfiltered == expected

    seen: dict[str, str] = {}
    for state in ("none", "in_progress", "passed", "failed", "inconclusive", "error"):
        for row in _rows(client, token, retest_state=state):
            assert row["retests"]["current_state"] == state
            # Mutually exclusive: no finding may be returned by two states.
            assert row["finding_id"] not in seen, (row["finding_id"], state)
            seen[row["finding_id"]] = state
    assert seen == expected


def test_invalid_filter_values_are_rejected(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _scenario(client, token, dns_resolver, db_session).finding()
    db_session.commit()

    assert _inbox(client, token, status="closed").status_code == 422
    assert _inbox(client, token, severity="catastrophic").status_code == 422
    assert _inbox(client, token, retest_state="pending").status_code == 422
    assert _inbox(client, token, retest_state="running").status_code == 422
    assert _inbox(client, token, target_id="not-a-uuid").status_code == 422


# ------------------------------------------------------ sorting & pagination


def test_default_order_is_promoted_at_then_id_descending(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    base = datetime.now(UTC)
    findings = [
        scenario.finding(created_at=base - timedelta(minutes=index)) for index in range(5)
    ]
    db_session.commit()

    assert [row["finding_id"] for row in _rows(client, token)] == [
        str(finding.id) for finding in findings
    ]


def test_identical_created_at_pages_without_duplicates_or_gaps(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    moment = datetime.now(UTC)
    findings = [scenario.finding(created_at=moment) for _ in range(7)]
    db_session.commit()

    collected: list[str] = []
    cursor = None
    for _ in range(10):
        payload = _inbox(client, token, page_size=1, cursor=cursor).json()
        collected.extend(row["finding_id"] for row in payload["items"])
        cursor = payload["next_cursor"]
        if cursor is None:
            break
    assert cursor is None
    assert len(collected) == len(set(collected)) == len(findings)
    assert set(collected) == {str(finding.id) for finding in findings}
    assert collected == sorted(collected, reverse=True)


def test_updated_at_changes_do_not_disturb_the_cursor(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    """created_at is immutable, so a live transition cannot reshuffle the page."""
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    base = datetime.now(UTC)
    findings = [
        scenario.finding(created_at=base - timedelta(minutes=index)) for index in range(4)
    ]
    db_session.commit()

    first = _inbox(client, token, page_size=2).json()
    oldest = findings[-1]
    assert (
        client.post(
            f"/v1/findings/{oldest.id}/start-remediation", headers=_auth(token)
        ).status_code
        == 200
    )
    second = _inbox(client, token, page_size=2, cursor=first["next_cursor"]).json()

    seen = [row["finding_id"] for row in first["items"] + second["items"]]
    assert seen == [str(finding.id) for finding in findings]


def test_malformed_cursors_return_400(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _scenario(client, token, dns_resolver, db_session).finding()
    db_session.commit()

    from base64 import urlsafe_b64encode

    def _b64(raw: str) -> str:
        return urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    for bad in (
        "not-base64!!",
        _b64("v2|2026-01-01T00:00:00+00:00|" + str(uuid4())),
        _b64("v1|not-a-date|" + str(uuid4())),
        _b64("v1|2026-01-01T00:00:00+00:00|not-a-uuid"),
        _b64("v1|2026-01-01T00:00:00+00:00"),
        _b64("v1|2026-01-01T00:00:00+00:00|" + str(uuid4()) + "|extra"),
    ):
        response = _inbox(client, token, cursor=bad)
        assert response.status_code == 400, (bad, response.text)
        assert response.json()["error"]["message"] == "Invalid findings inbox cursor"

    assert _inbox(client, token, cursor="").status_code == 200


def test_cursor_carries_no_org_state(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    scenario_b = _scenario(client, token_b, dns_resolver, db_session, hostname="b.example")
    old = scenario_b.finding(created_at=datetime.now(UTC) - timedelta(days=1))
    scenario_b.finding(created_at=datetime.now(UTC))
    scenario_a = _scenario(client, token_a, dns_resolver, db_session, hostname="a.example")
    scenario_a.finding(created_at=datetime.now(UTC) - timedelta(hours=1))
    db_session.commit()

    # A cursor minted inside org B only positions; org A's scope is reapplied.
    stolen = encode_inbox_cursor(created_at=old.created_at, finding_id=old.id)
    response = _inbox(client, token_a, cursor=stolen)
    assert response.status_code == 200
    assert all(
        row["target"]["domain"] == "a.example" for row in response.json()["items"]
    )


def test_page_size_bounds(client, make_token, seed_user_a, dns_resolver, db_session):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    _scenario(client, token, dns_resolver, db_session).finding()
    db_session.commit()

    assert _inbox(client, token, page_size=MAX_PAGE_SIZE).status_code == 200
    assert _inbox(client, token, page_size=MAX_PAGE_SIZE + 1).status_code == 422
    assert _inbox(client, token, page_size=0).status_code == 422


# ------------------------------------------------------- target authorization


def test_exact_target_authorization_states_round_trip(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    user_id, org_id = _ids(client, token)

    observed: dict[str, str] = {}
    base = datetime.now(UTC)

    # unverified: freshly created target.
    unverified_id = _create_target(client, token, "unverified.example")
    # verification_pending: verification started but TXT not published.
    pending_id = _create_target(client, token, "pending.example")
    assert (
        client.post(
            f"/v1/targets/{pending_id}/verification", headers=_auth(token)
        ).status_code
        == 200
    )
    # verified, then revoked.
    verified_id = _create_verified_target(client, token, "verified.example", dns_resolver)
    revoked_id = _create_verified_target(client, token, "revoked.example", dns_resolver)
    assert (
        client.post(
            f"/v1/targets/{revoked_id}/revoke", headers=_auth(token)
        ).status_code
        == 200
    )

    for index, (target_id, hostname) in enumerate(
        (
            (unverified_id, "unverified.example"),
            (pending_id, "pending.example"),
            (verified_id, "verified.example"),
            (revoked_id, "revoked.example"),
        )
    ):
        scenario = Scenario(
            db_session,
            organization_id=org_id,
            user_id=user_id,
            target_id=UUID(target_id),
            hostname=f"www.{hostname}",
        )
        finding = scenario.finding(created_at=base - timedelta(minutes=index))
        observed[hostname] = str(finding.id)
    db_session.commit()

    stored = {
        row.domain: row.status
        for row in db_session.scalars(
            select(AuthorizedTarget).where(AuthorizedTarget.organization_id == org_id)
        ).all()
    }
    # No invented "pending": these are the exact values targets.py writes.
    assert stored == {
        "unverified.example": "unverified",
        "pending.example": "verification_pending",
        "verified.example": "verified",
        "revoked.example": "revoked",
    }
    assert set(stored.values()) <= set(TARGET_AUTHORIZATION_STATUSES)

    for hostname, finding_id in observed.items():
        row = _row_for(client, token, finding_id)
        assert row["target"]["authorization_status"] == stored[hostname]
        assert row["target"]["domain"] == hostname
        if stored[hostname] == "verified":
            assert REASON_TARGET_NOT_VERIFIED not in _codes(row)
        else:
            assert REASON_TARGET_NOT_VERIFIED in _codes(row)


def test_revoked_target_finding_stays_visible(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session, hostname="gone.example")
    finding = scenario.finding()
    db_session.commit()
    assert (
        client.post(
            f"/v1/targets/{scenario.target_id}/revoke", headers=_auth(token)
        ).status_code
        == 200
    )

    row = _row_for(client, token, finding.id)
    assert row["target"]["authorization_status"] == "revoked"
    assert REASON_TARGET_NOT_VERIFIED in _codes(row)


# ------------------------------------------------------------------ privacy


def test_inbox_leaks_no_evidence_or_secret_material(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding(status="ready_for_retest")
    scenario.retest(finding, "failed", completed_at=datetime.now(UTC))
    db_session.commit()

    response = _inbox(client, token)
    assert response.status_code == 200
    body = response.text
    lowered = body.lower()

    assert "super-secret-token" not in body
    for forbidden in (
        '"evidence"',
        '"authorization"',
        "cookie",
        "snapshot_json",
        "control_snapshot",
        "observation_ids",
        '"candidate_id"',
        '"operation_id"',
        '"asset_id"',
        "validation_attempt_id",
        "recipient",
        "audit",
        "share",
    ):
        assert forbidden not in lowered, forbidden

    # `provenance` exists only as an attention-reason label, never as the
    # finding provenance chain of internal row identifiers.
    assert {
        reason["provenance"]
        for row in response.json()["items"]
        for reason in row["attention_reasons"]
    } <= {"finding_workflow", "retest_state", "target_authorization"}

    row = response.json()["items"][0]
    assert set(row) == {
        "finding_id",
        "target",
        "title",
        "finding_type",
        "severity",
        "status",
        "workflow",
        "remediation",
        "retests",
        "promoted_at",
        "last_updated_at",
        "attention_reasons",
    }
    assert set(row["remediation"]) == {
        "revision_count",
        "latest_recorded_at",
    }
    assert set(row["target"]) == {
        "target_id",
        "domain",
        "authorization_status",
        "asset_hostname",
    }


def test_scraped_asset_title_is_never_returned(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding()
    scenario.last_asset.title = "Internal Payroll Console -- do not index"
    db_session.commit()

    body = _inbox(client, token).text
    assert "Payroll" not in body
    assert _row_for(client, token, finding.id)["title"] == finding.title


def test_inbox_read_creates_no_audit_event(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    scenario.finding()
    db_session.commit()

    before = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert _inbox(client, token).status_code == 200
    after = db_session.scalar(select(func.count()).select_from(AuditEvent))
    assert after == before


# ------------------------------------------------------------------ summary


def test_summary_is_org_wide_and_independent_of_the_page(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    base = datetime.now(UTC)
    for index, finding_status in enumerate(
        ("open", "in_progress", "ready_for_retest", "resolved", "open")
    ):
        finding = scenario.finding(
            status=finding_status,
            created_at=base - timedelta(minutes=index),
            resolved_at=base if finding_status == "resolved" else None,
        )
        if index == 0:
            scenario.retest(finding, "failed", completed_at=base)
    db_session.commit()

    payload = _inbox(client, token, page_size=1).json()
    assert len(payload["items"]) == 1
    assert payload["summary"] == {
        "scope": "organization",
        "finding_count": 5,
        "open_finding_count": 4,
        "findings_without_any_retest": 4,
    }


def test_summary_excludes_other_organizations(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    _scenario(client, token_a, dns_resolver, db_session, hostname="a.example").finding()
    scenario_b = _scenario(client, token_b, dns_resolver, db_session, hostname="b.example")
    scenario_b.finding()
    scenario_b.finding(created_at=datetime.now(UTC) - timedelta(minutes=1))
    db_session.commit()

    assert _inbox(client, token_a).json()["summary"]["finding_count"] == 1
    assert _inbox(client, token_b).json()["summary"]["finding_count"] == 2


# ------------------------------------------------------------- empty states


def test_empty_inbox_returns_zeroed_summary(client, make_token, seed_user_a):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    payload = _inbox(client, token).json()
    assert payload["items"] == []
    assert payload["next_cursor"] is None
    assert payload["summary"] == {
        "scope": "organization",
        "finding_count": 0,
        "open_finding_count": 0,
        "findings_without_any_retest": 0,
    }


# ------------------------------------------------------------- backward compat


def test_legacy_findings_endpoint_is_unchanged(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    finding = scenario.finding()
    db_session.commit()

    legacy = client.get("/v1/findings", headers=_auth(token))
    assert legacy.status_code == 200
    payload = legacy.json()
    assert [item["id"] for item in payload] == [str(finding.id)]
    # The legacy contract still carries evidence, provenance and guidance.
    assert "evidence" in payload[0]
    assert "provenance" in payload[0]
    assert payload[0]["remediation_guidance"]


def test_mutation_endpoints_keep_their_authorization(
    client, make_token, seed_user_a, seed_user_b, dns_resolver, db_session
):
    clerk_a, org_a = seed_user_a
    clerk_b, org_b = seed_user_b
    token_a = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    token_b = make_token(sub=clerk_b, org_id=org_b, org_role="org:admin")
    scenario = _scenario(client, token_a, dns_resolver, db_session)
    finding = scenario.finding()
    db_session.commit()

    assert (
        client.post(
            f"/v1/findings/{finding.id}/start-remediation", headers=_auth(token_b)
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/v1/findings/{finding.id}/start-remediation", headers=_auth(token_a)
        ).status_code
        == 200
    )


# -------------------------------------------------------------- performance


def test_query_count_is_bounded_and_no_heavy_tables_are_touched(
    client, make_token, seed_user_a, dns_resolver, db_session, engine
):
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    user_id, org_id = _ids(client, token)
    base = datetime.now(UTC)
    for index in range(12):
        target_id = _create_verified_target(
            client, token, f"perf-{index:02d}.example", dns_resolver
        )
        scenario = Scenario(
            db_session,
            organization_id=org_id,
            user_id=user_id,
            target_id=UUID(target_id),
            hostname=f"www.perf-{index:02d}.example",
        )
        finding = scenario.finding(
            status="ready_for_retest", created_at=base - timedelta(minutes=index)
        )
        scenario.retest(
            finding,
            "failed",
            created_at=base - timedelta(hours=2),
            completed_at=base - timedelta(hours=2),
        )
        scenario.retest(finding, "passed", completed_at=base)
    db_session.commit()

    def _count(page_size: int) -> tuple[int, str]:
        statements: list[str] = []

        def _capture(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", _capture)
        try:
            response = _inbox(client, token, page_size=page_size)
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

    # Identical across page sizes proves no per-finding query. The remainder above
    # the service budget is the shared authentication dependency path.
    assert twelve == one, (one, twelve)
    assert twelve <= 20, twelve

    for column in ("evidence", "snapshot_json", "business_impact", "remediation_guidance"):
        assert column not in joined, column
    for table in (
        "operation_coverage_summaries",
        "operation_diff_summaries",
        "assessment_reports",
        "assessment_report_shares",
        "discovery_observations",
        "alert_episodes",
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
            payload = list_findings_inbox(session, organization=organization, page_size=12)
        finally:
            event.remove(engine, "before_cursor_execute", _capture_service)
        assert len(payload.items) == 12
        service_selects = [
            item
            for item in service_statements
            if item.lstrip().lower().startswith("select")
        ]
        # Page + org summary + latest terminal + retest and remediation rollups.
        assert len(service_selects) == 5, len(service_selects)
        service_sql = " ".join(service_statements).lower()
        assert "findings.evidence" not in service_sql
        assert "retest_attempts.evidence" not in service_sql
        assert "finding_remediation_revisions.summary" not in service_sql
    finally:
        session.close()


# ------------------------------------------------------------ UI contract
#
# The web app has no test runner, so these assert the dashboard's source-level
# contract: one organization-scoped finding collection, and no mutation
# affordances inside the read-only inbox.

DASHBOARD = (
    pathlib.Path(__file__).resolve().parents[3] / "apps/web/app/(app)/dashboard"
)
WEB_API = pathlib.Path(__file__).resolve().parents[3] / "apps/web/lib/api.ts"

MUTATIONS = (
    "startFindingRemediation",
    "markFindingReadyForRetest",
    "queueFindingRetest",
    "recordFindingRemediation",
)


def _dashboard_sources() -> dict[str, str]:
    assert DASHBOARD.is_dir(), DASHBOARD
    return {path.name: path.read_text() for path in DASHBOARD.glob("*.tsx")}


def test_dashboard_renders_exactly_one_organization_scoped_finding_list():
    sources = _dashboard_sources()
    inbox_callers = [name for name, src in sources.items() if "fetchFindingsInbox(" in src]
    legacy_callers = [name for name, src in sources.items() if "fetchFindings(" in src]

    assert inbox_callers == ["findings-inbox-panel.tsx"], inbox_callers
    # The legacy endpoint spans every membership, so rendering it beside the
    # active-org inbox would put two contradictory scopes on one page.
    assert legacy_callers == [], legacy_callers

    page = sources["page.tsx"]
    assert "FindingsSection" in page
    assert "FindingsPanel" not in page


def test_legacy_findings_client_remains_exported_for_compatibility():
    api = WEB_API.read_text()
    assert "export function fetchFindings(" in api
    assert '"/v1/findings"' in api
    assert "export function fetchFindingsInbox(" in api


def test_current_findings_inbox_renders_no_mutation_controls():
    inbox = _dashboard_sources()["findings-inbox-panel.tsx"]
    for mutation in MUTATIONS:
        assert mutation not in inbox, mutation
    for label in ("Start Remediation", "Mark Ready for Retest", "Run Retest"):
        assert label not in inbox, label
    # Selection is the only affordance, and it reaches the existing workflow.
    assert "onSelect(row.finding_id)" in inbox


def test_finding_workflow_actions_remain_reachable_from_detail():
    detail = _dashboard_sources()["findings-panel.tsx"]
    for mutation in MUTATIONS:
        assert mutation in detail, mutation
    assert "fetchFinding(" in detail
    assert "fetchFindingRemediation(" in detail
    assert "Record what you changed before requesting a retest." in detail
    assert "Do not include passwords, API keys, tokens, or other secrets." in detail
    assert "<textarea" in detail
    assert "dangerouslySetInnerHTML" not in detail
    assert "fetchFindings(" not in detail


def test_inbox_ui_labels_compact_remediation_metadata_and_no_score():
    inbox = _dashboard_sources()["findings-inbox-panel.tsx"]
    assert "Workflow:" in inbox
    assert "Remediation record:" in inbox
    for forbidden in (
        "remediation_present",
        "remediation_recorded",
        "remediation_updated_at",
        "guidance_available",
        "score",
        "grade",
        "risk level",
    ):
        assert forbidden not in inbox.lower(), forbidden


def test_inner_joins_never_drop_a_finding(
    client, make_token, seed_user_a, dns_resolver, db_session
):
    """asset_id and target_id are NOT NULL FKs, so the join chain must be total."""
    clerk_a, org_a = seed_user_a
    token = make_token(sub=clerk_a, org_id=org_a, org_role="org:admin")
    scenario = _scenario(client, token, dns_resolver, db_session)
    base = datetime.now(UTC)
    for index in range(4):
        scenario.finding(created_at=base - timedelta(minutes=index))
    db_session.commit()

    stored = db_session.scalar(
        select(func.count()).select_from(Finding).where(Finding.organization_id == scenario.organization_id)
    )
    payload = _inbox(client, token, page_size=MAX_PAGE_SIZE).json()
    assert len(payload["items"]) == stored == 4
    assert payload["summary"]["finding_count"] == stored

"""Deterministic operation coverage accounting. Discovery layer is frozen; follow-up is live."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.capabilities.manifest import MANIFEST_VERSION, manifest_snapshot
from app.models.asset import DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.coverage import OperationCoverageSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.retest import RetestAttempt
from app.models.validation import ValidationAttempt
from app.services.audit import record_audit

COVERAGE_SCHEMA_VERSION = 1
TERMINAL_STATUSES = frozenset({"completed", "failed", "stopped"})

OBSERVATION_DISCOVERED = "subdomain_discovered"
OBSERVATION_HTTP = "http_response_observed"
OBSERVATION_REACHABLE = "service_reachable"
OBSERVATION_NOT_OBTAINED = "http_observation_not_obtained"
OBSERVATION_FACTS = "discovery_coverage_facts"

REASON_PROBE_NO_RESULT = "probe_no_result"
REASON_HOST_NOT_REACHABLE = "host_not_reachable"
REASON_PROBE_FAILED = "probe_failed"
REASON_PROBE_TIMEOUT = "probe_timeout"
REASON_OPERATION_STOPPED = "operation_stopped"
REASON_OPERATION_FAILED = "operation_failed"
REASON_OBSERVATION_INCOMPLETE = "observation_incomplete"
REASON_AUTHORIZATION_SCOPE_EXCLUDED = "authorization_scope_excluded"
REASON_DISCOVERY_TRUNCATED = "discovery_truncated"
REASON_HEADER_EVIDENCE_UNAVAILABLE = "header_evidence_unavailable"
REASON_REDIRECT_HEADER_UNUSABLE = "redirect_header_evidence_unusable"
REASON_VALIDATION_NOT_ATTEMPTED = "validation_not_attempted"
REASON_VALIDATION_INCONCLUSIVE = "validation_inconclusive"
REASON_VALIDATION_FAILED = "validation_failed"
REASON_CAPABILITY_NOT_SUPPORTED = "capability_not_supported"

EXPLICIT_PROBE_OUTCOMES = frozenset(
    {REASON_HOST_NOT_REACHABLE, REASON_PROBE_FAILED, REASON_PROBE_TIMEOUT}
)

REASON_EXPLANATIONS = {
    REASON_PROBE_NO_RESULT: (
        "The HTTP observation stage produced no usable result for this hostname. "
        "The cause was not distinguishable."
    ),
    REASON_HOST_NOT_REACHABLE: (
        "The HTTP probe reported that this hostname was not reachable."
    ),
    REASON_PROBE_FAILED: "The HTTP probe failed while observing this hostname.",
    REASON_PROBE_TIMEOUT: "The HTTP probe timed out while observing this hostname.",
    REASON_OPERATION_STOPPED: "The operation stopped before HTTP observation completed.",
    REASON_OPERATION_FAILED: "The operation failed before HTTP observation completed.",
    REASON_OBSERVATION_INCOMPLETE: (
        "This hostname was discovered in scope but was not submitted to the HTTP observation stage."
    ),
    REASON_AUTHORIZATION_SCOPE_EXCLUDED: (
        "Discovered results were discarded because they were outside the authorized scope. "
        "That is not a probe failure."
    ),
    REASON_DISCOVERY_TRUNCATED: (
        "The discovery host list was truncated. Remaining inventory is unknown."
    ),
    REASON_HEADER_EVIDENCE_UNAVAILABLE: (
        "An HTTP observation was obtained, but response-header facts were not captured."
    ),
    REASON_REDIRECT_HEADER_UNUSABLE: (
        "Captured headers came from a redirected response and are not used as missing-HSTS evidence."
    ),
    REASON_VALIDATION_NOT_ATTEMPTED: "A candidate was generated and no completed validation exists.",
    REASON_VALIDATION_INCONCLUSIVE: "The latest completed validation was inconclusive.",
    REASON_VALIDATION_FAILED: "The latest completed validation failed.",
    REASON_CAPABILITY_NOT_SUPPORTED: "This class is outside Scout's current capability manifest.",
}

_TRUNC_RE = re.compile(r"truncated to (\d+) of (\d+)", re.I)

CLEARANCE_HEADLINE_RE = re.compile(
    r"("
    r"%\s*secure"
    r"|proved this application is secure"
    r"|vulnerability-free"
    r"|all clear"
    r"|no issues found"
    r"|clean scan"
    r"|confidence"
    r")",
    re.I,
)


def parse_truncation_note(note: str | None) -> tuple[bool, int | None, int | None]:
    if not note:
        return False, None, None
    match = _TRUNC_RE.search(note)
    if match:
        return True, int(match.group(2)), int(match.group(1))
    return True, None, None


def explanation_for(reason_code: str) -> str:
    return REASON_EXPLANATIONS.get(
        reason_code, "A coverage gap was recorded for this hostname."
    )


def _norm_host(value: Any) -> str:
    return str(value or "").lower().rstrip(".")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _ratio(num: int, den: int) -> dict[str, int | float] | None:
    if den <= 0:
        return None
    return {"numerator": num, "denominator": den, "value": round(num / den, 4)}


def _hostnames_from(observations: list[DiscoveryObservation], *types: str) -> set[str]:
    wanted = set(types)
    hosts: set[str] = set()
    for row in observations:
        if row.observation_type not in wanted:
            continue
        host = _norm_host((row.observation_metadata or {}).get("hostname"))
        if host:
            hosts.add(host)
    return hosts


def _facts_row(observations: list[DiscoveryObservation]) -> dict[str, Any]:
    for row in observations:
        if row.observation_type == OBSERVATION_FACTS:
            return dict(row.observation_metadata or {})
    return {}


def compute_discovery_coverage(db: Session, operation: Operation) -> dict[str, Any]:
    observations = list(
        db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.operation_id == operation.id
            )
        ).all()
    )
    snapshot = getattr(operation, "control_snapshot", None)
    exclusions = [str(item) for item in (getattr(snapshot, "exclusions", None) or [])]
    include_subdomains = bool(getattr(snapshot, "include_subdomains", False)) if snapshot else False

    facts = _facts_row(observations)
    discovered = _hostnames_from(observations, OBSERVATION_DISCOVERED)
    obtained = _hostnames_from(observations, OBSERVATION_HTTP, OBSERVATION_REACHABLE)
    not_obtained_rows = [
        row for row in observations if row.observation_type == OBSERVATION_NOT_OBTAINED
    ]
    not_obtained_hosts: dict[str, str] = {}
    for row in not_obtained_rows:
        meta = row.observation_metadata or {}
        host = _norm_host(meta.get("hostname"))
        if not host:
            continue
        reason = str(meta.get("reason_code") or REASON_PROBE_NO_RESULT)
        not_obtained_hosts[host] = reason

    http_probe_ran = bool(facts.get("http_probe_ran"))
    if http_probe_ran:
        submitted = set(discovered)
    else:
        submitted = set(obtained) | set(not_obtained_hosts)

    incomplete = discovered - submitted
    # Hosts submitted but with neither HTTP nor an explicit/neutral gap observation.
    missing_gap = submitted - obtained - set(not_obtained_hosts)
    if http_probe_ran:
        for host in missing_gap:
            not_obtained_hosts[host] = REASON_PROBE_NO_RESULT
    else:
        incomplete |= missing_gap

    not_obtained = set(not_obtained_hosts) - obtained
    incomplete -= obtained
    incomplete -= not_obtained

    headers_captured: list[str] = []
    header_unavailable: list[str] = []
    redirect_unusable: list[str] = []
    oldest: datetime | None = None
    newest: datetime | None = None
    for row in observations:
        if row.observation_type != OBSERVATION_HTTP:
            continue
        meta = row.observation_metadata or {}
        host = _norm_host(meta.get("hostname"))
        if not host or host not in obtained:
            continue
        if meta.get("headers_observed") is True:
            headers_captured.append(host)
        else:
            header_unavailable.append(host)
        if meta.get("redirected") is True:
            redirect_unusable.append(host)
        created = row.created_at
        if created is not None:
            if oldest is None or created < oldest:
                oldest = created
            if newest is None or created > newest:
                newest = created

    headers_captured = sorted(set(headers_captured))
    header_unavailable = sorted(set(header_unavailable))
    redirect_unusable = sorted(set(redirect_unusable))

    discarded = int(facts.get("discarded_out_of_scope") or 0)
    truncated = bool(facts.get("truncated"))
    truncated_from = facts.get("truncated_from")
    truncated_to = facts.get("truncated_to")
    if truncated_from is not None:
        truncated_from = int(truncated_from)
    if truncated_to is not None:
        truncated_to = int(truncated_to)

    incomplete_reason = REASON_OBSERVATION_INCOMPLETE
    if operation.status == "stopped":
        incomplete_reason = REASON_OPERATION_STOPPED
    elif operation.status == "failed":
        incomplete_reason = REASON_OPERATION_FAILED

    not_obtained_items = [
        {
            "hostname": host,
            "reason_code": not_obtained_hosts[host],
            "explanation": explanation_for(not_obtained_hosts[host]),
        }
        for host in sorted(not_obtained)
    ]
    incomplete_items = [
        {
            "hostname": host,
            "reason_code": incomplete_reason,
            "explanation": explanation_for(incomplete_reason),
        }
        for host in sorted(incomplete)
    ]

    surface = {
        "unit": "in_scope_hostname",
        "in_scope_discovered": len(discovered),
        "submitted_for_http_observation": len(submitted),
        "http_observation_obtained": len(obtained),
        "http_observation_not_obtained": len(not_obtained),
        "incomplete": len(incomplete),
        "hostnames": {
            "in_scope_discovered": sorted(discovered),
            "submitted_for_http_observation": sorted(submitted),
            "http_observation_obtained": sorted(obtained),
            "http_observation_not_obtained": not_obtained_items,
            "incomplete": incomplete_items,
        },
        "ratios": {
            "http_observation_obtained_of_in_scope_discovered": _ratio(
                len(obtained), len(discovered)
            ),
            "http_observation_obtained_of_submitted": _ratio(len(obtained), len(submitted)),
        },
    }
    http_evidence = {
        "unit": "http_observation",
        "http_observations": len(obtained),
        "headers_captured": len(headers_captured),
        "header_evidence_unavailable": len(header_unavailable),
        "redirect_header_evidence_unusable": len(redirect_unusable),
        "hostnames": {
            "headers_captured": headers_captured,
            "header_evidence_unavailable": [
                {
                    "hostname": host,
                    "reason_code": REASON_HEADER_EVIDENCE_UNAVAILABLE,
                    "explanation": explanation_for(REASON_HEADER_EVIDENCE_UNAVAILABLE),
                }
                for host in header_unavailable
            ],
            "redirect_header_evidence_unusable": [
                {
                    "hostname": host,
                    "reason_code": REASON_REDIRECT_HEADER_UNUSABLE,
                    "explanation": explanation_for(REASON_REDIRECT_HEADER_UNUSABLE),
                }
                for host in redirect_unusable
            ],
        },
        "ratios": {
            "headers_captured_of_http_observations": _ratio(
                len(headers_captured), len(obtained)
            ),
        },
    }
    scope_gaps: list[dict[str, Any]] = []
    if discarded:
        scope_gaps.append(
            {
                "reason_code": REASON_AUTHORIZATION_SCOPE_EXCLUDED,
                "count": discarded,
                "explanation": explanation_for(REASON_AUTHORIZATION_SCOPE_EXCLUDED),
            }
        )
    if truncated:
        scope_gaps.append(
            {
                "reason_code": REASON_DISCOVERY_TRUNCATED,
                "count": 1,
                "truncated_from": truncated_from,
                "truncated_to": truncated_to,
                "explanation": explanation_for(REASON_DISCOVERY_TRUNCATED),
            }
        )
    scope_boundaries = {
        "configured_exclusions": exclusions,
        "include_subdomains": include_subdomains,
        "discovered_results_discarded": discarded,
        "discovery_truncated": truncated,
        "truncated_from": truncated_from,
        "truncated_to": truncated_to,
        "gaps": scope_gaps,
    }
    capability = manifest_snapshot(version=MANIFEST_VERSION)
    freshness = {
        "oldest_http_observation_at": _iso(oldest),
        "newest_http_observation_at": _iso(newest),
        "operation_completed_at": _iso(operation.completed_at),
        "operation_stopped_at": _iso(operation.stopped_at),
        "operation_failed_at": _iso(operation.failed_at),
    }
    follow_up = compute_follow_up(db, operation)
    headline = build_headline(
        surface=surface,
        http_evidence=http_evidence,
        scope_boundaries=scope_boundaries,
        capability=capability,
        follow_up=follow_up,
        operation_status=operation.status,
    )
    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "capability_manifest_version": MANIFEST_VERSION,
        "capability_snapshot": capability,
        "surface": surface,
        "http_evidence": http_evidence,
        "scope_boundaries": scope_boundaries,
        "freshness": freshness,
        "headline": headline,
        "follow_up": follow_up,
    }


def compute_follow_up(db: Session, operation: Operation) -> dict[str, Any]:
    candidates = list(
        db.scalars(
            select(SecurityCandidate).where(SecurityCandidate.operation_id == operation.id)
        ).all()
    )
    attempts = list(
        db.scalars(
            select(ValidationAttempt).where(ValidationAttempt.operation_id == operation.id)
        ).all()
    )
    findings = list(
        db.scalars(select(Finding).where(Finding.operation_id == operation.id)).all()
    )
    finding_ids = [row.id for row in findings]
    retests: list[RetestAttempt] = []
    if finding_ids:
        retests = list(
            db.scalars(select(RetestAttempt).where(RetestAttempt.finding_id.in_(finding_ids))).all()
        )

    latest_by_candidate: dict[UUID, ValidationAttempt] = {}
    for attempt in attempts:
        current = latest_by_candidate.get(attempt.candidate_id)
        if current is None:
            latest_by_candidate[attempt.candidate_id] = attempt
            continue
        left = current.completed_at or current.created_at
        right = attempt.completed_at or attempt.created_at
        if right >= left:
            latest_by_candidate[attempt.candidate_id] = attempt

    completed_statuses = {"supported", "unsupported", "inconclusive", "failed"}
    latest_completed = [
        row for row in latest_by_candidate.values() if row.status in completed_statuses
    ]
    conclusive = sum(1 for row in latest_completed if row.status in {"supported", "unsupported"})
    inconclusive = sum(1 for row in latest_completed if row.status == "inconclusive")
    failed = sum(1 for row in latest_completed if row.status == "failed")
    not_attempted = sum(
        1
        for candidate in candidates
        if latest_by_candidate.get(candidate.id) is None
        or latest_by_candidate[candidate.id].status not in completed_statuses
    )

    retest_completed = [row for row in retests if row.status not in {"pending", "running"}]
    gaps: list[dict[str, Any]] = []
    if not_attempted:
        gaps.append(
            {
                "reason_code": REASON_VALIDATION_NOT_ATTEMPTED,
                "count": not_attempted,
                "explanation": explanation_for(REASON_VALIDATION_NOT_ATTEMPTED),
            }
        )
    if inconclusive:
        gaps.append(
            {
                "reason_code": REASON_VALIDATION_INCONCLUSIVE,
                "count": inconclusive,
                "explanation": explanation_for(REASON_VALIDATION_INCONCLUSIVE),
            }
        )
    if failed:
        gaps.append(
            {
                "reason_code": REASON_VALIDATION_FAILED,
                "count": failed,
                "explanation": explanation_for(REASON_VALIDATION_FAILED),
            }
        )

    return {
        "candidates_generated": len(candidates),
        "validations_attempted": len(latest_completed),
        "validations_conclusive": conclusive,
        "validations_inconclusive": inconclusive,
        "validations_failed": failed,
        "validations_not_attempted": not_attempted,
        "findings": len(findings),
        "retests_attempted": len(retest_completed),
        "retests_passed": sum(1 for row in retest_completed if row.status == "passed"),
        "retests_failed": sum(1 for row in retest_completed if row.status == "failed"),
        "retests_inconclusive": sum(1 for row in retest_completed if row.status == "inconclusive"),
        "retests_error": sum(1 for row in retest_completed if row.status == "error"),
        "gaps": gaps,
    }


def build_headline(
    *,
    surface: dict[str, Any],
    http_evidence: dict[str, Any],
    scope_boundaries: dict[str, Any],
    capability: dict[str, Any],
    follow_up: dict[str, Any],
    operation_status: str,
) -> str:
    obtained = int(surface.get("http_observation_obtained") or 0)
    discovered = int(surface.get("in_scope_discovered") or 0)
    submitted = int(surface.get("submitted_for_http_observation") or 0)
    not_obtained = int(surface.get("http_observation_not_obtained") or 0)
    incomplete = int(surface.get("incomplete") or 0)
    supported_n = len(capability.get("supported") or [])
    unsupported_n = len(capability.get("unsupported") or [])
    discarded = int(scope_boundaries.get("discovered_results_discarded") or 0)
    parts = [
        (
            f"Scout evaluated {obtained}/{discovered} in-scope hostnames with usable HTTP "
            f"observations using {supported_n} supported check classes."
        )
    ]
    if submitted != discovered:
        parts.append(
            f"{submitted}/{discovered} in-scope hostnames were submitted for HTTP observation."
        )
    if not_obtained:
        parts.append(
            f"{not_obtained} in-scope hostname(s) produced no usable HTTP observation."
        )
    if incomplete:
        verb = "stopped" if operation_status == "stopped" else (
            "failed" if operation_status == "failed" else "did not finish"
        )
        parts.append(
            f"{incomplete} in-scope hostname(s) were incomplete because the operation {verb}."
        )
    captured = int(http_evidence.get("headers_captured") or 0)
    unavailable = int(http_evidence.get("header_evidence_unavailable") or 0)
    http_n = int(http_evidence.get("http_observations") or 0)
    if http_n:
        parts.append(
            f"Response headers were captured on {captured}/{http_n} HTTP observations"
            + (
                f"; header evidence was unavailable on {unavailable}/{http_n}."
                if unavailable
                else "."
            )
        )
    if discarded:
        parts.append(
            f"{discarded} discovered result(s) were discarded by authorization scope."
        )
    if scope_boundaries.get("discovery_truncated"):
        parts.append("Discovery host list was truncated; remaining inventory is unknown.")
    parts.append(
        f"{unsupported_n} capability class(es) are outside current Scout capability."
    )
    findings = int(follow_up.get("findings") or 0)
    candidates = int(follow_up.get("candidates_generated") or 0)
    if findings == 0:
        parts.append(
            "No findings were promoted. That is not evidence that the application is secure."
        )
    if candidates == 0:
        parts.append("No security candidates were generated from observable surfaces.")
    headline = " ".join(parts)
    if CLEARANCE_HEADLINE_RE.search(headline):
        raise ValueError("coverage headline must not imply a security clearance")
    return headline


def _snapshot_row_values(
    operation: Operation, computed: dict[str, Any], *, source: str
) -> dict[str, Any]:
    return {
        "id": uuid.uuid4(),
        "operation_id": operation.id,
        "organization_id": operation.organization_id,
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "capability_manifest_version": int(computed["capability_manifest_version"]),
        "capability_snapshot": computed["capability_snapshot"],
        "surface": computed["surface"],
        "http_evidence": computed["http_evidence"],
        "scope_boundaries": computed["scope_boundaries"],
        "freshness": computed["freshness"],
        "headline": computed["headline"],
        "operation_status_at_freeze": operation.status,
        "source": source,
        "frozen_at": datetime.now(timezone.utc),
    }


def freeze_operation_coverage(
    db: Session,
    operation: Operation,
    *,
    source: str = "frozen",
    actor_type: str = "worker",
) -> OperationCoverageSummary | None:
    """Insert-only freeze. Safe to call in the same transaction as the terminal status write."""
    if operation.status not in TERMINAL_STATUSES:
        return None
    existing = db.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation.id
        )
    )
    if existing is not None:
        return existing

    computed = compute_discovery_coverage(db, operation)
    values = _snapshot_row_values(operation, computed, source=source)
    db.execute(
        pg_insert(OperationCoverageSummary)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["operation_id"])
    )
    db.flush()
    row = db.scalar(
        select(OperationCoverageSummary).where(
            OperationCoverageSummary.operation_id == operation.id
        )
    )
    if row is not None and row.id == values["id"]:
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type=actor_type,
            actor_user_id=operation.created_by_user_id,
            action="coverage.frozen",
            resource_type="operation",
            resource_id=operation.id,
            summary="Operation coverage snapshot frozen.",
            metadata={
                "operation_id": str(operation.id),
                "status": operation.status,
                "source": source,
            },
        )
    return row


def coverage_payload_from_snapshot(
    db: Session,
    operation: Operation,
    row: OperationCoverageSummary,
) -> dict[str, Any]:
    follow_up = compute_follow_up(db, operation)
    capability = dict(row.capability_snapshot or {})
    headline = build_headline(
        surface=dict(row.surface or {}),
        http_evidence=dict(row.http_evidence or {}),
        scope_boundaries=dict(row.scope_boundaries or {}),
        capability=capability,
        follow_up=follow_up,
        operation_status=row.operation_status_at_freeze or operation.status,
    )
    return {
        "schema_version": row.schema_version,
        "source": row.source,
        "frozen_at": _iso(row.frozen_at),
        "operation_status_at_freeze": row.operation_status_at_freeze,
        "capability_manifest_version": row.capability_manifest_version,
        "capability": capability,
        "surface": dict(row.surface or {}),
        "http_evidence": dict(row.http_evidence or {}),
        "scope_boundaries": dict(row.scope_boundaries or {}),
        "freshness": dict(row.freshness or {}),
        "headline": headline,
        "follow_up": follow_up,
    }


def assemble_live_coverage(db: Session, operation: Operation) -> dict[str, Any]:
    computed = compute_discovery_coverage(db, operation)
    return {
        "schema_version": computed["schema_version"],
        "source": "live",
        "frozen_at": None,
        "operation_status_at_freeze": None,
        "capability_manifest_version": computed["capability_manifest_version"],
        "capability": computed["capability_snapshot"],
        "surface": computed["surface"],
        "http_evidence": computed["http_evidence"],
        "scope_boundaries": computed["scope_boundaries"],
        "freshness": computed["freshness"],
        "headline": computed["headline"],
        "follow_up": computed["follow_up"],
    }

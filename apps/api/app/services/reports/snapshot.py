"""Frozen assessment snapshot assembly.

The digested ``content`` body contains no generation-time volatility: every
timestamp in it is a real source timestamp from the operation, the frozen
coverage/diff rows, or the finding/retest rows. Report identity and generation
time live in the undigested envelope, so identical semantic inputs always
produce an identical digest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.capabilities.manifest import UNSUPPORTED_CLASSES
from app.models.coverage import OperationCoverageSummary
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.models.operation_controls import OperationControlSnapshot
from app.models.organization import Organization
from app.models.retest import RetestAttempt
from app.services.coverage import compute_follow_up
from app.services.reports.redaction import (
    finding_report_evidence,
    guard_evidence_subtree,
    retest_report_evidence,
)
from app.services.reports.summary import (
    ACTION_REQUIRED_MIN_RANK,
    HEADLINE_LABELS,
    OPEN_FINDING_STATUSES,
    RESOLVED_FINDING_STATUSES,
    classify_headline,
    compute_coverage_limitations,
    headline_statement,
    severity_rank,
)

REPORT_SCHEMA_VERSION = 1

TERMINAL_INCOMPLETE_STATUSES = frozenset({"failed", "stopped"})

SAFETY_CONTROLS: tuple[str, ...] = (
    "Scout tested only hostnames inside the authorized scope frozen at operation start.",
    "Only unauthenticated HTTP GET and HEAD requests were issued.",
    "Response bodies were never stored; only allowlisted response-header facts were kept.",
    "No exploitation, no credential testing, and no destructive checks were performed.",
    "Validation and retest re-observed the same facts using the same allowlisted methods.",
)

_DIFF_CHANGE_FIELDS = ("change_type", "category", "significance", "match_key", "explanation")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def canonical_json(content: dict[str, Any]) -> str:
    return json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def content_digest(content: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def _scalar_or_none(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _diff_change(change: Any) -> dict[str, Any] | None:
    if not isinstance(change, dict):
        return None
    entry: dict[str, Any] = {}
    for field in _DIFF_CHANGE_FIELDS:
        value = _scalar_or_none(change.get(field))
        if value is not None:
            entry[field] = value
    before = _scalar_or_none(change.get("before"))
    after = _scalar_or_none(change.get("after"))
    if before is not None:
        entry["before"] = before
    if after is not None:
        entry["after"] = after
    return entry or None


def _change_context(row: OperationDiffSummary | None) -> dict[str, Any]:
    if row is None:
        return {
            "available": False,
            "explanation": (
                "No frozen change comparison exists for this operation, so Scout "
                "cannot report changes since a previous assessment."
            ),
        }
    changes = row.changes if isinstance(row.changes, list) else []
    regressions: list[dict[str, Any]] = []
    degradations: list[dict[str, Any]] = []
    reappeared: list[dict[str, Any]] = []
    for change in changes:
        entry = _diff_change(change)
        if entry is None:
            continue
        significance = entry.get("significance")
        if significance == "regression":
            regressions.append(entry)
            if entry.get("change_type") == "regression_resolved_condition_reappeared":
                reappeared.append(entry)
        elif significance == "coverage":
            degradations.append(entry)

    def _sort_key(item: dict[str, Any]) -> tuple[str, str]:
        return (str(item.get("change_type") or ""), str(item.get("match_key") or ""))

    return {
        "available": True,
        "comparability": row.comparability,
        "baseline_operation_id": str(row.baseline_operation_id)
        if row.baseline_operation_id
        else None,
        "diff_schema_version": row.schema_version,
        "diff_frozen_at": _iso(row.frozen_at),
        "diff_headline": row.headline,
        "security_signal_baseline_unavailable": bool(
            row.security_signal_baseline_unavailable
        ),
        "security_signal_comparison_suppressed": bool(
            row.security_signal_comparison_suppressed
        ),
        "security_signal_suppression_reason": row.security_signal_suppression_reason,
        "counts": dict(row.counts or {}),
        "security_regressions": sorted(regressions, key=_sort_key),
        "coverage_degradations": sorted(degradations, key=_sort_key),
        "resolved_conditions_reappeared": sorted(reappeared, key=_sort_key),
    }


def _retests_by_finding(
    db: Session, finding_ids: list[UUID]
) -> dict[UUID, list[RetestAttempt]]:
    if not finding_ids:
        return {}
    rows = list(
        db.scalars(
            select(RetestAttempt).where(RetestAttempt.finding_id.in_(finding_ids))
        ).all()
    )
    grouped: dict[UUID, list[RetestAttempt]] = {}
    for row in rows:
        grouped.setdefault(row.finding_id, []).append(row)
    for items in grouped.values():
        items.sort(
            key=lambda row: (
                row.completed_at or datetime.min.replace(tzinfo=UTC),
                row.created_at,
                str(row.id),
            )
        )
    return grouped


def _finding_entry(finding: Finding, retests: list[RetestAttempt]) -> dict[str, Any]:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    validation = evidence.get("validation") if isinstance(evidence, dict) else None
    validation = validation if isinstance(validation, dict) else {}
    asset = getattr(finding, "asset", None)

    terminal = [row for row in retests if row.status not in {"pending", "running"}]
    latest = terminal[-1] if terminal else None

    entry: dict[str, Any] = {
        "finding_id": str(finding.id),
        "title": finding.title,
        "summary": finding.summary,
        "observation_class": str(evidence.get("candidate_type") or ""),
        "severity": finding.severity,
        "severity_rank": severity_rank(finding.severity),
        "status": finding.status,
        "is_open": finding.status in OPEN_FINDING_STATUSES,
        "created_at": _iso(finding.created_at),
        "updated_at": _iso(finding.updated_at),
        "resolved_at": _iso(finding.resolved_at),
        "business_impact": finding.business_impact,
        "remediation_guidance": finding.remediation_guidance,
        "affected_asset": {
            "hostname": getattr(asset, "hostname", None),
            "url": getattr(asset, "url", None),
        },
        "validation": {
            "method": _scalar_or_none(validation.get("method")),
            "status": _scalar_or_none(validation.get("status")),
            "summary": _scalar_or_none(validation.get("summary")),
        },
        "retest_attempts": len(terminal),
        "latest_retest": None
        if latest is None
        else {
            "status": latest.status,
            "method": latest.method,
            "summary": latest.summary,
            "completed_at": _iso(latest.completed_at),
            "evidence": retest_report_evidence(latest.evidence),
        },
        "evidence": finding_report_evidence(evidence),
    }
    return entry


def _findings_content(db: Session, operation: Operation) -> list[dict[str, Any]]:
    findings = list(
        db.scalars(
            select(Finding)
            .options(selectinload(Finding.asset))
            .where(Finding.operation_id == operation.id)
        ).all()
    )
    grouped = _retests_by_finding(db, [row.id for row in findings])
    entries = [_finding_entry(row, grouped.get(row.id, [])) for row in findings]
    entries.sort(
        key=lambda item: (
            -int(item["severity_rank"]),
            str(item["affected_asset"].get("hostname") or ""),
            str(item["finding_id"]),
        )
    )
    return entries


def build_report_content(
    db: Session,
    operation: Operation,
    *,
    organization: Organization,
    control_snapshot: OperationControlSnapshot,
    coverage_row: OperationCoverageSummary,
    diff_row: OperationDiffSummary | None,
) -> dict[str, Any]:
    """Assemble the digested report body from frozen sources plus report-time follow-up."""
    completeness = (
        "incomplete" if operation.status in TERMINAL_INCOMPLETE_STATUSES else "complete"
    )

    follow_up = compute_follow_up(db, operation)
    surface = dict(coverage_row.surface or {})
    http_evidence = dict(coverage_row.http_evidence or {})
    scope_boundaries = dict(coverage_row.scope_boundaries or {})
    capability = dict(coverage_row.capability_snapshot or {})

    limitations = compute_coverage_limitations(
        surface=surface,
        http_evidence=http_evidence,
        scope_boundaries=scope_boundaries,
        follow_up=follow_up,
    )

    findings = _findings_content(db, operation)
    open_findings = [item for item in findings if item["is_open"]]
    resolved_findings = [
        item for item in findings if item["status"] in RESOLVED_FINDING_STATUSES
    ]
    elevated = [
        item
        for item in open_findings
        if int(item["severity_rank"]) >= ACTION_REQUIRED_MIN_RANK
    ]

    change_context = _change_context(diff_row)
    regression_count = len(change_context.get("security_regressions") or [])

    headline_status = classify_headline(
        assessment_completeness=completeness,
        open_findings=open_findings,
        coverage_limitation_count=len(limitations),
        regression_count=regression_count,
    )

    severity_counts_open: dict[str, int] = {}
    for item in open_findings:
        key = str(item["severity"])
        severity_counts_open[key] = severity_counts_open.get(key, 0) + 1

    content: dict[str, Any] = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "identity": {
            "organization_id": str(organization.id),
            "organization_name": organization.name,
            "target_id": str(operation.target_id),
            "target_domain": control_snapshot.target_domain,
            "target_authorization_status": control_snapshot.authorization_status,
            "operation_id": str(operation.id),
            "operation_source": control_snapshot.operation_source,
            "operation_status": operation.status,
            "testing_profile": control_snapshot.testing_profile,
            "assessment_completeness": completeness,
            "operation_created_at": _iso(operation.created_at),
            "operation_started_at": _iso(operation.started_at),
            "operation_completed_at": _iso(operation.completed_at),
            "operation_failed_at": _iso(operation.failed_at),
            "operation_stopped_at": _iso(operation.stopped_at),
        },
        "scope": {
            "source": "operation_control_snapshot",
            "explanation": (
                "Scope is the authorized boundary frozen when this operation started. "
                "Later edits to the target's scope do not change what this operation "
                "tested."
            ),
            "scope_root": control_snapshot.scope_root,
            "include_subdomains": bool(control_snapshot.include_subdomains),
            "exclusions": sorted(str(item) for item in (control_snapshot.exclusions or [])),
            "control_snapshot_created_at": _iso(control_snapshot.created_at),
        },
        "coverage": {
            "frozen_operation_coverage": {
                "source": "operation_coverage_summary",
                "explanation": (
                    "Discovery and HTTP observation coverage frozen when the operation "
                    "reached a terminal status."
                ),
                "freeze_source": coverage_row.source,
                "schema_version": coverage_row.schema_version,
                "frozen_at": _iso(coverage_row.frozen_at),
                "operation_status_at_freeze": coverage_row.operation_status_at_freeze,
                "capability_manifest_version": coverage_row.capability_manifest_version,
                "capability": capability,
                "surface": surface,
                "http_evidence": http_evidence,
                "scope_boundaries": scope_boundaries,
                "freshness": dict(coverage_row.freshness or {}),
                "headline": coverage_row.headline,
            },
            "follow_up_frozen_for_report": {
                "source": "computed_at_report_generation",
                "explanation": (
                    "Validation, finding and retest follow-up is live organization state. "
                    "These counts were computed once when this report was generated and "
                    "frozen here; they were not part of the operation coverage snapshot."
                ),
                "counts": {
                    key: value for key, value in follow_up.items() if key != "gaps"
                },
                "gaps": list(follow_up.get("gaps") or []),
            },
            "limitations": {
                "explanation": (
                    "Concrete coverage limitations recorded for this operation. Scout's "
                    "unsupported test classes are listed separately under methodology "
                    "and are not counted here."
                ),
                "coverage_limitation_count": len(limitations),
                "coverage_limitations": limitations,
            },
        },
        "findings": findings,
        "not_promoted": {
            "explanation": (
                "Deterministic candidates that were not promoted to findings are "
                "reported only as counts. Unpromoted candidates are not findings and "
                "no per-candidate hypothesis is presented as a security result."
            ),
            "candidates_generated": int(follow_up.get("candidates_generated") or 0),
            "validations_conclusive": int(follow_up.get("validations_conclusive") or 0),
            "validations_inconclusive": int(follow_up.get("validations_inconclusive") or 0),
            "validations_failed": int(follow_up.get("validations_failed") or 0),
            "validations_not_attempted": int(follow_up.get("validations_not_attempted") or 0),
        },
        "change_context": change_context,
        "summary": {
            "headline_status": headline_status,
            "headline_label": HEADLINE_LABELS[headline_status],
            "headline_statement": headline_statement(
                headline_status=headline_status,
                open_count=len(open_findings),
                elevated_count=len(elevated),
                coverage_limitation_count=len(limitations),
                regression_count=regression_count,
            ),
            "assessment_completeness": completeness,
            "findings_total": len(findings),
            "findings_open": len(open_findings),
            "findings_resolved": len(resolved_findings),
            "severity_counts_open": severity_counts_open,
            "regression_count": regression_count,
            "coverage_limitation_count": len(limitations),
        },
        "methodology": {
            "testing_profile": control_snapshot.testing_profile,
            "capability_manifest_version": coverage_row.capability_manifest_version,
            "supported_classes": list(capability.get("supported") or []),
            "unsupported_classes": [dict(item) for item in UNSUPPORTED_CLASSES],
            "safety_controls": list(SAFETY_CONTROLS),
        },
    }

    # Semi-structured source-derived JSON only; the typed schema above is not scanned.
    guard_evidence_subtree(content["coverage"], path="coverage")
    guard_evidence_subtree(content["change_context"], path="change_context")
    return content

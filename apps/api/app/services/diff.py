"""Immutable operation-to-operation comparison. Snapshot is historical state; changes are the diff."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, joinedload

from app.capabilities.manifest import MANIFEST_VERSION, manifest_snapshot
from app.models.asset import DiscoveryObservation
from app.models.candidate import SecurityCandidate
from app.models.diff import OperationDiffSummary
from app.models.finding import Finding
from app.models.operation import Operation
from app.services.audit import record_audit
from app.services.coverage import (
    CLEARANCE_HEADLINE_RE,
    OBSERVATION_HTTP,
    REASON_PROBE_NO_RESULT,
    TERMINAL_STATUSES,
    compute_discovery_coverage,
    explanation_for,
)
from app.services.http_evidence import hsts_header_present, is_https_html_success

DIFF_SCHEMA_VERSION = 1
COMPARISON_SNAPSHOT_SCHEMA_VERSION = 1

COMPARABILITY_NO_BASELINE = "no_baseline"
COMPARABILITY_NOT_COMPARABLE_SCOPE = "not_comparable_scope"
COMPARABILITY_PARTIAL_CAPABILITY = "partial_capability"
COMPARABILITY_COMPARABLE = "comparable"
COMPARABILITY_CURRENT_INCOMPLETE = "current_incomplete"
COMPARABILITY_BASELINE_COVERAGE_UNAVAILABLE = "baseline_coverage_unavailable"

CATEGORY_SURFACE = "surface"
CATEGORY_EVIDENCE = "evidence"
CATEGORY_SIGNAL = "security_signal"
CATEGORY_COVERAGE = "coverage"
CATEGORY_CONTRACT = "contract"
CATEGORY_REGRESSION = "regression"

SIGNIFICANCE_FACT = "fact"
SIGNIFICANCE_COVERAGE = "coverage"
SIGNIFICANCE_REGRESSION = "regression"

CHANGE_HOSTNAME_NEWLY_DISCOVERED = "hostname_newly_discovered"
CHANGE_HOSTNAME_NO_LONGER_DISCOVERED = "hostname_no_longer_discovered"
CHANGE_HTTP_OBSERVATION_GAINED = "http_observation_gained"
CHANGE_HTTP_OBSERVATION_LOST = "http_observation_lost"
CHANGE_RESPONSE_STATUS = "response_status_changed"
CHANGE_RESPONSE_TITLE = "response_title_changed"
CHANGE_FINAL_URL = "final_url_changed"
CHANGE_HEADERS_AVAILABLE = "header_evidence_became_available"
CHANGE_HEADERS_UNAVAILABLE = "header_evidence_became_unavailable"
CHANGE_HEADER_PRESENCE = "selected_header_presence_changed"
CHANGE_CANDIDATE_NEW = "candidate_new"
CHANGE_CANDIDATE_GONE = "candidate_no_longer_emitted"
CHANGE_HTTP_COVERAGE = "http_observation_coverage_changed"
CHANGE_HEADER_COVERAGE = "header_evidence_coverage_changed"
CHANGE_NO_RESULT_COUNT = "no_result_count_changed"
CHANGE_SCOPE = "scope_changed"
CHANGE_CAPABILITY = "capability_manifest_changed"
CHANGE_REGRESSION_HSTS = "regression_hsts_lost"
CHANGE_REGRESSION_RESOLVED = "regression_resolved_condition_reappeared"
CHANGE_REGRESSION_HEADER_EVIDENCE = "regression_header_evidence_lost"

_M10_EVENT_TYPES = frozenset(
    {
        "asset.new_since_previous",
        "asset.no_longer_observed",
        "asset.response_changed",
    }
)
_M10_OBSERVATION_TYPES = frozenset(
    {
        "asset_new_since_previous",
        "asset_no_longer_observed",
        "asset_response_changed",
    }
)


def _norm_host(value: Any) -> str:
    return str(value or "").lower().rstrip(".")


def _norm_title(value: Any) -> str:
    return " ".join(str(value or "").split())


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _sorted_hosts(hosts: set[str] | list[str]) -> list[str]:
    return sorted({_norm_host(item) for item in hosts if _norm_host(item)})


def _canonical_exclusions(values: Any) -> list[str]:
    return _sorted_hosts(list(values or []))


def _scope_identity(contract: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _norm_host(contract.get("scope_root")),
        bool(contract.get("include_subdomains")),
        tuple(_canonical_exclusions(contract.get("exclusions"))),
        str(contract.get("testing_profile") or "safe_production"),
    )


def _candidate_tuple(item: dict[str, Any]) -> tuple[str, str]:
    return (_norm_host(item.get("hostname")), str(item.get("candidate_type") or ""))


def _candidate_set(snapshot: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        _candidate_tuple(item)
        for item in (snapshot.get("emitted_candidates") or [])
        if _candidate_tuple(item)[0] and _candidate_tuple(item)[1]
    }


def _gap_reason(snapshot: dict[str, Any], hostname: str) -> str | None:
    gaps = snapshot.get("gaps") or {}
    row = gaps.get(hostname) or {}
    reason = row.get("reason_code")
    return str(reason) if reason else None


def _no_result_count(snapshot: dict[str, Any]) -> int:
    gaps = snapshot.get("gaps") or {}
    return sum(
        1
        for row in gaps.values()
        if isinstance(row, dict) and row.get("reason_code") == REASON_PROBE_NO_RESULT
    )


def _truncated(snapshot: dict[str, Any]) -> bool:
    contract = snapshot.get("contract") or {}
    return bool(contract.get("discovery_truncated"))


def previous_completed_operation(
    db: Session, *, operation: Operation
) -> Operation | None:
    return db.scalar(
        select(Operation)
        .options(joinedload(Operation.control_snapshot))
        .where(
            Operation.organization_id == operation.organization_id,
            Operation.target_id == operation.target_id,
            Operation.testing_profile == operation.testing_profile,
            Operation.status == "completed",
            Operation.id != operation.id,
        )
        .order_by(Operation.completed_at.desc().nullslast(), Operation.created_at.desc())
        .limit(1)
    )


def _http_evidence_from_observation(row: DiscoveryObservation) -> dict[str, Any] | None:
    meta = row.observation_metadata or {}
    host = _norm_host(meta.get("hostname"))
    if not host:
        return None
    status_code = meta.get("status_code")
    try:
        status_int = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_int = None
    headers = meta.get("headers") if isinstance(meta.get("headers"), dict) else {}
    present = meta.get("headers_present") if isinstance(meta.get("headers_present"), list) else []
    headers_observed = meta.get("headers_observed") is True
    redirected = bool(meta.get("redirected"))
    scheme = str(meta.get("scheme") or "").lower() or None
    content_type = meta.get("content_type") if isinstance(meta.get("content_type"), str) else None
    hsts = None
    if headers_observed:
        hsts = hsts_header_present(
            {str(k).lower(): str(v) for k, v in headers.items()},
            [str(item) for item in present],
        )
    applicable = bool(
        headers_observed
        and not redirected
        and is_https_html_success(
            scheme=scheme, content_type=content_type, status_code=status_int
        )
    )
    return {
        "status_code": status_int,
        "title": _norm_title(meta.get("title")),
        "final_url": str(meta.get("final_url") or meta.get("url") or "")[:2048],
        "headers_observed": headers_observed,
        "redirected": redirected,
        "content_type": content_type,
        "scheme": scheme,
        "hsts_present": hsts,
        "hsts_applicable": applicable,
    }


def build_comparison_snapshot(
    db: Session,
    operation: Operation,
    *,
    security_signals_complete: bool = True,
) -> dict[str, Any]:
    """Immutable semantic state for this operation. Unchanged facts are included."""
    coverage = compute_discovery_coverage(db, operation)
    surface = coverage.get("surface") or {}
    hostnames = surface.get("hostnames") or {}
    discovered = _sorted_hosts(hostnames.get("in_scope_discovered") or [])
    submitted = _sorted_hosts(hostnames.get("submitted_for_http_observation") or [])
    http_observed = _sorted_hosts(hostnames.get("http_observation_obtained") or [])
    gaps: dict[str, dict[str, str]] = {}
    for item in hostnames.get("http_observation_not_obtained") or []:
        if not isinstance(item, dict):
            continue
        host = _norm_host(item.get("hostname"))
        if not host:
            continue
        reason = str(item.get("reason_code") or REASON_PROBE_NO_RESULT)
        gaps[host] = {
            "reason_code": reason,
            "explanation": str(item.get("explanation") or explanation_for(reason)),
        }
    for item in hostnames.get("incomplete") or []:
        if not isinstance(item, dict):
            continue
        host = _norm_host(item.get("hostname"))
        if not host or host in gaps:
            continue
        reason = str(item.get("reason_code") or "observation_incomplete")
        gaps[host] = {
            "reason_code": reason,
            "explanation": str(item.get("explanation") or explanation_for(reason)),
        }

    observations = list(
        db.scalars(
            select(DiscoveryObservation).where(
                DiscoveryObservation.operation_id == operation.id,
                DiscoveryObservation.observation_type == OBSERVATION_HTTP,
            )
        ).all()
    )
    http_evidence: dict[str, dict[str, Any]] = {}
    for row in observations:
        payload = _http_evidence_from_observation(row)
        if payload is None:
            continue
        host = _norm_host((row.observation_metadata or {}).get("hostname"))
        if host not in http_observed:
            continue
        http_evidence[host] = payload

    emitted: list[dict[str, str]] = []
    if security_signals_complete:
        candidates = list(
            db.scalars(
                select(SecurityCandidate)
                .options(joinedload(SecurityCandidate.asset))
                .where(
                    SecurityCandidate.organization_id == operation.organization_id,
                    SecurityCandidate.operation_id == operation.id,
                )
            ).all()
        )
        for row in candidates:
            host = _norm_host(getattr(row.asset, "hostname", None))
            ctype = str(row.candidate_type or "")
            if host and ctype:
                emitted.append({"hostname": host, "candidate_type": ctype})
        emitted.sort(key=lambda item: (item["hostname"], item["candidate_type"]))

    snapshot = getattr(operation, "control_snapshot", None)
    scope_boundaries = coverage.get("scope_boundaries") or {}
    capability = dict(coverage.get("capability_snapshot") or manifest_snapshot())
    contract = {
        "scope_root": _norm_host(
            getattr(snapshot, "scope_root", None) or getattr(snapshot, "target_domain", None)
        ),
        "include_subdomains": bool(getattr(snapshot, "include_subdomains", False))
        if snapshot
        else bool(scope_boundaries.get("include_subdomains")),
        "exclusions": _canonical_exclusions(
            getattr(snapshot, "exclusions", None)
            if snapshot is not None
            else scope_boundaries.get("configured_exclusions")
        ),
        "testing_profile": str(
            getattr(snapshot, "testing_profile", None)
            or operation.testing_profile
            or "safe_production"
        ),
        "capability_manifest_version": int(
            coverage.get("capability_manifest_version") or MANIFEST_VERSION
        ),
        "capability_snapshot": capability,
        "discovery_truncated": bool(scope_boundaries.get("discovery_truncated")),
        "truncated_from": scope_boundaries.get("truncated_from"),
        "truncated_to": scope_boundaries.get("truncated_to"),
        "operation_source": str(operation.source or "manual"),
    }
    return {
        "schema_version": COMPARISON_SNAPSHOT_SCHEMA_VERSION,
        "operation_id": str(operation.id),
        "security_signals_complete": bool(security_signals_complete),
        "discovered": discovered,
        "submitted": submitted,
        "http_observed": http_observed,
        "gaps": gaps,
        "http_evidence": http_evidence,
        "emitted_candidates": emitted if security_signals_complete else [],
        "contract": contract,
    }


def reconstruct_pre_m18_snapshot(db: Session, operation: Operation) -> dict[str, Any]:
    """Surface/evidence only. Candidate history is not treated as reliable."""
    snapshot = build_comparison_snapshot(db, operation, security_signals_complete=False)
    snapshot["security_signals_complete"] = False
    snapshot["emitted_candidates"] = []
    contract = dict(snapshot.get("contract") or {})
    contract["capability_manifest_version"] = None
    snapshot["contract"] = contract
    return snapshot


def _change(
    *,
    category: str,
    change_type: str,
    significance: str,
    match_key: str | None,
    before: Any = None,
    after: Any = None,
    explanation: str,
) -> dict[str, Any]:
    return {
        "category": category,
        "change_type": change_type,
        "significance": significance,
        "match_key": match_key,
        "before": before,
        "after": after,
        "explanation": explanation,
    }


def _coverage_metric(
    *,
    change_type: str,
    before_n: int,
    before_d: int,
    after_n: int,
    after_d: int,
    truncated: bool,
    explanation: str,
) -> dict[str, Any] | None:
    if (before_n, before_d) == (after_n, after_d):
        return None
    direction = None
    if not truncated and before_d > 0 and after_d > 0:
        before_ratio = before_n / before_d
        after_ratio = after_n / after_d
        if after_ratio > before_ratio:
            direction = "improved"
        elif after_ratio < before_ratio:
            direction = "degraded"
        else:
            direction = "unchanged"
    return _change(
        category=CATEGORY_COVERAGE,
        change_type=change_type,
        significance=SIGNIFICANCE_COVERAGE,
        match_key=change_type,
        before={"numerator": before_n, "denominator": before_d},
        after={"numerator": after_n, "denominator": after_d, "direction": direction},
        explanation=explanation,
    )


def classify_comparability(
    *,
    current: Operation,
    current_snapshot: dict[str, Any],
    baseline: Operation | None,
    baseline_snapshot: dict[str, Any] | None,
) -> str:
    if current.status != "completed":
        return COMPARABILITY_CURRENT_INCOMPLETE
    if baseline is None:
        return COMPARABILITY_NO_BASELINE
    if baseline_snapshot is None:
        return COMPARABILITY_BASELINE_COVERAGE_UNAVAILABLE
    current_contract = current_snapshot.get("contract") or {}
    baseline_contract = baseline_snapshot.get("contract") or {}
    if _scope_identity(current_contract) != _scope_identity(baseline_contract):
        return COMPARABILITY_NOT_COMPARABLE_SCOPE
    current_version = current_contract.get("capability_manifest_version")
    baseline_version = baseline_contract.get("capability_manifest_version")
    if (
        current_version is not None
        and baseline_version is not None
        and int(current_version) != int(baseline_version)
    ):
        return COMPARABILITY_PARTIAL_CAPABILITY
    return COMPARABILITY_COMPARABLE


def resolved_condition_reappeared(
    db: Session,
    *,
    operation: Operation,
    emitted: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    if not emitted or operation.started_at is None:
        return []
    started = operation.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    rows = list(
        db.scalars(
            select(Finding)
            .options(joinedload(Finding.candidate).joinedload(SecurityCandidate.asset))
            .where(
                Finding.organization_id == operation.organization_id,
                Finding.resolved_at.is_not(None),
            )
        ).all()
    )
    changes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for finding in rows:
        if finding.resolved_at is None:
            continue
        resolved_at = finding.resolved_at
        if resolved_at.tzinfo is None:
            resolved_at = resolved_at.replace(tzinfo=timezone.utc)
        if resolved_at > started:
            continue
        candidate = finding.candidate
        asset = getattr(candidate, "asset", None) if candidate is not None else None
        host = _norm_host(getattr(asset, "hostname", None))
        ctype = str(getattr(candidate, "candidate_type", None) or "")
        key = (host, ctype)
        if key not in emitted or key in seen:
            continue
        seen.add(key)
        changes.append(
            _change(
                category=CATEGORY_REGRESSION,
                change_type=CHANGE_REGRESSION_RESOLVED,
                significance=SIGNIFICANCE_REGRESSION,
                match_key=f"{host}|{ctype}",
                before={"status": "resolved", "resolved_at": _iso(finding.resolved_at)},
                after={"hostname": host, "candidate_type": ctype, "emitted": True},
                explanation=(
                    f"A finding for {host}/{ctype} was resolved before this operation "
                    "started, and the same semantic candidate was emitted again."
                ),
            )
        )
    return changes


def diff_snapshots(
    *,
    current: dict[str, Any],
    baseline: dict[str, Any] | None,
    comparability: str,
    include_security_signals: bool,
) -> list[dict[str, Any]]:
    if baseline is None or comparability in {
        COMPARABILITY_NO_BASELINE,
        COMPARABILITY_CURRENT_INCOMPLETE,
        COMPARABILITY_BASELINE_COVERAGE_UNAVAILABLE,
    }:
        return []

    current_contract = current.get("contract") or {}
    baseline_contract = baseline.get("contract") or {}
    changes: list[dict[str, Any]] = []

    if comparability == COMPARABILITY_NOT_COMPARABLE_SCOPE:
        changes.append(
            _change(
                category=CATEGORY_CONTRACT,
                change_type=CHANGE_SCOPE,
                significance=SIGNIFICANCE_FACT,
                match_key="scope",
                before={
                    "scope_root": baseline_contract.get("scope_root"),
                    "include_subdomains": baseline_contract.get("include_subdomains"),
                    "exclusions": list(baseline_contract.get("exclusions") or []),
                },
                after={
                    "scope_root": current_contract.get("scope_root"),
                    "include_subdomains": current_contract.get("include_subdomains"),
                    "exclusions": list(current_contract.get("exclusions") or []),
                },
                explanation=(
                    "Authorization scope changed. Scout did not compare surfaces "
                    "because the runs did not measure the same authorized set."
                ),
            )
        )
        return changes

    if comparability == COMPARABILITY_PARTIAL_CAPABILITY:
        changes.append(
            _change(
                category=CATEGORY_CONTRACT,
                change_type=CHANGE_CAPABILITY,
                significance=SIGNIFICANCE_FACT,
                match_key="capability",
                before={"version": baseline_contract.get("capability_manifest_version")},
                after={"version": current_contract.get("capability_manifest_version")},
                explanation=(
                    "Capability manifest version changed. Security-signal comparison "
                    "is suppressed so a detector change is not treated as an "
                    "application change."
                ),
            )
        )

    current_discovered = set(current.get("discovered") or [])
    baseline_discovered = set(baseline.get("discovered") or [])
    current_http = set(current.get("http_observed") or [])
    baseline_http = set(baseline.get("http_observed") or [])
    current_evidence = dict(current.get("http_evidence") or {})
    baseline_evidence = dict(baseline.get("http_evidence") or {})

    for host in sorted(current_discovered - baseline_discovered):
        changes.append(
            _change(
                category=CATEGORY_SURFACE,
                change_type=CHANGE_HOSTNAME_NEWLY_DISCOVERED,
                significance=SIGNIFICANCE_FACT,
                match_key=host,
                before=None,
                after={"hostname": host, "http_observed": host in current_http},
                explanation=f"Hostname newly discovered in scope: {host}.",
            )
        )
    for host in sorted(baseline_discovered - current_discovered):
        changes.append(
            _change(
                category=CATEGORY_SURFACE,
                change_type=CHANGE_HOSTNAME_NO_LONGER_DISCOVERED,
                significance=SIGNIFICANCE_FACT,
                match_key=host,
                before={"hostname": host, "http_observed": host in baseline_http},
                after=None,
                explanation=f"Hostname no longer discovered in scope: {host}.",
            )
        )

    both = current_discovered & baseline_discovered
    for host in sorted(both):
        in_current = host in current_http
        in_baseline = host in baseline_http
        if in_current and not in_baseline:
            changes.append(
                _change(
                    category=CATEGORY_SURFACE,
                    change_type=CHANGE_HTTP_OBSERVATION_GAINED,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"reason_code": _gap_reason(baseline, host)},
                    after={"hostname": host},
                    explanation=f"HTTP observation gained for still-in-scope hostname {host}.",
                )
            )
        elif in_baseline and not in_current:
            reason = _gap_reason(current, host) or REASON_PROBE_NO_RESULT
            changes.append(
                _change(
                    category=CATEGORY_SURFACE,
                    change_type=CHANGE_HTTP_OBSERVATION_LOST,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"hostname": host},
                    after={"reason_code": reason, "explanation": explanation_for(reason)},
                    explanation=(
                        f"HTTP observation lost for still-in-scope hostname {host} "
                        f"({reason})."
                    ),
                )
            )

        if not (in_current and in_baseline):
            continue
        left = baseline_evidence.get(host) or {}
        right = current_evidence.get(host) or {}
        if left.get("status_code") != right.get("status_code"):
            changes.append(
                _change(
                    category=CATEGORY_EVIDENCE,
                    change_type=CHANGE_RESPONSE_STATUS,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"status_code": left.get("status_code")},
                    after={"status_code": right.get("status_code")},
                    explanation=f"HTTP status changed for {host}.",
                )
            )
        if _norm_title(left.get("title")) != _norm_title(right.get("title")):
            changes.append(
                _change(
                    category=CATEGORY_EVIDENCE,
                    change_type=CHANGE_RESPONSE_TITLE,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"title": left.get("title")},
                    after={"title": right.get("title")},
                    explanation=f"HTTP title changed for {host}.",
                )
            )
        if str(left.get("final_url") or "") != str(right.get("final_url") or ""):
            changes.append(
                _change(
                    category=CATEGORY_EVIDENCE,
                    change_type=CHANGE_FINAL_URL,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"final_url": left.get("final_url")},
                    after={"final_url": right.get("final_url")},
                    explanation=f"Final URL changed for {host}.",
                )
            )
        left_headers = left.get("headers_observed") is True
        right_headers = right.get("headers_observed") is True
        if right_headers and not left_headers:
            changes.append(
                _change(
                    category=CATEGORY_EVIDENCE,
                    change_type=CHANGE_HEADERS_AVAILABLE,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"headers_observed": False},
                    after={"headers_observed": True},
                    explanation=f"Header evidence became available for {host}.",
                )
            )
        if left_headers and not right_headers:
            changes.append(
                _change(
                    category=CATEGORY_EVIDENCE,
                    change_type=CHANGE_HEADERS_UNAVAILABLE,
                    significance=SIGNIFICANCE_FACT,
                    match_key=host,
                    before={"headers_observed": True},
                    after={"headers_observed": False},
                    explanation=f"Header evidence became unavailable for {host}.",
                )
            )
            changes.append(
                _change(
                    category=CATEGORY_REGRESSION,
                    change_type=CHANGE_REGRESSION_HEADER_EVIDENCE,
                    significance=SIGNIFICANCE_REGRESSION,
                    match_key=host,
                    before={"headers_observed": True},
                    after={"headers_observed": False},
                    explanation=(
                        f"Previously captured header evidence for {host} is no longer "
                        "available."
                    ),
                )
            )
        if left_headers and right_headers:
            left_applicable = left.get("hsts_applicable") is True
            right_applicable = right.get("hsts_applicable") is True
            if left.get("hsts_present") != right.get("hsts_present"):
                changes.append(
                    _change(
                        category=CATEGORY_EVIDENCE,
                        change_type=CHANGE_HEADER_PRESENCE,
                        significance=SIGNIFICANCE_FACT,
                        match_key=host,
                        before={"hsts_present": left.get("hsts_present")},
                        after={"hsts_present": right.get("hsts_present")},
                        explanation=(
                            f"Selected security-header presence changed for {host}."
                        ),
                    )
                )
            if (
                left_applicable
                and right_applicable
                and left.get("hsts_present") is True
                and right.get("hsts_present") is False
            ):
                changes.append(
                    _change(
                        category=CATEGORY_REGRESSION,
                        change_type=CHANGE_REGRESSION_HSTS,
                        significance=SIGNIFICANCE_REGRESSION,
                        match_key=host,
                        before={"hsts_present": True},
                        after={"hsts_present": False},
                        explanation=(
                            f"Applicable Strict-Transport-Security was present on {host} "
                            "and is now absent."
                        ),
                    )
                )

    truncated = _truncated(current) or _truncated(baseline)
    http_cov = _coverage_metric(
        change_type=CHANGE_HTTP_COVERAGE,
        before_n=len(baseline_http),
        before_d=len(baseline_discovered),
        after_n=len(current_http),
        after_d=len(current_discovered),
        truncated=truncated,
        explanation="HTTP observation coverage changed (obtained / in-scope discovered).",
    )
    if http_cov is not None:
        changes.append(http_cov)

    def _headers_captured(snapshot: dict[str, Any], observed: set[str]) -> int:
        evidence = snapshot.get("http_evidence") or {}
        return sum(
            1
            for host in observed
            if (evidence.get(host) or {}).get("headers_observed") is True
        )

    header_cov = _coverage_metric(
        change_type=CHANGE_HEADER_COVERAGE,
        before_n=_headers_captured(baseline, baseline_http),
        before_d=len(baseline_http),
        after_n=_headers_captured(current, current_http),
        after_d=len(current_http),
        truncated=truncated,
        explanation="Header-capture coverage changed (captured / HTTP observations).",
    )
    if header_cov is not None:
        changes.append(header_cov)

    before_nr = _no_result_count(baseline)
    after_nr = _no_result_count(current)
    if before_nr != after_nr:
        direction = None
        if not truncated:
            if after_nr < before_nr:
                direction = "improved"
            elif after_nr > before_nr:
                direction = "degraded"
        changes.append(
            _change(
                category=CATEGORY_COVERAGE,
                change_type=CHANGE_NO_RESULT_COUNT,
                significance=SIGNIFICANCE_COVERAGE,
                match_key=CHANGE_NO_RESULT_COUNT,
                before={"count": before_nr},
                after={"count": after_nr, "direction": direction},
                explanation="Count of probe_no_result hostnames changed.",
            )
        )

    if include_security_signals:
        current_keys = _candidate_set(current)
        baseline_keys = _candidate_set(baseline)
        for host, ctype in sorted(current_keys - baseline_keys):
            changes.append(
                _change(
                    category=CATEGORY_SIGNAL,
                    change_type=CHANGE_CANDIDATE_NEW,
                    significance=SIGNIFICANCE_FACT,
                    match_key=f"{host}|{ctype}",
                    before=None,
                    after={"hostname": host, "candidate_type": ctype},
                    explanation=f"Candidate newly emitted: {host}/{ctype}.",
                )
            )
        for host, ctype in sorted(baseline_keys - current_keys):
            changes.append(
                _change(
                    category=CATEGORY_SIGNAL,
                    change_type=CHANGE_CANDIDATE_GONE,
                    significance=SIGNIFICANCE_FACT,
                    match_key=f"{host}|{ctype}",
                    before={"hostname": host, "candidate_type": ctype},
                    after=None,
                    explanation=f"Candidate no longer emitted: {host}/{ctype}.",
                )
            )
    return changes


def _counts_from_changes(changes: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for row in changes:
        key = str(row.get("change_type") or "")
        if not key:
            continue
        counts[key] = int(counts.get(key) or 0) + 1
    counts["regressions"] = sum(
        1 for row in changes if row.get("significance") == SIGNIFICANCE_REGRESSION
    )
    return counts


def build_headline(
    *,
    comparability: str,
    changes: list[dict[str, Any]],
    security_signal_baseline_unavailable: bool,
    security_signal_comparison_suppressed: bool,
) -> str:
    if comparability == COMPARABILITY_NO_BASELINE:
        text = "No previous comparable completed operation."
    elif comparability == COMPARABILITY_CURRENT_INCOMPLETE:
        text = (
            "This run did not complete. It is not a comparable baseline or a full diff."
        )
    elif comparability == COMPARABILITY_NOT_COMPARABLE_SCOPE:
        text = (
            "Scout did not compare surfaces because authorization scope changed."
        )
    elif comparability == COMPARABILITY_BASELINE_COVERAGE_UNAVAILABLE:
        text = "The previous completed operation has no usable comparison snapshot."
    elif comparability == COMPARABILITY_PARTIAL_CAPABILITY:
        text = (
            "Capability manifest version changed. Factual surface and HTTP evidence "
            "were compared; security-signal comparison was suppressed."
        )
    elif not changes:
        text = "No changes versus the previous comparable completed operation."
    else:
        regressions = sum(
            1 for row in changes if row.get("significance") == SIGNIFICANCE_REGRESSION
        )
        facts = len(changes) - regressions
        text = (
            f"{facts} factual change(s) versus the previous comparable completed operation."
        )
        if regressions:
            text += f" {regressions} conservative security-significant regression(s)."
    if security_signal_baseline_unavailable:
        text += (
            " Security-signal comparison was unavailable because the previous run "
            "has no immutable emitted-candidate snapshot."
        )
    if security_signal_comparison_suppressed and comparability != COMPARABILITY_PARTIAL_CAPABILITY:
        text += " Security-signal comparison was suppressed."
    if CLEARANCE_HEADLINE_RE.search(text):
        raise ValueError("diff headline must not imply a security clearance")
    return text


def compute_operation_diff(
    db: Session,
    operation: Operation,
    *,
    security_signals_complete: bool = True,
) -> dict[str, Any]:
    current_snapshot = build_comparison_snapshot(
        db, operation, security_signals_complete=security_signals_complete
    )
    baseline = None
    baseline_snapshot = None
    security_signal_baseline_unavailable = False
    security_signal_comparison_suppressed = False
    suppression_reason = None

    if operation.status == "completed":
        baseline = previous_completed_operation(db, operation=operation)
        if baseline is not None:
            baseline_row = db.scalar(
                select(OperationDiffSummary).where(
                    OperationDiffSummary.operation_id == baseline.id
                )
            )
            if baseline_row is not None:
                baseline_snapshot = dict(baseline_row.comparison_snapshot or {})
                if not baseline_snapshot.get("security_signals_complete"):
                    security_signal_baseline_unavailable = True
            else:
                baseline_snapshot = reconstruct_pre_m18_snapshot(db, baseline)
                security_signal_baseline_unavailable = True

    comparability = classify_comparability(
        current=operation,
        current_snapshot=current_snapshot,
        baseline=baseline,
        baseline_snapshot=baseline_snapshot,
    )
    include_signals = (
        comparability == COMPARABILITY_COMPARABLE
        and not security_signal_baseline_unavailable
        and bool(current_snapshot.get("security_signals_complete"))
    )
    if comparability == COMPARABILITY_PARTIAL_CAPABILITY:
        security_signal_comparison_suppressed = True
        suppression_reason = (
            "Capability manifest version differs; detector semantics are not proven identical."
        )
        include_signals = False
    elif security_signal_baseline_unavailable and comparability in {
        COMPARABILITY_COMPARABLE,
        COMPARABILITY_PARTIAL_CAPABILITY,
    }:
        suppression_reason = (
            "Previous operation has no immutable emitted-candidate snapshot."
        )

    changes = diff_snapshots(
        current=current_snapshot,
        baseline=baseline_snapshot,
        comparability=comparability,
        include_security_signals=include_signals,
    )
    if include_signals:
        changes.extend(
            resolved_condition_reappeared(
                db,
                operation=operation,
                emitted=_candidate_set(current_snapshot),
            )
        )
    headline = build_headline(
        comparability=comparability,
        changes=changes,
        security_signal_baseline_unavailable=security_signal_baseline_unavailable,
        security_signal_comparison_suppressed=security_signal_comparison_suppressed,
    )
    counts = _counts_from_changes(changes)
    counts["comparability"] = comparability
    return {
        "schema_version": DIFF_SCHEMA_VERSION,
        "comparability": comparability,
        "baseline_operation_id": str(baseline.id) if baseline is not None else None,
        "baseline_completed_at": _iso(baseline.completed_at) if baseline is not None else None,
        "current_source": str(operation.source or "manual"),
        "baseline_source": str(baseline.source) if baseline is not None else None,
        "comparison_snapshot": current_snapshot,
        "changes": changes,
        "counts": counts,
        "headline": headline,
        "security_signal_baseline_unavailable": security_signal_baseline_unavailable,
        "security_signal_comparison_suppressed": security_signal_comparison_suppressed,
        "security_signal_suppression_reason": suppression_reason,
        "operation_status_at_freeze": operation.status,
    }


def freeze_operation_diff(
    db: Session,
    operation: Operation,
    *,
    source: str = "frozen",
    actor_type: str = "worker",
) -> OperationDiffSummary | None:
    if operation.status not in TERMINAL_STATUSES:
        return None
    existing = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if existing is not None:
        return existing
    # Crash/GET recovery of a missing snapshot cannot prove the original
    # emitted-candidate set. Persist surface/evidence only.
    persist_signals = source != "recovered"
    computed = compute_operation_diff(
        db, operation, security_signals_complete=persist_signals
    )
    baseline_id = computed["baseline_operation_id"]
    values = {
        "id": uuid.uuid4(),
        "operation_id": operation.id,
        "organization_id": operation.organization_id,
        "target_id": operation.target_id,
        "baseline_operation_id": UUID(baseline_id) if baseline_id else None,
        "schema_version": DIFF_SCHEMA_VERSION,
        "comparability": computed["comparability"],
        "comparison_snapshot": computed["comparison_snapshot"],
        "changes": computed["changes"],
        "counts": computed["counts"],
        "headline": computed["headline"],
        "security_signal_baseline_unavailable": computed[
            "security_signal_baseline_unavailable"
        ],
        "security_signal_comparison_suppressed": computed[
            "security_signal_comparison_suppressed"
        ],
        "security_signal_suppression_reason": computed[
            "security_signal_suppression_reason"
        ],
        "operation_status_at_freeze": operation.status,
        "source": source,
        "frozen_at": datetime.now(timezone.utc),
    }
    db.execute(
        pg_insert(OperationDiffSummary)
        .values(**values)
        .on_conflict_do_nothing(index_elements=["operation_id"])
    )
    db.flush()
    row = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if row is not None and row.id == values["id"]:
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type=actor_type,
            actor_user_id=operation.created_by_user_id,
            action="diff.frozen",
            resource_type="operation",
            resource_id=operation.id,
            summary="Operation comparison snapshot and diff frozen.",
            metadata={
                "operation_id": str(operation.id),
                "status": operation.status,
                "source": source,
                "reason": computed["comparability"],
            },
        )
    return row


def follow_up_findings(
    db: Session, operation: Operation, row: OperationDiffSummary
) -> list[dict[str, Any]]:
    frozen_at = row.frozen_at
    if frozen_at is None:
        return []
    if frozen_at.tzinfo is None:
        frozen_at = frozen_at.replace(tzinfo=timezone.utc)
    snapshot = dict(row.comparison_snapshot or {})
    emitted = _candidate_set(snapshot)
    discovered = set(snapshot.get("discovered") or [])
    findings = list(
        db.scalars(
            select(Finding)
            .options(joinedload(Finding.candidate).joinedload(SecurityCandidate.asset))
            .where(Finding.organization_id == operation.organization_id)
        ).all()
    )
    items: list[dict[str, Any]] = []
    for finding in findings:
        candidate = finding.candidate
        asset = getattr(candidate, "asset", None) if candidate is not None else None
        host = _norm_host(getattr(asset, "hostname", None))
        ctype = str(getattr(candidate, "candidate_type", None) or "")
        if (host, ctype) not in emitted and host not in discovered:
            continue
        created = finding.created_at
        updated = finding.updated_at
        resolved = finding.resolved_at
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if updated is not None and updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if resolved is not None and resolved.tzinfo is None:
            resolved = resolved.replace(tzinfo=timezone.utc)
        if created is not None and created > frozen_at:
            kind = "finding_promoted_after_snapshot"
        elif resolved is not None and resolved > frozen_at:
            kind = "finding_resolved_after_snapshot"
        elif updated is not None and updated > frozen_at:
            kind = "finding_state_changed_after_snapshot"
        else:
            continue
        items.append(
            {
                "change_type": kind,
                "hostname": host,
                "candidate_type": ctype,
                "finding_id": str(finding.id),
                "status": finding.status,
                "created_at": _iso(finding.created_at),
                "updated_at": _iso(finding.updated_at),
                "resolved_at": _iso(finding.resolved_at),
            }
        )
    items.sort(key=lambda item: (item["hostname"], item["candidate_type"], item["change_type"]))
    return items


def diff_payload_from_snapshot(
    db: Session,
    operation: Operation,
    row: OperationDiffSummary,
) -> dict[str, Any]:
    baseline = None
    if row.baseline_operation_id is not None:
        baseline = db.get(Operation, row.baseline_operation_id)
    return {
        "schema_version": row.schema_version,
        "source": row.source,
        "frozen_at": _iso(row.frozen_at),
        "comparability": row.comparability,
        "baseline_operation_id": str(row.baseline_operation_id)
        if row.baseline_operation_id
        else None,
        "baseline_completed_at": _iso(baseline.completed_at) if baseline is not None else None,
        "current_source": str(operation.source or "manual"),
        "baseline_source": str(baseline.source) if baseline is not None else None,
        "operation_status_at_freeze": row.operation_status_at_freeze,
        "security_signal_baseline_unavailable": bool(
            row.security_signal_baseline_unavailable
        ),
        "security_signal_comparison_suppressed": bool(
            row.security_signal_comparison_suppressed
        ),
        "security_signal_suppression_reason": row.security_signal_suppression_reason,
        "headline": row.headline,
        "counts": dict(row.counts or {}),
        "changes": list(row.changes or []),
        "comparison_snapshot": dict(row.comparison_snapshot or {}),
        "follow_up_findings": follow_up_findings(db, operation, row),
    }


def latest_diff_counts(db: Session, *, target_id: UUID) -> dict[str, Any]:
    operation = db.scalar(
        select(Operation)
        .where(Operation.target_id == target_id, Operation.status == "completed")
        .order_by(Operation.completed_at.desc().nullslast())
        .limit(1)
    )
    empty = {
        "comparability": COMPARABILITY_NO_BASELINE,
        "hostname_newly_discovered": 0,
        "hostname_no_longer_discovered": 0,
        "http_observation_gained": 0,
        "http_observation_lost": 0,
        "regressions": 0,
    }
    if operation is None:
        return empty
    row = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if row is None:
        return empty
    counts = dict(row.counts or {})
    counts.setdefault("comparability", row.comparability)
    counts.setdefault(
        "hostname_newly_discovered",
        counts.get(CHANGE_HOSTNAME_NEWLY_DISCOVERED, 0),
    )
    counts.setdefault(
        "hostname_no_longer_discovered",
        counts.get(CHANGE_HOSTNAME_NO_LONGER_DISCOVERED, 0),
    )
    counts.setdefault("http_observation_gained", counts.get(CHANGE_HTTP_OBSERVATION_GAINED, 0))
    counts.setdefault("http_observation_lost", counts.get(CHANGE_HTTP_OBSERVATION_LOST, 0))
    counts.setdefault("regressions", counts.get("regressions", 0))
    return counts

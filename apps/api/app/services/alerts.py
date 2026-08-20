"""Deterministic alerts from frozen M18 snapshots. Never from live Candidate rows."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.alert import (
    Alert,
    AlertEpisode,
    AlertGenerationReceipt,
    AlertUserState,
    NotificationOutbox,
)
from app.models.diff import OperationDiffSummary
from app.models.operation import Operation
from app.models.organization import OrganizationMembership
from app.models.target import AuthorizedTarget
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_actor_org, merge_auth_audit
from app.services.coverage import (
    EXPLICIT_PROBE_OUTCOMES,
    REASON_PROBE_NO_RESULT,
    TERMINAL_STATUSES,
)
from app.services.notification_runtime import enqueue_email_outbox
from app.services.diff import (
    CHANGE_CAPABILITY,
    CHANGE_CANDIDATE_GONE,
    CHANGE_CANDIDATE_NEW,
    CHANGE_FINAL_URL,
    CHANGE_HEADER_COVERAGE,
    CHANGE_HEADER_PRESENCE,
    CHANGE_HEADERS_AVAILABLE,
    CHANGE_HEADERS_UNAVAILABLE,
    CHANGE_HOSTNAME_NEWLY_DISCOVERED,
    CHANGE_HOSTNAME_NO_LONGER_DISCOVERED,
    CHANGE_HTTP_COVERAGE,
    CHANGE_HTTP_OBSERVATION_GAINED,
    CHANGE_HTTP_OBSERVATION_LOST,
    CHANGE_NO_RESULT_COUNT,
    CHANGE_REGRESSION_HEADER_EVIDENCE,
    CHANGE_REGRESSION_HSTS,
    CHANGE_REGRESSION_RESOLVED,
    CHANGE_RESPONSE_STATUS,
    CHANGE_RESPONSE_TITLE,
    CHANGE_SCOPE,
    COMPARABILITY_COMPARABLE,
    COMPARABILITY_CURRENT_INCOMPLETE,
    COMPARABILITY_NOT_COMPARABLE_SCOPE,
    COMPARABILITY_PARTIAL_CAPABILITY,
)

ALERT_SCHEMA_VERSION = 1
DISCLAIMER = (
    "Alerts are monitoring notifications. Zero alerts does not mean this "
    "application is secure."
)

CATEGORY_SECURITY = "security_regression"
CATEGORY_COVERAGE = "coverage_degradation"
CATEGORY_INFO = "informational"

PRIORITY_MEDIUM = "medium"
PRIORITY_LOW = "low"
PRIORITY_INFO = "info"

ALERT_HSTS_LOST = "hsts_lost"
ALERT_RESOLVED_REAPPEARED = "resolved_condition_reappeared"
ALERT_HEADER_EVIDENCE_LOST = "header_evidence_lost"
ALERT_HTTP_COVERAGE = "http_observation_coverage_degraded"
ALERT_HEADER_COVERAGE = "header_evidence_coverage_degraded"
ALERT_HTTP_LOST_EXPLICIT = "http_observation_lost_explicit"
ALERT_SCOPE = "scope_not_comparable"
ALERT_CAPABILITY = "capability_comparison_suppressed"

STATE_ACTIVE = "active"
STATE_RESOLVED = "resolved"
STATE_UNKNOWN = "unknown"

CHANNEL_IN_APP = "in_app"
DESTINATION_ORG = "org"

_SILENT_CHANGE_TYPES = frozenset(
    {
        CHANGE_RESPONSE_TITLE,
        CHANGE_RESPONSE_STATUS,
        CHANGE_FINAL_URL,
        CHANGE_HOSTNAME_NEWLY_DISCOVERED,
        CHANGE_HOSTNAME_NO_LONGER_DISCOVERED,
        CHANGE_HTTP_OBSERVATION_GAINED,
        CHANGE_HEADERS_AVAILABLE,
        CHANGE_HEADER_PRESENCE,
        CHANGE_CANDIDATE_NEW,
        CHANGE_CANDIDATE_GONE,
        CHANGE_NO_RESULT_COUNT,
    }
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm_host(value: Any) -> str:
    return str(value or "").lower().rstrip(".")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _candidate_set(snapshot: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (_norm_host(item.get("hostname")), str(item.get("candidate_type") or ""))
        for item in (snapshot.get("emitted_candidates") or [])
        if _norm_host(item.get("hostname")) and item.get("candidate_type")
    }


def _gap_reason(snapshot: dict[str, Any], hostname: str) -> str | None:
    row = (snapshot.get("gaps") or {}).get(hostname) or {}
    reason = row.get("reason_code")
    return str(reason) if reason else None


def _http_evidence(snapshot: dict[str, Any], hostname: str) -> dict[str, Any]:
    return dict((snapshot.get("http_evidence") or {}).get(hostname) or {})


def _truncated(snapshot: dict[str, Any]) -> bool:
    return bool((snapshot.get("contract") or {}).get("discovery_truncated"))


def _http_coverage(snapshot: dict[str, Any]) -> tuple[int, int]:
    discovered = list(snapshot.get("discovered") or [])
    observed = list(snapshot.get("http_observed") or [])
    return len(observed), len(discovered)


def _header_coverage(snapshot: dict[str, Any]) -> tuple[int, int]:
    observed = [_norm_host(item) for item in (snapshot.get("http_observed") or [])]
    evidence = snapshot.get("http_evidence") or {}
    captured = sum(
        1 for host in observed if (evidence.get(host) or {}).get("headers_observed") is True
    )
    return captured, len(observed)


def semantic_key(
    alert_type: str, *, hostname: str = "", extra: str = ""
) -> str:
    host = _norm_host(hostname) or "-"
    token = str(extra or "-")
    return f"{alert_type}|{host}|{token}"


def _copy_text(title: str, summary: str) -> tuple[str, str]:
    lowered = f"{title} {summary}".lower()
    banned = ("vulnerabilit", "secure", "critical", "high risk", "cleared")
    if any(word in lowered for word in banned):
        raise ValueError("alert copy must not imply a vulnerability or clearance")
    return title, summary


def _policy_copy(alert_type: str, *, hostname: str, extra: str = "") -> tuple[str, str]:
    host = hostname or "this hostname"
    if alert_type == ALERT_HSTS_LOST:
        return _copy_text(
            f"Applicable HSTS is no longer present on {host}",
            (
                f"The previous comparable run observed applicable "
                f"Strict-Transport-Security on {host}; this run did not."
            ),
        )
    if alert_type == ALERT_RESOLVED_REAPPEARED:
        return _copy_text(
            f"A previously resolved condition was emitted again on {host}",
            (
                f"A finding for {host}/{extra} was resolved before this operation "
                "started, and the same semantic candidate was emitted again."
            ),
        )
    if alert_type == ALERT_HEADER_EVIDENCE_LOST:
        return _copy_text(
            f"Response-header evidence is no longer captured for {host}",
            (
                "Scout could not capture response-header evidence that was "
                "available on the previous comparable run."
            ),
        )
    if alert_type == ALERT_HTTP_COVERAGE:
        return _copy_text(
            "HTTP observation coverage declined versus the previous comparable run",
            "Fewer in-scope discovered hostnames produced usable HTTP observations.",
        )
    if alert_type == ALERT_HEADER_COVERAGE:
        return _copy_text(
            "Header-capture coverage declined versus the previous comparable run",
            "A smaller share of HTTP observations included captured response headers.",
        )
    if alert_type == ALERT_HTTP_LOST_EXPLICIT:
        return _copy_text(
            f"HTTP observation was not obtained for {host}",
            (
                f"The previous comparable run had an HTTP observation for {host}; "
                f"this run recorded {extra or 'an explicit probe failure'}."
            ),
        )
    if alert_type == ALERT_SCOPE:
        return _copy_text(
            "Authorization scope changed; surfaces were not compared",
            "Scout did not compare host surfaces because the authorized set changed.",
        )
    if alert_type == ALERT_CAPABILITY:
        return _copy_text(
            "Capability version changed; security-signal comparison was suppressed",
            (
                "Detector semantics are not proven identical across this capability "
                "boundary, so security-signal comparison was not performed."
            ),
        )
    raise ValueError(f"unknown alert_type: {alert_type}")


def _sanitized_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "hostname",
        "candidate_type",
        "reason_code",
        "change_type",
        "headers_observed",
        "hsts_present",
        "hsts_applicable",
        "redirected",
        "numerator",
        "denominator",
        "direction",
        "reference_numerator",
        "reference_denominator",
        "opening_numerator",
        "opening_denominator",
        "comparability",
        "baseline_operation_id",
        "match_key",
        "resolved_at",
        "status_code",
    }
    blocked = {"headers", "body", "raw", "cookie", "set-cookie", "authorization"}
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key in blocked or key not in allowed:
            continue
        if isinstance(value, dict):
            continue
        cleaned[key] = value
    return cleaned


def _open_episodes(
    db: Session, *, organization_id: UUID, target_id: UUID
) -> list[AlertEpisode]:
    return list(
        db.scalars(
            select(AlertEpisode).where(
                AlertEpisode.organization_id == organization_id,
                AlertEpisode.target_id == target_id,
                AlertEpisode.status == "open",
            )
        ).all()
    )


def _latest_closed_episode(
    db: Session, *, organization_id: UUID, target_id: UUID, semantic_key: str
) -> AlertEpisode | None:
    return db.scalar(
        select(AlertEpisode)
        .where(
            AlertEpisode.organization_id == organization_id,
            AlertEpisode.target_id == target_id,
            AlertEpisode.semantic_key == semantic_key,
            AlertEpisode.status == "closed",
        )
        .order_by(AlertEpisode.closed_at.desc().nullslast(), AlertEpisode.opened_at.desc())
        .limit(1)
    )


def evaluate_episode_state(
    *,
    episode: AlertEpisode,
    snapshot: dict[str, Any],
    comparability: str,
    security_signals_comparable: bool,
) -> str:
    alert_type = episode.alert_type
    evidence = dict(episode.opening_evidence or {})
    host = _norm_host(evidence.get("hostname"))
    if comparability == COMPARABILITY_CURRENT_INCOMPLETE:
        return STATE_UNKNOWN
    if comparability == COMPARABILITY_NOT_COMPARABLE_SCOPE:
        if alert_type == ALERT_SCOPE:
            return STATE_ACTIVE
        return STATE_UNKNOWN
    if comparability == COMPARABILITY_PARTIAL_CAPABILITY:
        if alert_type in {ALERT_HSTS_LOST, ALERT_RESOLVED_REAPPEARED}:
            return STATE_UNKNOWN
        if alert_type == ALERT_CAPABILITY:
            return STATE_ACTIVE
    if alert_type == ALERT_HSTS_LOST:
        if host not in set(snapshot.get("http_observed") or []):
            return STATE_UNKNOWN
        row = _http_evidence(snapshot, host)
        if row.get("headers_observed") is not True:
            return STATE_UNKNOWN
        if row.get("redirected") is True or row.get("hsts_applicable") is not True:
            return STATE_UNKNOWN
        if row.get("hsts_present") is False:
            return STATE_ACTIVE
        if row.get("hsts_present") is True:
            return STATE_RESOLVED
        return STATE_UNKNOWN
    if alert_type == ALERT_HEADER_EVIDENCE_LOST:
        if host not in set(snapshot.get("http_observed") or []):
            return STATE_UNKNOWN
        row = _http_evidence(snapshot, host)
        if row.get("headers_observed") is False:
            return STATE_ACTIVE
        if row.get("headers_observed") is True:
            return STATE_RESOLVED
        return STATE_UNKNOWN
    if alert_type == ALERT_RESOLVED_REAPPEARED:
        if comparability == COMPARABILITY_PARTIAL_CAPABILITY or not security_signals_comparable:
            return STATE_UNKNOWN
        if host not in set(snapshot.get("http_observed") or []):
            return STATE_UNKNOWN
        ctype = str(evidence.get("candidate_type") or "")
        if (host, ctype) in _candidate_set(snapshot):
            return STATE_ACTIVE
        return STATE_RESOLVED
    if alert_type in {ALERT_HTTP_COVERAGE, ALERT_HEADER_COVERAGE}:
        if _truncated(snapshot):
            return STATE_UNKNOWN
        current_n, current_d = (
            _http_coverage(snapshot)
            if alert_type == ALERT_HTTP_COVERAGE
            else _header_coverage(snapshot)
        )
        ref_n = evidence.get("reference_numerator")
        ref_d = evidence.get("reference_denominator")
        try:
            ref_n_i = int(ref_n)
            ref_d_i = int(ref_d)
        except (TypeError, ValueError):
            return STATE_UNKNOWN
        if current_d <= 0 or ref_d_i <= 0:
            return STATE_UNKNOWN
        current_ratio = current_n / current_d
        reference_ratio = ref_n_i / ref_d_i
        if current_ratio + 1e-12 >= reference_ratio:
            return STATE_RESOLVED
        return STATE_ACTIVE
    if alert_type == ALERT_HTTP_LOST_EXPLICIT:
        if host in set(snapshot.get("http_observed") or []):
            return STATE_RESOLVED
        if host not in set(snapshot.get("discovered") or []):
            return STATE_UNKNOWN
        reason = _gap_reason(snapshot, host)
        if reason in EXPLICIT_PROBE_OUTCOMES:
            return STATE_ACTIVE
        return STATE_UNKNOWN
    if alert_type == ALERT_SCOPE:
        if comparability == COMPARABILITY_NOT_COMPARABLE_SCOPE:
            return STATE_ACTIVE
        if comparability == COMPARABILITY_COMPARABLE:
            return STATE_RESOLVED
        return STATE_UNKNOWN
    if alert_type == ALERT_CAPABILITY:
        if comparability == COMPARABILITY_PARTIAL_CAPABILITY:
            return STATE_ACTIVE
        if comparability == COMPARABILITY_COMPARABLE:
            return STATE_RESOLVED
        return STATE_UNKNOWN
    return STATE_UNKNOWN


def _triggers_from_changes(
    *,
    changes: list[dict[str, Any]],
    snapshot: dict[str, Any],
    comparability: str,
    security_signal_baseline_unavailable: bool,
) -> list[dict[str, Any]]:
    by_host: dict[str, set[str]] = {}
    for row in changes:
        host = _norm_host(row.get("match_key"))
        if "|" in str(row.get("match_key") or ""):
            host = _norm_host(str(row.get("match_key")).split("|", 1)[0])
        by_host.setdefault(host, set()).add(str(row.get("change_type") or ""))

    triggers: list[dict[str, Any]] = []
    for row in changes:
        change_type = str(row.get("change_type") or "")
        if change_type in _SILENT_CHANGE_TYPES:
            continue
        match_key = str(row.get("match_key") or "")
        host = _norm_host(match_key.split("|", 1)[0] if "|" in match_key else match_key)
        host_types = by_host.get(host, set())

        if change_type == CHANGE_REGRESSION_HSTS:
            triggers.append(
                _trigger(
                    ALERT_HSTS_LOST,
                    CATEGORY_SECURITY,
                    PRIORITY_MEDIUM,
                    hostname=host,
                    extra="",
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        if change_type in {CHANGE_REGRESSION_HEADER_EVIDENCE, CHANGE_HEADERS_UNAVAILABLE}:
            triggers.append(
                _trigger(
                    ALERT_HEADER_EVIDENCE_LOST,
                    CATEGORY_COVERAGE,
                    PRIORITY_LOW,
                    hostname=host,
                    extra="",
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        if change_type == CHANGE_REGRESSION_RESOLVED:
            if security_signal_baseline_unavailable:
                continue
            ctype = str((row.get("after") or {}).get("candidate_type") or "")
            if "|" in match_key:
                ctype = match_key.split("|", 1)[1]
            triggers.append(
                _trigger(
                    ALERT_RESOLVED_REAPPEARED,
                    CATEGORY_SECURITY,
                    PRIORITY_MEDIUM,
                    hostname=host,
                    extra=ctype,
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        if change_type == CHANGE_HTTP_COVERAGE:
            direction = (row.get("after") or {}).get("direction")
            if direction != "degraded":
                continue
            triggers.append(
                _coverage_trigger(
                    ALERT_HTTP_COVERAGE,
                    row,
                    snapshot=snapshot,
                    comparability=comparability,
                    current_metric=_http_coverage(snapshot),
                )
            )
            continue
        if change_type == CHANGE_HEADER_COVERAGE:
            direction = (row.get("after") or {}).get("direction")
            if direction != "degraded":
                continue
            triggers.append(
                _coverage_trigger(
                    ALERT_HEADER_COVERAGE,
                    row,
                    snapshot=snapshot,
                    comparability=comparability,
                    current_metric=_header_coverage(snapshot),
                )
            )
            continue
        if change_type == CHANGE_HTTP_OBSERVATION_LOST:
            reason = str((row.get("after") or {}).get("reason_code") or "")
            if reason == REASON_PROBE_NO_RESULT or reason not in EXPLICIT_PROBE_OUTCOMES:
                continue
            triggers.append(
                _trigger(
                    ALERT_HTTP_LOST_EXPLICIT,
                    CATEGORY_COVERAGE,
                    PRIORITY_INFO,
                    hostname=host,
                    extra=reason,
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        if change_type == CHANGE_SCOPE:
            triggers.append(
                _trigger(
                    ALERT_SCOPE,
                    CATEGORY_INFO,
                    PRIORITY_INFO,
                    hostname="",
                    extra="",
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        if change_type == CHANGE_CAPABILITY:
            triggers.append(
                _trigger(
                    ALERT_CAPABILITY,
                    CATEGORY_INFO,
                    PRIORITY_INFO,
                    hostname="",
                    extra="",
                    change=row,
                    snapshot=snapshot,
                    comparability=comparability,
                )
            )
            continue
        _ = host_types
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for trigger in triggers:
        key = str(trigger["semantic_key"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(trigger)
    return unique


def _trigger(
    alert_type: str,
    category: str,
    priority: str,
    *,
    hostname: str,
    extra: str,
    change: dict[str, Any],
    snapshot: dict[str, Any],
    comparability: str,
) -> dict[str, Any]:
    title, summary = _policy_copy(alert_type, hostname=hostname, extra=extra)
    evidence = _sanitized_evidence(
        {
            "hostname": hostname or None,
            "candidate_type": extra if alert_type == ALERT_RESOLVED_REAPPEARED else None,
            "reason_code": extra if alert_type == ALERT_HTTP_LOST_EXPLICIT else None,
            "change_type": change.get("change_type"),
            "match_key": change.get("match_key"),
            "comparability": comparability,
            "headers_observed": _http_evidence(snapshot, hostname).get("headers_observed"),
            "hsts_present": _http_evidence(snapshot, hostname).get("hsts_present"),
            "hsts_applicable": _http_evidence(snapshot, hostname).get("hsts_applicable"),
            "redirected": _http_evidence(snapshot, hostname).get("redirected"),
            "resolved_at": (change.get("before") or {}).get("resolved_at"),
        }
    )
    return {
        "alert_type": alert_type,
        "category": category,
        "priority": priority,
        "semantic_key": semantic_key(alert_type, hostname=hostname, extra=extra),
        "hostname": hostname,
        "extra": extra,
        "title": title,
        "summary": summary,
        "evidence": evidence,
    }


def _coverage_trigger(
    alert_type: str,
    change: dict[str, Any],
    *,
    snapshot: dict[str, Any],
    comparability: str,
    current_metric: tuple[int, int],
) -> dict[str, Any]:
    title, summary = _policy_copy(alert_type, hostname="", extra="")
    before = change.get("before") or {}
    after = change.get("after") or {}
    evidence = _sanitized_evidence(
        {
            "change_type": change.get("change_type"),
            "comparability": comparability,
            "reference_numerator": before.get("numerator"),
            "reference_denominator": before.get("denominator"),
            "opening_numerator": after.get("numerator"),
            "opening_denominator": after.get("denominator"),
            "numerator": current_metric[0],
            "denominator": current_metric[1],
            "direction": after.get("direction"),
        }
    )
    return {
        "alert_type": alert_type,
        "category": CATEGORY_COVERAGE,
        "priority": PRIORITY_LOW,
        "semantic_key": semantic_key(alert_type),
        "hostname": "",
        "extra": "",
        "title": title,
        "summary": summary,
        "evidence": evidence,
    }


def _insert_outbox(db: Session, alert: Alert) -> None:
    now = _now()
    payload = {
        "alert_id": str(alert.id),
        "alert_type": alert.alert_type,
        "category": alert.category,
        "priority": alert.priority,
        "title": alert.title,
        "summary": alert.summary,
        "semantic_key": alert.semantic_key,
        "operation_id": str(alert.operation_id),
        "disclaimer": DISCLAIMER,
        "evidence": dict(alert.evidence or {}),
    }
    db.execute(
        pg_insert(NotificationOutbox)
        .values(
            id=uuid.uuid4(),
            organization_id=alert.organization_id,
            alert_id=alert.id,
            channel=CHANNEL_IN_APP,
            destination_key=DESTINATION_ORG,
            status="delivered",
            payload=payload,
            attempt_count=1,
            last_error=None,
            available_at=now,
            created_at=now,
            delivered_at=now,
        )
        .on_conflict_do_nothing(
            constraint="uq_notification_outbox_destination"
        )
    )
    enqueue_email_outbox(db, alert)


def freeze_operation_alerts(
    db: Session,
    operation: Operation,
    *,
    source: str = "frozen",
    actor_type: str = "worker",
) -> AlertGenerationReceipt | None:
    if operation.status not in TERMINAL_STATUSES:
        return None
    diff = db.scalar(
        select(OperationDiffSummary).where(
            OperationDiffSummary.operation_id == operation.id
        )
    )
    if diff is None:
        return None
    existing = db.scalar(
        select(AlertGenerationReceipt).where(
            AlertGenerationReceipt.diff_summary_id == diff.id
        )
    )
    if existing is not None:
        return existing

    prior_alert_count = int(
        db.scalar(
            select(func.count()).select_from(Alert).where(Alert.diff_summary_id == diff.id)
        )
        or 0
    )
    created = 0
    if prior_alert_count:
        created = prior_alert_count
    elif operation.status == "completed":
        created = _generate_from_frozen_diff(
            db, operation=operation, diff=diff, actor_type=actor_type
        )

    receipt_id = uuid.uuid4()
    db.execute(
        pg_insert(AlertGenerationReceipt)
        .values(
            id=receipt_id,
            diff_summary_id=diff.id,
            operation_id=operation.id,
            organization_id=operation.organization_id,
            source=source,
            alert_count=created,
            created_at=_now(),
        )
        .on_conflict_do_nothing(index_elements=["diff_summary_id"])
    )
    db.flush()
    row = db.scalar(
        select(AlertGenerationReceipt).where(
            AlertGenerationReceipt.diff_summary_id == diff.id
        )
    )
    if row is not None and row.id == receipt_id:
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type=actor_type,
            actor_user_id=operation.created_by_user_id,
            action="alerts.frozen",
            resource_type="operation",
            resource_id=operation.id,
            summary="Operation alert episodes evaluated from the frozen comparison snapshot.",
            metadata={
                "operation_id": str(operation.id),
                "status": operation.status,
                "source": source,
                "alert_count": created,
            },
        )
    return row


def _generate_from_frozen_diff(
    db: Session,
    *,
    operation: Operation,
    diff: OperationDiffSummary,
    actor_type: str,
) -> int:
    snapshot = dict(diff.comparison_snapshot or {})
    comparability = str(diff.comparability or "")
    security_signals_comparable = (
        comparability == COMPARABILITY_COMPARABLE
        and bool(snapshot.get("security_signals_complete"))
        and not bool(diff.security_signal_baseline_unavailable)
        and not bool(diff.security_signal_comparison_suppressed)
    )
    now = _now()
    open_rows = _open_episodes(
        db, organization_id=operation.organization_id, target_id=operation.target_id
    )
    open_by_key = {row.semantic_key: row for row in open_rows}
    for episode in open_rows:
        state = evaluate_episode_state(
            episode=episode,
            snapshot=snapshot,
            comparability=comparability,
            security_signals_comparable=security_signals_comparable,
        )
        if state == STATE_ACTIVE:
            episode.last_seen_at = now
            episode.last_seen_operation_id = operation.id
            episode.last_seen_diff_summary_id = diff.id
        elif state == STATE_RESOLVED:
            episode.status = "closed"
            episode.closed_at = now
            episode.last_seen_at = now
            episode.last_seen_operation_id = operation.id
            episode.last_seen_diff_summary_id = diff.id
            open_by_key.pop(episode.semantic_key, None)
        # UNKNOWN: leave open, do not treat as resolved, no repeat alert.

    triggers = _triggers_from_changes(
        changes=list(diff.changes or []),
        snapshot=snapshot,
        comparability=comparability,
        security_signal_baseline_unavailable=bool(
            diff.security_signal_baseline_unavailable
        ),
    )
    created = 0
    for trigger in triggers:
        key = trigger["semantic_key"]
        if key in open_by_key:
            continue
        previous = _latest_closed_episode(
            db,
            organization_id=operation.organization_id,
            target_id=operation.target_id,
            semantic_key=key,
        )
        episode = AlertEpisode(
            organization_id=operation.organization_id,
            target_id=operation.target_id,
            semantic_key=key,
            alert_type=trigger["alert_type"],
            category=trigger["category"],
            priority=trigger["priority"],
            status="open",
            opened_at=now,
            last_seen_at=now,
            opening_operation_id=operation.id,
            opening_diff_summary_id=diff.id,
            last_seen_operation_id=operation.id,
            last_seen_diff_summary_id=diff.id,
            reopened_from_episode_id=previous.id if previous is not None else None,
            opening_evidence=dict(trigger["evidence"]),
        )
        db.add(episode)
        db.flush()
        alert = Alert(
            organization_id=operation.organization_id,
            target_id=operation.target_id,
            episode_id=episode.id,
            operation_id=operation.id,
            diff_summary_id=diff.id,
            alert_type=trigger["alert_type"],
            category=trigger["category"],
            priority=trigger["priority"],
            semantic_key=key,
            title=trigger["title"],
            summary=trigger["summary"],
            evidence=dict(trigger["evidence"]),
            created_at=now,
        )
        db.add(alert)
        db.flush()
        _insert_outbox(db, alert)
        record_audit(
            db,
            organization_id=operation.organization_id,
            actor_type=actor_type,
            actor_user_id=operation.created_by_user_id,
            action="alert.created",
            resource_type="alert",
            resource_id=alert.id,
            summary=trigger["title"],
            metadata={
                "operation_id": str(operation.id),
                "alert_id": str(alert.id),
                "alert_type": trigger["alert_type"],
                "target_id": str(operation.target_id),
            },
        )
        open_by_key[key] = episode
        created += 1
    db.flush()
    return created


def _require_org(db: Session, *, user_id: UUID, organization_id: UUID) -> None:
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")


def get_alert_or_404(db: Session, *, alert_id: UUID, user_id: UUID) -> Alert:
    from fastapi import HTTPException, status

    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    _require_org(db, user_id=user_id, organization_id=alert.organization_id)
    return alert


def list_alerts_for_user(
    db: Session,
    *,
    user_id: UUID,
    category: str | None = None,
    priority: str | None = None,
    unread: bool = False,
    include_dismissed: bool = False,
) -> list[tuple[Alert, AlertEpisode | None, AlertUserState | None, str | None]]:
    org_ids = set(
        db.scalars(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == user_id
            )
        ).all()
    )
    if not org_ids:
        return []
    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.organization_id.in_(org_ids))
            .order_by(Alert.created_at.desc())
        ).all()
    )
    if not alerts:
        return []
    states = {
        row.alert_id: row
        for row in db.scalars(
            select(AlertUserState).where(
                AlertUserState.user_id == user_id,
                AlertUserState.alert_id.in_([item.id for item in alerts]),
            )
        ).all()
    }
    episodes = {
        row.id: row
        for row in db.scalars(
            select(AlertEpisode).where(
                AlertEpisode.id.in_([item.episode_id for item in alerts])
            )
        ).all()
    }
    targets = {
        row.id: row.domain
        for row in db.scalars(
            select(AuthorizedTarget).where(
                AuthorizedTarget.id.in_({item.target_id for item in alerts})
            )
        ).all()
    }
    results: list[tuple[Alert, AlertEpisode | None, AlertUserState | None, str | None]] = []
    for alert in alerts:
        if category and alert.category != category:
            continue
        if priority and alert.priority != priority:
            continue
        state = states.get(alert.id)
        if not include_dismissed and state is not None and state.dismissed_at is not None:
            continue
        if unread and state is not None and state.read_at is not None:
            continue
        if unread and state is None:
            pass
        results.append((alert, episodes.get(alert.episode_id), state, targets.get(alert.target_id)))
    return results


def alert_summary_for_user(db: Session, *, user_id: UUID) -> dict[str, Any]:
    rows = list_alerts_for_user(db, user_id=user_id, include_dismissed=False)
    unread = 0
    by_category: dict[str, int] = {}
    for alert, _episode, state, _domain in rows:
        if state is None or state.read_at is None:
            unread += 1
        by_category[alert.category] = int(by_category.get(alert.category) or 0) + 1
    org_ids = set(
        db.scalars(
            select(OrganizationMembership.organization_id).where(
                OrganizationMembership.user_id == user_id
            )
        ).all()
    )
    open_episode_count = 0
    if org_ids:
        open_episode_count = int(
            db.scalar(
                select(func.count()).select_from(AlertEpisode).where(
                    AlertEpisode.organization_id.in_(org_ids),
                    AlertEpisode.status == "open",
                )
            )
            or 0
        )
    return {
        "unread_count": unread,
        "open_episode_count": open_episode_count,
        "visible_alert_count": len(rows),
        "by_category": by_category,
        "disclaimer": DISCLAIMER,
    }


def _user_state(db: Session, *, alert: Alert, user_id: UUID) -> AlertUserState:
    row = db.scalar(
        select(AlertUserState).where(
            AlertUserState.alert_id == alert.id,
            AlertUserState.user_id == user_id,
        )
    )
    if row is not None:
        return row
    row = AlertUserState(
        alert_id=alert.id,
        organization_id=alert.organization_id,
        user_id=user_id,
    )
    db.add(row)
    db.flush()
    return row


def mark_alert_read(db: Session, *, alert: Alert, actor: AuthorizedOrgActor) -> AlertUserState:
    assert_actor_org(actor, alert.organization_id, not_found="Alert not found")
    state = _user_state(db, alert=alert, user_id=actor.user_id)
    if state.read_at is None:
        state.read_at = _now()
        record_audit(
            db,
            organization_id=alert.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="alert.read",
            resource_type="alert",
            resource_id=alert.id,
            summary="Alert marked read.",
            metadata=merge_auth_audit(
                actor,
                {"alert_id": str(alert.id), "operation_id": str(alert.operation_id)},
            ),
        )
    db.commit()
    db.refresh(state)
    return state


def dismiss_alert(db: Session, *, alert: Alert, actor: AuthorizedOrgActor) -> AlertUserState:
    assert_actor_org(actor, alert.organization_id, not_found="Alert not found")
    state = _user_state(db, alert=alert, user_id=actor.user_id)
    now = _now()
    if state.read_at is None:
        state.read_at = now
    if state.dismissed_at is None:
        state.dismissed_at = now
        record_audit(
            db,
            organization_id=alert.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="alert.dismissed",
            resource_type="alert",
            resource_id=alert.id,
            summary="Alert dismissed for this user.",
            metadata=merge_auth_audit(
                actor,
                {"alert_id": str(alert.id), "operation_id": str(alert.operation_id)},
            ),
        )
    db.commit()
    db.refresh(state)
    return state


def acknowledge_alert(db: Session, *, alert: Alert, actor: AuthorizedOrgActor) -> Alert:
    """Org-level acknowledgement. Does not close the episode or hide it for others."""
    assert_actor_org(actor, alert.organization_id, not_found="Alert not found")
    state = _user_state(db, alert=alert, user_id=actor.user_id)
    if state.read_at is None:
        state.read_at = _now()
    if alert.acknowledged_at is None:
        alert.acknowledged_at = _now()
        alert.acknowledged_by_user_id = actor.user_id
        record_audit(
            db,
            organization_id=alert.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="alert.acknowledged",
            resource_type="alert",
            resource_id=alert.id,
            summary="Alert acknowledged for the organization.",
            metadata=merge_auth_audit(
                actor,
                {"alert_id": str(alert.id), "operation_id": str(alert.operation_id)},
            ),
        )
    db.commit()
    db.refresh(alert)
    return alert


def public_outbox_status(row: NotificationOutbox) -> dict[str, Any]:
    return {
        "channel": row.channel,
        "destination_key": row.destination_key,
        "status": row.status,
        "attempt_count": int(row.attempt_count or 0),
        "delivered_at": _iso(row.delivered_at),
        "last_error_code": row.last_error_code,
    }


def load_public_deliveries(
    db: Session, *, alert_ids: list[UUID]
) -> dict[UUID, list[dict[str, Any]]]:
    if not alert_ids:
        return {}
    rows = list(
        db.scalars(
            select(NotificationOutbox)
            .where(NotificationOutbox.alert_id.in_(alert_ids))
            .order_by(NotificationOutbox.created_at.asc())
        ).all()
    )
    grouped: dict[UUID, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.alert_id, []).append(public_outbox_status(row))
    return grouped


def serialize_alert_for_user(db: Session, *, alert: Alert, user_id: UUID) -> dict[str, Any]:
    episode = db.get(AlertEpisode, alert.episode_id)
    state = db.scalar(
        select(AlertUserState).where(
            AlertUserState.alert_id == alert.id,
            AlertUserState.user_id == user_id,
        )
    )
    target = db.get(AuthorizedTarget, alert.target_id)
    deliveries = load_public_deliveries(db, alert_ids=[alert.id]).get(alert.id, [])
    return serialize_alert(
        alert=alert,
        episode=episode,
        state=state,
        target_domain=target.domain if target is not None else None,
        deliveries=deliveries,
    )


def serialize_alert(
    *,
    alert: Alert,
    episode: AlertEpisode | None,
    state: AlertUserState | None,
    target_domain: str | None,
    deliveries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "organization_id": str(alert.organization_id),
        "target_id": str(alert.target_id),
        "target_domain": target_domain,
        "episode_id": str(alert.episode_id),
        "operation_id": str(alert.operation_id),
        "diff_summary_id": str(alert.diff_summary_id),
        "alert_type": alert.alert_type,
        "category": alert.category,
        "priority": alert.priority,
        "semantic_key": alert.semantic_key,
        "title": alert.title,
        "summary": alert.summary,
        "evidence": dict(alert.evidence or {}),
        "created_at": _iso(alert.created_at),
        "episode_status": episode.status if episode is not None else None,
        "reopened_from_episode_id": (
            str(episode.reopened_from_episode_id)
            if episode is not None and episode.reopened_from_episode_id
            else None
        ),
        "last_seen_operation_id": (
            str(episode.last_seen_operation_id) if episode is not None else None
        ),
        "acknowledged_at": _iso(alert.acknowledged_at),
        "acknowledged_by_user_id": (
            str(alert.acknowledged_by_user_id) if alert.acknowledged_by_user_id else None
        ),
        "read_at": _iso(state.read_at) if state is not None else None,
        "dismissed_at": _iso(state.dismissed_at) if state is not None else None,
        "deliveries": list(deliveries or []),
        "disclaimer": DISCLAIMER,
    }

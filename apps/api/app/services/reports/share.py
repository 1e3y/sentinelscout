"""Admin-minted, revocable external access to one immutable AssessmentReport."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.report import AssessmentReport
from app.models.report_share import (
    SHARE_CREATION_ORIGIN_MANUAL,
    AssessmentReportShare,
)
from app.services.audit import record_audit
from app.services.authorization import AuthorizedOrgActor, assert_admin_actor, merge_auth_audit
from app.services.reports.generate import (
    REPORT_NOT_FOUND_DETAIL,
    get_assessment_report_or_404,
)
from app.services.reports.pdf import (
    PdfRendererUnavailable,
    PdfSnapshotError,
    export_assessment_report_pdf,
    validate_snapshot_for_export,
)

ExpiresIn = Literal["24h", "7d", "30d"]

SHARE_SECRET_BYTES = 32
SHARE_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
SHARE_SECRET_MAX_BODY_BYTES = 512
SHARED_NOT_FOUND = "Shared report not found"
SHARED_UNAVAILABLE = "Shared report is unavailable"
INVALID_SHARE_REQUEST = "Invalid share request"
NO_STORE_HEADERS = {"Cache-Control": "private, no-store"}

_DUMMY_HASH = hashlib.sha256(b"scout-missing-share").hexdigest()
_EXPIRY_DELTAS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

_BLOCKED_PUBLIC_KEYS = frozenset(
    {
        "organization_id",
        "target_id",
        "operation_id",
        "finding_id",
        "candidate_id",
        "validation_id",
        "observation_id",
        "validation_attempt_id",
        "retest_id",
        "asset_id",
        "user_id",
        "generated_by",
        "created_by_user_id",
        "baseline_operation_id",
        "control_snapshot_id",
        "target_authorization_id",
    }
)


def hash_share_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def generate_share_secret() -> str:
    secret = secrets.token_urlsafe(SHARE_SECRET_BYTES)
    if not SHARE_SECRET_PATTERN.fullmatch(secret):
        raise RuntimeError("share secret generator produced an unexpected format")
    return secret


def _secrets_match(secret: str, secret_hash: str) -> bool:
    return hmac.compare_digest(hash_share_secret(secret), secret_hash)


def _now() -> datetime:
    return datetime.now(UTC)


def _share_http_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
        headers=dict(NO_STORE_HEADERS),
    )


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strip_blocked(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_blocked(item)
            for key, item in value.items()
            if key not in _BLOCKED_PUBLIC_KEYS
        }
    if isinstance(value, list):
        return [_strip_blocked(item) for item in value]
    return value


def _pick(mapping: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: mapping[key] for key in keys if key in mapping}


def build_share_public_report(report: AssessmentReport, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted customer-facing DTO. Integrity must already have passed."""
    envelope = _as_dict(snapshot.get("envelope"))
    content = _as_dict(snapshot.get("content"))
    identity = _as_dict(content.get("identity"))
    scope = _as_dict(content.get("scope"))
    coverage = _as_dict(content.get("coverage"))
    frozen = _as_dict(coverage.get("frozen_operation_coverage"))
    follow_up = _as_dict(coverage.get("follow_up_frozen_for_report"))
    limitations = _as_dict(coverage.get("limitations"))
    summary = _as_dict(content.get("summary"))
    methodology = _as_dict(content.get("methodology"))
    change = _as_dict(content.get("change_context"))

    public_findings: list[dict[str, Any]] = []
    for item in _as_list(content.get("findings")):
        if not isinstance(item, dict):
            continue
        latest = item.get("latest_retest")
        public_latest = None
        if isinstance(latest, dict):
            public_latest = _pick(
                latest, ("status", "method", "summary", "completed_at")
            )
        public_findings.append(
            {
                **_pick(
                    item,
                    (
                        "title",
                        "summary",
                        "observation_class",
                        "severity",
                        "status",
                        "is_open",
                        "created_at",
                        "updated_at",
                        "resolved_at",
                        "business_impact",
                        "remediation_guidance",
                        "retest_attempts",
                    ),
                ),
                "affected_asset": _pick(
                    _as_dict(item.get("affected_asset")), ("hostname", "url")
                ),
                "validation": _pick(
                    _as_dict(item.get("validation")), ("method", "status", "summary")
                ),
                "latest_retest": public_latest,
                "evidence": _strip_blocked(_as_dict(item.get("evidence"))),
            }
        )

    def _changes(key: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in _as_list(change.get(key)):
            if isinstance(item, dict):
                rows.append(
                    _pick(
                        item,
                        (
                            "change_type",
                            "category",
                            "significance",
                            "match_key",
                            "explanation",
                            "before",
                            "after",
                        ),
                    )
                )
        return rows

    supported: list[dict[str, Any]] = []
    for item in _as_list(methodology.get("supported_classes")):
        if isinstance(item, dict):
            supported.append(_pick(item, ("title", "applies_to")))
    unsupported: list[dict[str, Any]] = []
    for item in _as_list(methodology.get("unsupported_classes")):
        if isinstance(item, dict):
            unsupported.append(_pick(item, ("title", "explanation")))

    public_limitations: list[dict[str, Any]] = []
    for item in _as_list(limitations.get("coverage_limitations")):
        if isinstance(item, dict):
            public_limitations.append(_pick(item, ("reason_code", "count", "explanation")))

    follow_counts = {
        str(key): value
        for key, value in _as_dict(follow_up.get("counts")).items()
        if isinstance(value, (int, float)) and not str(key).endswith("_id")
    }
    not_promoted = _as_dict(content.get("not_promoted"))

    return {
        "report": {
            "id": str(report.id),
            "version": int(report.report_version),
            "generated_at": envelope.get("generated_at") or report.generated_at.isoformat(),
            "snapshot_digest": str(report.snapshot_digest),
            "assessment_completeness": report.assessment_completeness,
            "generation_origin": report.generation_origin,
        },
        "identity": _pick(
            identity,
            (
                "organization_name",
                "target_domain",
                "target_authorization_status",
                "operation_source",
                "operation_status",
                "testing_profile",
                "assessment_completeness",
                "operation_started_at",
                "operation_completed_at",
                "operation_failed_at",
                "operation_stopped_at",
            ),
        ),
        "scope": _pick(
            scope, ("explanation", "scope_root", "include_subdomains", "exclusions")
        ),
        "coverage": {
            "frozen": _pick(
                frozen,
                (
                    "explanation",
                    "headline",
                    "frozen_at",
                    "operation_status_at_freeze",
                    "capability_manifest_version",
                ),
            ),
            "follow_up": {
                "explanation": follow_up.get("explanation") or "",
                "counts": follow_counts,
            },
            "limitations": {
                "explanation": limitations.get("explanation") or "",
                "coverage_limitations": public_limitations,
            },
        },
        "summary": _pick(
            summary,
            (
                "headline_status",
                "headline_label",
                "headline_statement",
                "assessment_completeness",
                "findings_total",
                "findings_open",
                "findings_resolved",
                "severity_counts_open",
                "regression_count",
                "coverage_limitation_count",
            ),
        ),
        "findings": public_findings,
        "not_promoted": _pick(
            not_promoted,
            (
                "explanation",
                "candidates_generated",
                "validations_conclusive",
                "validations_inconclusive",
                "validations_failed",
                "validations_not_attempted",
            ),
        ),
        "change_context": {
            "available": bool(change.get("available")),
            **_pick(
                change,
                (
                    "explanation",
                    "comparability",
                    "diff_headline",
                    "security_signal_comparison_suppressed",
                    "security_signal_suppression_reason",
                ),
            ),
            "security_regressions": _changes("security_regressions"),
            "coverage_degradations": _changes("coverage_degradations"),
            "resolved_conditions_reappeared": _changes("resolved_conditions_reappeared"),
        },
        "methodology": {
            "testing_profile": methodology.get("testing_profile"),
            "capability_manifest_version": methodology.get("capability_manifest_version"),
            "supported_classes": supported,
            "unsupported_classes": unsupported,
            "safety_controls": [
                item for item in _as_list(methodology.get("safety_controls")) if isinstance(item, str)
            ],
        },
    }


def _share_is_active(share: AssessmentReportShare, *, now: datetime | None = None) -> bool:
    current = now or _now()
    expires = share.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return share.revoked_at is None and expires > current


def _share_status(share: AssessmentReportShare, *, now: datetime | None = None) -> str:
    current = now or _now()
    if share.revoked_at is not None:
        return "revoked"
    expires = share.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= current:
        return "expired"
    return "active"


def _load_share_and_report(
    db: Session, share_id: UUID
) -> tuple[AssessmentReportShare, AssessmentReport] | None:
    share = db.get(AssessmentReportShare, share_id)
    if share is None:
        return None
    report = db.get(AssessmentReport, share.report_id)
    if report is None:
        return None
    if share.organization_id != report.organization_id:
        return None
    return share, report


def _authorize_admin_for_report(
    db: Session,
    *,
    report_id: UUID,
    user_id: UUID,
    actor: AuthorizedOrgActor,
) -> AssessmentReport:
    report = get_assessment_report_or_404(db, report_id=report_id, user_id=user_id)
    assert_admin_actor(actor, report.organization_id, not_found=REPORT_NOT_FOUND_DETAIL)
    return report


def create_report_share(
    db: Session,
    *,
    report_id: UUID,
    actor: AuthorizedOrgActor,
    expires_in: ExpiresIn,
) -> tuple[AssessmentReportShare, str]:
    if expires_in not in _EXPIRY_DELTAS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid expiry")
    report = _authorize_admin_for_report(
        db, report_id=report_id, user_id=actor.user_id, actor=actor
    )
    secret = generate_share_secret()
    created_at = _now()
    share = AssessmentReportShare(
        organization_id=report.organization_id,
        report_id=report.id,
        created_by_user_id=actor.user_id,
        creation_origin=SHARE_CREATION_ORIGIN_MANUAL,
        delivery_outbox_id=None,
        secret_hash=hash_share_secret(secret),
        created_at=created_at,
        expires_at=created_at + _EXPIRY_DELTAS[expires_in],
        revoked_at=None,
    )
    db.add(share)
    db.flush()
    record_audit(
        db,
        organization_id=report.organization_id,
        actor_type="user",
        actor_user_id=actor.user_id,
        action="assessment_report_share.created",
        resource_type="assessment_report_share",
        resource_id=share.id,
        summary="External assessment report share created.",
        metadata=merge_auth_audit(
            actor,
            {
                "share_id": str(share.id),
                "report_id": str(report.id),
                "report_version": int(report.report_version),
                "expires_at": share.expires_at.isoformat(),
            },
        ),
    )
    db.commit()
    db.refresh(share)
    return share, secret


def list_report_shares(
    db: Session,
    *,
    report_id: UUID,
    actor: AuthorizedOrgActor,
) -> list[AssessmentReportShare]:
    report = _authorize_admin_for_report(
        db, report_id=report_id, user_id=actor.user_id, actor=actor
    )
    rows = list(
        db.scalars(
            select(AssessmentReportShare)
            .where(AssessmentReportShare.report_id == report.id)
            .order_by(AssessmentReportShare.created_at.desc())
        ).all()
    )
    consistent: list[AssessmentReportShare] = []
    for share in rows:
        linked = db.get(AssessmentReport, share.report_id)
        if (
            linked is None
            or share.organization_id != report.organization_id
            or share.organization_id != linked.organization_id
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL
            )
        consistent.append(share)
    return consistent


def revoke_report_share(
    db: Session,
    *,
    share_id: UUID,
    actor: AuthorizedOrgActor,
) -> AssessmentReportShare:
    loaded = _load_share_and_report(db, share_id)
    if loaded is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL)
    share, report = loaded
    get_assessment_report_or_404(db, report_id=report.id, user_id=actor.user_id)
    assert_admin_actor(actor, share.organization_id, not_found=REPORT_NOT_FOUND_DETAIL)
    if share.organization_id != report.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=REPORT_NOT_FOUND_DETAIL)
    if share.revoked_at is None:
        share.revoked_at = _now()
        record_audit(
            db,
            organization_id=share.organization_id,
            actor_type="user",
            actor_user_id=actor.user_id,
            action="assessment_report_share.revoked",
            resource_type="assessment_report_share",
            resource_id=share.id,
            summary="External assessment report share revoked.",
            metadata=merge_auth_audit(
                actor,
                {
                    "share_id": str(share.id),
                    "report_id": str(report.id),
                    "report_version": int(report.report_version),
                    "expires_at": share.expires_at.isoformat(),
                },
            ),
        )
        db.commit()
        db.refresh(share)
    return share


def _authorize_external_share(
    db: Session, *, share_id: UUID, secret: str
) -> tuple[AssessmentReportShare, AssessmentReport]:
    loaded = _load_share_and_report(db, share_id)
    if loaded is None:
        hmac.compare_digest(hash_share_secret(secret), _DUMMY_HASH)
        raise _share_http_error(status.HTTP_404_NOT_FOUND, SHARED_NOT_FOUND)
    share, report = loaded
    if not _secrets_match(secret, share.secret_hash) or not _share_is_active(share):
        raise _share_http_error(status.HTTP_404_NOT_FOUND, SHARED_NOT_FOUND)
    if share.organization_id != report.organization_id:
        raise _share_http_error(status.HTTP_404_NOT_FOUND, SHARED_NOT_FOUND)
    return share, report


def resolve_shared_report(
    db: Session, *, share_id: UUID, secret: str
) -> dict[str, Any]:
    share, report = _authorize_external_share(db, share_id=share_id, secret=secret)
    try:
        snapshot = validate_snapshot_for_export(report)
    except PdfSnapshotError as exc:
        raise _share_http_error(status.HTTP_503_SERVICE_UNAVAILABLE, SHARED_UNAVAILABLE) from exc
    if share.organization_id != report.organization_id:
        raise _share_http_error(status.HTTP_404_NOT_FOUND, SHARED_NOT_FOUND)
    return build_share_public_report(report, snapshot)


def export_shared_report_pdf(
    db: Session, *, share_id: UUID, secret: str
) -> tuple[bytes, str]:
    """Render PDF from the frozen snapshot after a successful authorization.

    A post-render re-read narrows the revoke window. It does not mean a
    revoke cannot commit between the final read and the HTTP response.
    After revoke COMMIT, every new authorization fails. A request already
    authorized or in flight before that commit may finish.
    """
    share, report = _authorize_external_share(db, share_id=share_id, secret=secret)
    try:
        pdf_bytes, filename = export_assessment_report_pdf(report)
    except PdfRendererUnavailable as exc:
        raise _share_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE, "PDF export is unavailable"
        ) from exc
    except PdfSnapshotError as exc:
        if exc.detail == "Report contains characters that cannot be exported":
            raise _share_http_error(status.HTTP_409_CONFLICT, exc.detail) from exc
        raise _share_http_error(status.HTTP_503_SERVICE_UNAVAILABLE, SHARED_UNAVAILABLE) from exc
    except Exception as exc:
        raise _share_http_error(
            status.HTTP_503_SERVICE_UNAVAILABLE, SHARED_UNAVAILABLE
        ) from exc
    db.expire(share)
    fresh = db.get(AssessmentReportShare, share.id)
    if (
        fresh is None
        or fresh.organization_id != report.organization_id
        or not _share_is_active(fresh)
        or not _secrets_match(secret, fresh.secret_hash)
    ):
        raise _share_http_error(status.HTTP_404_NOT_FOUND, SHARED_NOT_FOUND)
    return pdf_bytes, filename


async def read_external_share_secret(request: Request) -> str:
    """Parse the share secret without echoing it on validation failure."""
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > SHARE_SECRET_MAX_BODY_BYTES:
                raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST)
        except ValueError as exc:
            raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST) from exc
    try:
        raw = await request.body()
    except Exception as exc:
        raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST) from exc
    if len(raw) > SHARE_SECRET_MAX_BODY_BYTES:
        raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST) from exc
    if not isinstance(payload, dict):
        raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST)
    secret = payload.get("secret")
    if not isinstance(secret, str) or not SHARE_SECRET_PATTERN.fullmatch(secret):
        raise _share_http_error(status.HTTP_400_BAD_REQUEST, INVALID_SHARE_REQUEST)
    return secret


def share_url_for(share: AssessmentReportShare, secret: str) -> str:
    base = get_settings().frontend_url.rstrip("/")
    return f"{base}/share/{share.id}#{secret}"


def share_list_item(share: AssessmentReportShare) -> dict[str, Any]:
    return {
        "id": share.id,
        "report_id": share.report_id,
        "created_by_user_id": share.created_by_user_id,
        "creation_origin": share.creation_origin,
        "created_at": share.created_at,
        "expires_at": share.expires_at,
        "revoked_at": share.revoked_at,
        "status": _share_status(share),
    }

"""Shared M44/M46 DB filter tokens. Not used by the M30 inbox."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from app.models.finding import FINDING_SEVERITIES, OPEN_FINDING_STATUSES, Finding
from app.models.target import AuthorizedTarget

OMITTED_FILTER_TOKEN = "*"
REVIEW_SEVERITIES = FINDING_SEVERITIES
REVIEW_STATUSES = OPEN_FINDING_STATUSES


@dataclass(frozen=True)
class ReviewDimensionFilters:
    target_id: UUID | None
    severity: str | None
    status: str | None

    @property
    def target_token(self) -> str:
        return str(self.target_id) if self.target_id is not None else OMITTED_FILTER_TOKEN

    @property
    def severity_token(self) -> str:
        return self.severity if self.severity is not None else OMITTED_FILTER_TOKEN

    @property
    def status_token(self) -> str:
        return self.status if self.status is not None else OMITTED_FILTER_TOKEN

    @property
    def omitted(self) -> bool:
        return (
            self.target_id is None and self.severity is None and self.status is None
        )


def normalize_review_filters(
    *,
    target_id: UUID | None,
    severity: str | None,
    status: str | None,
) -> ReviewDimensionFilters:
    return ReviewDimensionFilters(
        target_id=UUID(str(target_id)) if target_id is not None else None,
        severity=severity,
        status=status,
    )


def parse_filter_token(raw: str, *, kind: str) -> str:
    if raw == OMITTED_FILTER_TOKEN:
        return raw
    if kind == "target":
        return str(UUID(raw))
    if kind == "severity" and raw in REVIEW_SEVERITIES:
        return raw
    if kind == "status" and raw in REVIEW_STATUSES:
        return raw
    raise ValueError(f"invalid {kind} filter token")


def apply_review_dimension_filters(stmt, filters: ReviewDimensionFilters):
    if filters.target_id is not None:
        stmt = stmt.where(AuthorizedTarget.id == filters.target_id)
    if filters.severity is not None:
        stmt = stmt.where(Finding.severity == filters.severity)
    if filters.status is not None:
        stmt = stmt.where(Finding.status == filters.status)
    return stmt

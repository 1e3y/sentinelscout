from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CoverageRatio(BaseModel):
    numerator: int
    denominator: int
    value: float


class CoverageFollowUpResponse(BaseModel):
    candidates_generated: int
    validations_attempted: int
    validations_conclusive: int
    validations_inconclusive: int
    validations_failed: int
    validations_not_attempted: int
    findings: int
    retests_attempted: int
    retests_passed: int
    retests_failed: int
    retests_inconclusive: int
    retests_error: int
    gaps: list[dict[str, Any]] = Field(default_factory=list)


class OperationCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    source: str
    frozen_at: datetime | str | None = None
    operation_status_at_freeze: str | None = None
    capability_manifest_version: int
    capability: dict[str, Any]
    surface: dict[str, Any]
    http_evidence: dict[str, Any]
    scope_boundaries: dict[str, Any]
    freshness: dict[str, Any]
    headline: str
    follow_up: CoverageFollowUpResponse

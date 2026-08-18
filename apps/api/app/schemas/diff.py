from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OperationDiffChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    change_type: str
    significance: str
    match_key: str | None = None
    before: Any = None
    after: Any = None
    explanation: str


class OperationDiffFollowUpFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_type: str
    hostname: str
    candidate_type: str
    finding_id: str
    status: str
    created_at: datetime | str | None = None
    updated_at: datetime | str | None = None
    resolved_at: datetime | str | None = None


class OperationDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    source: str
    frozen_at: datetime | str | None = None
    comparability: str
    baseline_operation_id: str | None = None
    baseline_completed_at: datetime | str | None = None
    current_source: str | None = None
    baseline_source: str | None = None
    operation_status_at_freeze: str | None = None
    security_signal_baseline_unavailable: bool = False
    security_signal_comparison_suppressed: bool = False
    security_signal_suppression_reason: str | None = None
    headline: str
    counts: dict[str, Any] = Field(default_factory=dict)
    changes: list[OperationDiffChange] = Field(default_factory=list)
    comparison_snapshot: dict[str, Any]
    follow_up_findings: list[OperationDiffFollowUpFinding] = Field(default_factory=list)

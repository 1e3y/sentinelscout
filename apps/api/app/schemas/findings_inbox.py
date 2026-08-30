"""Organization findings inbox DTOs.

Every value here is CURRENT operational state read from live tables. Nothing in
this module projects an M17 coverage freeze, an M18 diff, an M22 report snapshot,
or any other frozen assessment artifact.

Two naming rules are load bearing:

* ``workflow`` is a projection of ``findings.status``. Operator-authored
  remediation is a separate compact metadata block and never changes workflow.
* ``promoted_at`` is ``findings.created_at``, the moment a supported candidate
  became a Finding. It is not a first-detection timestamp and must never be
  renamed to imply one.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.finding_follow_up import FindingOwnerResponse

# Mirrors app.models.finding.FINDING_STATUSES / FINDING_SEVERITIES, which are
# enforced by ck_finding_status and ck_finding_severity.
FindingInboxStatus = Literal["open", "in_progress", "ready_for_retest", "resolved"]
FindingInboxSeverity = Literal["informational", "low", "medium", "high", "critical"]

# authorized_targets.status has no check constraint, so these are the exact
# values app.services.targets writes. test_findings_inbox pins them behaviorally.
TARGET_AUTHORIZATION_STATUSES = (
    "unverified",
    "verification_pending",
    "verified",
    "revoked",
)
TargetAuthorizationStatus = Literal[
    "unverified", "verification_pending", "verified", "revoked"
]

# Derived only from findings.status. Not an operator-authored remediation record.
FindingWorkflowState = Literal[
    "not_started", "in_progress", "ready_for_retest", "resolved_by_retest"
]

# Terminal subset of app.models.retest.RETEST_ATTEMPT_STATUSES.
TerminalRetestStatus = Literal["passed", "failed", "inconclusive", "error"]

# One mutually exclusive current state per finding. `in_progress` outranks any
# older terminal result, so a row can never be both in progress and failed.
CurrentRetestState = Literal[
    "none", "in_progress", "passed", "failed", "inconclusive", "error"
]

AttentionProvenance = Literal[
    "finding_workflow", "retest_state", "target_authorization"
]


class FindingInboxTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: UUID
    domain: str
    authorization_status: TargetAuthorizationStatus
    asset_hostname: str


class FindingInboxWorkflow(BaseModel):
    """Projection of findings.status, separate from remediation records."""

    model_config = ConfigDict(extra="forbid")

    state: FindingWorkflowState
    resolved_at: datetime | None = None


class FindingInboxRemediation(BaseModel):
    """Compact current metadata. Free-text remediation never enters the inbox."""

    model_config = ConfigDict(extra="forbid")

    revision_count: int
    latest_recorded_at: datetime | None = None


class FindingInboxLatestTerminalRetest(BaseModel):
    """Most recent non-active attempt. Kept even while a newer retest runs."""

    model_config = ConfigDict(extra="forbid")

    retest_attempt_id: UUID
    status: TerminalRetestStatus
    created_at: datetime
    completed_at: datetime | None = None


class FindingInboxRetests(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_state: CurrentRetestState
    attempt_count: int
    latest_terminal: FindingInboxLatestTerminalRetest | None = None


class FindingInboxAttentionReason(BaseModel):
    """A factual reason to look at this finding. Not a score, rank, or priority."""

    model_config = ConfigDict(extra="forbid")

    code: str
    label: str
    provenance: AttentionProvenance


class FindingInboxRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    target: FindingInboxTarget
    title: str
    finding_type: str
    severity: FindingInboxSeverity
    status: FindingInboxStatus
    workflow: FindingInboxWorkflow
    remediation: FindingInboxRemediation
    retests: FindingInboxRetests
    owner: FindingOwnerResponse | None = None
    follow_up_due_at: datetime | None = None
    promoted_at: datetime
    last_updated_at: datetime
    attention_reasons: list[FindingInboxAttentionReason] = Field(default_factory=list)


class FindingInboxSummary(BaseModel):
    """Counts across every finding in the active organization, not just this page."""

    model_config = ConfigDict(extra="forbid")

    scope: Literal["organization"] = "organization"
    finding_count: int
    open_finding_count: int
    findings_without_any_retest: int


class FindingInboxResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: UUID
    state: Literal["current"] = "current"
    page_size: int
    sort: Literal["promoted_at_desc"] = "promoted_at_desc"
    next_cursor: str | None = None
    summary: FindingInboxSummary
    items: list[FindingInboxRow] = Field(default_factory=list)

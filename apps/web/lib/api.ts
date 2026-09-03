const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type MeResponse = {
  id: string;
  clerk_user_id: string;
  email: string;
  name: string | null;
    created_at: string;
    active_organization_id: string | null;
    active_organization_role: "admin" | "member" | null;
};

export type OrganizationResponse = {
  id: string;
  clerk_org_id: string;
  name: string;
  role: string;
  created_at: string;
};

export type TargetAuthorization = {
  method: string;
  txt_name: string;
  txt_value: string;
  created_at: string;
  last_checked_at: string | null;
  verified_at: string | null;
};

export type TargetResponse = {
  id: string;
  organization_id: string;
  domain: string;
  status: string;
  created_at: string;
  updated_at: string;
  verified_at: string | null;
  revoked_at: string | null;
  authorization: TargetAuthorization | null;
};

export type TargetScopeResponse = {
  target_id: string;
  root_domain: string;
  include_subdomains: boolean;
  exclusions: string[];
  created_at: string;
  updated_at: string;
};

export type VerifyTargetResponse = {
  id: string;
  domain: string;
  status: string;
  verified: boolean;
  detail: string;
};

export type OperationControlSnapshotResponse = {
  id: string;
  operation_id: string;
  organization_id: string;
  target_id: string;
  target_domain: string;
  authorization_status: string;
  target_authorization_id: string | null;
  scope_root: string;
  include_subdomains: boolean;
  exclusions: string[];
  operation_source: string;
  testing_profile: string;
  created_by_user_id: string;
  created_at: string;
  notes: string | null;
};

export type OperationResponse = {
  id: string;
  organization_id: string;
  target_id: string;
  target_domain: string;
  created_by_user_id: string;
  status: string;
  source: string;
  testing_profile: string;
  stop_requested: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  failed_at: string | null;
  stopped_at: string | null;
  error_code: string | null;
  error_message: string | null;
  control_snapshot: OperationControlSnapshotResponse | null;
};

export type CoverageRatio = {
  numerator: number;
  denominator: number;
  value: number;
};

export type CoverageGap = {
  hostname?: string;
  reason_code: string;
  explanation: string;
  count?: number;
};

export type OperationCoverageResponse = {
  schema_version: number;
  source: string;
  frozen_at: string | null;
  operation_status_at_freeze: string | null;
  capability_manifest_version: number;
  capability: {
    version?: number;
    testing_profile?: string;
    supported: Array<{ id: string; title: string; explanation?: string }>;
    unsupported: Array<{ id: string; title: string; explanation?: string }>;
  };
  surface: {
    unit: string;
    in_scope_discovered: number;
    submitted_for_http_observation: number;
    http_observation_obtained: number;
    http_observation_not_obtained: number;
    incomplete: number;
    hostnames?: Record<string, unknown>;
    ratios?: Record<string, CoverageRatio | null>;
  };
  http_evidence: {
    unit: string;
    http_observations: number;
    headers_captured: number;
    header_evidence_unavailable: number;
    redirect_header_evidence_unusable: number;
    hostnames?: Record<string, unknown>;
    ratios?: Record<string, CoverageRatio | null>;
  };
  scope_boundaries: {
    configured_exclusions: string[];
    include_subdomains: boolean;
    discovered_results_discarded: number;
    discovery_truncated: boolean;
    truncated_from: number | null;
    truncated_to: number | null;
    gaps?: CoverageGap[];
  };
  freshness: {
    oldest_http_observation_at: string | null;
    newest_http_observation_at: string | null;
    operation_completed_at: string | null;
    operation_stopped_at?: string | null;
    operation_failed_at?: string | null;
  };
  headline: string;
  follow_up: {
    candidates_generated: number;
    validations_attempted: number;
    validations_conclusive: number;
    validations_inconclusive: number;
    validations_failed: number;
    validations_not_attempted: number;
    findings: number;
    retests_attempted: number;
    retests_passed: number;
    retests_failed: number;
    retests_inconclusive: number;
    retests_error: number;
    gaps: CoverageGap[];
  };
};

export type MonitoringConfigurationResponse = {
  id: string | null;
  organization_id: string;
  target_id: string;
  enabled: boolean;
  auto_generate_reports: boolean;
  auto_deliver_reports: boolean;
  auto_deliver_expires_in: "24h" | "7d" | "30d";
  recipient_count: number;
  recipients: string[] | null;
  email_delivery_enabled: boolean;
  frequency: string;
  next_run_at: string | null;
  last_run_at: string | null;
  disabled_reason: string | null;
  created_at: string | null;
  updated_at: string | null;
  latest_changes: {
    comparability?: string;
    hostname_newly_discovered?: number;
    hostname_no_longer_discovered?: number;
    http_observation_gained?: number;
    http_observation_lost?: number;
    regressions?: number;
    [key: string]: string | number | boolean | undefined;
  };
};

export type AssessmentHistoryCoverage = {
  frozen_at: string;
  source: string;
  operation_status_at_freeze: string;
  capability_manifest_version: number;
  headline: string;
  in_scope_discovered: number;
  submitted_for_http_observation: number;
  http_observation_obtained: number;
  http_observation_not_obtained: number;
  incomplete_hostnames: number;
  surface_coverage_ratio: {
    numerator: number;
    denominator: number;
    value: number | null;
  } | null;
  headers_captured: number;
  http_observations: number;
  header_evidence_unavailable: number;
  discovery_truncated: boolean;
  discovered_results_discarded: number;
};

export type AssessmentHistoryComparison = {
  comparability: string;
  baseline_operation_id: string | null;
  baseline_completed_at: string | null;
  headline: string;
  security_signal_baseline_unavailable: boolean;
  security_signal_comparison_suppressed: boolean;
  security_signal_suppression_reason: string | null;
};

export type AssessmentHistorySurfaceChanges = {
  hostnames_newly_discovered: number;
  hostnames_no_longer_discovered: number;
  http_observation_gained: number;
  http_observation_lost: number;
};

export type AssessmentHistorySignals = {
  candidates_newly_emitted: number;
  candidates_no_longer_emitted: number;
  conservative_regressions: number;
  regression_hsts_lost: number;
  regression_resolved_condition_reappeared: number;
  regression_header_evidence_lost: number;
};

export type AssessmentHistoryLatestReport = {
  id: string;
  report_version: number;
  version_count: number;
  generation_origin: "manual" | "scheduled_automatic";
  generated_at: string;
  headline_status: string;
  headline_label: string;
  assessment_completeness: string;
  findings_total: number;
  findings_open: number;
  findings_resolved: number;
  regression_count: number;
  coverage_limitation_count: number;
  severity_counts: Record<string, number>;
};

export type AssessmentHistoryRow = {
  operation_id: string;
  status: string;
  source: string;
  testing_profile: string;
  created_at: string;
  started_at: string | null;
  ended_at: string;
  completed_at: string | null;
  failed_at: string | null;
  stopped_at: string | null;
  error_code: string | null;
  error_message: string | null;
  completeness: "complete" | "incomplete";
  coverage: AssessmentHistoryCoverage | null;
  comparison: AssessmentHistoryComparison | null;
  surface_changes: AssessmentHistorySurfaceChanges | null;
  signals: AssessmentHistorySignals | null;
  latest_report: AssessmentHistoryLatestReport | null;
};

export type AssessmentHistoryResponse = {
  target_id: string;
  target_domain: string;
  page_size: number;
  next_cursor: string | null;
  items: AssessmentHistoryRow[];
};

export type AttentionProvenance =
  | "operation_history"
  | "frozen_assessment"
  | "current_state";

export type SecurityOverviewAttentionReason = {
  code: string;
  label: string;
  provenance: AttentionProvenance;
};

export type SecurityOverviewLatestTerminal = {
  operation_id: string;
  status: string;
  source: string;
  ended_at: string;
};

export type SecurityOverviewLatestCompleted = {
  operation_id: string;
  completed_at: string;
  source: string;
};

export type SecurityOverviewReport = {
  id: string;
  report_version: number;
  version_count: number;
  generation_origin: "manual" | "scheduled_automatic";
  generated_at: string;
  headline_status: string;
  headline_label: string;
  assessment_completeness: string;
};

export type SecurityOverviewAlerts = {
  active_episode_count: number;
  unacknowledged_active_episode_count: number;
};

export type SecurityOverviewAutomation = {
  monitoring_enabled: boolean;
  frequency: string | null;
  next_run_at: string | null;
  last_run_at: string | null;
  disabled_reason: string | null;
  auto_generate_reports: boolean;
  auto_deliver_reports: boolean;
  auto_deliver_expires_in: string | null;
  delivery_recipient_count: number;
  email_delivery_enabled: boolean;
};

export type SecurityOverviewStaleness = {
  is_stale: boolean | null;
  threshold_days: number | null;
  threshold_basis: "monitoring_cadence" | "not_applicable";
  days_since_last_completed: number | null;
};

export type SecurityOverviewRow = {
  target_id: string;
  domain: string;
  authorization_status: string;
  verified_at: string | null;
  revoked_at: string | null;
  latest_terminal: SecurityOverviewLatestTerminal | null;
  latest_completed: SecurityOverviewLatestCompleted | null;
  coverage: AssessmentHistoryCoverage | null;
  comparison: AssessmentHistoryComparison | null;
  signals: AssessmentHistorySignals | null;
  latest_report: SecurityOverviewReport | null;
  alerts: SecurityOverviewAlerts;
  automation: SecurityOverviewAutomation;
  staleness: SecurityOverviewStaleness;
  attention_reasons: SecurityOverviewAttentionReason[];
};

export type SecurityOverviewSummary = {
  scope: "organization";
  target_count: number;
  verified_targets_without_completed_assessment: number;
  targets_with_active_alert_episode: number;
};

export type SecurityOverviewResponse = {
  organization_id: string;
  page_size: number;
  sort: "domain_asc";
  next_cursor: string | null;
  summary: SecurityOverviewSummary;
  items: SecurityOverviewRow[];
};

export type OperationEventResponse = {
  id: string;
  operation_id: string;
  sequence: number;
  event_type: string;
  summary: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type AssetResponse = {
  id: string;
  organization_id: string;
  target_id: string;
  hostname: string;
  url: string;
  asset_type: string;
  status_code: number | null;
  title: string | null;
  source: string;
  first_seen_at: string;
  last_seen_at: string;
};

export type DiscoveryObservationResponse = {
  id: string;
  organization_id: string;
  operation_id: string;
  asset_id: string | null;
  observation_type: string;
  summary: string;
  metadata: Record<string, unknown>;
  source: string;
  created_at: string;
};

export type SecurityCandidateResponse = {
  id: string;
  organization_id: string;
  operation_id: string;
  asset_id: string;
  asset_hostname: string | null;
  asset_url: string | null;
  candidate_type: string;
  title: string;
  summary: string;
  status: string;
  source: string;
  evidence: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ValidationAttemptResponse = {
  id: string;
  organization_id: string;
  operation_id: string;
  candidate_id: string;
  asset_id: string;
  status: string;
  validation_method: string;
  summary: string;
  evidence: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
};

export type FindingProvenanceResponse = {
  chain: string[];
  finding_id: string;
  candidate_id: string;
  asset_id: string;
  operation_id: string;
  target_id: string | null;
  observation_ids: string[];
  validation_attempt_id: string | null;
  validation_method: string | null;
  retest_attempt_id: string | null;
  control_snapshot: {
    target_domain: string;
    authorization_status: string;
    scope_root: string;
    include_subdomains: boolean;
    exclusions: string[];
    testing_profile: string;
    operation_source: string;
  } | null;
};

export type FindingInboxStatus =
  | "open"
  | "in_progress"
  | "ready_for_retest"
  | "resolved";

export type FindingInboxSeverity =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type TargetAuthorizationStatus =
  | "unverified"
  | "verification_pending"
  | "verified"
  | "revoked";

export type FindingWorkflowState =
  | "not_started"
  | "in_progress"
  | "ready_for_retest"
  | "resolved_by_retest";

export type TerminalRetestStatus =
  | "passed"
  | "failed"
  | "inconclusive"
  | "error";

export type CurrentRetestState = "none" | "in_progress" | TerminalRetestStatus;

export type FindingInboxAttentionReason = {
  code: string;
  label: string;
  provenance: "finding_workflow" | "retest_state" | "target_authorization";
};

export type FindingInboxRow = {
  finding_id: string;
  target: {
    target_id: string;
    domain: string;
    authorization_status: TargetAuthorizationStatus;
    asset_hostname: string;
  };
  title: string;
  finding_type: string;
  severity: FindingInboxSeverity;
  status: FindingInboxStatus;
  workflow: {
    state: FindingWorkflowState;
    resolved_at: string | null;
  };
  remediation: {
    revision_count: number;
    latest_recorded_at: string | null;
  };
  retests: {
    current_state: CurrentRetestState;
    attempt_count: number;
    latest_terminal: {
      retest_attempt_id: string;
      status: TerminalRetestStatus;
      created_at: string;
      completed_at: string | null;
    } | null;
  };
  owner: FindingOwner | null;
  follow_up_due_at: string | null;
  promoted_at: string;
  last_updated_at: string;
  attention_reasons: FindingInboxAttentionReason[];
};

export type FindingInboxResponse = {
  organization_id: string;
  state: "current";
  page_size: number;
  sort: "promoted_at_desc";
  next_cursor: string | null;
  summary: {
    scope: "organization";
    finding_count: number;
    open_finding_count: number;
    findings_without_any_retest: number;
  };
  items: FindingInboxRow[];
};

export type FindingInboxFilters = {
  status?: FindingInboxStatus | "";
  severity?: FindingInboxSeverity | "";
  target_id?: string;
  retest_state?: CurrentRetestState | "";
  assigned_to_user_id?: string;
  unassigned?: boolean;
};

export type FindingOwner = {
  user_id: string;
  display_name: string | null;
  current_member: boolean;
};

export type FindingFollowUp = {
  owner: FindingOwner | null;
  follow_up_due_at: string | null;
};

export type FindingResponse = {
  id: string;
  organization_id: string;
  operation_id: string;
  candidate_id: string;
  asset_id: string;
  asset_hostname: string | null;
  asset_url: string | null;
  title: string;
  summary: string;
  severity: string;
  status: string;
  business_impact: string;
  remediation_guidance: string;
  evidence: Record<string, unknown>;
  provenance: FindingProvenanceResponse | null;
  follow_up: FindingFollowUp | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
};

export type FindingRemediationRevision = {
  id: string;
  revision_number: number;
  summary: string;
  created_at: string;
  created_by_user_id: string;
  created_by_name: string | null;
};

export type FindingRemediationHistory = {
  finding_id: string;
  revision_count: number;
  latest: FindingRemediationRevision | null;
  page_size: number;
  next_cursor: string | null;
  revisions: FindingRemediationRevision[];
};

export type FindingTimelineActor = {
  actor_type: "user" | "worker";
  user_id: string | null;
  display_name: string | null;
};

export type FindingTimelineEvent =
  | {
      event_id: string;
      event_type: "SUPPORTED_FINDING_PROMOTED";
      occurred_at: string;
      provenance: "finding_record";
      actor: FindingTimelineActor | null;
      title: string;
      details: { finding_id: string };
    }
  | {
      event_id: string;
      event_type: "REMEDIATION_STARTED" | "READY_FOR_RETEST";
      occurred_at: string;
      provenance: "human_workflow";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        from_status: FindingInboxStatus;
        to_status: FindingInboxStatus;
      };
    }
  | {
      event_id: string;
      event_type: "FOLLOW_UP_CHANGED";
      occurred_at: string;
      provenance: "human_workflow";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        previous_owner: {
          user_id: string;
          display_name: string | null;
        } | null;
        new_owner: {
          user_id: string;
          display_name: string | null;
        } | null;
        previous_due_at: string | null;
        new_due_at: string | null;
      };
    }
  | {
      event_id: string;
      event_type: "REMEDIATION_REVISION_RECORDED";
      occurred_at: string;
      provenance: "human_remediation";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        revision_id: string;
        revision_number: number;
        summary: string;
      };
    }
  | {
      event_id: string;
      event_type: "RETEST_QUEUED";
      occurred_at: string;
      provenance: "human_workflow";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        retest_attempt_id: string;
        status_at_read:
          | "pending"
          | "running"
          | "passed"
          | "failed"
          | "inconclusive"
          | "error";
        queued_at: string;
      };
    }
  | {
      event_id: string;
      event_type: "RETEST_COMPLETED";
      occurred_at: string;
      provenance: "scout_retest";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        retest_attempt_id: string;
        status: TerminalRetestStatus;
        completed_at: string;
        method: string;
        summary: string;
      };
    }
  | {
      event_id: string;
      event_type: "FINDING_RESOLVED";
      occurred_at: string;
      provenance: "finding_record";
      actor: FindingTimelineActor | null;
      title: string;
      details: {
        resolution_basis: "passing_retest" | "link_unavailable";
        resolving_retest_attempt_id: string | null;
        statement: string;
      };
    };

export type FindingTimelineHistoryGap =
  | "remediation_started_timestamp_unavailable"
  | "ready_for_retest_timestamp_unavailable"
  | "resolution_timestamp_unavailable"
  | "resolution_retest_link_unavailable"
  | "retest_completion_timestamp_unavailable"
  | "workflow_transition_ambiguous";

export type FindingTimelineResponse = {
  finding_id: string;
  current_status: FindingInboxStatus;
  current_retest_state: CurrentRetestState;
  remediation_revision_count: number;
  history_completeness: "complete" | "partial";
  history_gaps: FindingTimelineHistoryGap[];
  page_size: number;
  next_cursor: string | null;
  events: FindingTimelineEvent[];
};

export type AuditEventResponse = {
  id: string;
  organization_id: string;
  actor_type: string;
  actor_user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  summary: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type RetestAttemptResponse = {
  id: string;
  organization_id: string;
  finding_id: string;
  candidate_id: string;
  asset_id: string;
  original_validation_attempt_id: string;
  status: string;
  method: string;
  summary: string;
  evidence: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
};

export type AssessmentHeadlineStatus =
  | "assessment_incomplete"
  | "action_required"
  | "attention_recommended"
  | "no_open_supported_findings";

export type AssessmentReportSummaryResponse = {
  id: string;
  organization_id: string;
  target_id: string;
  operation_id: string;
  created_by_user_id: string | null;
  generation_origin: "manual" | "scheduled_automatic";
  target_domain: string;
  report_version: number;
  schema_version: number;
  snapshot_digest: string;
  operation_status_at_generation: string;
  assessment_completeness: "complete" | "incomplete";
  headline_status: AssessmentHeadlineStatus;
  headline_label: string;
  findings_total: number;
  findings_open: number;
  findings_resolved: number;
  regression_count: number;
  coverage_limitation_count: number;
  severity_counts: Record<string, number>;
  generated_at: string;
};

export type AssessmentReportCoverageLimitation = {
  reason_code: string;
  count: number;
  explanation: string;
  source: string;
};

export type AssessmentReportFinding = {
  finding_id: string;
  title: string;
  summary: string;
  observation_class: string;
  severity: string;
  severity_rank: number;
  status: string;
  is_open: boolean;
  created_at: string | null;
  updated_at: string | null;
  resolved_at: string | null;
  business_impact: string;
  remediation_guidance: string;
  affected_asset: { hostname: string | null; url: string | null };
  validation: {
    method: string | null;
    status: string | null;
    summary: string | null;
  };
  retest_attempts: number;
  latest_retest: {
    status: string;
    method: string;
    summary: string;
    completed_at: string | null;
    evidence: Record<string, unknown>;
  } | null;
  evidence: Record<string, unknown>;
};

export type AssessmentReportChange = {
  change_type?: string;
  category?: string;
  significance?: string;
  match_key?: string;
  explanation?: string;
  before?: string | number | boolean;
  after?: string | number | boolean;
};

export type AssessmentReportContent = {
  report_schema_version: number;
  identity: {
    organization_id: string;
    organization_name: string;
    target_id: string;
    target_domain: string;
    target_authorization_status: string;
    operation_id: string;
    operation_source: string;
    operation_status: string;
    testing_profile: string;
    assessment_completeness: "complete" | "incomplete";
    operation_created_at: string | null;
    operation_started_at: string | null;
    operation_completed_at: string | null;
    operation_failed_at: string | null;
    operation_stopped_at: string | null;
  };
  scope: {
    source: string;
    explanation: string;
    scope_root: string;
    include_subdomains: boolean;
    exclusions: string[];
    control_snapshot_created_at: string | null;
  };
  coverage: {
    frozen_operation_coverage: {
      source: string;
      explanation: string;
      freeze_source: string;
      schema_version: number;
      frozen_at: string | null;
      operation_status_at_freeze: string;
      capability_manifest_version: number;
      capability: {
        version?: number;
        supported?: { id: string; title: string; applies_to: string }[];
        unsupported?: { id: string; title: string; explanation: string }[];
      };
      surface: Record<string, unknown>;
      http_evidence: Record<string, unknown>;
      scope_boundaries: Record<string, unknown>;
      freshness: Record<string, unknown>;
      headline: string;
    };
    follow_up_frozen_for_report: {
      source: string;
      explanation: string;
      counts: Record<string, number>;
      gaps: AssessmentReportCoverageLimitation[];
    };
    limitations: {
      explanation: string;
      coverage_limitation_count: number;
      coverage_limitations: AssessmentReportCoverageLimitation[];
    };
  };
  findings: AssessmentReportFinding[];
  not_promoted: {
    explanation: string;
    candidates_generated: number;
    validations_conclusive: number;
    validations_inconclusive: number;
    validations_failed: number;
    validations_not_attempted: number;
  };
  change_context: {
    available: boolean;
    explanation?: string;
    comparability?: string;
    baseline_operation_id?: string | null;
    diff_frozen_at?: string | null;
    diff_headline?: string;
    security_signal_comparison_suppressed?: boolean;
    security_signal_suppression_reason?: string | null;
    counts?: Record<string, unknown>;
    security_regressions?: AssessmentReportChange[];
    coverage_degradations?: AssessmentReportChange[];
    resolved_conditions_reappeared?: AssessmentReportChange[];
  };
  summary: {
    headline_status: AssessmentHeadlineStatus;
    headline_label: string;
    headline_statement: string;
    assessment_completeness: "complete" | "incomplete";
    findings_total: number;
    findings_open: number;
    findings_resolved: number;
    severity_counts_open: Record<string, number>;
    regression_count: number;
    coverage_limitation_count: number;
  };
  methodology: {
    testing_profile: string;
    capability_manifest_version: number;
    supported_classes: { id: string; title: string; applies_to: string }[];
    unsupported_classes: { id: string; title: string; explanation: string }[];
    safety_controls: string[];
  };
};

export type AssessmentReportResponse = AssessmentReportSummaryResponse & {
  snapshot: {
    report_schema_version: number;
    envelope: {
      report_id: string;
      report_version: number;
      snapshot_digest: string;
      generated_at: string;
      origin?: "manual" | "scheduled_automatic";
      generated_by?: { user_id: string };
    };
    content: AssessmentReportContent;
  };
  automatic_delivery?: {
    job_status: string;
    last_error_code: string | null;
    frozen_recipient_count: number;
    outbox_count: number;
    delivered_count: number;
    skipped_count: number;
    pending_count: number;
    email_delivery_enabled: boolean;
  } | null;
};

async function apiFetch<T>(
  path: string,
  token: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`API ${path} failed (${response.status}): ${detail}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export function fetchMe(token: string): Promise<MeResponse> {
  return apiFetch<MeResponse>("/v1/me", token);
}

export function fetchOrganizations(token: string): Promise<OrganizationResponse[]> {
  return apiFetch<OrganizationResponse[]>("/v1/organizations", token);
}

export function fetchTargets(token: string): Promise<TargetResponse[]> {
  return apiFetch<TargetResponse[]>("/v1/targets", token);
}

export function fetchTargetMonitoring(
  token: string,
  targetId: string,
): Promise<MonitoringConfigurationResponse> {
  return apiFetch<MonitoringConfigurationResponse>(
    `/v1/targets/${targetId}/monitoring`,
    token,
  );
}

export function fetchAssessmentHistory(
  token: string,
  targetId: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<AssessmentHistoryResponse> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<AssessmentHistoryResponse>(
    `/v1/targets/${targetId}/assessment-history${query ? `?${query}` : ""}`,
    token,
  );
}

export function fetchSecurityOverview(
  token: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<SecurityOverviewResponse> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<SecurityOverviewResponse>(
    `/v1/security-overview${query ? `?${query}` : ""}`,
    token,
  );
}

export function updateTargetMonitoring(
  token: string,
  targetId: string,
  body: {
    enabled: boolean;
    frequency: "daily" | "weekly";
    auto_generate_reports?: boolean;
    auto_deliver_reports?: boolean;
    auto_deliver_expires_in?: "24h" | "7d" | "30d";
    recipients?: string[];
  },
): Promise<MonitoringConfigurationResponse> {
  return apiFetch<MonitoringConfigurationResponse>(
    `/v1/targets/${targetId}/monitoring`,
    token,
    {
      method: "PUT",
      body: JSON.stringify(body),
    },
  );
}

export function createTarget(token: string, domain: string): Promise<TargetResponse> {
  return apiFetch<TargetResponse>("/v1/targets", token, {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
}

export function startTargetVerification(
  token: string,
  targetId: string,
): Promise<TargetResponse> {
  return apiFetch<TargetResponse>(`/v1/targets/${targetId}/verification`, token, {
    method: "POST",
  });
}

export function verifyTarget(
  token: string,
  targetId: string,
): Promise<VerifyTargetResponse> {
  return apiFetch<VerifyTargetResponse>(`/v1/targets/${targetId}/verify`, token, {
    method: "POST",
  });
}

export function revokeTarget(token: string, targetId: string): Promise<TargetResponse> {
  return apiFetch<TargetResponse>(`/v1/targets/${targetId}/revoke`, token, {
    method: "POST",
  });
}

export function fetchTargetScope(
  token: string,
  targetId: string,
): Promise<TargetScopeResponse> {
  return apiFetch<TargetScopeResponse>(`/v1/targets/${targetId}/scope`, token);
}

export function updateTargetScope(
  token: string,
  targetId: string,
  body: { include_subdomains: boolean; exclusions: string[] },
): Promise<TargetScopeResponse> {
  return apiFetch<TargetScopeResponse>(`/v1/targets/${targetId}/scope`, token, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function fetchOperations(token: string): Promise<OperationResponse[]> {
  return apiFetch<OperationResponse[]>("/v1/operations", token);
}

export function createOperation(
  token: string,
  targetId: string,
): Promise<OperationResponse> {
  return apiFetch<OperationResponse>("/v1/operations", token, {
    method: "POST",
    body: JSON.stringify({ target_id: targetId }),
  });
}

export function fetchOperation(
  token: string,
  operationId: string,
): Promise<OperationResponse> {
  return apiFetch<OperationResponse>(`/v1/operations/${operationId}`, token);
}

export function fetchOperationEvents(
  token: string,
  operationId: string,
): Promise<OperationEventResponse[]> {
  return apiFetch<OperationEventResponse[]>(
    `/v1/operations/${operationId}/events`,
    token,
  );
}

export function stopOperation(
  token: string,
  operationId: string,
): Promise<OperationResponse> {
  return apiFetch<OperationResponse>(`/v1/operations/${operationId}/stop`, token, {
    method: "POST",
  });
}

export function fetchOperationAssets(
  token: string,
  operationId: string,
): Promise<AssetResponse[]> {
  return apiFetch<AssetResponse[]>(`/v1/operations/${operationId}/assets`, token);
}

export function fetchOperationObservations(
  token: string,
  operationId: string,
): Promise<DiscoveryObservationResponse[]> {
  return apiFetch<DiscoveryObservationResponse[]>(
    `/v1/operations/${operationId}/observations`,
    token,
  );
}

export function fetchOperationCoverage(
  token: string,
  operationId: string,
): Promise<OperationCoverageResponse> {
  return apiFetch<OperationCoverageResponse>(
    `/v1/operations/${operationId}/coverage`,
    token,
  );
}

export type OperationDiffChange = {
  category: string;
  change_type: string;
  significance: string;
  match_key: string | null;
  before: unknown;
  after: unknown;
  explanation: string;
};

export type OperationDiffResponse = {
  schema_version: number;
  source: string;
  frozen_at: string | null;
  comparability: string;
  baseline_operation_id: string | null;
  baseline_completed_at: string | null;
  current_source: string | null;
  baseline_source: string | null;
  operation_status_at_freeze: string | null;
  security_signal_baseline_unavailable: boolean;
  security_signal_comparison_suppressed: boolean;
  security_signal_suppression_reason: string | null;
  headline: string;
  counts: Record<string, unknown>;
  changes: OperationDiffChange[];
  comparison_snapshot: Record<string, unknown>;
  follow_up_findings: Array<{
    change_type: string;
    hostname: string;
    candidate_type: string;
    finding_id: string;
    status: string;
    created_at: string | null;
    updated_at: string | null;
    resolved_at: string | null;
  }>;
};

export function fetchOperationDiff(
  token: string,
  operationId: string,
): Promise<OperationDiffResponse> {
  return apiFetch<OperationDiffResponse>(
    `/v1/operations/${operationId}/diff`,
    token,
  );
}

export function fetchOperationCandidates(
  token: string,
  operationId: string,
): Promise<SecurityCandidateResponse[]> {
  return apiFetch<SecurityCandidateResponse[]>(
    `/v1/operations/${operationId}/candidates`,
    token,
  );
}

export function fetchCandidate(
  token: string,
  candidateId: string,
): Promise<SecurityCandidateResponse> {
  return apiFetch<SecurityCandidateResponse>(`/v1/candidates/${candidateId}`, token);
}

export function queueCandidateValidation(
  token: string,
  candidateId: string,
): Promise<ValidationAttemptResponse> {
  return apiFetch<ValidationAttemptResponse>(
    `/v1/candidates/${candidateId}/validate`,
    token,
    { method: "POST" },
  );
}

export function fetchCandidateValidationAttempts(
  token: string,
  candidateId: string,
): Promise<ValidationAttemptResponse[]> {
  return apiFetch<ValidationAttemptResponse[]>(
    `/v1/candidates/${candidateId}/validation-attempts`,
    token,
  );
}

export function promoteCandidate(
  token: string,
  candidateId: string,
): Promise<FindingResponse> {
  return apiFetch<FindingResponse>(`/v1/candidates/${candidateId}/promote`, token, {
    method: "POST",
  });
}

/**
 * Legacy cross-membership finding list. Kept for backward compatibility only;
 * the dashboard's organization-scoped collection is fetchFindingsInbox.
 */
export function fetchFindings(token: string): Promise<FindingResponse[]> {
  return apiFetch<FindingResponse[]>("/v1/findings", token);
}

export function fetchFindingsInbox(
  token: string,
  options: {
    page_size?: number;
    cursor?: string | null;
  } & FindingInboxFilters = {},
): Promise<FindingInboxResponse> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  if (options.status) params.set("status", options.status);
  if (options.severity) params.set("severity", options.severity);
  if (options.target_id) params.set("target_id", options.target_id);
  if (options.retest_state) params.set("retest_state", options.retest_state);
  if (options.assigned_to_user_id)
    params.set("assigned_to_user_id", options.assigned_to_user_id);
  if (options.unassigned === true) params.set("unassigned", "true");
  const query = params.toString();
  return apiFetch<FindingInboxResponse>(
    `/v1/findings/inbox${query ? `?${query}` : ""}`,
    token,
  );
}

export type AlertDeliveryStatus = {
  channel: string;
  destination_key: string;
  status: string;
  attempt_count: number;
  delivered_at: string | null;
  last_error_code: string | null;
};

export type AlertResponse = {
  id: string;
  organization_id: string;
  target_id: string;
  target_domain: string | null;
  episode_id: string;
  operation_id: string;
  diff_summary_id: string;
  alert_type: string;
  category: string;
  priority: string;
  semantic_key: string;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  created_at: string | null;
  episode_status: string | null;
  reopened_from_episode_id: string | null;
  last_seen_operation_id: string | null;
  acknowledged_at: string | null;
  acknowledged_by_user_id: string | null;
  read_at: string | null;
  dismissed_at: string | null;
  deliveries: AlertDeliveryStatus[];
  disclaimer: string;
};

export type AlertSummaryResponse = {
  unread_count: number;
  open_episode_count: number;
  visible_alert_count: number;
  by_category: Record<string, number>;
  disclaimer: string;
};

export type AlertListFilters = {
  category?: string;
  priority?: string;
  unread?: boolean;
  include_dismissed?: boolean;
};

export function fetchAlerts(
  token: string,
  filters: AlertListFilters = {},
): Promise<AlertResponse[]> {
  const params = new URLSearchParams();
  if (filters.category) params.set("category", filters.category);
  if (filters.priority) params.set("priority", filters.priority);
  if (filters.unread) params.set("unread", "true");
  if (filters.include_dismissed) params.set("include_dismissed", "true");
  const suffix = params.toString() ? `?${params.toString()}` : "";
  return apiFetch<AlertResponse[]>(`/v1/alerts${suffix}`, token);
}

export function fetchAlertSummary(token: string): Promise<AlertSummaryResponse> {
  return apiFetch<AlertSummaryResponse>("/v1/alerts/summary", token);
}

export function fetchAlert(token: string, alertId: string): Promise<AlertResponse> {
  return apiFetch<AlertResponse>(`/v1/alerts/${alertId}`, token);
}

export function markAlertRead(token: string, alertId: string): Promise<AlertResponse> {
  return apiFetch<AlertResponse>(`/v1/alerts/${alertId}/read`, token, {
    method: "POST",
  });
}

export function acknowledgeAlert(
  token: string,
  alertId: string,
): Promise<AlertResponse> {
  return apiFetch<AlertResponse>(`/v1/alerts/${alertId}/acknowledge`, token, {
    method: "POST",
  });
}

export function dismissAlert(token: string, alertId: string): Promise<AlertResponse> {
  return apiFetch<AlertResponse>(`/v1/alerts/${alertId}/dismiss`, token, {
    method: "POST",
  });
}

export type NotificationMember = {
  user_id: string;
  name: string | null;
  email: string;
  email_verified: boolean;
};

export type NotificationSettingsResponse = {
  organization_id: string;
  email_enabled: boolean;
  email_min_priority: string;
  finding_follow_up_reminders_enabled: boolean;
  recipients: NotificationMember[];
  members: NotificationMember[];
  can_manage: boolean;
};

export type NotificationSettingsUpdateRequest = {
  email_enabled: boolean;
  email_min_priority: string;
  finding_follow_up_reminders_enabled: boolean;
  recipient_user_ids: string[];
};

export function fetchNotificationSettings(
  token: string,
  orgId: string,
): Promise<NotificationSettingsResponse> {
  return apiFetch<NotificationSettingsResponse>(
    `/v1/organizations/${orgId}/notification-settings`,
    token,
  );
}

export function updateNotificationSettings(
  token: string,
  orgId: string,
  body: NotificationSettingsUpdateRequest,
): Promise<NotificationSettingsResponse> {
  return apiFetch<NotificationSettingsResponse>(
    `/v1/organizations/${orgId}/notification-settings`,
    token,
    { method: "PUT", body: JSON.stringify(body) },
  );
}

export type NotificationDeliveryClass =
  | "alert_email"
  | "report_delivery"
  | "follow_up_reminder";

export type NotificationDeliveryState =
  | "pending"
  | "processing"
  | "retrying"
  | "delivered"
  | "skipped"
  | "dead";

export type NotificationDeliverySafeReasonCode =
  | "recipient_unavailable"
  | "recipient_changed"
  | "delivery_revoked"
  | "delivery_expired"
  | "environment_restricted"
  | "finding_resolved"
  | "owner_changed"
  | "due_changed"
  | "follow_up_generation_changed"
  | "assignee_not_current_member"
  | "recipient_no_deliverable_email"
  | "reminders_disabled"
  | "identity_provider_unavailable"
  | "delivery_temporarily_unavailable"
  | "delivery_issue";

export type NotificationDeliveryRecipient =
  | {
      kind: "organization_member";
      user_id: string;
      display_name: string | null;
    }
  | { kind: "external_recipient" };

export type NotificationDeliveryDetail =
  | {
      delivery_class: "alert_email";
      alert_id: string;
      alert_type: string;
      priority: string;
      category: string;
    }
  | {
      delivery_class: "report_delivery";
      report_id: string;
      report_version: number | null;
      generation_origin: string | null;
    }
  | {
      delivery_class: "follow_up_reminder";
      finding_id: string;
      finding_title: string;
      due_at: string;
    };

export type NotificationDeliveryRow = {
  delivery_class: NotificationDeliveryClass;
  state: NotificationDeliveryState;
  safe_reason_code: NotificationDeliverySafeReasonCode | null;
  safe_reason_label: string | null;
  created_at: string;
  delivered_at: string | null;
  target: { target_id: string; domain: string } | null;
  detail: NotificationDeliveryDetail;
  recipient: NotificationDeliveryRecipient | null;
};

export type NotificationDeliveriesResponse = {
  configuration: {
    alert_email_enabled: boolean;
    follow_up_reminders_enabled: boolean;
    email_delivery_enabled: boolean;
  };
  items: NotificationDeliveryRow[];
  next_cursor: string | null;
};

export function fetchNotificationDeliveries(
  token: string,
  params?: {
    page_size?: number;
    cursor?: string;
    delivery_class?: NotificationDeliveryClass;
    state?: NotificationDeliveryState;
  },
): Promise<NotificationDeliveriesResponse> {
  const search = new URLSearchParams();
  if (params?.page_size != null) {
    search.set("page_size", String(params.page_size));
  }
  if (params?.cursor) search.set("cursor", params.cursor);
  if (params?.delivery_class) {
    search.set("delivery_class", params.delivery_class);
  }
  if (params?.state) search.set("state", params.state);
  const qs = search.toString();
  return apiFetch<NotificationDeliveriesResponse>(
    `/v1/notification-deliveries${qs ? `?${qs}` : ""}`,
    token,
  );
}

export function fetchFinding(
  token: string,
  findingId: string,
): Promise<FindingResponse> {
  return apiFetch<FindingResponse>(`/v1/findings/${findingId}`, token);
}

export function fetchFindingRemediation(
  token: string,
  findingId: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<FindingRemediationHistory> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<FindingRemediationHistory>(
    `/v1/findings/${findingId}/remediation${query ? `?${query}` : ""}`,
    token,
  );
}

export function fetchFindingTimeline(
  token: string,
  findingId: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<FindingTimelineResponse> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<FindingTimelineResponse>(
    `/v1/findings/${findingId}/timeline${query ? `?${query}` : ""}`,
    token,
  );
}

export function recordFindingRemediation(
  token: string,
  findingId: string,
  summary: string,
): Promise<FindingRemediationRevision> {
  return apiFetch<FindingRemediationRevision>(
    `/v1/findings/${findingId}/remediation`,
    token,
    { method: "POST", body: JSON.stringify({ summary }) },
  );
}

export function startFindingRemediation(
  token: string,
  findingId: string,
): Promise<FindingResponse> {
  return apiFetch<FindingResponse>(
    `/v1/findings/${findingId}/start-remediation`,
    token,
    { method: "POST" },
  );
}

export function markFindingReadyForRetest(
  token: string,
  findingId: string,
): Promise<FindingResponse> {
  return apiFetch<FindingResponse>(
    `/v1/findings/${findingId}/ready-for-retest`,
    token,
    { method: "POST" },
  );
}

export type OrganizationMember = {
  user_id: string;
  display_name: string | null;
};

export type OrganizationMembersResponse = {
  page_size: number;
  next_cursor: string | null;
  items: OrganizationMember[];
};

export function fetchOrganizationMembers(
  token: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<OrganizationMembersResponse> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<OrganizationMembersResponse>(
    `/v1/organization-members${query ? `?${query}` : ""}`,
    token,
  );
}

export function updateFindingFollowUp(
  token: string,
  findingId: string,
  body: {
    assigned_to_user_id: string | null;
    follow_up_due_at: string | null;
  },
): Promise<FindingFollowUp> {
  return apiFetch<FindingFollowUp>(`/v1/findings/${findingId}/follow-up`, token, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export type ReminderCustomerState =
  | "disabled"
  | "not_applicable"
  | "generation_unavailable"
  | "scheduled_for_future"
  | "awaiting_discovery"
  | "pending"
  | "processing"
  | "retrying"
  | "delivered"
  | "skipped"
  | "dead";

export type ReminderJobCustomerState =
  | "pending"
  | "processing"
  | "retrying"
  | "delivered"
  | "skipped"
  | "dead";

export type FindingFollowUpReminderStatus = {
  finding_id: string;
  reminders_enabled: boolean;
  email_delivery_enabled: boolean;
  state: ReminderCustomerState;
  current_generation: {
    due_at: string;
    owner: { user_id: string; display_name: string | null };
  } | null;
  reminder: {
    safe_reason_code: string | null;
    safe_reason_label: string | null;
    created_at: string;
    delivered_at: string | null;
  } | null;
};

export type FindingFollowUpReminderHistoryItem = {
  reminder_kind: "due";
  due_at: string;
  owner: { user_id: string; display_name: string | null } | null;
  state: ReminderJobCustomerState;
  safe_reason_code: string | null;
  safe_reason_label: string | null;
  created_at: string;
  delivered_at: string | null;
};

export type FindingFollowUpReminderHistory = {
  finding_id: string;
  page_size: number;
  next_cursor: string | null;
  items: FindingFollowUpReminderHistoryItem[];
};

export function fetchFindingFollowUpReminderStatus(
  token: string,
  findingId: string,
): Promise<FindingFollowUpReminderStatus> {
  return apiFetch<FindingFollowUpReminderStatus>(
    `/v1/findings/${findingId}/follow-up-reminder`,
    token,
  );
}

export function fetchFindingFollowUpReminderHistory(
  token: string,
  findingId: string,
  options: { page_size?: number; cursor?: string | null } = {},
): Promise<FindingFollowUpReminderHistory> {
  const params = new URLSearchParams();
  if (options.page_size != null) params.set("page_size", String(options.page_size));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return apiFetch<FindingFollowUpReminderHistory>(
    `/v1/findings/${findingId}/follow-up-reminders${query ? `?${query}` : ""}`,
    token,
  );
}

export function queueFindingRetest(
  token: string,
  findingId: string,
): Promise<RetestAttemptResponse> {
  return apiFetch<RetestAttemptResponse>(`/v1/findings/${findingId}/retest`, token, {
    method: "POST",
  });
}

export function fetchFindingRetests(
  token: string,
  findingId: string,
): Promise<RetestAttemptResponse[]> {
  return apiFetch<RetestAttemptResponse[]>(
    `/v1/findings/${findingId}/retests`,
    token,
  );
}

export type AuditEventFilters = {
  resource_type?: string;
  resource_id?: string;
  action?: string;
  created_after?: string;
  created_before?: string;
  limit?: number;
};

export function fetchAuditEvents(
  token: string,
  filters: AuditEventFilters = {},
): Promise<AuditEventResponse[]> {
  const params = new URLSearchParams();
  if (filters.resource_type) params.set("resource_type", filters.resource_type);
  if (filters.resource_id) params.set("resource_id", filters.resource_id);
  if (filters.action) params.set("action", filters.action);
  if (filters.created_after) params.set("created_after", filters.created_after);
  if (filters.created_before) params.set("created_before", filters.created_before);
  if (filters.limit != null) params.set("limit", String(filters.limit));
  const query = params.toString();
  return apiFetch<AuditEventResponse[]>(
    `/v1/audit-events${query ? `?${query}` : ""}`,
    token,
  );
}

export function generateAssessmentReport(
  token: string,
  operationId: string,
): Promise<AssessmentReportResponse> {
  return apiFetch<AssessmentReportResponse>(
    `/v1/operations/${operationId}/report`,
    token,
    { method: "POST" },
  );
}

export function fetchOperationReports(
  token: string,
  operationId: string,
): Promise<AssessmentReportSummaryResponse[]> {
  return apiFetch<AssessmentReportSummaryResponse[]>(
    `/v1/operations/${operationId}/reports`,
    token,
  );
}

export function fetchAssessmentReports(
  token: string,
  filters: { target_id?: string; operation_id?: string; limit?: number } = {},
): Promise<AssessmentReportSummaryResponse[]> {
  const params = new URLSearchParams();
  if (filters.target_id) params.set("target_id", filters.target_id);
  if (filters.operation_id) params.set("operation_id", filters.operation_id);
  if (filters.limit != null) params.set("limit", String(filters.limit));
  const query = params.toString();
  return apiFetch<AssessmentReportSummaryResponse[]>(
    `/v1/reports${query ? `?${query}` : ""}`,
    token,
  );
}

export function fetchAssessmentReport(
  token: string,
  reportId: string,
): Promise<AssessmentReportResponse> {
  return apiFetch<AssessmentReportResponse>(`/v1/reports/${reportId}`, token);
}

function filenameFromContentDisposition(header: string | null): string {
  const fallback = "assessment-report.pdf";
  if (!header) return fallback;
  const match = /filename="([^"]+)"/i.exec(header);
  const name = match?.[1] ?? "";
  if (!/^[a-z0-9][a-z0-9._-]*\.pdf$/.test(name)) return fallback;
  return name;
}

export async function createAssessmentReportShare(
  token: string,
  reportId: string,
  expiresIn: "24h" | "7d" | "30d",
): Promise<import("@/lib/shared-report").CreateReportShareResponse> {
  return apiFetch(`/v1/reports/${reportId}/shares`, token, {
    method: "POST",
    body: JSON.stringify({ expires_in: expiresIn }),
  });
}

export async function fetchAssessmentReportShares(
  token: string,
  reportId: string,
): Promise<import("@/lib/shared-report").ReportShareListItem[]> {
  return apiFetch(`/v1/reports/${reportId}/shares`, token);
}

export async function revokeAssessmentReportShare(
  token: string,
  shareId: string,
): Promise<void> {
  await apiFetch(`/v1/report-shares/${shareId}/revoke`, token, {
    method: "POST",
  });
}

export async function exportAssessmentReportPdf(
  token: string,
  reportId: string,
): Promise<{ blob: Blob; filename: string }> {
  const path = `/v1/reports/${reportId}/pdf`;
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/pdf",
    },
    cache: "no-store",
  });
  if (!response.ok) {
    if (response.status === 409) {
      let unsupportedCharacters = false;
      try {
        const payload = (await response.json()) as {
          error?: { message?: string };
        };
        unsupportedCharacters =
          payload.error?.message ===
          "Report contains characters that cannot be exported";
      } catch {
        unsupportedCharacters = false;
      }
      throw new Error(
        unsupportedCharacters
          ? "This report contains characters that the PDF exporter cannot render yet."
          : "This report cannot be exported.",
      );
    }
    if (response.status === 503) {
      throw new Error("PDF export is unavailable");
    }
    throw new Error(`Failed to export PDF (${response.status})`);
  }
  return {
    blob: await response.blob(),
    filename: filenameFromContentDisposition(
      response.headers.get("Content-Disposition"),
    ),
  };
}

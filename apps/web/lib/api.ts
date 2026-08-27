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
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
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

export function updateTargetMonitoring(
  token: string,
  targetId: string,
  body: {
    enabled: boolean;
    frequency: "daily" | "weekly";
    auto_generate_reports?: boolean;
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

export function fetchFindings(token: string): Promise<FindingResponse[]> {
  return apiFetch<FindingResponse[]>("/v1/findings", token);
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
  recipients: NotificationMember[];
  members: NotificationMember[];
  can_manage: boolean;
};

export type NotificationSettingsUpdateRequest = {
  email_enabled: boolean;
  email_min_priority: string;
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

export function fetchFinding(
  token: string,
  findingId: string,
): Promise<FindingResponse> {
  return apiFetch<FindingResponse>(`/v1/findings/${findingId}`, token);
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

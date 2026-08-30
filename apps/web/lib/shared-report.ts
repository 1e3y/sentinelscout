export type SharedReportFinding = {
  title?: string;
  summary?: string;
  observation_class?: string;
  severity?: string;
  status?: string;
  is_open?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  resolved_at?: string | null;
  business_impact?: string;
  remediation_guidance?: string;
  remediation_record?: {
    recorded?: boolean;
    revision_count?: number;
    latest_recorded_at?: string | null;
  };
  retest_attempts?: number;
  affected_asset?: { hostname?: string | null; url?: string | null };
  validation?: {
    method?: string | null;
    status?: string | null;
    summary?: string | null;
  };
  latest_retest?: {
    status?: string;
    method?: string;
    summary?: string;
    completed_at?: string | null;
  } | null;
  evidence?: Record<string, unknown>;
};

export type SharedReportChange = {
  change_type?: string;
  category?: string;
  significance?: string;
  match_key?: string;
  explanation?: string;
  before?: string | number | boolean;
  after?: string | number | boolean;
};

export function generationOriginLabel(origin?: string | null): string {
  if (origin === "scheduled_automatic") {
    return "Automatic (scheduled)";
  }
  return "Manual";
}

export type SharedReportPublic = {
  report: {
    id: string;
    version: number;
    generated_at: string;
    snapshot_digest: string;
    assessment_completeness: string;
    generation_origin?: "manual" | "scheduled_automatic";
  };
  identity: {
    organization_name?: string;
    target_domain?: string;
    target_authorization_status?: string;
    operation_source?: string;
    operation_status?: string;
    testing_profile?: string;
    assessment_completeness?: string;
    operation_started_at?: string | null;
    operation_completed_at?: string | null;
    operation_failed_at?: string | null;
    operation_stopped_at?: string | null;
  };
  scope: {
    explanation?: string;
    scope_root?: string;
    include_subdomains?: boolean;
    exclusions?: string[];
  };
  coverage: {
    frozen: {
      explanation?: string;
      headline?: string;
      frozen_at?: string | null;
      operation_status_at_freeze?: string;
      capability_manifest_version?: number;
    };
    follow_up: {
      explanation?: string;
      counts?: Record<string, number>;
    };
    limitations: {
      explanation?: string;
      coverage_limitations?: Array<{
        reason_code?: string;
        count?: number;
        explanation?: string;
      }>;
    };
  };
  summary: {
    headline_status?: string;
    headline_label?: string;
    headline_statement?: string;
    assessment_completeness?: string;
    findings_total?: number;
    findings_open?: number;
    findings_resolved?: number;
    severity_counts_open?: Record<string, number>;
    regression_count?: number;
    coverage_limitation_count?: number;
  };
  findings: SharedReportFinding[];
  not_promoted: {
    explanation?: string;
    candidates_generated?: number;
    validations_conclusive?: number;
    validations_inconclusive?: number;
    validations_failed?: number;
    validations_not_attempted?: number;
  };
  change_context: {
    available: boolean;
    explanation?: string;
    comparability?: string;
    diff_headline?: string;
    security_signal_comparison_suppressed?: boolean;
    security_signal_suppression_reason?: string | null;
    security_regressions?: SharedReportChange[];
    coverage_degradations?: SharedReportChange[];
    resolved_conditions_reappeared?: SharedReportChange[];
  };
  methodology: {
    testing_profile?: string;
    capability_manifest_version?: number;
    supported_classes?: Array<{ title?: string; applies_to?: string }>;
    unsupported_classes?: Array<{ title?: string; explanation?: string }>;
    safety_controls?: string[];
  };
};

export type ReportShareListItem = {
  id: string;
  report_id: string;
  created_by_user_id: string | null;
  creation_origin?: "manual" | "scheduled_automatic";
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  status: "active" | "expired" | "revoked";
};

export type CreateReportShareResponse = {
  id: string;
  expires_at: string;
  expires_in: "24h" | "7d" | "30d";
  share_url: string;
};

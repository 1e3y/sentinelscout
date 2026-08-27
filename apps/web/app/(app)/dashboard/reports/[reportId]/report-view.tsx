import type {
  AssessmentReportChange,
  AssessmentReportContent,
  AssessmentReportFinding,
  AssessmentReportResponse,
} from "@/lib/api";
import { generationOriginLabel } from "@/lib/shared-report";

const HEADLINE_TONE: Record<string, string> = {
  assessment_incomplete: "border-amber-300 bg-amber-50 text-amber-900",
  action_required: "border-red-300 bg-red-50 text-red-900",
  attention_recommended: "border-yellow-300 bg-yellow-50 text-yellow-900",
  no_open_supported_findings: "border-zinc-300 bg-zinc-50 text-zinc-900",
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "border-red-300 text-red-800",
  high: "border-red-200 text-red-700",
  medium: "border-amber-300 text-amber-800",
  low: "border-zinc-300 text-zinc-700",
  informational: "border-zinc-200 text-zinc-600",
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="report-section space-y-3 border-t border-zinc-200 pt-6">
      <h2 className="text-lg font-medium tracking-tight">{title}</h2>
      {children}
    </section>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-zinc-500">{label}</dt>
      <dd className="text-sm text-zinc-800">{value}</dd>
    </div>
  );
}

function IncompleteBanner({ content }: { content: AssessmentReportContent }) {
  if (content.identity.assessment_completeness !== "incomplete") return null;
  return (
    <div
      data-testid="assessment-incomplete-banner"
      className="report-incomplete rounded-md border-2 border-amber-400 bg-amber-50 px-4 py-3"
    >
      <p className="text-sm font-semibold uppercase tracking-wide text-amber-900">
        Assessment Incomplete
      </p>
      <p className="mt-1 text-sm text-amber-900">
        {content.summary.headline_statement}
      </p>
      <p className="mt-1 text-xs text-amber-800">
        Operation status: {content.identity.operation_status}. Coverage of the
        authorized scope is partial.
      </p>
    </div>
  );
}

function EvidenceList({ evidence }: { evidence: Record<string, unknown> }) {
  const observed = (evidence.observed_facts ?? {}) as Record<string, unknown>;
  const signals = (evidence.deterministic_signals ?? {}) as Record<string, unknown>;
  const headers = (evidence.missing_security_headers ?? []) as {
    header_name: string;
    observed: boolean;
  }[];
  const entries = Object.entries(observed);
  const signalEntries = Object.entries(signals);

  if (!entries.length && !signalEntries.length && !headers.length) {
    return (
      <p className="text-xs text-zinc-500">
        No customer-safe structured evidence fields were recorded for this finding.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {entries.length ? (
        <dl className="grid gap-1 sm:grid-cols-2">
          {entries.map(([key, value]) => (
            <Field
              key={key}
              label={key.replaceAll("_", " ")}
              value={
                Array.isArray(value) ? value.join(", ") : String(value ?? "—")
              }
            />
          ))}
        </dl>
      ) : null}
      {headers.length ? (
        <div>
          <p className="text-xs uppercase tracking-wide text-zinc-500">
            Security headers not observed
          </p>
          <ul className="list-inside list-disc text-sm text-zinc-800">
            {headers.map((header) => (
              <li key={header.header_name}>
                <span className="font-mono text-xs">{header.header_name}</span> — not
                present on the observed response
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {signalEntries.length ? (
        <dl className="grid gap-1">
          {signalEntries.map(([key, value]) => (
            <Field
              key={key}
              label={key.replaceAll("_", " ")}
              value={
                Array.isArray(value) ? value.join("; ") : String(value ?? "—")
              }
            />
          ))}
        </dl>
      ) : null}
    </div>
  );
}

function FindingCard({ finding }: { finding: AssessmentReportFinding }) {
  return (
    <article className="report-finding space-y-3 rounded-md border border-zinc-200 p-4">
      <header className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded border px-2 py-0.5 text-xs uppercase tracking-wide ${
              SEVERITY_TONE[finding.severity] ?? "border-zinc-300 text-zinc-700"
            }`}
          >
            {finding.severity}
          </span>
          <span className="rounded border border-zinc-300 px-2 py-0.5 text-xs text-zinc-700">
            {finding.is_open ? "Open" : "Resolved"} · {finding.status}
          </span>
          <span className="font-mono text-xs text-zinc-500">
            {finding.observation_class}
          </span>
        </div>
        <h3 className="text-base font-medium">{finding.title}</h3>
        <p className="text-sm text-zinc-700">{finding.summary}</p>
      </header>

      <dl className="grid gap-2 sm:grid-cols-2">
        <Field
          label="Affected asset"
          value={
            finding.affected_asset.url ?? finding.affected_asset.hostname ?? "—"
          }
        />
        <Field
          label="Validation"
          value={`${finding.validation.status ?? "—"} · ${
            finding.validation.method ?? "—"
          }`}
        />
        <Field label="First observed" value={formatTime(finding.created_at)} />
        <Field
          label="State last changed"
          value={formatTime(finding.updated_at)}
        />
      </dl>

      <div className="space-y-1">
        <p className="text-xs uppercase tracking-wide text-zinc-500">
          Business impact
        </p>
        <p className="text-sm text-zinc-800">{finding.business_impact}</p>
      </div>
      <div className="space-y-1">
        <p className="text-xs uppercase tracking-wide text-zinc-500">Remediation</p>
        <p className="text-sm text-zinc-800">{finding.remediation_guidance}</p>
      </div>

      {finding.latest_retest ? (
        <div className="space-y-1 rounded border border-zinc-200 bg-zinc-50 p-3">
          <p className="text-xs uppercase tracking-wide text-zinc-500">
            Latest retest at report generation
          </p>
          <p className="text-sm text-zinc-800">
            {finding.latest_retest.status} · {finding.latest_retest.method} ·{" "}
            {formatTime(finding.latest_retest.completed_at)}
          </p>
          <p className="text-sm text-zinc-700">{finding.latest_retest.summary}</p>
        </div>
      ) : (
        <p className="text-xs text-zinc-500">
          No completed retest existed when this report was generated.
        </p>
      )}

      <div className="space-y-1">
        <p className="text-xs uppercase tracking-wide text-zinc-500">
          Evidence Scout observed
        </p>
        <EvidenceList evidence={finding.evidence} />
      </div>
    </article>
  );
}

function ChangeList({
  title,
  changes,
}: {
  title: string;
  changes: AssessmentReportChange[];
}) {
  if (!changes.length) return null;
  return (
    <div className="space-y-1">
      <p className="text-xs uppercase tracking-wide text-zinc-500">{title}</p>
      <ul className="list-inside list-disc space-y-1 text-sm text-zinc-800">
        {changes.map((change, index) => (
          <li key={`${change.change_type}-${change.match_key}-${index}`}>
            <span className="font-mono text-xs">{change.change_type}</span>
            {change.match_key ? ` · ${change.match_key}` : ""}
            {change.explanation ? ` — ${change.explanation}` : ""}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AssessmentReportView({ report }: { report: AssessmentReportResponse }) {
  const { envelope, content } = report.snapshot;
  const { identity, scope, coverage, summary, methodology, change_context } = content;
  const frozen = coverage.frozen_operation_coverage;
  const followUp = coverage.follow_up_frozen_for_report;
  const openFindings = content.findings.filter((item) => item.is_open);
  const closedFindings = content.findings.filter((item) => !item.is_open);

  return (
    <article className="report-root space-y-6">
      <header className="space-y-3">
        <p className="text-xs uppercase tracking-wide text-zinc-500">
          Sentinel Scout security assessment
        </p>
        <h1 className="text-2xl font-semibold tracking-tight">
          {identity.target_domain}
        </h1>
        <IncompleteBanner content={content} />
        <div
          className={`rounded-md border px-4 py-3 ${
            HEADLINE_TONE[summary.headline_status] ??
            "border-zinc-300 bg-zinc-50 text-zinc-900"
          }`}
        >
          <p
            data-testid="headline-label"
            className="text-sm font-semibold uppercase tracking-wide"
          >
            {summary.headline_label}
          </p>
          <p className="mt-1 text-sm">{summary.headline_statement}</p>
        </div>
        <dl className="grid gap-2 text-sm sm:grid-cols-3">
          <Field label="Organization" value={identity.organization_name} />
          <Field label="Report generated" value={formatTime(envelope.generated_at)} />
          <Field
            label="Generation"
            value={generationOriginLabel(
              envelope.origin ?? report.generation_origin,
            )}
          />
          <Field label="Report version" value={`v${envelope.report_version}`} />
          <Field label="Operation status" value={identity.operation_status} />
          <Field
            label="Completeness"
            value={identity.assessment_completeness}
          />
          <Field
            label="Snapshot digest"
            value={
              <span className="font-mono text-xs break-all">
                {envelope.snapshot_digest}
              </span>
            }
          />
        </dl>
      </header>

      <Section id="executive-summary" title="1. Executive Summary">
        {identity.assessment_completeness === "incomplete" ? (
          <p
            data-testid="executive-incomplete-marker"
            className="text-sm font-semibold text-amber-900"
          >
            Assessment Incomplete — this operation did not run to completion and the
            results below cover only part of the authorized scope.
          </p>
        ) : null}
        <p className="text-sm text-zinc-800">{summary.headline_statement}</p>
        <dl className="grid gap-2 text-sm sm:grid-cols-4">
          <Field label="Findings total" value={summary.findings_total} />
          <Field label="Open findings" value={summary.findings_open} />
          <Field label="Resolved findings" value={summary.findings_resolved} />
          <Field
            label="Coverage limitations"
            value={summary.coverage_limitation_count}
          />
        </dl>
        {Object.keys(summary.severity_counts_open).length ? (
          <p className="text-sm text-zinc-700">
            Open findings by severity:{" "}
            {Object.entries(summary.severity_counts_open)
              .map(([severity, count]) => `${severity} ${count}`)
              .join(", ")}
            .
          </p>
        ) : null}
      </Section>

      <Section id="assessment-scope" title="2. Assessment Scope">
        {identity.assessment_completeness === "incomplete" ? (
          <p
            data-testid="scope-incomplete-marker"
            className="text-sm font-semibold text-amber-900"
          >
            Operation status {identity.operation_status} — Assessment Incomplete.
          </p>
        ) : null}
        <p className="text-sm text-zinc-700">{scope.explanation}</p>
        <dl className="grid gap-2 text-sm sm:grid-cols-2">
          <Field label="Scope root" value={scope.scope_root} />
          <Field
            label="Subdomains"
            value={scope.include_subdomains ? "In scope" : "Root only"}
          />
          <Field
            label="Target authorization at launch"
            value={identity.target_authorization_status}
          />
          <Field label="Testing profile" value={identity.testing_profile} />
          <Field label="Operation source" value={identity.operation_source} />
          <Field
            label="Operation window"
            value={`${formatTime(identity.operation_started_at)} → ${formatTime(
              identity.operation_completed_at ??
                identity.operation_stopped_at ??
                identity.operation_failed_at,
            )}`}
          />
        </dl>
        <div>
          <p className="text-xs uppercase tracking-wide text-zinc-500">Exclusions</p>
          {scope.exclusions.length ? (
            <ul className="list-inside list-disc text-sm text-zinc-800">
              {scope.exclusions.map((item) => (
                <li key={item} className="font-mono text-xs">
                  {item}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-zinc-700">None configured.</p>
          )}
        </div>
      </Section>

      <Section id="what-scout-tested" title="3. What Scout Tested">
        <p className="text-sm text-zinc-700">{frozen.explanation}</p>
        <ul className="list-inside list-disc space-y-1 text-sm text-zinc-800">
          {(methodology.supported_classes ?? []).map((item) => (
            <li key={item.id}>
              {item.title}
              <span className="text-zinc-500"> — applies to {item.applies_to}</span>
            </li>
          ))}
        </ul>
        <p className="text-sm text-zinc-700">{frozen.headline}</p>
      </Section>

      <Section id="coverage" title="4. Coverage &amp; Limitations">
        <p className="text-sm text-zinc-700">{coverage.limitations.explanation}</p>
        {coverage.limitations.coverage_limitations.length ? (
          <ul className="space-y-1 text-sm text-zinc-800">
            {coverage.limitations.coverage_limitations.map((limitation) => (
              <li key={limitation.reason_code}>
                <span className="font-mono text-xs">{limitation.reason_code}</span> ·{" "}
                {limitation.count} — {limitation.explanation}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-zinc-700">
            No concrete coverage limitation was recorded for this operation.
          </p>
        )}
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-zinc-500">
            Frozen operation coverage (frozen {formatTime(frozen.frozen_at)})
          </p>
          <p className="text-sm text-zinc-700">
            Operation status at freeze: {frozen.operation_status_at_freeze}. Capability
            manifest v{frozen.capability_manifest_version}.
          </p>
        </div>
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-zinc-500">
            Follow-up frozen for this report
          </p>
          <p className="text-sm text-zinc-700">{followUp.explanation}</p>
          <dl className="grid gap-1 text-sm sm:grid-cols-3">
            {Object.entries(followUp.counts).map(([key, value]) => (
              <Field key={key} label={key.replaceAll("_", " ")} value={value} />
            ))}
          </dl>
        </div>
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-wide text-zinc-500">
            Test classes Scout does not perform
          </p>
          <ul className="list-inside list-disc space-y-1 text-sm text-zinc-800">
            {methodology.unsupported_classes.map((item) => (
              <li key={item.id}>
                {item.title}
                <span className="text-zinc-500"> — {item.explanation}</span>
              </li>
            ))}
          </ul>
        </div>
      </Section>

      <Section id="findings" title="5. Findings">
        {content.findings.length ? (
          <div className="space-y-4">
            {openFindings.map((finding) => (
              <FindingCard key={finding.finding_id} finding={finding} />
            ))}
            {closedFindings.map((finding) => (
              <FindingCard key={finding.finding_id} finding={finding} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-zinc-700">
            Scout promoted no supported findings from this operation.
          </p>
        )}
        <p className="text-sm text-zinc-700">{content.not_promoted.explanation}</p>
        <dl className="grid gap-1 text-sm sm:grid-cols-3">
          <Field
            label="Candidates generated"
            value={content.not_promoted.candidates_generated}
          />
          <Field
            label="Validations conclusive"
            value={content.not_promoted.validations_conclusive}
          />
          <Field
            label="Validations inconclusive"
            value={content.not_promoted.validations_inconclusive}
          />
          <Field
            label="Validations failed"
            value={content.not_promoted.validations_failed}
          />
          <Field
            label="Validations not attempted"
            value={content.not_promoted.validations_not_attempted}
          />
        </dl>
      </Section>

      <Section id="remediation-status" title="6. Remediation Status">
        {content.findings.length ? (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wide text-zinc-500">
                <th className="py-1">Finding</th>
                <th className="py-1">Severity</th>
                <th className="py-1">State at generation</th>
                <th className="py-1">Latest retest</th>
              </tr>
            </thead>
            <tbody>
              {content.findings.map((finding) => (
                <tr key={finding.finding_id} className="border-t border-zinc-100">
                  <td className="py-1 pr-2">{finding.title}</td>
                  <td className="py-1 pr-2">{finding.severity}</td>
                  <td className="py-1 pr-2">{finding.status}</td>
                  <td className="py-1">
                    {finding.latest_retest ? finding.latest_retest.status : "none"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-zinc-700">
            No findings were promoted, so there is no remediation state to report.
          </p>
        )}
      </Section>

      <Section id="changes" title="7. Changes Since Previous Assessment">
        {change_context.available ? (
          <div className="space-y-3">
            <dl className="grid gap-2 text-sm sm:grid-cols-2">
              <Field
                label="Comparability"
                value={change_context.comparability ?? "—"}
              />
              <Field
                label="Baseline operation"
                value={
                  <span className="font-mono text-xs break-all">
                    {change_context.baseline_operation_id ?? "none"}
                  </span>
                }
              />
            </dl>
            {change_context.diff_headline ? (
              <p className="text-sm text-zinc-700">{change_context.diff_headline}</p>
            ) : null}
            {change_context.security_signal_comparison_suppressed ? (
              <p className="text-sm text-zinc-700">
                Security-signal comparison was suppressed:{" "}
                {change_context.security_signal_suppression_reason ?? "not stated"}.
              </p>
            ) : null}
            <ChangeList
              title="Security regressions"
              changes={change_context.security_regressions ?? []}
            />
            <ChangeList
              title="Coverage degradations"
              changes={change_context.coverage_degradations ?? []}
            />
            <ChangeList
              title="Resolved conditions reappeared"
              changes={change_context.resolved_conditions_reappeared ?? []}
            />
          </div>
        ) : (
          <p className="text-sm text-zinc-700">{change_context.explanation}</p>
        )}
      </Section>

      <Section id="methodology" title="8. Methodology &amp; Safety Controls">
        <p className="text-sm text-zinc-700">
          Testing profile {methodology.testing_profile}, capability manifest v
          {methodology.capability_manifest_version}.
        </p>
        <ul className="list-inside list-disc space-y-1 text-sm text-zinc-800">
          {methodology.safety_controls.map((control) => (
            <li key={control}>{control}</li>
          ))}
        </ul>
        <p className="text-xs text-zinc-500">
          This report renders only the immutable snapshot recorded at generation time.
          Report identity {envelope.report_id}, schema v
          {content.report_schema_version}.
        </p>
      </Section>
    </article>
  );
}

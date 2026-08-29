"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";
import {
  fetchSecurityOverview,
  type SecurityOverviewAttentionReason,
  type SecurityOverviewRow,
  type SecurityOverviewSummary,
} from "@/lib/api";
import { generationOriginLabel } from "@/lib/shared-report";

type Props = {
  enabled: boolean;
};

const PROVENANCE_LABELS: Record<string, string> = {
  operation_history: "Run history",
  frozen_assessment: "Frozen assessment",
  current_state: "Current",
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function statusLabel(status: string): string {
  if (status === "completed") return "Completed";
  if (status === "failed") return "Failed";
  if (status === "stopped") return "Stopped";
  return status;
}

function sourceLabel(source: string): string {
  return source === "scheduled" ? "Scheduled" : "Manual";
}

function authorizationLabel(status: string): string {
  if (status === "verified") return "Verified";
  if (status === "revoked") return "Revoked";
  if (status === "verification_pending") return "Verification pending";
  return "Unverified";
}

function latestRunLine(row: SecurityOverviewRow): string {
  if (!row.latest_terminal) return "No completed, failed, or stopped run yet";
  const { status, source, ended_at } = row.latest_terminal;
  return `${statusLabel(status)} · ${sourceLabel(source)} · ${formatTime(ended_at)}`;
}

function lastCompletedLine(row: SecurityOverviewRow): string {
  if (!row.latest_completed) return "Never completed";
  return `${formatTime(row.latest_completed.completed_at)} · ${sourceLabel(
    row.latest_completed.source,
  )}`;
}

function coverageLine(row: SecurityOverviewRow): string {
  if (!row.latest_completed) {
    return "No completed assessment, so no frozen coverage exists";
  }
  if (!row.coverage) return "Coverage snapshot unavailable";
  const { http_observation_obtained, in_scope_discovered, source } = row.coverage;
  const recovered = source === "recovered" ? " Recovered snapshot." : "";
  return `${http_observation_obtained}/${in_scope_discovered} in-scope hostnames had HTTP observations.${recovered}`;
}

function comparisonLine(row: SecurityOverviewRow): string {
  if (!row.latest_completed) {
    return "No completed assessment, so no frozen comparison exists";
  }
  if (!row.comparison) return "Comparison snapshot unavailable";
  return row.comparison.headline;
}

function signalsLine(row: SecurityOverviewRow): string {
  if (!row.signals) {
    return "Comparison of emitted candidates is unavailable for this assessment.";
  }
  const {
    conservative_regressions: regressions,
    candidates_newly_emitted: added,
    candidates_no_longer_emitted: removed,
  } = row.signals;
  return `${regressions} conservative security-significant regression${
    regressions === 1 ? "" : "s"
  }. ${added} newly emitted candidate${added === 1 ? "" : "s"}. ${removed} candidate${
    removed === 1 ? "" : "s"
  } no longer emitted.`;
}

function alertsLine(row: SecurityOverviewRow): string {
  const { active_episode_count: active, unacknowledged_active_episode_count: unack } =
    row.alerts;
  if (active === 0) return "No active alert episodes";
  return `${active} active alert episode${active === 1 ? "" : "s"}, ${unack} unacknowledged`;
}

function monitoringLine(row: SecurityOverviewRow): string {
  const { monitoring_enabled, frequency, disabled_reason } = row.automation;
  if (!monitoring_enabled) {
    return disabled_reason
      ? `Monitoring off. ${disabled_reason}`
      : "Monitoring off";
  }
  return `Monitoring on · ${frequency === "daily" ? "Daily" : "Weekly"}`;
}

function automationLine(row: SecurityOverviewRow): string {
  const {
    auto_generate_reports,
    auto_deliver_reports,
    delivery_recipient_count,
    auto_deliver_expires_in,
  } = row.automation;
  const reports = auto_generate_reports
    ? "Automatic reports on"
    : "Automatic reports off";
  if (!auto_deliver_reports) return `${reports} · Automatic delivery off`;
  const expiry = auto_deliver_expires_in ? ` · Links expire in ${auto_deliver_expires_in}` : "";
  return `${reports} · Automatic delivery on to ${delivery_recipient_count} recipient${
    delivery_recipient_count === 1 ? "" : "s"
  }${expiry}`;
}

function stalenessLine(row: SecurityOverviewRow): string {
  const { is_stale, threshold_days, days_since_last_completed } = row.staleness;
  if (days_since_last_completed == null) {
    return "No completed assessment, so freshness does not apply";
  }
  const age = `Last completed assessment: ${days_since_last_completed} day${
    days_since_last_completed === 1 ? "" : "s"
  } ago`;
  if (is_stale == null) {
    return `${age}. No active monitoring cadence defines expected freshness.`;
  }
  if (is_stale) {
    return `${age}, beyond the ${threshold_days}-day cadence expectation.`;
  }
  return `${age}, within the ${threshold_days}-day cadence expectation.`;
}

function reportLine(row: SecurityOverviewRow): string {
  const report = row.latest_report;
  if (!report) return "No report for the last completed assessment";
  const versions =
    report.version_count > 1
      ? `Report v${report.report_version} (${report.version_count} versions)`
      : `Report v${report.report_version}`;
  return `${versions} · ${generationOriginLabel(report.generation_origin)} · ${
    report.headline_label
  }`;
}

function AttentionList({
  reasons,
}: {
  reasons: SecurityOverviewAttentionReason[];
}) {
  if (reasons.length === 0) {
    return (
      <p className="text-sm text-zinc-700">
        No current attention reasons. This is not a statement that the application
        is secure.
      </p>
    );
  }
  return (
    <ul className="flex flex-wrap gap-2">
      {reasons.map((reason) => (
        <li
          key={reason.code}
          className="rounded-md border border-amber-300 bg-amber-50 px-2 py-1 text-xs text-amber-950"
        >
          <span className="font-medium">{reason.label}</span>
          <span className="text-amber-900">
            {" "}
            ({PROVENANCE_LABELS[reason.provenance] ?? reason.provenance})
          </span>
        </li>
      ))}
    </ul>
  );
}

function OverviewCard({ row }: { row: SecurityOverviewRow }) {
  return (
    <article className="space-y-3 rounded-md border border-zinc-200 bg-white p-4 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <Link
          className="font-medium text-zinc-900 underline underline-offset-2"
          href="#assessment-history"
        >
          {row.domain}
        </Link>
        <p className="text-xs text-zinc-600">
          {authorizationLabel(row.authorization_status)}
        </p>
      </div>

      <div>
        <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
          Attention
        </h4>
        <AttentionList reasons={row.attention_reasons} />
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <section>
          <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
            Run history
          </h4>
          <dl className="mt-1 grid gap-1 text-zinc-700">
            <div>
              <dt className="text-xs text-zinc-500">Latest run</dt>
              <dd>{latestRunLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Last complete assessment</dt>
              <dd>{lastCompletedLine(row)}</dd>
            </div>
          </dl>
        </section>

        <section>
          <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
            Frozen assessment
          </h4>
          <dl className="mt-1 grid gap-1 text-zinc-700">
            <div>
              <dt className="text-xs text-zinc-500">Coverage</dt>
              <dd>{coverageLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Comparison</dt>
              <dd>{comparisonLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Security signals</dt>
              <dd>{signalsLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Report</dt>
              <dd>
                {row.latest_report ? (
                  <Link
                    className="underline underline-offset-2"
                    href={`/dashboard/reports/${row.latest_report.id}`}
                  >
                    {reportLine(row)}
                  </Link>
                ) : (
                  reportLine(row)
                )}
              </dd>
            </div>
          </dl>
        </section>

        <section>
          <h4 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
            Current
          </h4>
          <dl className="mt-1 grid gap-1 text-zinc-700">
            <div>
              <dt className="text-xs text-zinc-500">Alerts</dt>
              <dd>{alertsLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Monitoring</dt>
              <dd>{monitoringLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Automation</dt>
              <dd>{automationLine(row)}</dd>
            </div>
            <div>
              <dt className="text-xs text-zinc-500">Freshness</dt>
              <dd>{stalenessLine(row)}</dd>
            </div>
          </dl>
        </section>
      </div>
    </article>
  );
}

function summaryLine(summary: SecurityOverviewSummary): string {
  return `${summary.target_count} target${
    summary.target_count === 1 ? "" : "s"
  } in this organization. ${
    summary.verified_targets_without_completed_assessment
  } verified target${
    summary.verified_targets_without_completed_assessment === 1 ? " has" : "s have"
  } no completed assessment. ${summary.targets_with_active_alert_episode} target${
    summary.targets_with_active_alert_episode === 1 ? " has" : "s have"
  } an active alert episode.`;
}

export function SecurityOverviewPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [items, setItems] = useState<SecurityOverviewRow[]>([]);
  const [summary, setSummary] = useState<SecurityOverviewSummary | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  async function load(cursor?: string | null) {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return;
    }
    const page = await fetchSecurityOverview(token, { page_size: 20, cursor });
    // Rows are rendered in the exact order the server returned. Attention is shown
    // per card and is never used to re-rank a loaded page.
    setItems((current) => (cursor ? [...current, ...page.items] : page.items));
    setSummary(page.summary);
    setNextCursor(page.next_cursor);
  }

  function refresh() {
    if (!enabled) return;
    startTransition(async () => {
      setError(null);
      try {
        await load();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load security overview",
        );
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Security Overview</h2>
          <p className="text-sm text-zinc-600">
            Every authorized target in this organization, ordered by domain. Frozen
            assessment evidence and current operational state are labelled
            separately. This is not a security score.
          </p>
        </div>
        <button
          type="button"
          disabled={!enabled || pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => refresh()}
        >
          Refresh
        </button>
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </p>
      ) : null}

      {!enabled ? (
        <p className="text-sm text-zinc-600">
          Select an organization to view the security overview.
        </p>
      ) : (
        <>
          {summary ? (
            <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm text-zinc-700">
              <p>{summaryLine(summary)}</p>
              <p className="text-xs text-zinc-600">
                Counts cover the whole organization. Showing {items.length} of{" "}
                {summary.target_count} targets.
              </p>
            </div>
          ) : null}

          {summary && summary.target_count === 0 ? (
            <p className="text-sm text-zinc-600">
              No authorized targets yet. Add and verify a target to begin.
            </p>
          ) : null}

          <div className="space-y-3">
            {items.map((row) => (
              <OverviewCard key={row.target_id} row={row} />
            ))}
          </div>

          {nextCursor ? (
            <button
              type="button"
              disabled={pending}
              className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
              onClick={() => {
                startTransition(async () => {
                  try {
                    await load(nextCursor);
                  } catch (err) {
                    setError(
                      err instanceof Error
                        ? err.message
                        : "Failed to load more targets",
                    );
                  }
                });
              }}
            >
              Load more targets
            </button>
          ) : null}
        </>
      )}
    </section>
  );
}

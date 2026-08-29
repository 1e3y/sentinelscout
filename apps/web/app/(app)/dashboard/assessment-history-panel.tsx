"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";
import {
  fetchAssessmentHistory,
  fetchTargets,
  type AssessmentHistoryRow,
  type TargetResponse,
} from "@/lib/api";
import { generationOriginLabel } from "@/lib/shared-report";

type Props = {
  enabled: boolean;
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

function completenessLabel(completeness: string): string {
  return completeness === "complete" ? "Completed" : "Incomplete";
}

function sourceLabel(source: string): string {
  return source === "scheduled" ? "Scheduled" : "Manual";
}

function coverageLine(row: AssessmentHistoryRow): string {
  if (!row.coverage) return "Coverage snapshot unavailable";
  const obtained = row.coverage.http_observation_obtained;
  const discovered = row.coverage.in_scope_discovered;
  const recovered =
    row.coverage.source === "recovered" ? " Recovered snapshot." : "";
  return `${obtained}/${discovered} in-scope hostnames had HTTP observations.${recovered}`;
}

function comparisonLine(row: AssessmentHistoryRow): string {
  if (!row.comparison) return "Comparison snapshot unavailable";
  return row.comparison.headline;
}

function reportLine(row: AssessmentHistoryRow): string {
  const report = row.latest_report;
  if (!report) return "No report for this assessment";
  const versions =
    report.version_count > 1
      ? `Report v${report.report_version} (${report.version_count} versions)`
      : `Report v${report.report_version}`;
  return `${versions} · ${generationOriginLabel(report.generation_origin)}`;
}

function HistoryCard({ row }: { row: AssessmentHistoryRow }) {
  const [expanded, setExpanded] = useState(false);
  const incomplete = row.completeness === "incomplete";

  return (
    <article className="space-y-2 rounded-md border border-zinc-200 bg-white p-4 text-sm">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <time className="font-medium text-zinc-900" dateTime={row.ended_at}>
          {formatTime(row.ended_at)}
        </time>
        <p className="text-xs text-zinc-600">
          {statusLabel(row.status)} · {completenessLabel(row.completeness)} ·{" "}
          {sourceLabel(row.source)}
        </p>
      </div>

      {incomplete ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-950">
          This assessment did not finish. Shown values are partial and are not a
          full assessment of the authorized scope.
        </p>
      ) : null}

      <dl className="grid gap-2 text-zinc-700">
        <div>
          <dt className="text-zinc-500">Coverage</dt>
          <dd>{coverageLine(row)}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Comparison</dt>
          <dd>{comparisonLine(row)}</dd>
        </div>
        {row.signals ? (
          <div>
            <dt className="text-zinc-500">Security signals</dt>
            <dd>
              {row.signals.candidates_newly_emitted} new emitted candidate
              {row.signals.candidates_newly_emitted === 1 ? "" : "s"}.{" "}
              {row.signals.candidates_no_longer_emitted} candidate
              {row.signals.candidates_no_longer_emitted === 1 ? "" : "s"} no
              longer emitted. {row.signals.conservative_regressions} conservative
              security-significant regression
              {row.signals.conservative_regressions === 1 ? "" : "s"}.
            </dd>
          </div>
        ) : (
          <div>
            <dt className="text-zinc-500">Security signals</dt>
            <dd>Comparison of emitted candidates is unavailable for this run.</dd>
          </div>
        )}
        <div>
          <dt className="text-zinc-500">Report</dt>
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

      <button
        type="button"
        className="text-xs underline underline-offset-2"
        aria-expanded={expanded}
        onClick={() => setExpanded((current) => !current)}
      >
        {expanded ? "Hide details" : "Show details"}
      </button>

      {expanded ? (
        <div className="space-y-2 border-t border-zinc-100 pt-3 text-xs text-zinc-700">
          {row.coverage ? (
            <p>
              Submitted {row.coverage.submitted_for_http_observation}/
              {row.coverage.in_scope_discovered} for HTTP observation.{" "}
              {row.coverage.http_observation_not_obtained} hostname
              {row.coverage.http_observation_not_obtained === 1 ? "" : "s"}{" "}
              without a usable HTTP observation. Headers captured on{" "}
              {row.coverage.headers_captured}/{row.coverage.http_observations}{" "}
              observations.
              {row.coverage.discovery_truncated
                ? " Discovery host list was truncated."
                : ""}
            </p>
          ) : (
            <p>No frozen coverage snapshot exists for this operation.</p>
          )}
          {row.surface_changes ? (
            <p>
              Surface vs frozen baseline:{" "}
              {row.surface_changes.hostnames_newly_discovered} newly discovered,{" "}
              {row.surface_changes.hostnames_no_longer_discovered} no longer
              discovered, {row.surface_changes.http_observation_gained} HTTP
              observations gained, {row.surface_changes.http_observation_lost}{" "}
              lost.
            </p>
          ) : null}
          {row.signals ? (
            <p>
              Regressions recorded at freeze: HSTS lost{" "}
              {row.signals.regression_hsts_lost}; previously resolved condition
              reappeared {row.signals.regression_resolved_condition_reappeared};
              header evidence lost {row.signals.regression_header_evidence_lost}.
            </p>
          ) : null}
          {row.comparison?.security_signal_suppression_reason ? (
            <p>{row.comparison.security_signal_suppression_reason}</p>
          ) : null}
          {row.latest_report ? (
            <p>
              As recorded in report v{row.latest_report.report_version} on{" "}
              {formatTime(row.latest_report.generated_at)}:{" "}
              {row.latest_report.headline_label}.{" "}
              {row.latest_report.findings_open} open supported finding
              {row.latest_report.findings_open === 1 ? "" : "s"} at generation
              time. This is report-time state, not current remediation state.
            </p>
          ) : null}
          {row.error_code ? (
            <p>
              Error code {row.error_code}
              {row.error_message ? `: ${row.error_message}` : ""}
            </p>
          ) : null}
          <p className="text-zinc-500">
            <Link
              className="underline underline-offset-2"
              href="/dashboard"
            >
              Open this operation from the Operations panel
            </Link>{" "}
            for coverage and comparison detail.
          </p>
        </div>
      ) : null}
    </article>
  );
}

export function AssessmentHistoryPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [items, setItems] = useState<AssessmentHistoryRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const verifiedTargets = targets.filter((target) => target.status === "verified");
  const selected = targets.find((target) => target.id === selectedId) ?? null;

  async function loadHistory(targetId: string, cursor?: string | null) {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return;
    }
    const page = await fetchAssessmentHistory(token, targetId, {
      page_size: 20,
      cursor,
    });
    setItems((current) => (cursor ? [...current, ...page.items] : page.items));
    setNextCursor(page.next_cursor);
  }

  function refresh() {
    if (!enabled) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const list = await fetchTargets(token);
        setTargets(list);
        const verified = list.filter((target) => target.status === "verified");
        const nextId =
          (selectedId && verified.some((target) => target.id === selectedId) && selectedId) ||
          verified[0]?.id ||
          null;
        setSelectedId(nextId);
        if (nextId) {
          await loadHistory(nextId);
        } else {
          setItems([]);
          setNextCursor(null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load assessment history");
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
          <h2 className="text-lg font-medium">Assessment History</h2>
          <p className="text-sm text-zinc-600">
            Chronological frozen snapshots for one authorized target. This is not a
            security score.
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
          Select an organization to view assessment history.
        </p>
      ) : verifiedTargets.length === 0 ? (
        <p className="text-sm text-zinc-600">
          Select a target to see assessment history. Verify a target first.
        </p>
      ) : (
        <div className="grid gap-4 md:grid-cols-[14rem_1fr]">
          <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-200 bg-white">
            {verifiedTargets.map((target) => (
              <li key={target.id}>
                <button
                  type="button"
                  className={`w-full px-3 py-2 text-left text-sm ${
                    target.id === selectedId ? "bg-zinc-100" : ""
                  }`}
                  onClick={() => {
                    setSelectedId(target.id);
                    startTransition(async () => {
                      try {
                        setError(null);
                        await loadHistory(target.id);
                      } catch (err) {
                        setError(
                          err instanceof Error
                            ? err.message
                            : "Failed to load assessment history",
                        );
                      }
                    });
                  }}
                >
                  <div className="font-medium">{target.domain}</div>
                </button>
              </li>
            ))}
          </ul>

          <div className="space-y-3">
            {selected && items.length === 0 && !pending ? (
              <p className="text-sm text-zinc-600">
                No completed, failed, or stopped assessments yet.
              </p>
            ) : null}
            {items.map((row) => (
              <HistoryCard key={row.operation_id} row={row} />
            ))}
            {nextCursor ? (
              <button
                type="button"
                disabled={pending}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
                onClick={() => {
                  if (!selectedId) return;
                  startTransition(async () => {
                    try {
                      await loadHistory(selectedId, nextCursor);
                    } catch (err) {
                      setError(
                        err instanceof Error
                          ? err.message
                          : "Failed to load more history",
                      );
                    }
                  });
                }}
              >
                Load older assessments
              </button>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}

"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState, useTransition } from "react";
import {
  fetchFindingsInbox,
  type CurrentRetestState,
  type FindingInboxFilters,
  type FindingInboxResponse,
  type FindingInboxRow,
  type FindingWorkflowState,
  type TargetAuthorizationStatus,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  selectedFindingId: string | null;
  onSelect: (findingId: string) => void;
  reloadToken: number;
};

const PAGE_SIZE = 20;

const WORKFLOW_LABELS: Record<FindingWorkflowState, string> = {
  not_started: "Remediation not started",
  in_progress: "Remediation in progress",
  ready_for_retest: "Ready for retest",
  resolved_by_retest: "Resolved by passing retest",
};

const RETEST_LABELS: Record<CurrentRetestState, string> = {
  none: "No retest run",
  in_progress: "Retest in progress",
  passed: "Latest retest passed",
  failed: "Latest retest failed",
  inconclusive: "Latest retest inconclusive",
  error: "Latest retest errored",
};

const AUTHORIZATION_LABELS: Record<TargetAuthorizationStatus, string> = {
  unverified: "Unverified",
  verification_pending: "Verification pending",
  verified: "Verified",
  revoked: "Revoked",
};

const STATUS_OPTIONS = [
  ["", "Any status"],
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["ready_for_retest", "Ready for retest"],
  ["resolved", "Resolved"],
] as const;

const SEVERITY_OPTIONS = [
  ["", "Any severity"],
  ["informational", "Informational"],
  ["low", "Low"],
  ["medium", "Medium"],
  ["high", "High"],
  ["critical", "Critical"],
] as const;

const RETEST_OPTIONS = [
  ["", "Any retest state"],
  ["none", "No retest run"],
  ["in_progress", "Retest in progress"],
  ["passed", "Passed"],
  ["failed", "Failed"],
  ["inconclusive", "Inconclusive"],
  ["error", "Error"],
] as const;

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

const EMPTY_FILTERS: FindingInboxFilters = {
  status: "",
  severity: "",
  retest_state: "",
};

export function FindingsInboxPanel({
  enabled,
  selectedFindingId,
  onSelect,
  reloadToken,
}: Props) {
  const { getToken } = useAuth();
  const [payload, setPayload] = useState<FindingInboxResponse | null>(null);
  const [rows, setRows] = useState<FindingInboxRow[]>([]);
  const [filters, setFilters] = useState<FindingInboxFilters>(EMPTY_FILTERS);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const load = useCallback(
    (cursor: string | null, append: boolean) => {
      if (!enabled) return;
      startTransition(async () => {
        setError(null);
        try {
          const token = await getToken();
          if (!token) {
            setError("Missing session token");
            return;
          }
          const next = await fetchFindingsInbox(token, {
            page_size: PAGE_SIZE,
            cursor,
            ...filters,
          });
          setPayload(next);
          // Server order is authoritative; rows are never re-sorted here.
          setRows((prev) => (append ? [...prev, ...next.items] : next.items));
        } catch (err) {
          setError(
            err instanceof Error ? err.message : "Failed to load current findings",
          );
        }
      });
    },
    [enabled, filters, getToken],
  );

  useEffect(() => {
    load(null, false);
  }, [load, reloadToken]);

  const summary = payload?.summary ?? null;

  return (
    <section className="space-y-4" aria-labelledby="current-findings-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="current-findings-heading" className="text-lg font-medium">
            Current Findings
          </h2>
          <p className="text-sm text-zinc-600">
            Live state for every supported finding in your active organization.
            These values are read from the current workflow and retest records,
            not from a frozen assessment snapshot.
          </p>
        </div>
        <button
          type="button"
          disabled={!enabled || pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => load(null, false)}
        >
          Refresh
        </button>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          {error}
        </p>
      ) : null}

      {!enabled ? (
        <p className="text-sm text-zinc-600">
          Select an organization to view current findings.
        </p>
      ) : (
        <>
          {summary ? (
            <dl className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-md border border-zinc-200 bg-white px-3 py-2">
                <dt className="text-xs text-zinc-500">Supported findings</dt>
                <dd className="text-lg font-medium">{summary.finding_count}</dd>
              </div>
              <div className="rounded-md border border-zinc-200 bg-white px-3 py-2">
                <dt className="text-xs text-zinc-500">Not yet resolved</dt>
                <dd className="text-lg font-medium">
                  {summary.open_finding_count}
                </dd>
              </div>
              <div className="rounded-md border border-zinc-200 bg-white px-3 py-2">
                <dt className="text-xs text-zinc-500">
                  No retest attempt recorded
                </dt>
                <dd className="text-lg font-medium">
                  {summary.findings_without_any_retest}
                </dd>
                <p className="mt-1 text-xs text-zinc-500">
                  Counts every finding with no attempt on record, including those
                  not yet marked ready for retest.
                </p>
              </div>
            </dl>
          ) : null}

          <div className="flex flex-wrap gap-3">
            <label className="text-sm">
              <span className="sr-only">Filter by status</span>
              <select
                className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                value={filters.status ?? ""}
                disabled={pending}
                onChange={(event) =>
                  setFilters((prev) => ({
                    ...prev,
                    status: event.target.value as FindingInboxFilters["status"],
                  }))
                }
              >
                {STATUS_OPTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm">
              <span className="sr-only">Filter by severity</span>
              <select
                className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                value={filters.severity ?? ""}
                disabled={pending}
                onChange={(event) =>
                  setFilters((prev) => ({
                    ...prev,
                    severity: event.target
                      .value as FindingInboxFilters["severity"],
                  }))
                }
              >
                {SEVERITY_OPTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm">
              <span className="sr-only">Filter by retest state</span>
              <select
                className="rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                value={filters.retest_state ?? ""}
                disabled={pending}
                onChange={(event) =>
                  setFilters((prev) => ({
                    ...prev,
                    retest_state: event.target
                      .value as FindingInboxFilters["retest_state"],
                  }))
                }
              >
                {RETEST_OPTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {rows.length === 0 ? (
            <p className="text-sm text-zinc-600">
              {filters.status || filters.severity || filters.retest_state
                ? "No current findings match these filters."
                : "No supported findings yet. Absence of findings is not a security clearance."}
            </p>
          ) : (
            <ul className="space-y-2">
              {rows.map((row) => {
                const selected = row.finding_id === selectedFindingId;
                return (
                  <li key={row.finding_id}>
                    <button
                      type="button"
                      aria-current={selected ? "true" : undefined}
                      className={`w-full rounded-md border px-3 py-3 text-left ${
                        selected
                          ? "border-zinc-400 bg-zinc-50"
                          : "border-zinc-200 bg-white"
                      }`}
                      onClick={() => onSelect(row.finding_id)}
                    >
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <span className="font-medium">{row.title}</span>
                        <span className="font-mono text-xs text-zinc-500">
                          {row.target.domain}
                        </span>
                      </div>
                      <div className="mt-1 font-mono text-xs text-zinc-500 break-all">
                        {row.target.asset_hostname} · {row.finding_type}
                      </div>
                      <dl className="mt-2 grid gap-x-4 gap-y-1 text-xs text-zinc-700 sm:grid-cols-2">
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Severity:</dt>
                          <dd className="font-mono">{row.severity}</dd>
                        </div>
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Workflow:</dt>
                          <dd>{WORKFLOW_LABELS[row.workflow.state]}</dd>
                        </div>
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Retest:</dt>
                          <dd>
                            {RETEST_LABELS[row.retests.current_state]}
                            {row.retests.current_state === "in_progress" &&
                            row.retests.latest_terminal ? (
                              <span className="text-zinc-500">
                                {" "}
                                (previous:{" "}
                                {row.retests.latest_terminal.status})
                              </span>
                            ) : null}
                          </dd>
                        </div>
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Target:</dt>
                          <dd>
                            {AUTHORIZATION_LABELS[
                              row.target.authorization_status
                            ]}
                          </dd>
                        </div>
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Last updated:</dt>
                          <dd>{formatTime(row.last_updated_at)}</dd>
                        </div>
                        <div className="flex gap-1">
                          <dt className="text-zinc-500">Promoted:</dt>
                          <dd>{formatTime(row.promoted_at)}</dd>
                        </div>
                      </dl>
                      {row.attention_reasons.length > 0 ? (
                        <ul className="mt-2 flex flex-wrap gap-1.5">
                          {row.attention_reasons.map((reason) => (
                            <li
                              key={reason.code}
                              className="rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700"
                            >
                              {reason.label}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                      {row.target.authorization_status !== "verified" ? (
                        <p className="mt-2 text-xs text-zinc-600">
                          Retest is unavailable while this target is{" "}
                          {AUTHORIZATION_LABELS[
                            row.target.authorization_status
                          ].toLowerCase()}
                          .
                        </p>
                      ) : null}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          {payload?.next_cursor ? (
            <button
              type="button"
              disabled={pending}
              className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
              onClick={() => load(payload.next_cursor, true)}
            >
              Load more
            </button>
          ) : null}
        </>
      )}
    </section>
  );
}

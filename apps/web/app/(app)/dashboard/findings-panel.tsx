"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState, useTransition } from "react";
import {
  fetchFinding,
  fetchFindingRetests,
  markFindingReadyForRetest,
  queueFindingRetest,
  startFindingRemediation,
  type FindingResponse,
  type RetestAttemptResponse,
} from "@/lib/api";

type Props = {
  findingId: string | null;
  onFindingChanged: () => void;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function statusLabel(status: string): string {
  switch (status) {
    case "in_progress":
      return "In progress";
    case "ready_for_retest":
      return "Ready for retest";
    case "resolved":
      return "Resolved";
    default:
      return "Open";
  }
}

function retestOutcomeLabel(status: string): string | null {
  switch (status) {
    case "passed":
      return "PASS";
    case "failed":
      return "FAIL";
    case "inconclusive":
      return "INCONCLUSIVE";
    case "error":
      return "ERROR";
    case "pending":
    case "running":
      return "Retest in progress";
    default:
      return null;
  }
}

/**
 * Detail and workflow actions for one finding. The organization-scoped
 * collection lives in FindingsInboxPanel; this panel never lists findings, so
 * the dashboard cannot show two lists with different org scopes.
 */
export function FindingsPanel({ findingId, onFindingChanged }: Props) {
  const { getToken } = useAuth();
  const [selected, setSelected] = useState<FindingResponse | null>(null);
  const [retests, setRetests] = useState<RetestAttemptResponse[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const latestRetest = retests[retests.length - 1] ?? null;
  const retestActive =
    latestRetest?.status === "pending" || latestRetest?.status === "running";

  const load = useCallback(() => {
    startTransition(async () => {
      setError(null);
      setMessage(null);
      if (!findingId) {
        setSelected(null);
        setRetests([]);
        return;
      }
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const [finding, attempts] = await Promise.all([
          fetchFinding(token, findingId),
          fetchFindingRetests(token, findingId),
        ]);
        setSelected(finding);
        setRetests(attempts);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load finding");
      }
    });
  }, [findingId, getToken]);

  useEffect(() => {
    load();
  }, [load]);

  function runAction(
    action: (token: string, id: string) => Promise<unknown>,
    successMessage: string,
    failureMessage: string,
  ) {
    if (!selected) return;
    startTransition(async () => {
      setError(null);
      setMessage(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        await action(token, selected.id);
        setMessage(successMessage);
        const [finding, attempts] = await Promise.all([
          fetchFinding(token, selected.id),
          fetchFindingRetests(token, selected.id),
        ]);
        setSelected(finding);
        setRetests(attempts);
        onFindingChanged();
      } catch (err) {
        setError(err instanceof Error ? err.message : failureMessage);
      }
    });
  }

  return (
    <section className="space-y-4" aria-labelledby="finding-detail-heading">
      <div>
        <h2 id="finding-detail-heading" className="text-lg font-medium">
          Finding detail
        </h2>
        <p className="text-sm text-zinc-600">
          Evidence, provenance and remediation workflow for the finding selected
          above. Resolution only after a passing retest.
        </p>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
          {message}
        </p>
      ) : null}

      {!selected ? (
        <p className="text-sm text-zinc-600">
          Select a finding from Current Findings to see its evidence and
          remediation workflow.
        </p>
      ) : (
        <div className="space-y-4 rounded-md border border-zinc-200 bg-white p-4 text-sm">
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-wide text-zinc-500">
              Evidence-supported
            </p>
            <h3 className="text-base font-medium">{selected.title}</h3>
          </div>

          <dl className="grid gap-2 text-zinc-700">
            <div>
              <dt className="text-zinc-500">Severity</dt>
              <dd className="font-mono text-xs">{selected.severity}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Affected asset</dt>
              <dd className="font-mono text-xs break-all">
                {selected.asset_hostname ?? selected.asset_id}
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Status</dt>
              <dd>{statusLabel(selected.status)}</dd>
            </div>
            {selected.status === "resolved" ? (
              <div>
                <dt className="text-zinc-500">Resolved at</dt>
                <dd>{formatTime(selected.resolved_at)}</dd>
              </div>
            ) : null}
            <div>
              <dt className="text-zinc-500">Business impact</dt>
              <dd>{selected.business_impact}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Remediation guidance</dt>
              <dd>{selected.remediation_guidance}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Created</dt>
              <dd>{formatTime(selected.created_at)}</dd>
            </div>
          </dl>

          {selected.provenance ? (
            <div className="space-y-2 border-t border-zinc-100 pt-4">
              <h4 className="text-sm font-medium tracking-wide text-zinc-800">
                PROVENANCE
              </h4>
              <p className="font-mono text-xs text-zinc-600">
                {(selected.provenance.observation_ids[0]
                  ? "Observation"
                  : "Observation (none)") +
                  " → Candidate → Safe validation → Finding" +
                  (selected.provenance.retest_attempt_id ? " → Retest" : "") +
                  (selected.status === "resolved" ? " → Resolved" : "")}
              </p>
              <dl className="grid gap-2 text-xs text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Observation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.observation_ids.length > 0
                      ? selected.provenance.observation_ids.join(", ")
                      : "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Candidate</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.candidate_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Safe validation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.validation_attempt_id ?? "—"}
                    {selected.provenance.validation_method
                      ? ` · ${selected.provenance.validation_method}`
                      : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Finding</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.finding_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Asset / Operation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.asset_id} ·{" "}
                    {selected.provenance.operation_id}
                  </dd>
                </div>
                {selected.provenance.retest_attempt_id ? (
                  <div>
                    <dt className="text-zinc-500">Retest</dt>
                    <dd className="font-mono break-all">
                      {selected.provenance.retest_attempt_id}
                    </dd>
                  </div>
                ) : null}
              </dl>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2">
            {selected.status === "open" ? (
              <button
                type="button"
                disabled={pending}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                onClick={() =>
                  runAction(
                    startFindingRemediation,
                    "Remediation started.",
                    "Failed to start remediation",
                  )
                }
              >
                Start Remediation
              </button>
            ) : null}
            {selected.status === "in_progress" ? (
              <button
                type="button"
                disabled={pending}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                onClick={() =>
                  runAction(
                    markFindingReadyForRetest,
                    "Marked ready for retest.",
                    "Failed to mark ready for retest",
                  )
                }
              >
                Mark Ready for Retest
              </button>
            ) : null}
            {selected.status === "ready_for_retest" ? (
              <button
                type="button"
                disabled={pending || retestActive}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                onClick={() =>
                  runAction(
                    queueFindingRetest,
                    "Safe retest queued. Worker will recheck the original observable condition.",
                    "Failed to queue retest",
                  )
                }
              >
                {retestActive ? "Retest in progress" : "Run Retest"}
              </button>
            ) : null}
          </div>

          {latestRetest ? (
            <div className="space-y-1 rounded-md bg-zinc-50 px-3 py-2 text-xs text-zinc-700">
              {retestOutcomeLabel(latestRetest.status) ? (
                <p className="font-medium tracking-wide text-zinc-800">
                  {retestOutcomeLabel(latestRetest.status)}
                </p>
              ) : null}
              <p>{latestRetest.summary}</p>
              <p>
                <span className="text-zinc-500">Retest method: </span>
                <span className="font-mono">{latestRetest.method}</span>
              </p>
              <p>
                <span className="text-zinc-500">
                  Original validation reference:{" "}
                </span>
                <span className="font-mono break-all">
                  {latestRetest.original_validation_attempt_id}
                </span>
              </p>
              {latestRetest.evidence?.recheck &&
              typeof latestRetest.evidence.recheck === "object" ? (
                <p>
                  <span className="text-zinc-500">Observable evidence: </span>
                  <span className="font-mono break-all">
                    {JSON.stringify(latestRetest.evidence.recheck)}
                  </span>
                </p>
              ) : null}
              <p>
                <span className="text-zinc-500">Timestamp: </span>
                {formatTime(latestRetest.completed_at ?? latestRetest.created_at)}
              </p>
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}

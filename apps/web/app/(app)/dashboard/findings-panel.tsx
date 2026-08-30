"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState, useTransition } from "react";
import { FindingActivityTimeline } from "./finding-activity-timeline";
import {
  fetchFinding,
  fetchFindingTimeline,
  markFindingReadyForRetest,
  queueFindingRetest,
  recordFindingRemediation,
  startFindingRemediation,
  type FindingResponse,
  type FindingTimelineResponse,
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

/**
 * Detail and workflow actions for one finding. The organization-scoped
 * collection lives in FindingsInboxPanel; this panel never lists findings, so
 * the dashboard cannot show two lists with different org scopes.
 */
export function FindingsPanel({ findingId, onFindingChanged }: Props) {
  const { getToken } = useAuth();
  const [selected, setSelected] = useState<FindingResponse | null>(null);
  const [timeline, setTimeline] = useState<FindingTimelineResponse | null>(null);
  const [remediationSummary, setRemediationSummary] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const retestActive = timeline?.current_retest_state === "in_progress";

  const load = useCallback(() => {
    startTransition(async () => {
      setError(null);
      setMessage(null);
      if (!findingId) {
        setSelected(null);
        setTimeline(null);
        setRemediationSummary("");
        return;
      }
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const [finding, activity] = await Promise.all([
          fetchFinding(token, findingId),
          fetchFindingTimeline(token, findingId),
        ]);
        setSelected(finding);
        setTimeline(activity);
        setRemediationSummary("");
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
        const [finding, activity] = await Promise.all([
          fetchFinding(token, selected.id),
          fetchFindingTimeline(token, selected.id),
        ]);
        setSelected(finding);
        setTimeline(activity);
        onFindingChanged();
      } catch (err) {
        setError(err instanceof Error ? err.message : failureMessage);
      }
    });
  }

  function saveRemediationRevision() {
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
        await recordFindingRemediation(token, selected.id, remediationSummary);
        const activity = await fetchFindingTimeline(token, selected.id);
        setTimeline(activity);
        setRemediationSummary("");
        setMessage("Remediation recorded.");
        onFindingChanged();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to record remediation",
        );
      }
    });
  }

  function loadMoreActivity() {
    if (!selected || !timeline?.next_cursor) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const next = await fetchFindingTimeline(token, selected.id, {
          cursor: timeline.next_cursor,
        });
        setTimeline((current) =>
          current
            ? {
                ...next,
                events: [...current.events, ...next.events],
              }
            : next,
        );
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load finding activity",
        );
      }
    });
  }

  const remediationCharacterCount = Array.from(remediationSummary).length;
  const remediationCanSave =
    remediationSummary.trim().length > 0 &&
    remediationCharacterCount <= 4000 &&
    selected?.status !== "resolved";
  const readyForRetestBlocked =
    selected?.status === "in_progress" &&
    (timeline?.remediation_revision_count ?? 0) === 0;

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

          {timeline ? (
            <FindingActivityTimeline
              timeline={timeline}
              pending={pending}
              onLoadMore={loadMoreActivity}
            />
          ) : null}

          <div className="space-y-3 border-t border-zinc-100 pt-4">
            <div>
              <h4 className="text-sm font-medium text-zinc-800">
                Remediation record
              </h4>
              <p className="text-xs text-zinc-600">
                Customer-recorded remediation describes work performed; it is not
                verification. Only a passing retest confirms the condition is no
                longer present.
              </p>
            </div>

            <p className="text-xs text-zinc-500">
              {timeline?.remediation_revision_count
                ? `${timeline.remediation_revision_count} remediation revision${
                    timeline.remediation_revision_count === 1 ? "" : "s"
                  } recorded. Full history appears above.`
                : "No remediation has been recorded."}
            </p>

            {selected.status !== "resolved" ? (
              <div className="space-y-2">
                <label className="block text-xs font-medium text-zinc-700">
                  Record what changed
                  <textarea
                    value={remediationSummary}
                    disabled={pending}
                    rows={5}
                    className="mt-1 block w-full rounded-md border border-zinc-300 p-2 text-sm disabled:opacity-50"
                    onChange={(event) => setRemediationSummary(event.target.value)}
                  />
                </label>
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <p className="text-zinc-500">
                    Do not include passwords, API keys, tokens, or other secrets.
                  </p>
                  <p
                    className={
                      remediationCharacterCount > 4000
                        ? "text-red-700"
                        : "text-zinc-500"
                    }
                  >
                    {remediationCharacterCount}/4000
                  </p>
                </div>
                <button
                  type="button"
                  disabled={pending || !remediationCanSave}
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                  onClick={saveRemediationRevision}
                >
                  Record remediation
                </button>
              </div>
            ) : (
              <p className="text-xs text-zinc-500">
                Resolved findings cannot receive new remediation revisions.
              </p>
            )}
          </div>

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
              <div>
                <button
                  type="button"
                  disabled={pending || readyForRetestBlocked}
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
                {readyForRetestBlocked ? (
                  <p className="mt-1 text-xs text-zinc-500">
                    Record what you changed before requesting a retest.
                  </p>
                ) : null}
              </div>
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
        </div>
      )}
    </section>
  );
}

"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  createOperation,
  fetchCandidateValidationAttempts,
  fetchOperation,
  fetchOperationAssets,
  fetchOperationCandidates,
  fetchOperationCoverage,
  fetchOperationDiff,
  fetchOperationEvents,
  fetchOperationObservations,
  fetchOperations,
  fetchTargets,
  promoteCandidate,
  queueCandidateValidation,
  stopOperation,
  type AssetResponse,
  type DiscoveryObservationResponse,
  type OperationCoverageResponse,
  type OperationDiffResponse,
  type OperationEventResponse,
  type OperationResponse,
  type SecurityCandidateResponse,
  type TargetResponse,
  type ValidationAttemptResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export function OperationsPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [operations, setOperations] = useState<OperationResponse[]>([]);
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<OperationResponse | null>(null);
  const [events, setEvents] = useState<OperationEventResponse[]>([]);
  const [assets, setAssets] = useState<AssetResponse[]>([]);
  const [observations, setObservations] = useState<DiscoveryObservationResponse[]>(
    [],
  );
  const [coverage, setCoverage] = useState<OperationCoverageResponse | null>(null);
  const [diff, setDiff] = useState<OperationDiffResponse | null>(null);
  const [candidates, setCandidates] = useState<SecurityCandidateResponse[]>([]);
  const [validationByCandidate, setValidationByCandidate] = useState<
    Record<string, ValidationAttemptResponse[]>
  >({});
  const [createTargetId, setCreateTargetId] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const visibleEvents = events.filter((event) => event.operation_id === selectedId);
  const verifiedTargets = targets.filter((target) => target.status === "verified");
  const resolvedCreateTargetId = verifiedTargets.some((target) => target.id === createTargetId)
    ? createTargetId
    : (verifiedTargets[0]?.id ?? "");
  const isActive =
    selected?.status === "queued" || selected?.status === "running";

  async function withToken<T>(fn: (token: string) => Promise<T>): Promise<T | null> {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return null;
    }
    return fn(token);
  }

  async function loadDetail(operationId: string) {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return;
    }
    const [op, nextEvents, nextAssets, nextObservations, nextCandidates, nextCoverage, nextDiff] =
      await Promise.all([
        fetchOperation(token, operationId),
        fetchOperationEvents(token, operationId),
        fetchOperationAssets(token, operationId),
        fetchOperationObservations(token, operationId),
        fetchOperationCandidates(token, operationId),
        fetchOperationCoverage(token, operationId),
        fetchOperationDiff(token, operationId),
      ]);
    setSelected(op);
    setEvents(nextEvents);
    setAssets(nextAssets);
    setObservations(nextObservations);
    setCandidates(nextCandidates);
    setCoverage(nextCoverage);
    setDiff(nextDiff);
    const attemptEntries = await Promise.all(
      nextCandidates.map(async (candidate) => {
        const attempts = await fetchCandidateValidationAttempts(token, candidate.id);
        return [candidate.id, attempts] as const;
      }),
    );
    setValidationByCandidate(Object.fromEntries(attemptEntries));
    setOperations((prev) => prev.map((item) => (item.id === op.id ? op : item)));
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
        const [ops, tgs] = await Promise.all([
          fetchOperations(token),
          fetchTargets(token),
        ]);
        setOperations(ops);
        setTargets(tgs);
        setSelectedId((current) => {
          if (current && ops.some((op) => op.id === current)) return current;
          return ops[0]?.id ?? null;
        });

        const verified = tgs.filter((t) => t.status === "verified");
        setCreateTargetId((current) => {
          if (current && verified.some((t) => t.id === current)) return current;
          return verified[0]?.id ?? "";
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load operations");
      }
    });
  }

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    startTransition(async () => {
      try {
        const token = await getToken();
        if (!token || cancelled) return;
        const [ops, tgs] = await Promise.all([
          fetchOperations(token),
          fetchTargets(token),
        ]);
        if (cancelled) return;
        setOperations(ops);
        setTargets(tgs);
        setSelectedId((current) => {
          if (current && ops.some((op) => op.id === current)) return current;
          return ops[0]?.id ?? null;
        });

        const verified = tgs.filter((t) => t.status === "verified");
        setCreateTargetId((current) => {
          if (current && verified.some((t) => t.id === current)) return current;
          return verified[0]?.id ?? "";
        });
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load operations");
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [enabled, getToken]);

  useEffect(() => {
    if (!selectedId || !enabled) return;
    let cancelled = false;
    void (async () => {
      try {
        await loadDetail(selectedId);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load operation");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, enabled, getToken]);

  useEffect(() => {
    if (!selectedId || !enabled || !isActive) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          if (cancelled) return;
          await loadDetail(selectedId);
        } catch {
          // Keep last good state; next poll retries.
        }
      })();
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, enabled, isActive, getToken]);

  if (!enabled) {
    return (
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Operations</h2>
        <p className="text-sm text-zinc-600">
          Select an active organization to manage Scout operations.
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-medium">Operations</h2>
        <button
          type="button"
          onClick={refresh}
          disabled={pending}
          className="text-sm text-zinc-600 underline"
        >
          Refresh
        </button>
      </div>

      <form
        className="flex flex-col gap-2 sm:flex-row sm:items-center"
        onSubmit={(event) => {
          event.preventDefault();
          if (!resolvedCreateTargetId) return;
          startTransition(async () => {
            setError(null);
            setMessage(null);
            try {
              const created = await withToken((token) =>
                createOperation(token, resolvedCreateTargetId),
              );
              if (!created) return;
              setMessage(`Queued operation ${created.id}`);
              const ops = await withToken(fetchOperations);
              if (ops) {
                setOperations(ops);
                setSelectedId(created.id);
                setSelected(created);
              }
            } catch (err) {
              setError(
                err instanceof Error ? err.message : "Failed to create operation",
              );
            }
          });
        }}
      >
        <select
          value={resolvedCreateTargetId}
          onChange={(event) => setCreateTargetId(event.target.value)}
          className="min-w-0 flex-1 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm"
          required
        >
          <option value="" disabled>
            Select a verified target
          </option>
          {verifiedTargets.map((target) => (
            <option key={target.id} value={target.id}>
              {target.domain}
            </option>
          ))}
        </select>
        <button
          type="submit"
          disabled={pending || verifiedTargets.length === 0}
          className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          Create operation
        </button>
      </form>

      {verifiedTargets.length === 0 ? (
        <p className="text-sm text-zinc-600">
          Verify a target before creating an operation.
        </p>
      ) : null}

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="rounded-md border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-700">
          {message}
        </p>
      ) : null}

      {operations.length === 0 ? (
        <p className="text-sm text-zinc-600">No operations yet.</p>
      ) : (
        <ul className="divide-y divide-zinc-200 rounded-md border border-zinc-200 bg-white">
          {operations.map((operation) => (
            <li key={operation.id}>
              <button
                type="button"
                onClick={() => setSelectedId(operation.id)}
                className={`flex w-full flex-col gap-1 px-4 py-3 text-left text-sm sm:flex-row sm:items-center sm:justify-between ${
                  selectedId === operation.id ? "bg-zinc-100" : ""
                }`}
              >
                <span className="font-mono text-xs">{operation.id}</span>
                <span>{operation.target_domain}</span>
                <span className="font-mono text-xs text-zinc-500">
                  {operation.status}
                </span>
                <span className="text-xs text-zinc-500">
                  {formatTime(operation.created_at)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {selected ? (
        <div className="space-y-4 rounded-md border border-zinc-200 bg-white p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2 text-sm">
              <h3 className="font-medium">Operation detail</h3>
              <dl className="grid gap-2 text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Operation ID</dt>
                  <dd className="font-mono text-xs break-all">{selected.id}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Target</dt>
                  <dd>{selected.target_domain}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Status</dt>
                  <dd className="font-mono text-xs">{selected.status}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Source</dt>
                  <dd className="font-mono text-xs">
                    {selected.source === "scheduled" ? "scheduled" : "manual"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Created</dt>
                  <dd>{formatTime(selected.created_at)}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Started</dt>
                  <dd>{formatTime(selected.started_at)}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Completed</dt>
                  <dd>{formatTime(selected.completed_at)}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">In-scope hostnames</dt>
                  <dd>
                    {coverage
                      ? `${coverage.surface.http_observation_obtained}/${coverage.surface.in_scope_discovered} with HTTP observations`
                      : "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Security candidates</dt>
                  <dd>{coverage?.follow_up.candidates_generated ?? candidates.length}</dd>
                </div>
                {selected.error_message ? (
                  <div>
                    <dt className="text-zinc-500">Error</dt>
                    <dd>
                      <span className="font-mono text-xs">{selected.error_code}</span>
                      {": "}
                      {selected.error_message}
                    </dd>
                  </div>
                ) : null}
              </dl>
            </div>

            {isActive ? (
              <button
                type="button"
                disabled={pending || selected.stop_requested}
                className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 disabled:opacity-50"
                onClick={() => {
                  startTransition(async () => {
                    setError(null);
                    setMessage(null);
                    try {
                      const updated = await withToken((token) =>
                        stopOperation(token, selected.id),
                      );
                      if (!updated) return;
                      setSelected(updated);
                      setMessage(
                        updated.status === "stopped"
                          ? "Operation stopped."
                          : "Stop requested. Worker will halt cooperatively.",
                      );
                      await loadDetail(selected.id);
                    } catch (err) {
                      setError(
                        err instanceof Error ? err.message : "Failed to stop operation",
                      );
                    }
                  });
                }}
              >
                {selected.stop_requested ? "Stop requested" : "Stop operation"}
              </button>
            ) : null}
          </div>

          {selected.control_snapshot ? (
            <div className="space-y-2 border-t border-zinc-100 pt-4">
              <h4 className="text-sm font-medium tracking-wide text-zinc-800">
                OPERATION CONTROLS
              </h4>
              <p className="text-xs text-zinc-500">
                Immutable boundary captured when this operation was created.
              </p>
              <dl className="grid gap-2 text-sm text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Target</dt>
                  <dd>{selected.control_snapshot.target_domain}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Authorization at launch</dt>
                  <dd className="font-mono text-xs">
                    {selected.control_snapshot.authorization_status}
                    {selected.control_snapshot.target_authorization_id
                      ? ` · ${selected.control_snapshot.target_authorization_id}`
                      : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Scope</dt>
                  <dd className="font-mono text-xs">
                    {selected.control_snapshot.scope_root}
                    {selected.control_snapshot.include_subdomains
                      ? " · include subdomains"
                      : " · root only"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Exclusions</dt>
                  <dd className="font-mono text-xs">
                    {selected.control_snapshot.exclusions.length > 0
                      ? selected.control_snapshot.exclusions.join(", ")
                      : "None"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Testing profile</dt>
                  <dd className="font-mono text-xs">
                    {selected.control_snapshot.testing_profile}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Source</dt>
                  <dd className="font-mono text-xs">
                    {selected.control_snapshot.operation_source}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Created by</dt>
                  <dd className="font-mono text-xs break-all">
                    {selected.control_snapshot.created_by_user_id}
                  </dd>
                </div>
              </dl>
            </div>
          ) : null}

          {coverage ? (
            <div className="space-y-3 border-t border-zinc-100 pt-4">
              <h4 className="text-sm font-medium tracking-wide text-zinc-800">
                COVERAGE
              </h4>
              <p className="text-sm text-zinc-700">{coverage.headline}</p>
              <p className="text-xs text-zinc-500">
                Coverage is not a security outcome. Unique in-scope hostnames
                are the surface unit. Header capture is a fact about an HTTP
                observation, not a separate host state. Unsupported classes are
                capability boundaries, not failed probes.
              </p>
              <div>
                <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  Surface coverage
                </h5>
                <dl className="mt-2 grid gap-2 text-sm text-zinc-700">
                  <div>
                    <dt className="text-zinc-500">In-scope discovered</dt>
                    <dd>{coverage.surface.in_scope_discovered}</dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">Submitted for HTTP observation</dt>
                    <dd>{coverage.surface.submitted_for_http_observation}</dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">HTTP observation obtained</dt>
                    <dd>{coverage.surface.http_observation_obtained}</dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">HTTP observation not obtained</dt>
                    <dd>{coverage.surface.http_observation_not_obtained}</dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">Incomplete</dt>
                    <dd>{coverage.surface.incomplete}</dd>
                  </div>
                </dl>
              </div>
              <div>
                <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  HTTP evidence (subordinate)
                </h5>
                <p className="mt-1 text-sm text-zinc-700">
                  Response headers captured on{" "}
                  {coverage.http_evidence.headers_captured}/
                  {coverage.http_evidence.http_observations} HTTP observations
                  {coverage.http_evidence.header_evidence_unavailable
                    ? `; unavailable on ${coverage.http_evidence.header_evidence_unavailable}/${coverage.http_evidence.http_observations}.`
                    : "."}
                </p>
              </div>
              <div>
                <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  Scope and capability boundaries
                </h5>
                <dl className="mt-2 grid gap-2 text-sm text-zinc-700">
                  <div>
                    <dt className="text-zinc-500">Configured exclusions</dt>
                    <dd className="font-mono text-xs">
                      {coverage.scope_boundaries.configured_exclusions.length > 0
                        ? coverage.scope_boundaries.configured_exclusions.join(
                            ", ",
                          )
                        : "None"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">Discarded by authorization scope</dt>
                    <dd>
                      {coverage.scope_boundaries.discovered_results_discarded}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">Discovery truncated</dt>
                    <dd>
                      {coverage.scope_boundaries.discovery_truncated
                        ? `Yes (${coverage.scope_boundaries.truncated_to} of ${coverage.scope_boundaries.truncated_from})`
                        : "No"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-zinc-500">Unsupported capability classes</dt>
                    <dd>
                      {coverage.capability.unsupported.length} classes in
                      manifest v{coverage.capability_manifest_version}
                    </dd>
                  </div>
                </dl>
                <ul className="mt-2 list-disc pl-5 text-xs text-zinc-600">
                  {coverage.capability.unsupported.map((item) => (
                    <li key={item.id}>
                      {item.title}
                      {item.explanation ? ` — ${item.explanation}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                  Security outcomes
                </h5>
                <p className="mt-1 text-sm text-zinc-700">
                  Candidates {coverage.follow_up.candidates_generated}; validations
                  attempted {coverage.follow_up.validations_attempted} (conclusive{" "}
                  {coverage.follow_up.validations_conclusive}, inconclusive{" "}
                  {coverage.follow_up.validations_inconclusive}, failed{" "}
                  {coverage.follow_up.validations_failed}, not attempted{" "}
                  {coverage.follow_up.validations_not_attempted}); findings{" "}
                  {coverage.follow_up.findings}.
                </p>
              </div>
              <p className="text-xs text-zinc-500">
                Newest HTTP observation:{" "}
                {formatTime(coverage.freshness.newest_http_observation_at)} ·
                snapshot {coverage.source}
                {coverage.frozen_at ? ` at ${formatTime(coverage.frozen_at)}` : ""}
              </p>
            </div>
          ) : null}

          {diff ? (
            <div className="space-y-3 border-t border-zinc-100 pt-4">
              <h4 className="text-sm font-medium tracking-wide text-zinc-800">
                CHANGES SINCE PREVIOUS COMPARABLE RUN
              </h4>
              <p className="text-sm text-zinc-700">{diff.headline}</p>
              <p className="text-xs text-zinc-500">
                Comparability {diff.comparability}
                {diff.baseline_operation_id
                  ? ` · baseline ${diff.baseline_operation_id}`
                  : ""}
                . Hostnames, evidence, and security signals are separate. This is
                not a security score.
              </p>
              {diff.comparability === "not_comparable_scope" ? (
                <p className="text-sm text-zinc-700">
                  Scout did not compare surfaces because authorization scope
                  changed.
                </p>
              ) : null}
              {["surface", "evidence", "security_signal", "coverage"].map(
                (category) => {
                  const rows = diff.changes.filter(
                    (item) => item.category === category,
                  );
                  if (rows.length === 0) return null;
                  const newRows = rows.filter((item) => {
                    const type = item.change_type;
                    if (type.includes("unavailable") || type.includes("lost") || type.includes("no_longer")) {
                      return false;
                    }
                    return (
                      type.includes("new") ||
                      type.includes("gained") ||
                      type.includes("newly") ||
                      type.includes("became_available")
                    );
                  });
                  const goneRows = rows.filter(
                    (item) =>
                      item.change_type.includes("no_longer") ||
                      item.change_type.includes("lost") ||
                      item.change_type.includes("unavailable"),
                  );
                  const changedRows = rows.filter(
                    (item) =>
                      !newRows.includes(item) && !goneRows.includes(item),
                  );
                  const title =
                    category === "surface"
                      ? "Surface"
                      : category === "evidence"
                        ? "Evidence"
                        : category === "security_signal"
                          ? "Security signals"
                          : "Coverage";
                  return (
                    <div key={category}>
                      <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                        {title}
                      </h5>
                      <dl className="mt-2 grid gap-2 text-sm text-zinc-700">
                        <div>
                          <dt className="text-zinc-500">New</dt>
                          <dd>
                            {newRows.length === 0
                              ? "None"
                              : newRows.map((item) => item.explanation).join(" ")}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-zinc-500">Changed</dt>
                          <dd>
                            {changedRows.length === 0
                              ? "None"
                              : changedRows
                                  .map((item) => item.explanation)
                                  .join(" ")}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-zinc-500">No longer observed</dt>
                          <dd>
                            {goneRows.length === 0
                              ? "None"
                              : goneRows.map((item) => item.explanation).join(" ")}
                          </dd>
                        </div>
                      </dl>
                    </div>
                  );
                },
              )}
              {diff.changes.some((item) => item.significance === "regression") ? (
                <div>
                  <h5 className="text-xs font-medium uppercase tracking-wide text-zinc-500">
                    Security-significant regressions
                  </h5>
                  <ul className="mt-2 list-disc pl-5 text-sm text-zinc-700">
                    {diff.changes
                      .filter((item) => item.significance === "regression")
                      .map((item) => (
                        <li key={`${item.change_type}-${item.match_key}`}>
                          {item.explanation}
                        </li>
                      ))}
                  </ul>
                </div>
              ) : null}
              {diff.follow_up_findings.length > 0 ? (
                <p className="text-xs text-zinc-500">
                  Finding updates after this snapshot:{" "}
                  {diff.follow_up_findings
                    .map(
                      (item) =>
                        `${item.hostname}/${item.candidate_type} ${item.change_type}`,
                    )
                    .join("; ")}
                  . These do not rewrite frozen changes.
                </p>
              ) : null}
            </div>
          ) : null}

          <div className="space-y-2">
            <h4 className="text-sm font-medium">Discovered assets</h4>
            {assets.length === 0 ? (
              <p className="text-sm text-zinc-600">
                No assets discovered for this operation.
              </p>
            ) : (
              <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-100">
                {assets.map((asset) => (
                  <li key={asset.id} className="px-3 py-2 text-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium">{asset.hostname}</span>
                      <span className="font-mono text-xs text-zinc-500">
                        {asset.asset_type}
                        {asset.status_code != null ? ` · ${asset.status_code}` : ""}
                      </span>
                    </div>
                    {asset.url ? (
                      <p className="break-all font-mono text-xs text-zinc-600">
                        {asset.url}
                      </p>
                    ) : null}
                    {asset.title ? (
                      <p className="text-xs text-zinc-500">{asset.title}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-medium">Observations</h4>
            {observations.length === 0 ? (
              <p className="text-sm text-zinc-600">No observations yet.</p>
            ) : (
              <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-100">
                {observations.map((observation) => (
                  <li key={observation.id} className="px-3 py-2 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-zinc-500">
                        {observation.observation_type}
                      </span>
                      <span className="text-xs text-zinc-500">
                        {formatTime(observation.created_at)}
                      </span>
                    </div>
                    <p className="text-zinc-700">{observation.summary}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-medium">Security candidates</h4>
            <p className="text-xs text-zinc-500">
              Candidate — not confirmed. Hypotheses from reconnaissance; safe
              validation only rechecks observable evidence.
            </p>
            {candidates.length === 0 ? (
              <p className="text-sm text-zinc-600">
                No security candidates were generated from observable surfaces.
                That is not evidence that the application is secure.
              </p>
            ) : (
              <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-100">
                {candidates.map((candidate) => {
                  const evidence = candidate.evidence ?? {};
                  const why =
                    typeof evidence.why === "string"
                      ? evidence.why
                      : candidate.summary;
                  const reasons = Array.isArray(evidence.reasons)
                    ? evidence.reasons.filter(
                        (item): item is string => typeof item === "string",
                      )
                    : [];
                  const attempts = validationByCandidate[candidate.id] ?? [];
                  const latestAttempt = attempts[attempts.length - 1];
                  const activeAttempt =
                    latestAttempt &&
                    (latestAttempt.status === "pending" ||
                      latestAttempt.status === "running");
                  const statusLabel =
                    candidate.status === "needs_review"
                      ? "Needs review"
                      : candidate.status === "dismissed"
                        ? "Dismissed"
                        : candidate.status === "supported"
                          ? "Supported by evidence"
                          : "Candidate";
                  const attemptOutcome =
                    latestAttempt?.status === "supported"
                      ? "SUPPORTED BY EVIDENCE"
                      : latestAttempt?.status === "unsupported"
                        ? "UNSUPPORTED"
                        : latestAttempt?.status === "inconclusive"
                          ? "INCONCLUSIVE"
                          : latestAttempt?.status === "failed"
                            ? "VALIDATION FAILED"
                            : latestAttempt?.status === "pending" ||
                                latestAttempt?.status === "running"
                              ? "VALIDATION IN PROGRESS"
                              : null;
                  const observationIds = Array.isArray(
                    latestAttempt?.evidence?.observation_ids,
                  )
                    ? latestAttempt.evidence.observation_ids.filter(
                        (item): item is string => typeof item === "string",
                      )
                    : [];
                  return (
                    <li key={candidate.id} className="space-y-2 px-3 py-3 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-medium">{candidate.title}</span>
                        <span className="font-mono text-xs text-zinc-500">
                          {statusLabel}
                        </span>
                      </div>
                      <p className="text-xs uppercase tracking-wide text-zinc-500">
                        Candidate — not confirmed
                      </p>
                      <dl className="grid gap-1 text-zinc-700">
                        <div>
                          <dt className="text-zinc-500">Asset</dt>
                          <dd className="font-mono text-xs break-all">
                            {candidate.asset_hostname ?? candidate.asset_id}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-zinc-500">Why Scout flagged it</dt>
                          <dd>{why}</dd>
                        </div>
                        {reasons.length > 0 ? (
                          <div>
                            <dt className="text-zinc-500">Evidence notes</dt>
                            <dd>
                              <ul className="list-disc pl-4 text-xs text-zinc-600">
                                {reasons.map((reason) => (
                                  <li key={reason}>{reason}</li>
                                ))}
                              </ul>
                            </dd>
                          </div>
                        ) : null}
                        <div>
                          <dt className="text-zinc-500">Status</dt>
                          <dd>{statusLabel}</dd>
                        </div>
                      </dl>

                      <div className="flex flex-wrap gap-2">
                        {candidate.status !== "dismissed" &&
                        candidate.status !== "supported" ? (
                          <button
                            type="button"
                            disabled={pending || Boolean(activeAttempt)}
                            className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                            onClick={() => {
                              startTransition(async () => {
                                setError(null);
                                setMessage(null);
                                try {
                                  await withToken((token) =>
                                    queueCandidateValidation(token, candidate.id),
                                  );
                                  setMessage(
                                    "Safe validation queued. Worker will confirm observable evidence.",
                                  );
                                  if (selectedId) await loadDetail(selectedId);
                                } catch (err) {
                                  setError(
                                    err instanceof Error
                                      ? err.message
                                      : "Failed to queue validation",
                                  );
                                }
                              });
                            }}
                          >
                            {activeAttempt
                              ? "Validation queued…"
                              : "Run Safe Validation"}
                          </button>
                        ) : null}
                        {candidate.status === "supported" ? (
                          <button
                            type="button"
                            disabled={pending}
                            className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                            onClick={() => {
                              startTransition(async () => {
                                setError(null);
                                setMessage(null);
                                try {
                                  await withToken((token) =>
                                    promoteCandidate(token, candidate.id),
                                  );
                                  setMessage(
                                    "Finding created from supported candidate. See Findings below.",
                                  );
                                  if (selectedId) await loadDetail(selectedId);
                                } catch (err) {
                                  setError(
                                    err instanceof Error
                                      ? err.message
                                      : "Failed to promote candidate",
                                  );
                                }
                              });
                            }}
                          >
                            Promote to Finding
                          </button>
                        ) : null}
                      </div>

                      {latestAttempt ? (
                        <div className="space-y-1 rounded-md bg-zinc-50 px-3 py-2 text-xs text-zinc-700">
                          {attemptOutcome ? (
                            <p className="font-medium tracking-wide text-zinc-800">
                              {attemptOutcome}
                            </p>
                          ) : null}
                          <p>
                            <span className="text-zinc-500">Validation method: </span>
                            <span className="font-mono">
                              {latestAttempt.validation_method}
                            </span>
                          </p>
                          <p>{latestAttempt.summary}</p>
                          {latestAttempt.evidence?.method ? (
                            <p>
                              <span className="text-zinc-500">
                                Observable evidence:{" "}
                              </span>
                              {typeof latestAttempt.evidence.reachable === "boolean"
                                ? `reachable=${String(latestAttempt.evidence.reachable)}`
                                : null}
                              {typeof latestAttempt.evidence.status_code === "number"
                                ? ` status=${latestAttempt.evidence.status_code}`
                                : null}
                              {Array.isArray(latestAttempt.evidence.staging_markers)
                                ? ` markers=${latestAttempt.evidence.staging_markers.join(",")}`
                                : null}
                              {typeof latestAttempt.evidence.observed_header ===
                              "string"
                                ? ` header=${latestAttempt.evidence.observed_header}`
                                : null}
                            </p>
                          ) : null}
                          {observationIds.length > 0 ? (
                            <p>
                              <span className="text-zinc-500">
                                Source observations:{" "}
                              </span>
                              <span className="font-mono break-all">
                                {observationIds.join(", ")}
                              </span>
                            </p>
                          ) : null}
                          <p>
                            <span className="text-zinc-500">Timestamp: </span>
                            {formatTime(
                              latestAttempt.completed_at ?? latestAttempt.created_at,
                            )}
                          </p>
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="space-y-2">
            <h4 className="text-sm font-medium">Event history</h4>
            {visibleEvents.length === 0 ? (
              <p className="text-sm text-zinc-600">No events.</p>
            ) : (
              <ol className="divide-y divide-zinc-100 rounded-md border border-zinc-100">
                {visibleEvents.map((event) => (
                  <li key={event.id} className="px-3 py-2 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-zinc-500">
                        #{event.sequence} {event.event_type}
                      </span>
                      <span className="text-xs text-zinc-500">
                        {formatTime(event.created_at)}
                      </span>
                    </div>
                    <p className="text-zinc-700">{event.summary}</p>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
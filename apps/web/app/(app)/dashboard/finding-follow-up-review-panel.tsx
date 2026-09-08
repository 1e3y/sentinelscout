"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import {
  FindingFollowUpDueModal,
  type DueDateIntent,
} from "./finding-follow-up-due-modal";
import { FindingReviewFilters } from "./finding-review-filters";
import { parseApiError } from "@/lib/api-error";
import {
  fetchFindingFollowUpReview,
  fetchTargets,
  type FindingFollowUpDueState,
  type FindingFollowUpReviewItem,
  type FindingFollowUpReviewResponse,
  type FindingReviewSeverity,
  type FindingReviewStatus,
  type TargetResponse,
} from "@/lib/api";
import { organizationMemberLabel } from "@/lib/organization-member-label";
import {
  shouldApplyReviewResult,
  type FollowUpReviewRequestSnapshot,
} from "@/lib/review-request-snapshot";

type Props = {
  enabled: boolean;
  organizationId: string | null;
  selectedFindingId: string | null;
  onOpenFinding: (findingId: string) => void;
};

type FilterValue = "all" | FindingFollowUpDueState;

const PAGE_SIZE = 50;
const INVALID_CURSOR = "Invalid finding follow-up review cursor";

const FILTERS: Array<{ value: FilterValue; label: string }> = [
  { value: "all", label: "All" },
  { value: "no_due_date", label: "No due date" },
  { value: "upcoming", label: "Upcoming" },
  { value: "overdue", label: "Overdue" },
];

const DUE_ACTION_LABELS: Record<FindingFollowUpDueState, string> = {
  no_due_date: "Set due date",
  upcoming: "Change due date",
  overdue: "Change due date",
};

function formatTime(value: string): string {
  return new Date(value).toLocaleString();
}

function dueLabel(item: FindingFollowUpReviewItem): string {
  if (item.due_state === "no_due_date" || !item.follow_up_due_at) {
    return "No due date";
  }
  const when = formatTime(item.follow_up_due_at);
  if (item.due_state === "overdue") {
    return `Overdue — ${when}`;
  }
  return `Due ${when}`;
}

function assigneeLabel(item: FindingFollowUpReviewItem): string {
  if (item.assignee == null) return "Unassigned";
  return organizationMemberLabel(item.assignee.display_name);
}

function emptyCopy(filtered: boolean): string {
  return filtered
    ? "No active findings match the selected follow-up filters."
    : "No matching findings.";
}

export function FindingFollowUpReviewPanel({
  enabled,
  organizationId,
  selectedFindingId,
  onOpenFinding,
}: Props) {
  const { getToken } = useAuth();
  const [payload, setPayload] = useState<FindingFollowUpReviewResponse | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [refreshWarning, setRefreshWarning] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [currentDueNotice, setCurrentDueNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterValue>("all");
  const [targetId, setTargetId] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [appliedOrgId, setAppliedOrgId] = useState(organizationId);
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [targetsLoading, setTargetsLoading] = useState(false);
  const [targetsError, setTargetsError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [dueIntent, setDueIntent] = useState<DueDateIntent | null>(null);
  const [dueGeneration, setDueGeneration] = useState(0);

  const generationRef = useRef(0);
  const pageCursorRef = useRef<string | null>(null);
  const nextInFlightRef = useRef<string | null>(null);
  const latestRequestRef = useRef<FollowUpReviewRequestSnapshot | null>(null);
  const mountedRef = useRef(true);
  const targetGenerationRef = useRef(0);
  const recoveringCursorRef = useRef(false);
  const viewRef = useRef<FollowUpReviewRequestSnapshot>({
    organizationId,
    targetId: null,
    severity: null,
    status: null,
    cursor: null,
    generation: 0,
    dueState: null,
  });

  if (appliedOrgId !== organizationId) {
    setAppliedOrgId(organizationId);
    setTargetId("");
    setTargets([]);
    setTargetsError(null);
  }

  const currentSnapshot = useCallback(
    (cursor: string | null): FollowUpReviewRequestSnapshot => ({
      organizationId,
      targetId: targetId || null,
      severity: (severity || null) as FindingReviewSeverity | null,
      status: (status || null) as FindingReviewStatus | null,
      cursor,
      generation: generationRef.current,
      dueState: filter === "all" ? null : filter,
    }),
    [filter, organizationId, severity, status, targetId],
  );

  const loadRef = useRef<(cursor: string | null) => void>(() => {});

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    viewRef.current = currentSnapshot(pageCursorRef.current);
  }, [currentSnapshot]);

  const applyIfCurrent = useCallback(
    (request: FollowUpReviewRequestSnapshot, next: FindingFollowUpReviewResponse) => {
      const live = currentSnapshot(pageCursorRef.current);
      live.generation = generationRef.current;
      if (
        !shouldApplyReviewResult({
          mounted: mountedRef.current,
          latest: latestRequestRef.current,
          live,
          request,
        })
      ) {
        return false;
      }
      pageCursorRef.current = request.cursor;
      recoveringCursorRef.current = false;
      viewRef.current = currentSnapshot(request.cursor);
      setPayload(next);
      return true;
    },
    [currentSnapshot],
  );

  const fetchPage = useCallback(
    async (request: FollowUpReviewRequestSnapshot) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing session token");
      }
      return fetchFindingFollowUpReview(token, {
        page_size: PAGE_SIZE,
        cursor: request.cursor,
        target_id: request.targetId,
        severity: request.severity as FindingReviewSeverity | null,
        status: request.status as FindingReviewStatus | null,
        ...(request.dueState
          ? { due_state: request.dueState as FindingFollowUpDueState }
          : {}),
      });
    },
    [getToken],
  );

  const load = useCallback(
    (cursor: string | null) => {
      if (!enabled || !organizationId) return;
      const request = currentSnapshot(cursor);
      if (cursor) {
        if (nextInFlightRef.current) return;
        nextInFlightRef.current = cursor;
      }
      latestRequestRef.current = request;
      viewRef.current = request;
      startTransition(async () => {
        setError(null);
        try {
          const next = await fetchPage(request);
          applyIfCurrent(request, next);
        } catch (err) {
          const live = currentSnapshot(pageCursorRef.current);
          live.generation = generationRef.current;
          if (
            !shouldApplyReviewResult({
              mounted: mountedRef.current,
              latest: latestRequestRef.current,
              live,
              request,
            })
          ) {
            return;
          }
          const parsed = parseApiError(
            err,
            "Finding follow-up review could not be loaded.",
          );
          if (
            cursor &&
            parsed.status === 400 &&
            parsed.message === INVALID_CURSOR &&
            !recoveringCursorRef.current
          ) {
            recoveringCursorRef.current = true;
            pageCursorRef.current = null;
            generationRef.current += 1;
            loadRef.current(null);
            return;
          }
          setError(parsed.message);
        } finally {
          if (nextInFlightRef.current === cursor) {
            nextInFlightRef.current = null;
          }
        }
      });
    },
    [applyIfCurrent, currentSnapshot, enabled, fetchPage, organizationId],
  );

  useEffect(() => {
    loadRef.current = load;
  }, [load]);

  useEffect(() => {
    generationRef.current += 1;
    pageCursorRef.current = null;
    nextInFlightRef.current = null;
    latestRequestRef.current = null;
    recoveringCursorRef.current = false;
    viewRef.current = currentSnapshot(null);
    load(null);
  }, [currentSnapshot, load, organizationId, targetId, severity, status, filter]);

  useEffect(() => {
    if (!enabled || !organizationId) return;
    const generation = targetGenerationRef.current + 1;
    targetGenerationRef.current = generation;
    const org = organizationId;
    startTransition(async () => {
      setTargetsLoading(true);
      setTargetsError(null);
      try {
        const token = await getToken();
        if (!token) throw new Error("Missing session token");
        const rows = await fetchTargets(token);
        if (targetGenerationRef.current !== generation) return;
        if (viewRef.current.organizationId !== org) return;
        setTargets(rows);
      } catch {
        if (targetGenerationRef.current !== generation) return;
        if (viewRef.current.organizationId !== org) return;
        setTargets([]);
        setTargetsError("Targets could not be loaded.");
      } finally {
        if (targetGenerationRef.current === generation) {
          setTargetsLoading(false);
        }
      }
    });
  }, [enabled, getToken, organizationId]);

  const refreshFirstPageCurrent = useCallback(async () => {
    pageCursorRef.current = null;
    nextInFlightRef.current = null;
    const request = {
      ...viewRef.current,
      cursor: null,
      generation: generationRef.current,
    };
    latestRequestRef.current = request;
    viewRef.current = request;
    const next = await fetchPage(request);
    applyIfCurrent(request, next);
  }, [applyIfCurrent, fetchPage]);

  const handleWriteSucceeded = useCallback(async () => {
    setSuccess("Follow-up due date updated.");
    setRefreshWarning(null);
    setNotice(null);
    setCurrentDueNotice(null);
    setError(null);
    try {
      await refreshFirstPageCurrent();
    } catch {
      setRefreshWarning(
        "Due date updated, but the follow-up review could not be refreshed.",
      );
    }
  }, [refreshFirstPageCurrent]);

  const handleAlreadyDue = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice("The follow-up due date is already set to this time.");
    setCurrentDueNotice(null);
    setError(null);
    try {
      await refreshFirstPageCurrent();
    } catch {
      setError("Finding follow-up review could not be loaded.");
    }
  }, [refreshFirstPageCurrent]);

  const handleResolvedConflict = useCallback(() => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(null);
    setCurrentDueNotice(null);
    void refreshFirstPageCurrent().catch(() => {
      setError("Finding follow-up review could not be loaded.");
    });
  }, [refreshFirstPageCurrent]);

  const handleTransportUncertain = useCallback(
    async (currentDueLabel: string | null) => {
      setSuccess(null);
      setRefreshWarning(null);
      setError(null);
      setNotice(
        "We couldn't confirm whether the follow-up due date was updated. Refresh the finding before trying again.",
      );
      setCurrentDueNotice(
        currentDueLabel
          ? `Current follow-up due date: ${currentDueLabel}`
          : null,
      );
      try {
        await refreshFirstPageCurrent();
      } catch {
        setError("Finding follow-up review could not be loaded.");
      }
    },
    [refreshFirstPageCurrent],
  );

  if (!enabled) return null;

  const filtered = Boolean(targetId || severity || status || filter !== "all");

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Finding follow-up review</h2>
          <p className="text-sm text-zinc-600">
            Active findings for this organization, classified by the stored
            follow-up due date. Set or change a due date here, or open the
            finding for the full follow-up workflow.
          </p>
        </div>
        <button
          type="button"
          disabled={pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => {
            generationRef.current += 1;
            pageCursorRef.current = null;
            nextInFlightRef.current = null;
            load(null);
          }}
        >
          Refresh
        </button>
      </div>

      {success ? <p className="text-sm text-zinc-800">{success}</p> : null}
      {refreshWarning ? (
        <p className="text-sm text-amber-800">{refreshWarning}</p>
      ) : null}
      {notice ? <p className="text-sm text-zinc-800">{notice}</p> : null}
      {currentDueNotice ? (
        <p className="text-sm text-zinc-800">{currentDueNotice}</p>
      ) : null}
      {error ? <p className="text-sm text-red-800">{error}</p> : null}

      <div className="flex flex-wrap gap-2">
        {FILTERS.map((option) => (
          <button
            key={option.value}
            type="button"
            className={`rounded-md border px-3 py-1.5 text-sm ${
              filter === option.value
                ? "border-zinc-900 bg-zinc-900 text-white"
                : "border-zinc-300"
            }`}
            onClick={() => setFilter(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>

      <FindingReviewFilters
        targetId={targetId}
        severity={severity}
        status={status}
        targets={targets}
        targetsLoading={targetsLoading}
        targetsError={targetsError}
        disabled={pending}
        onTargetId={setTargetId}
        onSeverity={setSeverity}
        onStatus={setStatus}
      />

      {payload == null && !error ? (
        <p className="text-sm text-zinc-600">
          {pending ? "Loading…" : "No follow-up review loaded."}
        </p>
      ) : payload != null && payload.items.length === 0 ? (
        <p className="text-sm text-zinc-600">{emptyCopy(filtered)}</p>
      ) : payload != null ? (
        <ul className="divide-y divide-zinc-200 border-t border-zinc-200">
          {payload.items.map((item) => {
            const selected = item.finding_id === selectedFindingId;
            return (
              <li
                key={item.finding_id}
                className={`flex flex-wrap items-start justify-between gap-3 py-3 ${
                  selected ? "bg-zinc-50" : ""
                }`}
              >
                <div className="min-w-0 space-y-1 text-sm">
                  <p className="font-medium text-zinc-900">{item.title}</p>
                  <dl className="flex flex-wrap gap-x-4 gap-y-1 text-zinc-600">
                    <div>
                      <dt className="sr-only">Target</dt>
                      <dd>{item.target_label}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Severity</dt>
                      <dd>{item.severity}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Status</dt>
                      <dd>{item.status.replaceAll("_", " ")}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Assignee</dt>
                      <dd>{assigneeLabel(item)}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Due</dt>
                      <dd>{dueLabel(item)}</dd>
                    </div>
                  </dl>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
                    onClick={() => {
                      setDueGeneration((value) => value + 1);
                      setDueIntent({
                        findingId: item.finding_id,
                        title: item.title,
                        targetLabel: item.target_label,
                        dueState: item.due_state,
                      });
                    }}
                  >
                    {DUE_ACTION_LABELS[item.due_state]}
                  </button>
                  <button
                    type="button"
                    className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
                    onClick={() => onOpenFinding(item.finding_id)}
                  >
                    Open finding
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}

      {payload?.next_cursor ? (
        <button
          type="button"
          disabled={pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => load(payload.next_cursor)}
        >
          Next page
        </button>
      ) : null}

      {dueIntent ? (
        <FindingFollowUpDueModal
          key={dueGeneration}
          intent={dueIntent}
          onClose={() => setDueIntent(null)}
          onWriteSucceeded={handleWriteSucceeded}
          onAlreadyDue={handleAlreadyDue}
          onResolvedConflict={handleResolvedConflict}
          onTransportUncertain={handleTransportUncertain}
        />
      ) : null}
    </section>
  );
}

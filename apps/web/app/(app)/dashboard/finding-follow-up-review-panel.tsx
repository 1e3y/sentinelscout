"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import {
  FindingFollowUpDueModal,
  type DueDateIntent,
} from "./finding-follow-up-due-modal";
import { parseApiError } from "@/lib/api-error";
import {
  fetchFindingFollowUpReview,
  type FindingFollowUpDueState,
  type FindingFollowUpReviewItem,
  type FindingFollowUpReviewResponse,
} from "@/lib/api";
import { organizationMemberLabel } from "@/lib/organization-member-label";

type Props = {
  enabled: boolean;
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

export function FindingFollowUpReviewPanel({
  enabled,
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
  const [pending, startTransition] = useTransition();
  const [dueIntent, setDueIntent] = useState<DueDateIntent | null>(null);
  const [dueGeneration, setDueGeneration] = useState(0);
  const pageCursorRef = useRef<string | null>(null);
  const recoveringCursorRef = useRef(false);

  const fetchPage = useCallback(
    async (cursor: string | null, dueFilter: FilterValue) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing session token");
      }
      return fetchFindingFollowUpReview(token, {
        page_size: PAGE_SIZE,
        cursor,
        ...(dueFilter === "all" ? {} : { due_state: dueFilter }),
      });
    },
    [getToken],
  );

  const load = useCallback(
    (cursor: string | null, dueFilter: FilterValue) => {
      if (!enabled) return;
      startTransition(async () => {
        setError(null);
        try {
          const next = await fetchPage(cursor, dueFilter);
          pageCursorRef.current = cursor;
          recoveringCursorRef.current = false;
          setPayload(next);
        } catch (err) {
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
            try {
              const fresh = await fetchPage(null, dueFilter);
              setPayload(fresh);
              setError(null);
              return;
            } catch (refreshErr) {
              setPayload(null);
              setError(
                parseApiError(
                  refreshErr,
                  "Finding follow-up review could not be loaded.",
                ).message,
              );
              return;
            }
          }
          setError(parsed.message);
        }
      });
    },
    [enabled, fetchPage],
  );

  const refreshFirstPage = useCallback(async () => {
    pageCursorRef.current = null;
    const next = await fetchPage(null, filter);
    setPayload(next);
  }, [fetchPage, filter]);

  useEffect(() => {
    load(null, filter);
  }, [load, filter]);

  function changeFilter(next: FilterValue) {
    pageCursorRef.current = null;
    setPayload(null);
    setFilter(next);
  }

  const handleWriteSucceeded = useCallback(async () => {
    setSuccess("Follow-up due date updated.");
    setRefreshWarning(null);
    setNotice(null);
    setCurrentDueNotice(null);
    setError(null);
    try {
      await refreshFirstPage();
    } catch {
      setRefreshWarning(
        "Due date updated, but the follow-up review could not be refreshed.",
      );
    }
  }, [refreshFirstPage]);

  const handleAlreadyDue = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice("The follow-up due date is already set to this time.");
    setCurrentDueNotice(null);
    setError(null);
    try {
      await refreshFirstPage();
    } catch {
      setError("Finding follow-up review could not be loaded.");
    }
  }, [refreshFirstPage]);

  const handleResolvedConflict = useCallback(() => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(null);
    setCurrentDueNotice(null);
    void refreshFirstPage().catch(() => {
      setError("Finding follow-up review could not be loaded.");
    });
  }, [refreshFirstPage]);

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
        await refreshFirstPage();
      } catch {
        setError("Finding follow-up review could not be loaded.");
      }
    },
    [refreshFirstPage],
  );

  if (!enabled) return null;

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
            pageCursorRef.current = null;
            load(null, filter);
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
            onClick={() => changeFilter(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>

      {payload == null && !error ? (
        <p className="text-sm text-zinc-600">
          {pending ? "Loading…" : "No follow-up review loaded."}
        </p>
      ) : payload != null && payload.items.length === 0 ? (
        <p className="text-sm text-zinc-600">No matching findings.</p>
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
          onClick={() => load(payload.next_cursor, filter)}
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

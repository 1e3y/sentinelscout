"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import {
  FindingOwnershipAssignModal,
  type OwnershipAssignIntent,
} from "./finding-ownership-assign-modal";
import {
  fetchFindingOwnershipReview,
  type FindingOwnershipAssignmentState,
  type FindingOwnershipReviewItem,
  type FindingOwnershipReviewResponse,
} from "@/lib/api";
import { organizationMemberLabel } from "@/lib/organization-member-label";

type Props = {
  enabled: boolean;
  selectedFindingId: string | null;
  onOpenFinding: (findingId: string) => void;
};

const PAGE_SIZE = 50;

const ASSIGNMENT_LABELS: Record<FindingOwnershipAssignmentState, string> = {
  unassigned: "Unassigned",
  current_member: "Current member",
  not_current_member: "No longer a current organization member",
};

const ACTION_LABELS: Record<FindingOwnershipAssignmentState, string> = {
  unassigned: "Assign owner",
  not_current_member: "Reassign owner",
  current_member: "Change owner",
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function assigneeLabel(item: FindingOwnershipReviewItem): string {
  if (item.assignee == null) return "Unassigned";
  return organizationMemberLabel(item.assignee.display_name);
}

export function FindingOwnershipReviewPanel({
  enabled,
  selectedFindingId,
  onOpenFinding,
}: Props) {
  const { getToken } = useAuth();
  const [payload, setPayload] = useState<FindingOwnershipReviewResponse | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [refreshWarning, setRefreshWarning] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [assignIntent, setAssignIntent] = useState<OwnershipAssignIntent | null>(
    null,
  );
  const [assignGeneration, setAssignGeneration] = useState(0);
  const pageCursorRef = useRef<string | null>(null);

  const fetchPage = useCallback(
    async (cursor: string | null) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing session token");
      }
      return fetchFindingOwnershipReview(token, {
        page_size: PAGE_SIZE,
        cursor,
      });
    },
    [getToken],
  );

  const load = useCallback(
    (cursor: string | null) => {
      if (!enabled) return;
      startTransition(async () => {
        setError(null);
        try {
          const next = await fetchPage(cursor);
          pageCursorRef.current = cursor;
          setPayload(next);
        } catch (err) {
          setError(
            err instanceof Error
              ? err.message
              : "Finding ownership could not be verified.",
          );
        }
      });
    },
    [enabled, fetchPage],
  );

  const refreshCurrentPage = useCallback(async () => {
    const next = await fetchPage(pageCursorRef.current);
    setPayload(next);
  }, [fetchPage]);

  useEffect(() => {
    load(null);
  }, [load]);

  const handleWriteSucceeded = useCallback(async () => {
    setSuccess("Finding owner updated.");
    setRefreshWarning(null);
    setNotice(null);
    setError(null);
    try {
      await refreshCurrentPage();
    } catch {
      setRefreshWarning(
        "Assignment updated, but ownership review could not be refreshed.",
      );
    }
  }, [refreshCurrentPage]);

  const handleAlreadyOwner = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice("The selected member is already the current owner.");
    setError(null);
    try {
      await refreshCurrentPage();
    } catch {
      setError("Finding ownership could not be verified.");
    }
  }, [refreshCurrentPage]);

  const handleResolvedConflict = useCallback(() => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(null);
    void refreshCurrentPage().catch(() => {
      setError("Finding ownership could not be verified.");
    });
  }, [refreshCurrentPage]);

  if (!enabled) return null;

  return (
    <section className="space-y-3">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Finding ownership review</h2>
          <p className="text-sm text-zinc-600">
            Active findings for this organization. Membership is checked against
            the current organization directory. Assign or reassign a current
            member here, or open the finding for the full follow-up workflow.
          </p>
        </div>
        <button
          type="button"
          disabled={pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => load(null)}
        >
          Refresh
        </button>
      </div>

      {success ? <p className="text-sm text-zinc-800">{success}</p> : null}
      {refreshWarning ? (
        <p className="text-sm text-amber-800">{refreshWarning}</p>
      ) : null}
      {notice ? <p className="text-sm text-zinc-800">{notice}</p> : null}
      {error ? <p className="text-sm text-red-800">{error}</p> : null}

      {payload == null && !error ? (
        <p className="text-sm text-zinc-600">
          {pending ? "Loading…" : "No ownership review loaded."}
        </p>
      ) : payload != null && payload.items.length === 0 ? (
        <p className="text-sm text-zinc-600">No active findings.</p>
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
                      <dt className="sr-only">Assignment</dt>
                      <dd>{ASSIGNMENT_LABELS[item.assignment_state]}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Assignee</dt>
                      <dd>{assigneeLabel(item)}</dd>
                    </div>
                    <div>
                      <dt className="sr-only">Follow-up due</dt>
                      <dd>Due {formatTime(item.follow_up_due_at)}</dd>
                    </div>
                  </dl>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
                    onClick={() => {
                      setAssignGeneration((value) => value + 1);
                      setAssignIntent({
                        findingId: item.finding_id,
                        title: item.title,
                        targetLabel: item.target_label,
                        assignmentState: item.assignment_state,
                      });
                    }}
                  >
                    {ACTION_LABELS[item.assignment_state]}
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

      {assignIntent ? (
        <FindingOwnershipAssignModal
          key={assignGeneration}
          intent={assignIntent}
          onClose={() => setAssignIntent(null)}
          onWriteSucceeded={handleWriteSucceeded}
          onAlreadyOwner={handleAlreadyOwner}
          onResolvedConflict={handleResolvedConflict}
        />
      ) : null}
    </section>
  );
}

"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState, useTransition } from "react";
import {
  fetchFindingOwnershipReview,
  type FindingOwnershipAssignmentState,
  type FindingOwnershipReviewItem,
  type FindingOwnershipReviewResponse,
} from "@/lib/api";

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

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function assigneeLabel(item: FindingOwnershipReviewItem): string {
  if (item.assignee == null) return "—";
  return item.assignee.display_name ?? "—";
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
  const [pending, startTransition] = useTransition();

  const load = useCallback(
    (nextCursor: string | null = null) => {
      if (!enabled) return;
      startTransition(async () => {
        setError(null);
        try {
          const token = await getToken();
          if (!token) {
            setError("Missing session token");
            return;
          }
          const next = await fetchFindingOwnershipReview(token, {
            page_size: PAGE_SIZE,
            cursor: nextCursor ?? undefined,
          });
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
    [enabled, getToken],
  );

  useEffect(() => {
    load(null);
  }, [load]);

  if (!enabled) return null;

  return (
    <section className="space-y-3">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Finding ownership review</h2>
          <p className="text-sm text-zinc-600">
            Active findings for this organization. Membership is checked against
            the current organization directory. Reassignment happens on the
            finding page.
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

      {error ? (
        <p className="text-sm text-red-800">{error}</p>
      ) : payload == null ? (
        <p className="text-sm text-zinc-600">
          {pending ? "Loading…" : "No ownership review loaded."}
        </p>
      ) : payload.items.length === 0 ? (
        <p className="text-sm text-zinc-600">No active findings.</p>
      ) : (
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
                <button
                  type="button"
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
                  onClick={() => onOpenFinding(item.finding_id)}
                >
                  Open finding
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
          onClick={() => load(payload.next_cursor)}
        >
          Next page
        </button>
      ) : null}
    </section>
  );
}

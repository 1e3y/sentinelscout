"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { FindingOwnershipAssignModal, type OwnershipAssignIntent } from "./finding-ownership-assign-modal";
import {
  FindingOwnershipBulkAssignModal,
  type BulkOwnershipAssignIntent,
} from "./finding-ownership-bulk-assign-modal";
import { FindingReviewFilters } from "./finding-review-filters";
import {
  fetchFindingOwnershipReview,
  fetchTargets,
  type FindingOwnershipAssignmentState,
  type FindingOwnershipReviewItem,
  type FindingOwnershipReviewResponse,
  type FindingReviewSeverity,
  type FindingReviewStatus,
  type TargetResponse,
} from "@/lib/api";
import { organizationMemberLabel } from "@/lib/organization-member-label";
import {
  ownershipRefreshCursor,
  sameReviewCollection,
  shouldApplyReviewResult,
  type OwnershipReviewRequestSnapshot,
} from "@/lib/review-request-snapshot";

type Props = {
  enabled: boolean;
  organizationId: string | null;
  selectedFindingId: string | null;
  onOpenFinding: (findingId: string) => void;
};

const PAGE_SIZE = 50;
const MAX_BULK_SELECTION = 50;

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

function emptyCopy(filtered: boolean): string {
  return filtered
    ? "No findings match the selected filters."
    : "No active findings.";
}

export function FindingOwnershipReviewPanel({
  enabled,
  organizationId,
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
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkIntent, setBulkIntent] = useState<BulkOwnershipAssignIntent | null>(
    null,
  );
  const [bulkGeneration, setBulkGeneration] = useState(0);
  const [bulkEpoch, setBulkEpoch] = useState(0);
  const [targetId, setTargetId] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [appliedOrgId, setAppliedOrgId] = useState(organizationId);
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [targetsLoading, setTargetsLoading] = useState(false);
  const [targetsError, setTargetsError] = useState<string | null>(null);

  const generationRef = useRef(0);
  const pageCursorRef = useRef<string | null>(null);
  const nextInFlightRef = useRef<string | null>(null);
  const latestRequestRef = useRef<OwnershipReviewRequestSnapshot | null>(null);
  const mountedRef = useRef(true);
  const targetGenerationRef = useRef(0);
  const openedPageRef = useRef<OwnershipReviewRequestSnapshot | null>(null);
  const viewRef = useRef<OwnershipReviewRequestSnapshot>({
    organizationId,
    targetId: null,
    severity: null,
    status: null,
    cursor: null,
    generation: 0,
  });

  if (appliedOrgId !== organizationId) {
    setAppliedOrgId(organizationId);
    setTargetId("");
    setTargets([]);
    setTargetsError(null);
    setSelectedIds([]);
    setBulkIntent(null);
    setBulkEpoch((value) => value + 1);
  }

  const currentSnapshot = useCallback(
    (cursor: string | null): OwnershipReviewRequestSnapshot => ({
      organizationId,
      targetId: targetId || null,
      severity: (severity || null) as FindingReviewSeverity | null,
      status: (status || null) as FindingReviewStatus | null,
      cursor,
      generation: generationRef.current,
    }),
    [organizationId, targetId, severity, status],
  );

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
    (request: OwnershipReviewRequestSnapshot, next: FindingOwnershipReviewResponse) => {
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
      viewRef.current = currentSnapshot(request.cursor);
      setPayload(next);
      setSelectedIds([]);
      setBulkIntent(null);
      setBulkEpoch((value) => value + 1);
      return true;
    },
    [currentSnapshot],
  );

  const invalidateBulk = useCallback(() => {
    setBulkEpoch((value) => value + 1);
    setSelectedIds([]);
    setBulkIntent(null);
  }, []);

  const isBulkSubmitCurrent = useCallback(
    (generation: number) => generation === bulkEpoch,
    [bulkEpoch],
  );

  const fetchPage = useCallback(
    async (request: OwnershipReviewRequestSnapshot) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing session token");
      }
      return fetchFindingOwnershipReview(token, {
        page_size: PAGE_SIZE,
        cursor: request.cursor,
        target_id: request.targetId,
        severity: request.severity as FindingReviewSeverity | null,
        status: request.status as FindingReviewStatus | null,
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
          if (applyIfCurrent(request, next)) {
            setError(null);
          }
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
          setError(
            err instanceof Error
              ? err.message
              : "Finding ownership could not be verified.",
          );
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
    generationRef.current += 1;
    pageCursorRef.current = null;
    nextInFlightRef.current = null;
    latestRequestRef.current = null;
    viewRef.current = currentSnapshot(null);
    load(null);
  }, [currentSnapshot, load, organizationId, targetId, severity, status]);

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

  const refreshAfterMutation = useCallback(async () => {
    const opened = openedPageRef.current;
    const live = viewRef.current;
    const cursor = ownershipRefreshCursor(opened, live);
    if (cursor == null) {
      pageCursorRef.current = null;
    }
    const request = {
      ...live,
      cursor,
      generation: generationRef.current,
    };
    latestRequestRef.current = request;
    viewRef.current = request;
    const next = await fetchPage(request);
    applyIfCurrent(request, next);
  }, [applyIfCurrent, fetchPage]);

  const handleWriteSucceeded = useCallback(async () => {
    setSuccess("Finding owner updated.");
    setRefreshWarning(null);
    setNotice(null);
    setError(null);
    try {
      await refreshAfterMutation();
    } catch {
      setRefreshWarning(
        "Assignment updated, but ownership review could not be refreshed.",
      );
    }
  }, [refreshAfterMutation]);

  const handleAlreadyOwner = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice("The selected member is already the current owner.");
    setError(null);
    try {
      await refreshAfterMutation();
    } catch {
      setError("Finding ownership could not be verified.");
    }
  }, [refreshAfterMutation]);

  const handleResolvedConflict = useCallback(() => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(null);
    void refreshAfterMutation().catch(() => {
      setError("Finding ownership could not be verified.");
    });
  }, [refreshAfterMutation]);

  const handleTransportUncertain = useCallback(async () => {
    const opened = openedPageRef.current;
    const live = viewRef.current;
    if (
      !mountedRef.current ||
      opened == null ||
      opened.generation !== generationRef.current ||
      live.generation !== generationRef.current ||
      !sameReviewCollection(opened, live)
    ) {
      return;
    }
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(
      "The assignment outcome could not be confirmed. Ownership review was refreshed.",
    );
    setError(null);
    try {
      await refreshAfterMutation();
    } catch {
      const current = viewRef.current;
      if (
        !mountedRef.current ||
        opened.generation !== generationRef.current ||
        current.generation !== generationRef.current ||
        !sameReviewCollection(opened, current)
      ) {
        return;
      }
      setRefreshWarning(
        "The assignment outcome could not be confirmed, and ownership review could not be refreshed.",
      );
    }
  }, [refreshAfterMutation]);

  const handleBulkWriteSucceeded = useCallback(async () => {
    setSuccess("Selected findings assigned.");
    setRefreshWarning(null);
    setNotice(null);
    setError(null);
    invalidateBulk();
    try {
      await refreshAfterMutation();
    } catch {
      setRefreshWarning(
        "Assignment updated, but ownership review could not be refreshed.",
      );
    }
  }, [invalidateBulk, refreshAfterMutation]);

  const handleBulkTransportUncertain = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setNotice(null);
    setError(
      "Bulk assignment outcome could not be confirmed. Ownership review was refreshed.",
    );
    invalidateBulk();
    try {
      await refreshAfterMutation();
    } catch {
      setError(
        "Bulk assignment outcome could not be confirmed. Ownership review was refreshed.",
      );
    }
  }, [invalidateBulk, refreshAfterMutation]);

  const toggleSelected = useCallback((findingId: string) => {
    setSelectedIds((current) => {
      if (current.includes(findingId)) {
        return current.filter((id) => id !== findingId);
      }
      if (current.length >= MAX_BULK_SELECTION) return current;
      return [...current, findingId];
    });
  }, []);

  const selectVisible = useCallback(() => {
    if (payload == null) return;
    setSelectedIds(
      payload.items.map((item) => item.finding_id).slice(0, MAX_BULK_SELECTION),
    );
  }, [payload]);

  const openBulkAssign = useCallback(() => {
    if (payload == null || selectedIds.length === 0) return;
    const selected = new Set(selectedIds);
    const items = payload.items
      .filter((item) => selected.has(item.finding_id))
      .slice(0, MAX_BULK_SELECTION)
      .map((item) => ({
        finding_id: item.finding_id,
        expected_follow_up: {
          assigned_to_user_id: item.assignee?.user_id ?? null,
          follow_up_due_at: item.follow_up_due_at,
        },
      }));
    if (items.length === 0) return;
    openedPageRef.current = currentSnapshot(pageCursorRef.current);
    setBulkGeneration((value) => value + 1);
    setBulkIntent({
      selectedCount: items.length,
      items,
      submitGeneration: bulkEpoch,
    });
  }, [bulkEpoch, currentSnapshot, payload, selectedIds]);

  if (!enabled) return null;

  const filtered = Boolean(targetId || severity || status);

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
          onClick={() => {
            invalidateBulk();
            generationRef.current += 1;
            pageCursorRef.current = null;
            nextInFlightRef.current = null;
            load(null);
          }}
        >
          Refresh
        </button>
      </div>

      <FindingReviewFilters
        targetId={targetId}
        severity={severity}
        status={status}
        targets={targets}
        targetsLoading={targetsLoading}
        targetsError={targetsError}
        disabled={pending}
        onTargetId={(value) => {
          invalidateBulk();
          setTargetId(value);
        }}
        onSeverity={(value) => {
          invalidateBulk();
          setSeverity(value);
        }}
        onStatus={(value) => {
          invalidateBulk();
          setStatus(value);
        }}
      />

      {success ? <p className="text-sm text-zinc-800">{success}</p> : null}
      {refreshWarning ? (
        <p className="text-sm text-amber-800">{refreshWarning}</p>
      ) : null}
      {notice ? <p className="text-sm text-zinc-800">{notice}</p> : null}
      {error ? <p className="text-sm text-red-800">{error}</p> : null}

      {payload != null && payload.items.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={pending}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={selectVisible}
          >
            Select visible
          </button>
          <p className="text-sm text-zinc-600">{selectedIds.length} selected</p>
          <button
            type="button"
            disabled={pending || selectedIds.length === 0}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={openBulkAssign}
          >
            Assign selected
          </button>
        </div>
      ) : null}

      {payload == null && !error ? (
        <p className="text-sm text-zinc-600">
          {pending ? "Loading…" : "No ownership review loaded."}
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
                <label className="mt-1 flex items-start">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={selectedIds.includes(item.finding_id)}
                    onChange={() => toggleSelected(item.finding_id)}
                    aria-label={`Select ${item.title}`}
                  />
                </label>
                <div className="min-w-0 flex-1 space-y-1 text-sm">
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
                      openedPageRef.current = currentSnapshot(pageCursorRef.current);
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
          onClick={() => {
            invalidateBulk();
            load(payload.next_cursor);
          }}
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
          onTransportUncertain={handleTransportUncertain}
        />
      ) : null}

      {bulkIntent ? (
        <FindingOwnershipBulkAssignModal
          key={bulkGeneration}
          intent={bulkIntent}
          isSubmitCurrent={isBulkSubmitCurrent}
          onClose={() => setBulkIntent(null)}
          onWriteSucceeded={handleBulkWriteSucceeded}
          onTransportUncertain={handleBulkTransportUncertain}
        />
      ) : null}
    </section>
  );
}

"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import {
  FindingFollowUpBulkDueModal,
  type BulkFollowUpDueIntent,
} from "./finding-follow-up-bulk-due-modal";
import {
  FindingFollowUpBulkEditModal,
  type BulkFollowUpEditIntent,
} from "./finding-follow-up-bulk-edit-modal";
import { FindingFollowUpBulkClearModal } from "./finding-follow-up-bulk-clear-modal";
import {
  FindingFollowUpDueModal,
  type DueDateIntent,
} from "./finding-follow-up-due-modal";
import { FindingReviewFilters } from "./finding-review-filters";
import { parseApiError } from "@/lib/api-error";
import {
  fetchFindingFollowUpReview,
  fetchTargets,
  type BulkFollowUpClearResponse,
  type BulkFollowUpEditResponse,
  type BulkFollowUpDueResponse,
  type FindingFollowUpDueState,
  type FindingFollowUpReviewItem,
  type FindingFollowUpReviewResponse,
  type FindingReviewSeverity,
  type FindingReviewStatus,
  type TargetResponse,
} from "@/lib/api";
import {
  sameBulkFollowUpClearIdentity,
  type BulkFollowUpClearIntent,
  type BulkFollowUpClearMode,
} from "@/lib/bulk-follow-up-clear";
import {
  sameBulkFollowUpEditIdentity,
  sameFollowUpReviewSnapshot,
} from "@/lib/bulk-follow-up-edit";
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
const MAX_BULK_SELECTION = 50;
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
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkDueIntent, setBulkDueIntent] =
    useState<BulkFollowUpDueIntent | null>(null);
  const [bulkDueGeneration, setBulkDueGeneration] = useState(0);
  const [bulkDueEpoch, setBulkDueEpoch] = useState(0);
  const [bulkEditIntent, setBulkEditIntent] =
    useState<BulkFollowUpEditIntent | null>(null);
  const [bulkEditSubmitGeneration, setBulkEditSubmitGeneration] = useState(0);
  const [bulkEditModalGeneration, setBulkEditModalGeneration] = useState(0);
  const [bulkClearIntent, setBulkClearIntent] =
    useState<BulkFollowUpClearIntent | null>(null);
  const [bulkClearSubmitGeneration, setBulkClearSubmitGeneration] = useState(0);
  const [bulkClearModalGeneration, setBulkClearModalGeneration] = useState(0);
  const [reviewReplacing, setReviewReplacing] = useState(false);

  const generationRef = useRef(0);
  const pageCursorRef = useRef<string | null>(null);
  const nextInFlightRef = useRef<string | null>(null);
  const latestRequestRef = useRef<FollowUpReviewRequestSnapshot | null>(null);
  const mountedRef = useRef(true);
  const targetGenerationRef = useRef(0);
  const recoveringCursorRef = useRef(false);
  const reviewReplacementRef = useRef(0);
  const bulkEditIntentRef = useRef<BulkFollowUpEditIntent | null>(null);
  const bulkEditSubmitGenerationRef = useRef(0);
  const bulkEditModalGenerationRef = useRef(0);
  const bulkEditReconciliationRef = useRef(0);
  const bulkClearIntentRef = useRef<BulkFollowUpClearIntent | null>(null);
  const bulkClearSubmitGenerationRef = useRef(0);
  const bulkClearModalGenerationRef = useRef(0);
  const bulkClearReconciliationRef = useRef(0);
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
    setSelectedIds([]);
    setBulkDueIntent(null);
    setBulkDueEpoch((value) => value + 1);
    setBulkEditIntent(null);
    setBulkClearIntent(null);
    setBulkClearSubmitGeneration((value) => value + 1);
    setBulkClearModalGeneration((value) => value + 1);
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
      bulkEditIntentRef.current = null;
      bulkEditSubmitGenerationRef.current += 1;
      bulkEditModalGenerationRef.current += 1;
      bulkEditReconciliationRef.current += 1;
      bulkClearIntentRef.current = null;
      bulkClearSubmitGenerationRef.current += 1;
      bulkClearModalGenerationRef.current += 1;
      bulkClearReconciliationRef.current += 1;
    };
  }, []);

  useEffect(() => {
    viewRef.current = currentSnapshot(pageCursorRef.current);
  }, [currentSnapshot]);

  const invalidateBulkClearIntent = useCallback(() => {
    bulkClearIntentRef.current = null;
    bulkClearSubmitGenerationRef.current += 1;
    bulkClearModalGenerationRef.current += 1;
    bulkClearReconciliationRef.current += 1;
    setBulkClearIntent(null);
    setBulkClearSubmitGeneration(bulkClearSubmitGenerationRef.current);
    setBulkClearModalGeneration(bulkClearModalGenerationRef.current);
  }, []);

  useEffect(() => {
    bulkClearIntentRef.current = null;
    bulkClearSubmitGenerationRef.current += 1;
    bulkClearModalGenerationRef.current += 1;
    bulkClearReconciliationRef.current += 1;
  }, [organizationId]);

  const invalidateBulkEditIntent = useCallback(() => {
    bulkEditIntentRef.current = null;
    bulkEditSubmitGenerationRef.current += 1;
    bulkEditModalGenerationRef.current += 1;
    bulkEditReconciliationRef.current += 1;
    setBulkEditIntent(null);
    setBulkEditSubmitGeneration(bulkEditSubmitGenerationRef.current);
    setBulkEditModalGeneration(bulkEditModalGenerationRef.current);
  }, []);

  const invalidateBulkDue = useCallback(() => {
    setBulkDueEpoch((value) => value + 1);
    setSelectedIds([]);
    setBulkDueIntent(null);
    invalidateBulkEditIntent();
    invalidateBulkClearIntent();
  }, [invalidateBulkClearIntent, invalidateBulkEditIntent]);

  const isBulkDueSubmitCurrent = useCallback(
    (generation: number) => generation === bulkDueEpoch,
    [bulkDueEpoch],
  );

  const isBulkEditIntentCurrent = useCallback(
    (intent: BulkFollowUpEditIntent) => {
      const currentIntent = bulkEditIntentRef.current;
      if (!mountedRef.current || currentIntent == null || !organizationId) {
        return false;
      }
      const liveSnapshot = currentSnapshot(pageCursorRef.current);
      liveSnapshot.generation = generationRef.current;
      const liveIdentity = {
        organizationId,
        reviewSnapshot: liveSnapshot,
        submitGeneration: bulkEditSubmitGenerationRef.current,
        modalGeneration: bulkEditModalGenerationRef.current,
      };
      return (
        intent.submitGeneration === bulkEditSubmitGeneration &&
        intent.modalGeneration === bulkEditModalGeneration &&
        sameBulkFollowUpEditIdentity(intent, currentIntent) &&
        sameBulkFollowUpEditIdentity(intent, liveIdentity)
      );
    },
    [
      bulkEditModalGeneration,
      bulkEditSubmitGeneration,
      currentSnapshot,
      organizationId,
    ],
  );

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
      invalidateBulkDue();
      return true;
    },
    [currentSnapshot, invalidateBulkDue],
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
      const replacement = reviewReplacementRef.current + 1;
      reviewReplacementRef.current = replacement;
      invalidateBulkDue();
      setReviewReplacing(true);
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
          if (reviewReplacementRef.current === replacement) {
            setReviewReplacing(false);
          }
        }
      });
    },
    [
      applyIfCurrent,
      currentSnapshot,
      enabled,
      fetchPage,
      invalidateBulkDue,
      organizationId,
    ],
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
    invalidateBulkDue();
    const replacement = reviewReplacementRef.current + 1;
    reviewReplacementRef.current = replacement;
    setReviewReplacing(true);
    generationRef.current += 1;
    pageCursorRef.current = null;
    nextInFlightRef.current = null;
    recoveringCursorRef.current = false;
    const request = currentSnapshot(null);
    latestRequestRef.current = request;
    viewRef.current = request;
    try {
      const next = await fetchPage(request);
      applyIfCurrent(request, next);
    } finally {
      if (reviewReplacementRef.current === replacement) {
        setReviewReplacing(false);
      }
    }
  }, [applyIfCurrent, currentSnapshot, fetchPage, invalidateBulkDue]);

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

  const handleBulkDueWriteSucceeded = useCallback(
    async (response: BulkFollowUpDueResponse) => {
      setSuccess(
        response.changed_count === 0
          ? "Selected findings already use this follow-up due date."
          : `Follow-up due date updated for ${response.changed_count} selected ${
              response.changed_count === 1 ? "finding" : "findings"
            }.`,
      );
      setRefreshWarning(null);
      setNotice(null);
      setCurrentDueNotice(null);
      setError(null);
      invalidateBulkDue();
      try {
        await refreshFirstPageCurrent();
      } catch {
        setRefreshWarning(
          "Due dates were updated, but the follow-up review could not be refreshed.",
        );
      }
    },
    [invalidateBulkDue, refreshFirstPageCurrent],
  );

  const handleBulkDueConflict = useCallback(
    async (message: string) => {
      setSuccess(null);
      setRefreshWarning(null);
      setCurrentDueNotice(null);
      setError(null);
      setNotice(message);
      invalidateBulkDue();
      try {
        await refreshFirstPageCurrent();
      } catch {
        setError("Finding follow-up review could not be loaded.");
      }
    },
    [invalidateBulkDue, refreshFirstPageCurrent],
  );

  const handleBulkDueTransportUncertain = useCallback(async () => {
    setSuccess(null);
    setRefreshWarning(null);
    setCurrentDueNotice(null);
    setError(null);
    invalidateBulkDue();
    try {
      await refreshFirstPageCurrent();
      setNotice(
        "Bulk due-date update outcome could not be confirmed. Follow-up review was refreshed.",
      );
    } catch {
      setNotice("Bulk due-date update outcome could not be confirmed.");
      setRefreshWarning("Follow-up review could not be refreshed.");
    }
  }, [invalidateBulkDue, refreshFirstPageCurrent]);

  const isBulkEditReconciliationCurrent = useCallback(
    (
      reconciliationGeneration: number,
      reviewSnapshot: FollowUpReviewRequestSnapshot,
    ) =>
      mountedRef.current &&
      bulkEditReconciliationRef.current === reconciliationGeneration &&
      sameFollowUpReviewSnapshot(reviewSnapshot, currentSnapshot(null)),
    [currentSnapshot],
  );

  const handleBulkEditWriteSucceeded = useCallback(
    async (
      intent: BulkFollowUpEditIntent,
      response: BulkFollowUpEditResponse,
    ) => {
      if (!isBulkEditIntentCurrent(intent)) return;
      setSuccess(
        response.changed_count === 0
          ? "Selected findings already use this follow-up owner and due date."
          : `Follow-up updated for ${response.changed_count} selected ${
              response.changed_count === 1 ? "finding" : "findings"
            }.`,
      );
      setRefreshWarning(null);
      setNotice(null);
      setCurrentDueNotice(null);
      setError(null);
      invalidateBulkDue();
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkEditReconciliationRef.current + 1;
      bulkEditReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkEditReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setRefreshWarning(
          "Follow-up was updated, but the follow-up review could not be refreshed.",
        );
      }
    },
    [
      currentSnapshot,
      invalidateBulkDue,
      isBulkEditIntentCurrent,
      isBulkEditReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const handleBulkEditConflict = useCallback(
    async (intent: BulkFollowUpEditIntent) => {
      if (!isBulkEditIntentCurrent(intent)) return;
      setSuccess(null);
      setRefreshWarning(null);
      setCurrentDueNotice(null);
      setError(null);
      setNotice(
        "Selected follow-up changed before this edit could be applied. Review the refreshed list and select findings again.",
      );
      invalidateBulkDue();
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkEditReconciliationRef.current + 1;
      bulkEditReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkEditReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setError("Finding follow-up review could not be loaded.");
      }
    },
    [
      currentSnapshot,
      invalidateBulkDue,
      isBulkEditIntentCurrent,
      isBulkEditReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const handleBulkEditTransportUncertain = useCallback(
    async (intent: BulkFollowUpEditIntent) => {
      if (!isBulkEditIntentCurrent(intent)) return;
      setSuccess(null);
      setRefreshWarning(null);
      setCurrentDueNotice(null);
      setError(null);
      setNotice(
        "Bulk follow-up edit outcome could not be confirmed. Review the refreshed list before trying again.",
      );
      invalidateBulkDue();
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkEditReconciliationRef.current + 1;
      bulkEditReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkEditReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setRefreshWarning("Follow-up review could not be refreshed.");
      }
    },
    [
      currentSnapshot,
      invalidateBulkDue,
      isBulkEditIntentCurrent,
      isBulkEditReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const isBulkClearIntentCurrent = useCallback(
    (intent: BulkFollowUpClearIntent) => {
      const currentIntent = bulkClearIntentRef.current;
      if (!mountedRef.current || currentIntent == null || !organizationId) {
        return false;
      }
      const liveSnapshot = currentSnapshot(pageCursorRef.current);
      liveSnapshot.generation = generationRef.current;
      const liveIdentity = {
        surface: "follow-up-review" as const,
        organizationId,
        reviewSnapshot: liveSnapshot,
        submitGeneration: bulkClearSubmitGenerationRef.current,
        modalGeneration: bulkClearModalGenerationRef.current,
      };
      return (
        sameBulkFollowUpClearIdentity(intent, currentIntent) &&
        sameBulkFollowUpClearIdentity(intent, liveIdentity) &&
        intent.submitGeneration === bulkClearSubmitGeneration &&
        intent.modalGeneration === bulkClearModalGeneration
      );
    },
    [
      bulkClearModalGeneration,
      bulkClearSubmitGeneration,
      currentSnapshot,
      organizationId,
    ],
  );

  const isBulkClearReconciliationCurrent = useCallback(
    (
      reconciliationGeneration: number,
      reviewSnapshot: FollowUpReviewRequestSnapshot,
    ) =>
      mountedRef.current &&
      bulkClearReconciliationRef.current === reconciliationGeneration &&
      sameFollowUpReviewSnapshot(reviewSnapshot, currentSnapshot(null)),
    [currentSnapshot],
  );

  const handleBulkClearWriteSucceeded = useCallback(
    async (
      intent: BulkFollowUpClearIntent,
      response: BulkFollowUpClearResponse,
    ) => {
      if (!isBulkClearIntentCurrent(intent)) return;
      const noun =
        intent.clear_owner && intent.clear_due
          ? "Follow-up"
          : intent.clear_due
            ? "Due dates"
            : "Owners";
      setSuccess(
        response.changed_count === 0
          ? "Selected findings already match this clear."
          : `${noun} cleared for ${response.changed_count} selected ${
              response.changed_count === 1 ? "finding" : "findings"
            }.`,
      );
      setRefreshWarning(null);
      setNotice(null);
      setCurrentDueNotice(null);
      setError(null);
      invalidateBulkClearIntent();
      setSelectedIds([]);
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkClearReconciliationRef.current + 1;
      bulkClearReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkClearReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setRefreshWarning(
          "Follow-up was cleared, but the follow-up review could not be refreshed.",
        );
      }
    },
    [
      currentSnapshot,
      invalidateBulkClearIntent,
      isBulkClearIntentCurrent,
      isBulkClearReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const handleBulkClearConflict = useCallback(
    async (intent: BulkFollowUpClearIntent) => {
      if (!isBulkClearIntentCurrent(intent)) return;
      setSuccess(null);
      setRefreshWarning(null);
      setCurrentDueNotice(null);
      setError(null);
      setNotice(
        "Selected follow-up changed before this clear could be applied. Review the refreshed list and select findings again.",
      );
      invalidateBulkClearIntent();
      setSelectedIds([]);
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkClearReconciliationRef.current + 1;
      bulkClearReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkClearReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setError("Finding follow-up review could not be loaded.");
      }
    },
    [
      currentSnapshot,
      invalidateBulkClearIntent,
      isBulkClearIntentCurrent,
      isBulkClearReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const handleBulkClearTransportUncertain = useCallback(
    async (intent: BulkFollowUpClearIntent) => {
      if (!isBulkClearIntentCurrent(intent)) return;
      setSuccess(null);
      setRefreshWarning(null);
      setCurrentDueNotice(null);
      setError(null);
      setNotice(
        "Bulk follow-up clear outcome could not be confirmed. Review the refreshed list before trying again.",
      );
      invalidateBulkClearIntent();
      setSelectedIds([]);
      const refresh = refreshFirstPageCurrent();
      const reconciliationGeneration = bulkClearReconciliationRef.current + 1;
      bulkClearReconciliationRef.current = reconciliationGeneration;
      const reviewSnapshot = currentSnapshot(null);
      try {
        await refresh;
      } catch {
        if (
          !isBulkClearReconciliationCurrent(
            reconciliationGeneration,
            reviewSnapshot,
          )
        ) {
          return;
        }
        setRefreshWarning("Follow-up review could not be refreshed.");
      }
    },
    [
      currentSnapshot,
      invalidateBulkClearIntent,
      isBulkClearIntentCurrent,
      isBulkClearReconciliationCurrent,
      refreshFirstPageCurrent,
    ],
  );

  const toggleBulkDueSelected = useCallback(
    (findingId: string) => {
      if (reviewReplacing) return;
      invalidateBulkClearIntent();
      invalidateBulkEditIntent();
      setSelectedIds((current) => {
        if (current.includes(findingId)) {
          return current.filter((id) => id !== findingId);
        }
        if (current.length >= MAX_BULK_SELECTION) return current;
        return [...current, findingId];
      });
    },
    [invalidateBulkClearIntent, invalidateBulkEditIntent, reviewReplacing],
  );

  const selectVisibleForBulkDue = useCallback(() => {
    if (payload == null || reviewReplacing) return;
    invalidateBulkClearIntent();
    invalidateBulkEditIntent();
    setSelectedIds(
      payload.items.map((item) => item.finding_id).slice(0, MAX_BULK_SELECTION),
    );
  }, [invalidateBulkClearIntent, invalidateBulkEditIntent, payload, reviewReplacing]);

  const openBulkDue = useCallback(() => {
    if (payload == null || reviewReplacing || selectedIds.length === 0) return;
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
    if (items.length !== selectedIds.length || items.length === 0) {
      invalidateBulkDue();
      return;
    }
    setBulkDueGeneration((value) => value + 1);
    setBulkDueIntent({
      selectedCount: items.length,
      items,
      submitGeneration: bulkDueEpoch,
      evaluationTime: payload.evaluation_time,
    });
  }, [
    bulkDueEpoch,
    invalidateBulkDue,
    payload,
    reviewReplacing,
    selectedIds,
  ]);

  const openBulkEdit = useCallback(() => {
    if (
      payload == null ||
      reviewReplacing ||
      selectedIds.length === 0 ||
      !organizationId
    ) {
      return;
    }
    const selected = new Set(selectedIds);
    const items = Object.freeze(
      payload.items
        .filter((item) => selected.has(item.finding_id))
        .slice(0, MAX_BULK_SELECTION)
        .map((item) =>
          Object.freeze({
            finding_id: item.finding_id,
            expected_follow_up: Object.freeze({
              assigned_to_user_id: item.assignee?.user_id ?? null,
              follow_up_due_at: item.follow_up_due_at,
            }),
          }),
        ),
    );
    if (items.length !== selectedIds.length || items.length === 0) {
      invalidateBulkDue();
      return;
    }
    const reviewSnapshot = Object.freeze({
      ...currentSnapshot(pageCursorRef.current),
      generation: generationRef.current,
    });
    const modalGeneration = bulkEditModalGenerationRef.current + 1;
    bulkEditModalGenerationRef.current = modalGeneration;
    setBulkEditModalGeneration(modalGeneration);
    const submitGeneration = bulkEditSubmitGenerationRef.current;
    setBulkEditSubmitGeneration(submitGeneration);
    const intent = Object.freeze({
      organizationId,
      reviewSnapshot,
      selectedCount: items.length,
      items,
      submitGeneration,
      modalGeneration,
    });
    bulkEditIntentRef.current = intent;
    setBulkEditIntent(intent);
  }, [
    currentSnapshot,
    invalidateBulkDue,
    organizationId,
    payload,
    reviewReplacing,
    selectedIds,
  ]);

  const openBulkClear = useCallback(
    (mode: BulkFollowUpClearMode) => {
      if (
        payload == null ||
        reviewReplacing ||
        selectedIds.length === 0 ||
        !organizationId
      ) {
        return;
      }
      const selected = new Set(selectedIds);
      const items = Object.freeze(
        payload.items
          .filter((item) => selected.has(item.finding_id))
          .slice(0, MAX_BULK_SELECTION)
          .map((item) =>
            Object.freeze({
              finding_id: item.finding_id,
              expected_follow_up: Object.freeze({
                assigned_to_user_id: item.assignee?.user_id ?? null,
                follow_up_due_at: item.follow_up_due_at,
              }),
            }),
          ),
      );
      if (items.length !== selectedIds.length || items.length === 0) {
        invalidateBulkClearIntent();
        return;
      }
      const reviewSnapshot = Object.freeze({
        ...currentSnapshot(pageCursorRef.current),
        generation: generationRef.current,
      });
      const modalGeneration = bulkClearModalGenerationRef.current + 1;
      bulkClearModalGenerationRef.current = modalGeneration;
      setBulkClearModalGeneration(modalGeneration);
      const submitGeneration = bulkClearSubmitGenerationRef.current;
      setBulkClearSubmitGeneration(submitGeneration);
      const intent = Object.freeze({
        surface: "follow-up-review" as const,
        organizationId,
        reviewSnapshot,
        selectedCount: items.length,
        items,
        clear_owner: mode !== "due",
        clear_due: mode !== "owner",
        submitGeneration,
        modalGeneration,
      });
      bulkClearIntentRef.current = intent;
      setBulkClearIntent(intent);
    },
    [
      currentSnapshot,
      invalidateBulkClearIntent,
      organizationId,
      payload,
      reviewReplacing,
      selectedIds,
    ],
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
            onClick={() => {
              invalidateBulkDue();
              setFilter(option.value);
            }}
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
        onTargetId={(value) => {
          invalidateBulkDue();
          setTargetId(value);
        }}
        onSeverity={(value) => {
          invalidateBulkDue();
          setSeverity(value);
        }}
        onStatus={(value) => {
          invalidateBulkDue();
          setStatus(value);
        }}
      />

      {payload != null && payload.items.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={reviewReplacing}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={selectVisibleForBulkDue}
          >
            Select visible
          </button>
          <span className="text-sm text-zinc-600">
            {selectedIds.length} selected
          </span>
          <button
            type="button"
            disabled={reviewReplacing || selectedIds.length === 0}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={invalidateBulkDue}
          >
            Clear selection
          </button>
          <button
            type="button"
            disabled={reviewReplacing || selectedIds.length === 0}
            className="rounded-md border border-zinc-900 bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            onClick={openBulkDue}
          >
            Set due date for selected
          </button>
          <button
            type="button"
            disabled={reviewReplacing || selectedIds.length === 0}
            className="rounded-md border border-zinc-900 bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            onClick={openBulkEdit}
          >
            Edit follow-up for selected
          </button>
          <button
            type="button"
            disabled={reviewReplacing || selectedIds.length === 0}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={() => openBulkClear("due")}
          >
            Clear due dates for selected
          </button>
          <button
            type="button"
            disabled={reviewReplacing || selectedIds.length === 0}
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            onClick={() => openBulkClear("both")}
          >
            Clear follow-up for selected
          </button>
        </div>
      ) : null}

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
            const bulkSelected = selectedIds.includes(item.finding_id);
            return (
              <li
                key={item.finding_id}
                className={`flex flex-wrap items-start justify-between gap-3 py-3 ${
                  selected ? "bg-zinc-50" : ""
                }`}
              >
                <label className="flex items-center gap-2 text-sm text-zinc-700">
                  <input
                    type="checkbox"
                    checked={bulkSelected}
                    disabled={reviewReplacing}
                    aria-label={`Select ${item.title} for bulk due-date update`}
                    onChange={() => toggleBulkDueSelected(item.finding_id)}
                  />
                  <span className="sr-only">Select finding</span>
                </label>
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

      {bulkDueIntent ? (
        <FindingFollowUpBulkDueModal
          key={bulkDueGeneration}
          intent={bulkDueIntent}
          isSubmitCurrent={isBulkDueSubmitCurrent}
          onClose={() => setBulkDueIntent(null)}
          onWriteSucceeded={handleBulkDueWriteSucceeded}
          onAuthoritativeConflict={handleBulkDueConflict}
          onTransportUncertain={handleBulkDueTransportUncertain}
        />
      ) : null}

      {bulkEditIntent ? (
        <FindingFollowUpBulkEditModal
          key={bulkEditModalGeneration}
          intent={bulkEditIntent}
          isIntentCurrent={isBulkEditIntentCurrent}
          onClose={(intent) => {
            if (!isBulkEditIntentCurrent(intent)) return;
            invalidateBulkEditIntent();
          }}
          onWriteSucceeded={handleBulkEditWriteSucceeded}
          onAuthoritativeConflict={handleBulkEditConflict}
          onTransportUncertain={handleBulkEditTransportUncertain}
        />
      ) : null}

      {bulkClearIntent ? (
        <FindingFollowUpBulkClearModal
          key={bulkClearModalGeneration}
          intent={bulkClearIntent}
          isIntentCurrent={isBulkClearIntentCurrent}
          onClose={(intent) => {
            if (!isBulkClearIntentCurrent(intent)) return;
            invalidateBulkClearIntent();
          }}
          onWriteSucceeded={handleBulkClearWriteSucceeded}
          onAuthoritativeConflict={handleBulkClearConflict}
          onTransportUncertain={handleBulkClearTransportUncertain}
        />
      ) : null}
    </section>
  );
}

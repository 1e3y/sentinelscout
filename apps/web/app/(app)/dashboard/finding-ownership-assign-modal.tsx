"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useRef, useState } from "react";
import { OrganizationMemberPicker } from "./organization-member-picker";
import { parseApiError } from "@/lib/api-error";
import {
  fetchFinding,
  fetchOrganizationMembers,
  type FindingOwnershipAssignmentState,
  type OrganizationMember,
} from "@/lib/api";
import { isTransportAmbiguousError } from "@/lib/api-error";
import {
  projectInlineOwnershipSnapshot,
  snapshotsDueEqual,
  snapshotsOwnerEqual,
  type InlineOwnershipSnapshot,
} from "@/lib/inline-ownership-snapshot";
import {
  organizationMemberLabel,
  organizationMemberPickerLabel,
} from "@/lib/organization-member-label";
import { updateFindingOwnershipConditionally } from "@/lib/update-finding-ownership-conditional";

const MEMBER_PAGE_SIZE = 50;
const FINDING_READ_FAILED = "This finding could not be loaded.";
const OWNERSHIP_UPDATE_FAILED = "Finding ownership could not be updated.";
const RESOLVED_CLIENT = "This finding can no longer be updated.";
const OWNER_DRIFT =
  "The current finding owner changed. Review the latest state, then save again to apply your selected owner.";
const DUE_DRIFT =
  "The follow-up due date changed. Review the latest date, then save again to apply your selected owner.";
const FOLLOW_UP_CHANGED = "Finding follow-up changed. Refresh and try again.";
const RESOLVED_API =
  "Resolved findings cannot change follow-up ownership or due date";
const STALE_OWNER_API = "Assignee must be a current organization member";
const STALE_OWNER =
  "This assignee is no longer eligible. Choose a current organization member.";
const PROVIDER_UNAVAILABLE_API = "Failed to verify organization membership";
const PROVIDER_UNAVAILABLE =
  "Organization membership could not be verified. Try again later.";
const TRANSPORT_UNCERTAIN =
  "We couldn't confirm whether the owner was updated. The current state was refreshed; review it before trying again.";

export type OwnershipAssignIntent = {
  findingId: string;
  title: string;
  targetLabel: string;
  assignmentState: FindingOwnershipAssignmentState;
};

type Props = {
  intent: OwnershipAssignIntent | null;
  onClose: () => void;
  onWriteSucceeded: () => Promise<void>;
  onAlreadyOwner: () => Promise<void>;
  onResolvedConflict: () => void;
  onTransportUncertain: () => Promise<void>;
};

function formatDue(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function confirmationCopy(
  assignmentState: FindingOwnershipAssignmentState,
  currentLabel: string,
  selectedLabel: string,
): string {
  if (assignmentState === "unassigned") {
    return `Assign this finding to ${selectedLabel}?`;
  }
  if (assignmentState === "not_current_member") {
    return `Reassign this finding to ${selectedLabel}?`;
  }
  return `Change the finding owner from ${currentLabel} to ${selectedLabel}?`;
}

export function FindingOwnershipAssignModal({
  intent,
  onClose,
  onWriteSucceeded,
  onAlreadyOwner,
  onResolvedConflict,
  onTransportUncertain,
}: Props) {
  const { getToken } = useAuth();
  const generationRef = useRef(0);
  const loadMoreCursorRef = useRef<string | null>(null);
  const saveInFlightRef = useRef(false);

  const [snapshot, setSnapshot] = useState<InlineOwnershipSnapshot | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [findingLoading, setFindingLoading] = useState(true);
  const [pickerLoading, setPickerLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [saving, setSaving] = useState(false);
  const [mutationDisabled, setMutationDisabled] = useState(false);
  const [readError, setReadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!intent) return;
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    let cancelled = false;

    async function open(current: OwnershipAssignIntent) {
      try {
        const token = await getToken();
        if (!token) {
          if (generationRef.current !== generation) return;
          setFindingLoading(false);
          setReadError("Missing session token");
          return;
        }
        const finding = await fetchFinding(token, current.findingId);
        if (cancelled || generationRef.current !== generation) return;
        const next = projectInlineOwnershipSnapshot(finding);
        setSnapshot(next);
        setFindingLoading(false);
        if (next.status === "resolved") {
          setMutationDisabled(true);
          setError(RESOLVED_CLIENT);
          onResolvedConflict();
          return;
        }
        setPickerLoading(true);
        const page = await fetchOrganizationMembers(token, {
          page_size: MEMBER_PAGE_SIZE,
        });
        if (cancelled || generationRef.current !== generation) return;
        setMembers(dedupeMembers(page.items));
        setNextCursor(page.next_cursor);
        setPickerLoading(false);
      } catch (err) {
        if (cancelled || generationRef.current !== generation) return;
        setFindingLoading(false);
        setPickerLoading(false);
        setReadError(parseApiError(err, FINDING_READ_FAILED).message);
      }
    }

    void open(intent);
    return () => {
      cancelled = true;
      generationRef.current += 1;
    };
  }, [intent, getToken, onResolvedConflict]);

  async function loadMore() {
    if (!intent || mutationDisabled || saving) return;
    const cursor = nextCursor;
    if (!cursor || loadingMore) return;
    if (loadMoreCursorRef.current === cursor) return;
    const generation = generationRef.current;
    loadMoreCursorRef.current = cursor;
    setLoadingMore(true);
    try {
      const token = await getToken();
      if (!token) {
        if (generationRef.current !== generation) return;
        setError("Missing session token");
        return;
      }
      const page = await fetchOrganizationMembers(token, {
        page_size: MEMBER_PAGE_SIZE,
        cursor,
      });
      if (generationRef.current !== generation) return;
      setMembers((prev) => dedupeMembers([...prev, ...page.items]));
      setNextCursor(page.next_cursor);
    } catch (err) {
      if (generationRef.current !== generation) return;
      setError(parseApiError(err, "Organization members could not be loaded.").message);
    } finally {
      if (generationRef.current === generation) {
        setLoadingMore(false);
        loadMoreCursorRef.current = null;
      }
    }
  }

  async function save() {
    if (!intent || !snapshot || mutationDisabled) return;
    if (!selectedUserId || saveInFlightRef.current) return;
    const generation = generationRef.current;
    const currentIntent = intent;
    const proposedOwnerUserId = selectedUserId;
    saveInFlightRef.current = true;
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const token = await getToken();
      if (!token) {
        if (generationRef.current !== generation) return;
        setError("Missing session token");
        return;
      }
      let finding;
      try {
        finding = await fetchFinding(token, currentIntent.findingId);
      } catch (err) {
        if (generationRef.current !== generation) return;
        setError(parseApiError(err, FINDING_READ_FAILED).message);
        return;
      }
      if (generationRef.current !== generation) return;
      const fresh = projectInlineOwnershipSnapshot(finding);

      if (fresh.status === "resolved") {
        setSnapshot(fresh);
        setMutationDisabled(true);
        setError(RESOLVED_CLIENT);
        onResolvedConflict();
        return;
      }

      if (!snapshotsOwnerEqual(snapshot, fresh)) {
        setSnapshot(fresh);
        if (proposedOwnerUserId === fresh.owner_user_id) {
          await onAlreadyOwner();
          if (generationRef.current === generation) {
            onClose();
          }
          return;
        }
        setNotice(OWNER_DRIFT);
        return;
      }

      if (!snapshotsDueEqual(snapshot, fresh)) {
        setSnapshot(fresh);
        if (proposedOwnerUserId === fresh.owner_user_id) {
          await onAlreadyOwner();
          if (generationRef.current === generation) {
            onClose();
          }
          return;
        }
        setNotice(DUE_DRIFT);
        return;
      }

      if (proposedOwnerUserId === fresh.owner_user_id) {
        setSnapshot(fresh);
        await onAlreadyOwner();
        if (generationRef.current === generation) {
          onClose();
        }
        return;
      }

      try {
        await updateFindingOwnershipConditionally({
          token,
          findingId: currentIntent.findingId,
          proposedOwnerUserId,
          authoritativeOwnerUserId: fresh.owner_user_id,
          authoritativeDueAt: fresh.follow_up_due_at,
        });
      } catch (err) {
        // The write can commit after this modal was replaced. Fence every old
        // modal before applying copy, callbacks, refreshes, or close effects.
        if (generationRef.current !== generation) return;
        const parsed = parseApiError(err, OWNERSHIP_UPDATE_FAILED);
        const concurrency =
          parsed.status === 409 && parsed.message === FOLLOW_UP_CHANGED;
        const transportUncertain = isTransportAmbiguousError(err);

        if (concurrency || transportUncertain) {
          try {
            const refreshed = await fetchFinding(token, currentIntent.findingId);
            if (generationRef.current !== generation) return;
            const refreshedSnapshot = projectInlineOwnershipSnapshot(refreshed);
            setSnapshot(refreshedSnapshot);
            if (refreshedSnapshot.status === "resolved") {
              setMutationDisabled(true);
              setError(RESOLVED_CLIENT);
              onResolvedConflict();
              return;
            }
            if (
              concurrency &&
              proposedOwnerUserId === refreshedSnapshot.owner_user_id
            ) {
              await onAlreadyOwner();
              if (generationRef.current === generation) {
                onClose();
              }
              return;
            }
          } catch {
            if (generationRef.current !== generation) return;
          }

          if (transportUncertain) {
            if (generationRef.current !== generation) return;
            setNotice(TRANSPORT_UNCERTAIN);
            await onTransportUncertain();
            return;
          }
          setNotice(FOLLOW_UP_CHANGED);
          return;
        }

        if (parsed.status === 409 && parsed.message === RESOLVED_API) {
          setMutationDisabled(true);
          setError(RESOLVED_CLIENT);
          onResolvedConflict();
          return;
        }
        if (parsed.status === 400 && parsed.message === STALE_OWNER_API) {
          setError(STALE_OWNER);
          return;
        }
        if (
          parsed.status === 502 &&
          parsed.message === PROVIDER_UNAVAILABLE_API
        ) {
          setError(PROVIDER_UNAVAILABLE);
          return;
        }
        setError(parsed.message);
        return;
      }
      if (generationRef.current !== generation) return;
      await onWriteSucceeded();
      if (generationRef.current === generation) {
        onClose();
      }
    } catch (err) {
      if (generationRef.current !== generation) return;
      setError(parseApiError(err, OWNERSHIP_UPDATE_FAILED).message);
    } finally {
      if (generationRef.current === generation) {
        saveInFlightRef.current = false;
        setSaving(false);
      }
    }
  }

  if (!intent) return null;

  const currentOwnerLabel = snapshot
    ? snapshot.owner_user_id
      ? organizationMemberLabel(snapshot.owner_display_name)
      : "Unassigned"
    : "…";
  const selectedMember = members.find((row) => row.user_id === selectedUserId);
  const selectedLabel = selectedMember
    ? organizationMemberPickerLabel(
        selectedMember.display_name,
        selectedMember.user_id,
        members,
      )
    : organizationMemberLabel(null);
  const saveDisabled =
    mutationDisabled ||
    findingLoading ||
    pickerLoading ||
    saving ||
    !snapshot ||
    !selectedUserId ||
    selectedUserId === snapshot.owner_user_id;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="ownership-assign-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="ownership-assign-title" className="text-lg font-medium">
            {intent.assignmentState === "unassigned"
              ? "Assign owner"
              : intent.assignmentState === "not_current_member"
                ? "Reassign owner"
                : "Change owner"}
          </h3>
          <p className="mt-1 text-sm text-zinc-600">
            {intent.title} · {intent.targetLabel}
          </p>
        </div>

        {findingLoading ? (
          <p className="text-sm text-zinc-600">Loading finding…</p>
        ) : readError ? (
          <p className="text-sm text-red-800">{readError}</p>
        ) : snapshot ? (
          <dl className="grid gap-2 text-sm text-zinc-700">
            <div>
              <dt className="text-zinc-500">Current owner</dt>
              <dd>{currentOwnerLabel}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Current due date</dt>
              <dd>{formatDue(snapshot.follow_up_due_at)}</dd>
            </div>
          </dl>
        ) : null}

        {!readError && !mutationDisabled && snapshot ? (
          <OrganizationMemberPicker
            members={members}
            selectedUserId={selectedUserId}
            disabled={saving}
            loading={pickerLoading}
            nextCursor={nextCursor}
            loadingMore={loadingMore}
            onSelect={(userId) => {
              setSelectedUserId(userId);
              setNotice(null);
              setError(null);
            }}
            onLoadMore={() => {
              void loadMore();
            }}
          />
        ) : null}

        {selectedUserId && snapshot && !mutationDisabled ? (
          <div className="space-y-1 text-sm text-zinc-700">
            <p>
              {confirmationCopy(
                intent.assignmentState,
                currentOwnerLabel,
                selectedLabel,
              )}
            </p>
            <p className="text-xs text-zinc-600">
              This changes the current finding owner. The existing follow-up due
              date will not be changed.
            </p>
          </div>
        ) : null}

        {notice ? <p className="text-sm text-zinc-800">{notice}</p> : null}
        {error ? <p className="text-sm text-red-800">{error}</p> : null}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="button"
            className="rounded-md border border-zinc-900 bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            disabled={saveDisabled}
            onClick={() => {
              void save();
            }}
          >
            {saving ? "Saving…" : "Save assignment"}
          </button>
        </div>
      </div>
    </div>
  );
}

function dedupeMembers(rows: OrganizationMember[]): OrganizationMember[] {
  const seen = new Set<string>();
  const out: OrganizationMember[] = [];
  for (const row of rows) {
    if (seen.has(row.user_id)) continue;
    seen.add(row.user_id);
    out.push(row);
  }
  return out;
}

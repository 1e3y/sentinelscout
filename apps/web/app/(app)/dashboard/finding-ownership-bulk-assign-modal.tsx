"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useRef, useState } from "react";
import { OrganizationMemberPicker } from "./organization-member-picker";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import { postBulkOwnershipAssign } from "@/lib/bulk-ownership-assign";
import {
  fetchOrganizationMembers,
  type BulkOwnershipAssignItem,
  type OrganizationMember,
} from "@/lib/api";
import {
  organizationMemberLabel,
  organizationMemberPickerLabel,
} from "@/lib/organization-member-label";

const MEMBER_PAGE_SIZE = 50;
const ASSIGN_FAILED = "Finding ownership could not be updated.";
const TRANSPORT_UNCERTAIN =
  "Bulk assignment outcome could not be confirmed. Ownership review was refreshed.";

export type BulkOwnershipAssignIntent = {
  selectedCount: number;
  items: BulkOwnershipAssignItem[];
  submitGeneration: number;
};

type Props = {
  intent: BulkOwnershipAssignIntent;
  isSubmitCurrent: (generation: number) => boolean;
  onClose: () => void;
  onWriteSucceeded: () => Promise<void>;
  onTransportUncertain: () => Promise<void>;
};

export function FindingOwnershipBulkAssignModal({
  intent,
  isSubmitCurrent,
  onClose,
  onWriteSucceeded,
  onTransportUncertain,
}: Props) {
  const { getToken } = useAuth();
  const generationRef = useRef(0);
  const loadMoreCursorRef = useRef<string | null>(null);
  const saveInFlightRef = useRef(false);

  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [pickerLoading, setPickerLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    let cancelled = false;

    async function open() {
      try {
        const token = await getToken();
        if (!token) {
          if (generationRef.current !== generation) return;
          setPickerLoading(false);
          setError("Missing session token");
          return;
        }
        const page = await fetchOrganizationMembers(token, {
          page_size: MEMBER_PAGE_SIZE,
        });
        if (cancelled || generationRef.current !== generation) return;
        setMembers(dedupeMembers(page.items));
        setNextCursor(page.next_cursor);
        setPickerLoading(false);
      } catch (err) {
        if (cancelled || generationRef.current !== generation) return;
        setPickerLoading(false);
        setError(parseApiError(err, "Organization members could not be loaded.").message);
      }
    }

    void open();
    return () => {
      cancelled = true;
      generationRef.current += 1;
    };
  }, [getToken, intent]);

  async function loadMore() {
    if (saving) return;
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
      setMembers((current) => dedupeMembers([...current, ...page.items]));
      setNextCursor(page.next_cursor);
    } catch (err) {
      if (generationRef.current !== generation) return;
      setError(parseApiError(err, "Organization members could not be loaded.").message);
    } finally {
      if (generationRef.current === generation) {
        setLoadingMore(false);
        if (loadMoreCursorRef.current === cursor) {
          loadMoreCursorRef.current = null;
        }
      }
    }
  }

  async function save() {
    if (saveInFlightRef.current || saving || !selectedUserId) return;
    if (!isSubmitCurrent(intent.submitGeneration)) {
      onClose();
      return;
    }
    saveInFlightRef.current = true;
    setSaving(true);
    setError(null);
    const generation = generationRef.current;
    try {
      const token = await getToken();
      if (!token) {
        setError("Missing session token");
        return;
      }
      if (!isSubmitCurrent(intent.submitGeneration)) {
        onClose();
        return;
      }
      await postBulkOwnershipAssign(token, {
        assigned_to_user_id: selectedUserId,
        items: intent.items,
      });
      await onWriteSucceeded();
      if (generationRef.current === generation && isSubmitCurrent(intent.submitGeneration)) {
        onClose();
      }
    } catch (err) {
      if (generationRef.current !== generation) return;
      if (isTransportAmbiguousError(err)) {
        setError(TRANSPORT_UNCERTAIN);
        await onTransportUncertain();
        return;
      }
      setError(parseApiError(err, ASSIGN_FAILED).message);
    } finally {
      if (generationRef.current === generation) {
        saveInFlightRef.current = false;
        setSaving(false);
      }
    }
  }

  const selectedMember = members.find((row) => row.user_id === selectedUserId);
  const selectedLabel = selectedMember
    ? organizationMemberPickerLabel(
        selectedMember.display_name,
        selectedMember.user_id,
        members,
      )
    : organizationMemberLabel(null);
  const saveDisabled = pickerLoading || saving || !selectedUserId;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="ownership-bulk-assign-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="ownership-bulk-assign-title" className="text-lg font-medium">
            Assign selected findings
          </h3>
          <p className="mt-1 text-sm text-zinc-600">
            {intent.selectedCount} selected. Ownership will change. Existing
            follow-up due dates will not change.
          </p>
        </div>

        <OrganizationMemberPicker
          members={members}
          selectedUserId={selectedUserId}
          disabled={saving}
          loading={pickerLoading}
          nextCursor={nextCursor}
          loadingMore={loadingMore}
          onSelect={(userId) => {
            setSelectedUserId(userId);
            setError(null);
          }}
          onLoadMore={() => {
            void loadMore();
          }}
        />

        {selectedUserId ? (
          <div className="space-y-1 text-sm text-zinc-700">
            <p>
              Assign {intent.selectedCount} selected findings to {selectedLabel}?
            </p>
            <p className="text-xs text-zinc-600">
              This changes ownership for the selected findings. Existing
              follow-up due dates will not change.
            </p>
          </div>
        ) : null}

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
            {saving ? "Saving…" : "Assign selected"}
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

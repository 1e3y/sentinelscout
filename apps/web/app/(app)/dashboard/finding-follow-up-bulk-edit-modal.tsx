"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState } from "react";
import { OrganizationMemberPicker } from "./organization-member-picker";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import {
  postBulkFollowUpEdit,
  type BulkFollowUpEditIdentity,
} from "@/lib/bulk-follow-up-edit";
import type {
  BulkFollowUpEditItem,
  BulkFollowUpEditResponse,
  OrganizationMember,
} from "@/lib/api";
import { fetchOrganizationMembers } from "@/lib/api";
import {
  LOCAL_TIMEZONE_LABEL,
  formatLocalDuePreview,
  localDateTimeMessage,
  parseLocalDateTimeInput,
} from "@/lib/datetime-local";
import {
  organizationMemberLabel,
  organizationMemberPickerLabel,
} from "@/lib/organization-member-label";

const MEMBER_PAGE_SIZE = 50;
const UPDATE_FAILED = "Selected finding follow-up could not be updated.";
const STALE_OWNER_API = "Assignee must be a current organization member";
const PROVIDER_UNAVAILABLE_API = "Failed to verify organization membership";
const STALE_OWNER =
  "The selected owner is no longer a current organization member. Choose another owner.";
const PROVIDER_UNAVAILABLE =
  "Organization membership could not be verified. Try again later.";

export type BulkFollowUpEditIntent = BulkFollowUpEditIdentity & {
  selectedCount: number;
  items: readonly BulkFollowUpEditItem[];
};

type Props = {
  intent: BulkFollowUpEditIntent;
  isIntentCurrent: (intent: BulkFollowUpEditIntent) => boolean;
  onClose: (intent: BulkFollowUpEditIntent) => void;
  onWriteSucceeded: (
    intent: BulkFollowUpEditIntent,
    response: BulkFollowUpEditResponse,
  ) => Promise<void>;
  onAuthoritativeConflict: (intent: BulkFollowUpEditIntent) => Promise<void>;
  onTransportUncertain: (intent: BulkFollowUpEditIntent) => Promise<void>;
};

export function FindingFollowUpBulkEditModal({
  intent,
  isIntentCurrent,
  onClose,
  onWriteSucceeded,
  onAuthoritativeConflict,
  onTransportUncertain,
}: Props) {
  const { getToken } = useAuth();
  const mountedRef = useRef(true);
  const activeRef = useRef(true);
  const localGenerationRef = useRef(0);
  const loadMoreCursorRef = useRef<string | null>(null);
  const saveInFlightRef = useRef(false);

  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [dueDraft, setDueDraft] = useState("");
  const [pickerLoading, setPickerLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isCurrent = useCallback(
    (localGeneration: number): boolean =>
      mountedRef.current &&
      activeRef.current &&
      localGenerationRef.current === localGeneration &&
      isIntentCurrent(intent),
    [intent, isIntentCurrent],
  );

  function closeCurrentModal() {
    if (!activeRef.current) return;
    const notifyParent = isCurrent(localGenerationRef.current);
    activeRef.current = false;
    localGenerationRef.current += 1;
    if (notifyParent) onClose(intent);
  }

  useEffect(() => {
    mountedRef.current = true;
    activeRef.current = true;
    const localGeneration = localGenerationRef.current + 1;
    localGenerationRef.current = localGeneration;

    async function open() {
      try {
        const token = await getToken();
        if (!isCurrent(localGeneration)) return;
        if (!token) {
          setPickerLoading(false);
          setError("Missing session token");
          return;
        }
        const page = await fetchOrganizationMembers(token, {
          page_size: MEMBER_PAGE_SIZE,
        });
        if (!isCurrent(localGeneration)) return;
        setMembers(dedupeMembers(page.items));
        setNextCursor(page.next_cursor);
        setPickerLoading(false);
      } catch (err) {
        if (!isCurrent(localGeneration)) return;
        setPickerLoading(false);
        setError(
          parseApiError(err, "Organization members could not be loaded.").message,
        );
      }
    }

    void open();
    return () => {
      mountedRef.current = false;
      activeRef.current = false;
      localGenerationRef.current += 1;
    };
  }, [getToken, intent, isCurrent]);

  async function loadMore() {
    const cursor = nextCursor;
    if (saving || !cursor || loadingMore) return;
    if (loadMoreCursorRef.current === cursor) return;
    const localGeneration = localGenerationRef.current;
    if (!isCurrent(localGeneration)) return;
    loadMoreCursorRef.current = cursor;
    setLoadingMore(true);
    try {
      const token = await getToken();
      if (!isCurrent(localGeneration)) return;
      if (!token) {
        setError("Missing session token");
        return;
      }
      const page = await fetchOrganizationMembers(token, {
        page_size: MEMBER_PAGE_SIZE,
        cursor,
      });
      if (!isCurrent(localGeneration)) return;
      setMembers((current) => dedupeMembers([...current, ...page.items]));
      setNextCursor(page.next_cursor);
    } catch (err) {
      if (!isCurrent(localGeneration)) return;
      setError(
        parseApiError(err, "Organization members could not be loaded.").message,
      );
    } finally {
      if (isCurrent(localGeneration)) {
        setLoadingMore(false);
        if (loadMoreCursorRef.current === cursor) {
          loadMoreCursorRef.current = null;
        }
      }
    }
  }

  const parsedDraft = parseLocalDateTimeInput(dueDraft);
  const draftError =
    dueDraft && !parsedDraft.ok ? localDateTimeMessage(parsedDraft.reason) : null;

  async function save() {
    if (
      saveInFlightRef.current ||
      saving ||
      !selectedUserId ||
      !parsedDraft.ok
    ) {
      return;
    }
    const localGeneration = localGenerationRef.current;
    if (!isCurrent(localGeneration)) {
      closeCurrentModal();
      return;
    }

    const proposedOwner = selectedUserId;
    const proposedDue = parsedDraft.iso;
    const immutableIntentItems = intent.items;
    saveInFlightRef.current = true;
    setSaving(true);
    setError(null);
    try {
      const token = await getToken();
      if (!isCurrent(localGeneration)) return;
      if (!token) {
        setError("Missing session token");
        return;
      }
      if (!isCurrent(localGeneration)) return;
      const response = await postBulkFollowUpEdit(token, {
        assigned_to_user_id: proposedOwner,
        follow_up_due_at: proposedDue,
        items: immutableIntentItems,
      });
      if (!isCurrent(localGeneration)) return;
      await onWriteSucceeded(intent, response);
      if (!isCurrent(localGeneration)) return;
      closeCurrentModal();
    } catch (err) {
      if (!isCurrent(localGeneration)) return;
      if (isTransportAmbiguousError(err)) {
        if (!isCurrent(localGeneration)) return;
        await onTransportUncertain(intent);
        if (!isCurrent(localGeneration)) return;
        return;
      }
      const parsed = parseApiError(err, UPDATE_FAILED);
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
      if (parsed.status === 404 || parsed.status === 409) {
        if (!isCurrent(localGeneration)) return;
        await onAuthoritativeConflict(intent);
        if (!isCurrent(localGeneration)) return;
        return;
      }
      setError(UPDATE_FAILED);
    } finally {
      if (isCurrent(localGeneration)) {
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
  const saveDisabled =
    pickerLoading || saving || !selectedUserId || !parsedDraft.ok;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="follow-up-bulk-edit-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="follow-up-bulk-edit-title" className="text-lg font-medium">
            Edit follow-up for selected findings
          </h3>
          <p className="mt-1 text-sm text-zinc-600">
            {intent.selectedCount} selected. The same owner and required due
            date will be applied to every selected finding.
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

        <label className="block text-sm text-zinc-700">
          <span className="text-zinc-500">New due date (required)</span>
          <input
            type="datetime-local"
            required
            value={dueDraft}
            disabled={saving}
            className="mt-1 w-full rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
            onChange={(event) => {
              setDueDraft(event.target.value);
              setError(null);
            }}
          />
        </label>
        <p className="text-xs text-zinc-600">{LOCAL_TIMEZONE_LABEL}</p>
        {parsedDraft.ok ? (
          <p className="text-sm text-zinc-700">
            {formatLocalDuePreview(parsedDraft.iso)}
          </p>
        ) : null}
        {draftError ? <p className="text-sm text-red-800">{draftError}</p> : null}

        {selectedUserId && parsedDraft.ok ? (
          <p className="text-sm text-zinc-700">
            Set {selectedLabel} as owner and update the due date for{" "}
            {intent.selectedCount} selected{" "}
            {intent.selectedCount === 1 ? "finding" : "findings"}?
          </p>
        ) : null}

        {error ? <p className="text-sm text-red-800">{error}</p> : null}

        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
            onClick={closeCurrentModal}
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
            {saving ? "Saving…" : "Edit selected follow-up"}
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

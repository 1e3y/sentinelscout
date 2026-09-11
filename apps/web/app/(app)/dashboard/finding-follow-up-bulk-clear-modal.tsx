"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState } from "react";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import {
  postBulkFollowUpClear,
  type BulkFollowUpClearIntent,
  type BulkFollowUpClearMode,
} from "@/lib/bulk-follow-up-clear";
import type { BulkFollowUpClearResponse } from "@/lib/api";

const UPDATE_FAILED = "Selected finding follow-up could not be cleared.";
const VALIDATION_FAILED = "Selected follow-up could not be cleared.";
const RATE_LIMITED = "Too many follow-up updates. Try again later.";

const MODE_COPY: Record<
  BulkFollowUpClearMode,
  { title: string; description: string }
> = {
  owner: {
    title: "Unassign selected findings",
    description: "Owner will be removed. Due dates will stay unchanged.",
  },
  due: {
    title: "Clear due dates for selected findings",
    description: "Due dates will be cleared. Owners will stay unchanged.",
  },
  both: {
    title: "Clear follow-up for selected findings",
    description: "Owners and due dates will be cleared.",
  },
};

function modeOf(intent: BulkFollowUpClearIntent): BulkFollowUpClearMode {
  if (intent.clear_owner && intent.clear_due) return "both";
  if (intent.clear_owner) return "owner";
  return "due";
}

type Props = {
  intent: BulkFollowUpClearIntent;
  isIntentCurrent: (intent: BulkFollowUpClearIntent) => boolean;
  onClose: (intent: BulkFollowUpClearIntent) => void;
  onWriteSucceeded: (
    intent: BulkFollowUpClearIntent,
    response: BulkFollowUpClearResponse,
  ) => Promise<void>;
  onAuthoritativeConflict: (intent: BulkFollowUpClearIntent) => Promise<void>;
  onTransportUncertain: (intent: BulkFollowUpClearIntent) => Promise<void>;
};

export function FindingFollowUpBulkClearModal({
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
  const saveInFlightRef = useRef(false);

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
    return () => {
      mountedRef.current = false;
      activeRef.current = false;
      localGenerationRef.current += 1;
    };
  }, [intent]);

  async function save() {
    if (saveInFlightRef.current || saving) {
      return;
    }
    const localGeneration = localGenerationRef.current;
    if (!isCurrent(localGeneration)) {
      closeCurrentModal();
      return;
    }

    const immutableIntentItems = intent.items;
    const clearOwner = intent.clear_owner;
    const clearDue = intent.clear_due;
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
      const response = await postBulkFollowUpClear(token, {
        clear_owner: clearOwner,
        clear_due: clearDue,
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
      if (parsed.status === 404 || parsed.status === 409) {
        if (!isCurrent(localGeneration)) return;
        await onAuthoritativeConflict(intent);
        if (!isCurrent(localGeneration)) return;
        return;
      }
      if (parsed.status === 429) {
        setError(parsed.message || RATE_LIMITED);
        return;
      }
      if (parsed.status === 422) {
        setError(parsed.message || VALIDATION_FAILED);
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

  const mode = modeOf(intent);
  const copy = MODE_COPY[mode];
  const findingWord = intent.selectedCount === 1 ? "finding" : "findings";

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="follow-up-bulk-clear-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="follow-up-bulk-clear-title" className="text-lg font-medium">
            {copy.title}
          </h3>
          <p className="mt-1 text-sm text-zinc-600">
            {intent.selectedCount} selected {findingWord}. {copy.description}
          </p>
        </div>

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
            disabled={saving}
            className="rounded-md border border-zinc-900 bg-zinc-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            onClick={() => {
              void save();
            }}
          >
            {saving ? "Saving…" : copy.title}
          </button>
        </div>
      </div>
    </div>
  );
}

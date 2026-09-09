"use client";

import { useAuth } from "@clerk/nextjs";
import { useRef, useState } from "react";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import { postBulkFollowUpDue } from "@/lib/bulk-follow-up-due";
import type {
  BulkFollowUpDueItem,
  BulkFollowUpDueResponse,
} from "@/lib/api";
import {
  LOCAL_TIMEZONE_LABEL,
  formatLocalDuePreview,
  localDateTimeMessage,
  parseLocalDateTimeInput,
} from "@/lib/datetime-local";

const UPDATE_FAILED = "Selected follow-up due dates could not be updated.";
const STALE_OWNER_API = "Assignee must be a current organization member";
const PROVIDER_UNAVAILABLE_API = "Failed to verify organization membership";
const STALE_OWNER =
  "One or more current finding owners are no longer eligible. Resolve ownership before changing due dates.";
const PROVIDER_UNAVAILABLE =
  "Organization membership could not be verified. Try again later.";

export type BulkFollowUpDueIntent = {
  selectedCount: number;
  items: BulkFollowUpDueItem[];
  submitGeneration: number;
  evaluationTime: string;
};

type Props = {
  intent: BulkFollowUpDueIntent;
  isSubmitCurrent: (generation: number) => boolean;
  onClose: () => void;
  onWriteSucceeded: (response: BulkFollowUpDueResponse) => Promise<void>;
  onAuthoritativeConflict: (message: string) => Promise<void>;
  onTransportUncertain: () => Promise<void>;
};

export function FindingFollowUpBulkDueModal({
  intent,
  isSubmitCurrent,
  onClose,
  onWriteSucceeded,
  onAuthoritativeConflict,
  onTransportUncertain,
}: Props) {
  const { getToken } = useAuth();
  const saveInFlightRef = useRef(false);
  const [dueDraft, setDueDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parsedDraft = parseLocalDateTimeInput(dueDraft);
  const draftError =
    dueDraft && !parsedDraft.ok ? localDateTimeMessage(parsedDraft.reason) : null;

  async function save() {
    if (
      saveInFlightRef.current ||
      saving ||
      !parsedDraft.ok ||
      !isSubmitCurrent(intent.submitGeneration)
    ) {
      if (!isSubmitCurrent(intent.submitGeneration)) onClose();
      return;
    }
    saveInFlightRef.current = true;
    setSaving(true);
    setError(null);
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
      const response = await postBulkFollowUpDue(token, {
        follow_up_due_at: parsedDraft.iso,
        items: intent.items,
      });
      await onWriteSucceeded(response);
    } catch (err) {
      if (isTransportAmbiguousError(err)) {
        await onTransportUncertain();
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
        await onAuthoritativeConflict(parsed.message);
        return;
      }
      setError(parsed.message);
    } finally {
      saveInFlightRef.current = false;
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="follow-up-bulk-due-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="follow-up-bulk-due-title" className="text-lg font-medium">
            Set due date for selected findings
          </h3>
          <p className="mt-1 text-sm text-zinc-600">
            {intent.selectedCount} selected. The same follow-up due date will be
            applied to each selected finding. Current owners will not change.
          </p>
        </div>

        <label className="block text-sm text-zinc-700">
          <span className="text-zinc-500">New due date</span>
          <input
            type="datetime-local"
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
        <p className="text-xs text-zinc-600">
          This changes follow-up due dates only. Current finding owners will not
          change.
        </p>

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
            disabled={saving || !parsedDraft.ok}
            onClick={() => {
              void save();
            }}
          >
            {saving ? "Saving…" : "Set due date for selected"}
          </button>
        </div>
      </div>
    </div>
  );
}

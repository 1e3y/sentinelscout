"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useRef, useState } from "react";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import {
  fetchFinding,
  type FindingFollowUpDueState,
} from "@/lib/api";
import {
  LOCAL_TIMEZONE_LABEL,
  dueInstantsEqual,
  formatLocalDateTimeInput,
  formatLocalDuePreview,
  localDateTimeMessage,
  parseLocalDateTimeInput,
} from "@/lib/datetime-local";
import {
  projectInlineDueDateSnapshot,
  snapshotsDueEqual,
  snapshotsOwnerEqual,
  type InlineDueDateSnapshot,
} from "@/lib/inline-due-date-snapshot";
import { organizationMemberLabel } from "@/lib/organization-member-label";
import { writeFindingFollowUpDueConditionally } from "@/lib/update-finding-follow-up-conditional";

const FINDING_READ_FAILED = "This finding could not be loaded.";
const DUE_UPDATE_FAILED = "Follow-up due date could not be updated.";
const TRANSPORT_UNCERTAIN =
  "We couldn't confirm whether the follow-up due date was updated. Refresh the finding before trying again.";
const RESOLVED_CLIENT = "This finding can no longer be updated.";
const OWNER_DRIFT =
  "The current finding owner changed. Review the latest owner before saving the due date.";
const DUE_DRIFT =
  "The follow-up due date changed. Review the latest date. Your proposed time was kept.";
const STALE_OWNER =
  "This assignee is no longer eligible. Resolve ownership before changing the due date.";
const PROVIDER_UNAVAILABLE =
  "Organization membership could not be verified. Try again later.";
const CONCURRENCY = "Finding follow-up changed. Refresh and try again.";
const RATE_LIMITED = "Too many follow-up updates. Try again later.";
const VALIDATION = "Enter a valid follow-up due date.";

export type DueDateIntent = {
  findingId: string;
  title: string;
  targetLabel: string;
  dueState: FindingFollowUpDueState;
};

type Props = {
  intent: DueDateIntent | null;
  onClose: () => void;
  onWriteSucceeded: () => Promise<void>;
  onAlreadyDue: () => Promise<void>;
  onResolvedConflict: () => void;
  onTransportUncertain: (currentDueLabel: string | null) => Promise<void>;
};

function formatDue(value: string | null): string {
  if (!value) return "No due date";
  return formatLocalDuePreview(value) || new Date(value).toLocaleString();
}

function mutationErrorCopy(err: unknown): string {
  const parsed = parseApiError(err, DUE_UPDATE_FAILED);
  if (parsed.status === 400) return STALE_OWNER;
  if (parsed.status === 502) return PROVIDER_UNAVAILABLE;
  if (parsed.status === 429) return parsed.message || RATE_LIMITED;
  if (parsed.status === 422) return parsed.message || VALIDATION;
  if (parsed.status === 409) {
    if (parsed.message === CONCURRENCY) return CONCURRENCY;
    return RESOLVED_CLIENT;
  }
  return parsed.message;
}

export function FindingFollowUpDueModal({
  intent,
  onClose,
  onWriteSucceeded,
  onAlreadyDue,
  onResolvedConflict,
  onTransportUncertain,
}: Props) {
  const { getToken } = useAuth();
  const generationRef = useRef(0);
  const saveInFlightRef = useRef(false);

  const [snapshot, setSnapshot] = useState<InlineDueDateSnapshot | null>(null);
  const [dueDraft, setDueDraft] = useState("");
  const [dirty, setDirty] = useState(false);
  const [findingLoading, setFindingLoading] = useState(true);
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

    async function open(current: DueDateIntent) {
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
        const next = projectInlineDueDateSnapshot(finding);
        setSnapshot(next);
        setDueDraft(
          next.follow_up_due_at
            ? formatLocalDateTimeInput(next.follow_up_due_at)
            : "",
        );
        setDirty(false);
        setFindingLoading(false);
        if (next.status === "resolved") {
          setMutationDisabled(true);
          setError(RESOLVED_CLIENT);
          onResolvedConflict();
        }
      } catch (err) {
        if (cancelled || generationRef.current !== generation) return;
        setFindingLoading(false);
        setReadError(parseApiError(err, FINDING_READ_FAILED).message);
      }
    }

    void open(intent);
    return () => {
      cancelled = true;
      generationRef.current += 1;
    };
  }, [intent, getToken, onResolvedConflict]);

  const parsedDraft = parseLocalDateTimeInput(dueDraft);
  const proposedIso = parsedDraft.ok ? parsedDraft.iso : null;

  async function save() {
    if (!intent || !snapshot || mutationDisabled) return;
    if (!dirty || !parsedDraft.ok || !proposedIso || saveInFlightRef.current) {
      return;
    }
    const generation = generationRef.current;
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
      const finding = await fetchFinding(token, intent.findingId);
      if (generationRef.current !== generation) return;
      const fresh = projectInlineDueDateSnapshot(finding);
      setSnapshot(fresh);

      if (fresh.status === "resolved") {
        setMutationDisabled(true);
        setError(RESOLVED_CLIENT);
        onResolvedConflict();
        return;
      }

      if (!snapshotsOwnerEqual(snapshot, fresh)) {
        setNotice(OWNER_DRIFT);
        return;
      }

      if (!snapshotsDueEqual(snapshot, fresh)) {
        setNotice(DUE_DRIFT);
        return;
      }

      if (dueInstantsEqual(proposedIso, fresh.follow_up_due_at)) {
        await onAlreadyDue();
        if (generationRef.current === generation) {
          onClose();
        }
        return;
      }

      const snapshotOwner = fresh.owner_user_id;
      const snapshotDue = fresh.follow_up_due_at;
      await writeFindingFollowUpDueConditionally(token, intent.findingId, {
        assigned_to_user_id: snapshotOwner,
        follow_up_due_at: proposedIso,
        expected_follow_up: {
          assigned_to_user_id: snapshotOwner,
          follow_up_due_at: snapshotDue,
        },
      });
      await onWriteSucceeded();
      if (generationRef.current === generation) {
        onClose();
      }
    } catch (err) {
      if (generationRef.current !== generation) return;
      if (isTransportAmbiguousError(err)) {
        let currentDueLabel: string | null = null;
        try {
          const token = await getToken();
          if (token) {
            const finding = await fetchFinding(token, intent.findingId);
            if (generationRef.current !== generation) return;
            const fresh = projectInlineDueDateSnapshot(finding);
            setSnapshot(fresh);
            currentDueLabel = formatDue(fresh.follow_up_due_at);
          }
        } catch {
          // Fresh state is optional after a lost response.
        }
        setError(TRANSPORT_UNCERTAIN);
        await onTransportUncertain(currentDueLabel);
        return;
      }
      const parsed = parseApiError(err, DUE_UPDATE_FAILED);
      if (parsed.status === 409 && parsed.message === CONCURRENCY) {
        try {
          const token = await getToken();
          if (token) {
            const finding = await fetchFinding(token, intent.findingId);
            if (generationRef.current !== generation) return;
            setSnapshot(projectInlineDueDateSnapshot(finding));
          }
        } catch {
          // Keep the concurrency copy even if refresh fails.
        }
        setNotice(CONCURRENCY);
        setError(null);
        return;
      }
      setError(mutationErrorCopy(err));
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
  const draftError =
    dirty && !parsedDraft.ok ? localDateTimeMessage(parsedDraft.reason) : null;
  const saveDisabled =
    mutationDisabled ||
    findingLoading ||
    saving ||
    !snapshot ||
    !dirty ||
    !parsedDraft.ok;

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 px-4">
      <div
        role="dialog"
        aria-labelledby="follow-up-due-title"
        className="w-full max-w-lg space-y-4 rounded-md border border-zinc-200 bg-white p-5 shadow-lg"
      >
        <div>
          <h3 id="follow-up-due-title" className="text-lg font-medium">
            {intent.dueState === "no_due_date"
              ? "Set due date"
              : "Change due date"}
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
          <div className="space-y-2">
            <label className="block text-sm text-zinc-700">
              <span className="text-zinc-500">New due date</span>
              <input
                type="datetime-local"
                value={dueDraft}
                disabled={saving}
                className="mt-1 w-full rounded-md border border-zinc-300 px-3 py-1.5 text-sm"
                onChange={(event) => {
                  setDueDraft(event.target.value);
                  setDirty(true);
                  setNotice(null);
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
            {draftError ? (
              <p className="text-sm text-red-800">{draftError}</p>
            ) : null}
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
            {saving ? "Saving…" : "Save due date"}
          </button>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useRef, useState } from "react";
import { FindingActivityTimeline } from "./finding-activity-timeline";
import { isTransportAmbiguousError, parseApiError } from "@/lib/api-error";
import {
  fetchFinding,
  fetchFindingFollowUpReminderHistory,
  fetchFindingFollowUpReminderStatus,
  fetchFindingTimeline,
  fetchOrganizationMembers,
  markFindingReadyForRetest,
  queueFindingRetest,
  recordFindingRemediation,
  startFindingRemediation,
  updateFindingFollowUpConditionally,
  type FindingFollowUp,
  type FindingFollowUpReminderHistoryItem,
  type FindingFollowUpReminderStatus,
  type FindingResponse,
  type FindingTimelineResponse,
  type OrganizationMember,
  type ReminderCustomerState,
} from "@/lib/api";
import {
  LOCAL_TIMEZONE_LABEL,
  formatLocalDateTimeInput,
  formatLocalDuePreview,
  localDateTimeMessage,
  parseLocalDateTimeInput,
} from "@/lib/datetime-local";

type Props = {
  organizationId: string | null;
  findingId: string | null;
  onFindingChanged: () => void;
};

type RequestIdentity = {
  organizationId: string | null;
  findingId: string | null;
  generation: number;
};

const FOLLOW_UP_UPDATE_FAILED = "Failed to save follow-up";
const FOLLOW_UP_CHANGED = "Finding follow-up changed. Refresh and try again.";
const RESOLVED_API =
  "Resolved findings cannot change follow-up ownership or due date";
const RESOLVED_CLIENT = "This finding can no longer be updated.";
const STALE_OWNER_API = "Assignee must be a current organization member";
const STALE_OWNER =
  "This assignee is no longer eligible. Choose a current organization member.";
const PROVIDER_UNAVAILABLE_API = "Failed to verify organization membership";
const PROVIDER_UNAVAILABLE =
  "Organization membership could not be verified. Try again later.";
const TRANSPORT_UNCERTAIN =
  "We couldn't confirm whether the follow-up was saved. The current state was refreshed; review it before trying again.";

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function statusLabel(status: string): string {
  switch (status) {
    case "in_progress":
      return "In progress";
    case "ready_for_retest":
      return "Ready for retest";
    case "resolved":
      return "Resolved";
    default:
      return "Open";
  }
}

function dueWording(
  dueAt: string | null | undefined,
  status: string,
): string | null {
  if (!dueAt) return null;
  if (status === "resolved") return null;
  const due = new Date(dueAt).getTime();
  if (Number.isNaN(due)) return null;
  return due <= Date.now() ? "Overdue" : "Upcoming";
}

function reminderStateLabel(state: ReminderCustomerState): string {
  switch (state) {
    case "disabled":
      return "Follow-up reminders are turned off for this organization.";
    case "not_applicable":
      return "No follow-up reminder applies to this Finding.";
    case "generation_unavailable":
      return "Reminder scheduling is unavailable for this older follow-up state.";
    case "scheduled_for_future":
      return "Reminder will become eligible at the due time.";
    case "awaiting_discovery":
      return "Waiting for due reminder scheduling.";
    case "pending":
      return "Reminder pending.";
    case "processing":
      return "Reminder is being sent.";
    case "retrying":
      return "Delivery retry pending.";
    case "delivered":
      return "Reminder delivered.";
    case "skipped":
      return "Reminder safely skipped.";
    case "dead":
      return "Delivery could not be completed.";
  }
}

/**
 * Detail and workflow actions for one finding. The organization-scoped
 * collection lives in FindingsInboxPanel; this panel never lists findings, so
 * the dashboard cannot show two lists with different org scopes.
 */
export function FindingsPanel({
  organizationId,
  findingId,
  onFindingChanged,
}: Props) {
  const { getToken } = useAuth();
  const mountedRef = useRef(false);
  const organizationIdRef = useRef<string | null>(organizationId);
  const findingIdRef = useRef<string | null>(findingId);
  const generationRef = useRef(0);
  const paginationCursorRef = useRef<string | null>(null);
  const [selected, setSelected] = useState<FindingResponse | null>(null);
  const [timeline, setTimeline] = useState<FindingTimelineResponse | null>(null);
  const [remediationSummary, setRemediationSummary] = useState("");
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [ownerDraft, setOwnerDraft] = useState("");
  const [dueDraft, setDueDraft] = useState("");
  const [dueDirty, setDueDirty] = useState(false);
  const [reminderStatus, setReminderStatus] =
    useState<FindingFollowUpReminderStatus | null>(null);
  const [reminderHistory, setReminderHistory] = useState<
    FindingFollowUpReminderHistoryItem[]
  >([]);
  const [showReminderHistory, setShowReminderHistory] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const retestActive = timeline?.current_retest_state === "in_progress";

  const isIdentityCurrent = useCallback((identity: RequestIdentity) => {
    return (
      mountedRef.current &&
      organizationIdRef.current === identity.organizationId &&
      findingIdRef.current === identity.findingId &&
      generationRef.current === identity.generation
    );
  }, []);

  const resetDrafts = useCallback((finding: FindingResponse) => {
    setOwnerDraft(finding.follow_up?.owner?.user_id ?? "");
    setDueDraft(
      finding.follow_up?.follow_up_due_at
        ? formatLocalDateTimeInput(finding.follow_up.follow_up_due_at)
        : "",
    );
    setDueDirty(false);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
    };
  }, []);

  useEffect(() => {
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    organizationIdRef.current = organizationId;
    findingIdRef.current = findingId;
    paginationCursorRef.current = null;
    const identity: RequestIdentity = {
      organizationId,
      findingId,
      generation,
    };

    // This effect is the identity boundary for externally selected context.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSelected(null);
    setTimeline(null);
    setMembers([]);
    setReminderStatus(null);
    setReminderHistory([]);
    setShowReminderHistory(false);
    setRemediationSummary("");
    setOwnerDraft("");
    setDueDraft("");
    setDueDirty(false);
    setMessage(null);
    setNotice(null);
    setError(null);
    setPending(false);

    if (!organizationId || !findingId) {
      return () => {
        if (generationRef.current === generation) {
          generationRef.current += 1;
        }
      };
    }

    setPending(true);
    void (async () => {
      try {
        const token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        const [finding, activity, memberPage, reminder] = await Promise.all([
          fetchFinding(token, findingId),
          fetchFindingTimeline(token, findingId),
          fetchOrganizationMembers(token, { page_size: 100 }),
          fetchFindingFollowUpReminderStatus(token, findingId),
        ]);
        if (!isIdentityCurrent(identity)) return;
        setSelected(finding);
        setTimeline(activity);
        setMembers(memberPage.items);
        setReminderStatus(reminder);
        resetDrafts(finding);
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        setError(err instanceof Error ? err.message : "Failed to load finding");
      } finally {
        if (isIdentityCurrent(identity)) {
          setPending(false);
        }
      }
    })();

    return () => {
      if (generationRef.current === generation) {
        generationRef.current += 1;
      }
      paginationCursorRef.current = null;
    };
  }, [
    findingId,
    getToken,
    isIdentityCurrent,
    organizationId,
    resetDrafts,
  ]);

  function identityForFinding(id: string): RequestIdentity | null {
    const identity = {
      organizationId: organizationIdRef.current,
      findingId: id,
      generation: generationRef.current,
    };
    return isIdentityCurrent(identity) ? identity : null;
  }

  async function reconcileCurrent(
    identity: RequestIdentity,
    token: string,
    retainDrafts: boolean,
  ): Promise<boolean> {
    try {
      const [finding, activity, reminder] = await Promise.all([
        fetchFinding(token, identity.findingId!),
        fetchFindingTimeline(token, identity.findingId!),
        fetchFindingFollowUpReminderStatus(token, identity.findingId!),
      ]);
      if (!isIdentityCurrent(identity)) return false;
      setSelected(finding);
      setTimeline(activity);
      setReminderStatus(reminder);
      setReminderHistory([]);
      setShowReminderHistory(false);
      if (!retainDrafts) resetDrafts(finding);
      if (!isIdentityCurrent(identity)) return false;
      onFindingChanged();
      return true;
    } catch {
      return false;
    }
  }

  function runAction(
    action: (token: string, id: string) => Promise<unknown>,
    successMessage: string,
    failureMessage: string,
  ) {
    if (!selected) return;
    const identity = identityForFinding(selected.id);
    if (!identity) return;
    setPending(true);
    setError(null);
    setNotice(null);
    setMessage(null);
    void (async () => {
      try {
        const token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        await action(token, identity.findingId!);
        if (!isIdentityCurrent(identity)) return;
        const [finding, activity] = await Promise.all([
          fetchFinding(token, identity.findingId!),
          fetchFindingTimeline(token, identity.findingId!),
        ]);
        if (!isIdentityCurrent(identity)) return;
        setSelected(finding);
        setTimeline(activity);
        resetDrafts(finding);
        setMessage(successMessage);
        if (!isIdentityCurrent(identity)) return;
        onFindingChanged();
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        setError(err instanceof Error ? err.message : failureMessage);
      } finally {
        if (isIdentityCurrent(identity)) {
          setPending(false);
        }
      }
    })();
  }

  function saveRemediationRevision() {
    if (!selected) return;
    const identity = identityForFinding(selected.id);
    if (!identity) return;
    const summary = remediationSummary.trim();
    if (!summary) {
      setError("Remediation summary is required");
      return;
    }
    setPending(true);
    setError(null);
    setNotice(null);
    setMessage(null);
    void (async () => {
      try {
        const token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        await recordFindingRemediation(token, identity.findingId!, summary);
        if (!isIdentityCurrent(identity)) return;
        const [finding, activity] = await Promise.all([
          fetchFinding(token, identity.findingId!),
          fetchFindingTimeline(token, identity.findingId!),
        ]);
        if (!isIdentityCurrent(identity)) return;
        setSelected(finding);
        setTimeline(activity);
        resetDrafts(finding);
        setRemediationSummary("");
        setMessage("Remediation revision recorded");
        if (!isIdentityCurrent(identity)) return;
        onFindingChanged();
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        setError(
          err instanceof Error ? err.message : "Failed to record remediation",
        );
      } finally {
        if (isIdentityCurrent(identity)) {
          setPending(false);
        }
      }
    })();
  }

  function saveFollowUp() {
    if (!selected || selected.status === "resolved") return;
    const identity = identityForFinding(selected.id);
    if (!identity) return;
    const authoritativeOwner = selected.follow_up?.owner?.user_id ?? null;
    const authoritativeDue = selected.follow_up?.follow_up_due_at ?? null;
    let desiredDue = authoritativeDue;
    if (dueDirty) {
      if (!dueDraft) {
        desiredDue = null;
      } else {
        const parsed = parseLocalDateTimeInput(dueDraft);
        if (!parsed.ok) {
          setError(localDateTimeMessage(parsed.reason));
          setNotice(null);
          setMessage(null);
          return;
        }
        desiredDue = parsed.iso;
      }
    }

    setPending(true);
    setError(null);
    setNotice(null);
    setMessage(null);
    void (async () => {
      let token: string | null = null;
      let writeStarted = false;
      let writtenFollowUp: FindingFollowUp | null = null;
      try {
        token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        writeStarted = true;
        writtenFollowUp = await updateFindingFollowUpConditionally(
          token,
          identity.findingId!,
          {
            assigned_to_user_id: ownerDraft || null,
            follow_up_due_at: desiredDue,
            expected_follow_up: {
              assigned_to_user_id: authoritativeOwner,
              follow_up_due_at: authoritativeDue,
            },
          },
        );
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        if (writeStarted && isTransportAmbiguousError(err)) {
          if (token) {
            await reconcileCurrent(identity, token, true);
          }
          if (!isIdentityCurrent(identity)) return;
          setError(null);
          setNotice(TRANSPORT_UNCERTAIN);
          return;
        }

        const parsed = parseApiError(err, FOLLOW_UP_UPDATE_FAILED);
        if (parsed.status === 409 && parsed.message === FOLLOW_UP_CHANGED) {
          if (token) {
            await reconcileCurrent(identity, token, true);
          }
          if (!isIdentityCurrent(identity)) return;
          setError(null);
          setNotice(FOLLOW_UP_CHANGED);
          return;
        }
        if (parsed.status === 409 && parsed.message === RESOLVED_API) {
          if (token) {
            await reconcileCurrent(identity, token, false);
          }
          if (!isIdentityCurrent(identity)) return;
          setError(RESOLVED_CLIENT);
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

      if (!token || !writtenFollowUp || !isIdentityCurrent(identity)) return;
      const authoritativeFollowUp = writtenFollowUp;
      setSelected((current) => {
        if (!current || !isIdentityCurrent(identity)) return current;
        return { ...current, follow_up: authoritativeFollowUp };
      });
      setOwnerDraft(authoritativeFollowUp.owner?.user_id ?? "");
      setDueDraft(
        authoritativeFollowUp.follow_up_due_at
          ? formatLocalDateTimeInput(authoritativeFollowUp.follow_up_due_at)
          : "",
      );
      setDueDirty(false);
      setReminderHistory([]);
      setShowReminderHistory(false);
      setMessage("Follow-up saved");
      if (!isIdentityCurrent(identity)) return;
      onFindingChanged();

      const [activityResult, reminderResult] = await Promise.allSettled([
        fetchFindingTimeline(token, identity.findingId!),
        fetchFindingFollowUpReminderStatus(token, identity.findingId!),
      ]);
      if (!isIdentityCurrent(identity)) return;
      if (activityResult.status === "fulfilled") {
        setTimeline(activityResult.value);
      }
      if (reminderResult.status === "fulfilled") {
        setReminderStatus(reminderResult.value);
      }
      if (
        activityResult.status === "rejected" ||
        reminderResult.status === "rejected"
      ) {
        setError(
          "Follow-up was saved, but related detail could not be refreshed.",
        );
      }
    })().finally(() => {
      if (isIdentityCurrent(identity)) {
        setPending(false);
      }
    });
  }

  function loadReminderHistory() {
    if (!selected) return;
    const identity = identityForFinding(selected.id);
    if (!identity) return;
    setPending(true);
    setError(null);
    setNotice(null);
    void (async () => {
      try {
        const token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        const history = await fetchFindingFollowUpReminderHistory(
          token,
          identity.findingId!,
          { page_size: 20 },
        );
        if (!isIdentityCurrent(identity)) return;
        setReminderHistory(history.items);
        setShowReminderHistory(true);
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        setError(
          err instanceof Error ? err.message : "Failed to load reminder history",
        );
      } finally {
        if (isIdentityCurrent(identity)) {
          setPending(false);
        }
      }
    })();
  }

  function loadMoreActivity() {
    if (!selected || !timeline?.next_cursor) return;
    const identity = identityForFinding(selected.id);
    if (!identity) return;
    const cursor = timeline.next_cursor;
    if (paginationCursorRef.current === cursor) return;
    paginationCursorRef.current = cursor;
    setPending(true);
    setError(null);
    setNotice(null);
    void (async () => {
      try {
        const token = await getToken();
        if (!isIdentityCurrent(identity)) return;
        if (!token) {
          setError("Missing session token");
          return;
        }
        const next = await fetchFindingTimeline(token, identity.findingId!, {
          cursor,
        });
        if (!isIdentityCurrent(identity)) return;
        setTimeline((current) => {
          if (!isIdentityCurrent(identity)) return current;
          return current
            ? {
                ...next,
                events: [...current.events, ...next.events],
              }
            : next;
        });
      } catch (err) {
        if (!isIdentityCurrent(identity)) return;
        setError(
          err instanceof Error ? err.message : "Failed to load finding activity",
        );
      } finally {
        if (
          isIdentityCurrent(identity) &&
          paginationCursorRef.current === cursor
        ) {
          paginationCursorRef.current = null;
          setPending(false);
        }
      }
    })();
  }

  const remediationCharacterCount = Array.from(remediationSummary).length;
  const parsedDueDraft = dueDraft
    ? parseLocalDateTimeInput(dueDraft)
    : null;
  const dueDraftError =
    dueDirty && parsedDueDraft && !parsedDueDraft.ok
      ? localDateTimeMessage(parsedDueDraft.reason)
      : null;
  const remediationCanSave =
    remediationSummary.trim().length > 0 &&
    remediationCharacterCount <= 4000 &&
    selected?.status !== "resolved";
  const readyForRetestBlocked =
    selected?.status === "in_progress" &&
    (timeline?.remediation_revision_count ?? 0) === 0;

  return (
    <section className="space-y-4" aria-labelledby="finding-detail-heading">
      <div>
        <h2 id="finding-detail-heading" className="text-lg font-medium">
          Finding detail
        </h2>
        <p className="text-sm text-zinc-600">
          Evidence, provenance and remediation workflow for the finding selected
          above. Resolution only after a passing retest.
        </p>
      </div>

      {error ? (
        <p
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
          {message}
        </p>
      ) : null}
      {notice ? (
        <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          {notice}
        </p>
      ) : null}

      {!selected ? (
        <p className="text-sm text-zinc-600">
          Select a finding from Current Findings to see its evidence and
          remediation workflow.
        </p>
      ) : (
        <div className="space-y-4 rounded-md border border-zinc-200 bg-white p-4 text-sm">
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-wide text-zinc-500">
              Evidence-supported
            </p>
            <h3 className="text-base font-medium">{selected.title}</h3>
          </div>

          <dl className="grid gap-2 text-zinc-700">
            <div>
              <dt className="text-zinc-500">Severity</dt>
              <dd className="font-mono text-xs">{selected.severity}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Affected asset</dt>
              <dd className="font-mono text-xs break-all">
                {selected.asset_hostname ?? selected.asset_id}
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Status</dt>
              <dd>{statusLabel(selected.status)}</dd>
            </div>
            {selected.status === "resolved" ? (
              <div>
                <dt className="text-zinc-500">Resolved at</dt>
                <dd>{formatTime(selected.resolved_at)}</dd>
              </div>
            ) : null}
            <div>
              <dt className="text-zinc-500">Business impact</dt>
              <dd>{selected.business_impact}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Remediation guidance</dt>
              <dd>{selected.remediation_guidance}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Created</dt>
              <dd>{formatTime(selected.created_at)}</dd>
            </div>
          </dl>

          {selected.provenance ? (
            <div className="space-y-2 border-t border-zinc-100 pt-4">
              <h4 className="text-sm font-medium tracking-wide text-zinc-800">
                PROVENANCE
              </h4>
              <p className="font-mono text-xs text-zinc-600">
                {(selected.provenance.observation_ids[0]
                  ? "Observation"
                  : "Observation (none)") +
                  " → Candidate → Safe validation → Finding" +
                  (selected.provenance.retest_attempt_id ? " → Retest" : "") +
                  (selected.status === "resolved" ? " → Resolved" : "")}
              </p>
              <dl className="grid gap-2 text-xs text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Observation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.observation_ids.length > 0
                      ? selected.provenance.observation_ids.join(", ")
                      : "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Candidate</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.candidate_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Safe validation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.validation_attempt_id ?? "—"}
                    {selected.provenance.validation_method
                      ? ` · ${selected.provenance.validation_method}`
                      : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Finding</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.finding_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Asset / Operation</dt>
                  <dd className="font-mono break-all">
                    {selected.provenance.asset_id} ·{" "}
                    {selected.provenance.operation_id}
                  </dd>
                </div>
                {selected.provenance.retest_attempt_id ? (
                  <div>
                    <dt className="text-zinc-500">Retest</dt>
                    <dd className="font-mono break-all">
                      {selected.provenance.retest_attempt_id}
                    </dd>
                  </div>
                ) : null}
              </dl>
            </div>
          ) : null}

          <div className="space-y-3 border-t border-zinc-100 pt-4">
            <div>
              <h4 className="text-sm font-medium text-zinc-800">Follow-up</h4>
              <p className="text-xs text-zinc-600">
                Optional owner and due date for operational follow-up. Not a
                severity SLA and not verification.
              </p>
            </div>
            {selected.status === "resolved" ? (
              <dl className="grid gap-2 text-xs text-zinc-700 sm:grid-cols-2">
                <div>
                  <dt className="text-zinc-500">Owner</dt>
                  <dd>
                    {selected.follow_up?.owner
                      ? selected.follow_up.owner.current_member
                        ? (selected.follow_up.owner.display_name ??
                          "Organization member")
                        : `${selected.follow_up.owner.display_name ?? "Organization member"} (no longer a member)`
                      : "Unassigned"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Due</dt>
                  <dd>
                    {formatTime(selected.follow_up?.follow_up_due_at)}
                  </dd>
                </div>
              </dl>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2 rounded-md border border-zinc-200 bg-zinc-50 p-3 sm:col-span-2">
                  <h5 className="text-xs font-medium text-zinc-800">
                    Current server state
                  </h5>
                  <dl className="grid gap-2 text-xs text-zinc-700 sm:grid-cols-2">
                    <div>
                      <dt className="text-zinc-500">Current owner</dt>
                      <dd>
                        {selected.follow_up?.owner
                          ? selected.follow_up.owner.current_member
                            ? (selected.follow_up.owner.display_name ??
                              "Organization member")
                            : `${selected.follow_up.owner.display_name ?? "Organization member"} (no longer a member)`
                          : "Unassigned"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Current due</dt>
                      <dd>
                        {selected.follow_up?.follow_up_due_at
                          ? formatTime(selected.follow_up.follow_up_due_at)
                          : "No due date"}
                      </dd>
                    </div>
                  </dl>
                </div>
                <label className="text-xs text-zinc-700">
                  <span className="text-zinc-500">Proposed owner</span>
                  <select
                    className="mt-1 w-full rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                    value={ownerDraft}
                    disabled={pending}
                    onChange={(event) => {
                      setOwnerDraft(event.target.value);
                      setError(null);
                      setNotice(null);
                      setMessage(null);
                    }}
                  >
                    <option value="">Unassigned</option>
                    {members.map((member) => (
                      <option key={member.user_id} value={member.user_id}>
                        {member.display_name ?? "Organization member"}
                      </option>
                    ))}
                    {selected.follow_up?.owner &&
                    !selected.follow_up.owner.current_member &&
                    !members.some(
                      (member) =>
                        member.user_id === selected.follow_up?.owner?.user_id,
                    ) ? (
                      <option value={selected.follow_up.owner.user_id}>
                        {(selected.follow_up.owner.display_name ??
                          "Organization member") + " (no longer a member)"}
                      </option>
                    ) : null}
                  </select>
                </label>
                <label className="text-xs text-zinc-700">
                  <span className="text-zinc-500">Proposed due date</span>
                  <input
                    type="datetime-local"
                    className="mt-1 w-full rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                    value={dueDraft}
                    disabled={pending}
                    onChange={(event) => {
                      setDueDraft(event.target.value);
                      setDueDirty(true);
                      setError(null);
                      setNotice(null);
                      setMessage(null);
                    }}
                  />
                  <span className="mt-1 block text-zinc-500">
                    {LOCAL_TIMEZONE_LABEL}
                  </span>
                  {parsedDueDraft?.ok ? (
                    <span className="mt-1 block text-zinc-700">
                      {formatLocalDuePreview(parsedDueDraft.iso)}
                    </span>
                  ) : null}
                  {dueDraftError ? (
                    <span className="mt-1 block text-red-700">
                      {dueDraftError}
                    </span>
                  ) : null}
                </label>
                <div className="sm:col-span-2">
                  {dueWording(
                    selected.follow_up?.follow_up_due_at,
                    selected.status,
                  ) ? (
                    <p className="mb-2 text-xs text-zinc-600">
                      Current due state:{" "}
                      {dueWording(
                        selected.follow_up?.follow_up_due_at,
                        selected.status,
                      )}
                    </p>
                  ) : null}
                  <button
                    type="button"
                    className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm disabled:opacity-50"
                    disabled={pending || Boolean(dueDraftError)}
                    onClick={saveFollowUp}
                  >
                    Save follow-up
                  </button>
                </div>
              </div>
            )}
          </div>

          {reminderStatus ? (
            <div className="space-y-3 border-t border-zinc-100 pt-4">
              <div>
                <h4 className="text-sm font-medium text-zinc-800">
                  Follow-up reminder
                </h4>
                <p className="text-xs text-zinc-600">
                  Read-only delivery status for the current follow-up. Not
                  verification and not Finding activity history.
                </p>
              </div>
              <dl className="grid gap-2 text-xs text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Status</dt>
                  <dd>{reminderStateLabel(reminderStatus.state)}</dd>
                </div>
                {reminderStatus.state === "scheduled_for_future" &&
                reminderStatus.current_generation ? (
                  <div>
                    <dt className="text-zinc-500">Eligible at</dt>
                    <dd>
                      {formatTime(reminderStatus.current_generation.due_at)}
                    </dd>
                  </div>
                ) : null}
                {reminderStatus.state === "pending" &&
                !reminderStatus.email_delivery_enabled ? (
                  <div>
                    <dt className="text-zinc-500">Delivery</dt>
                    <dd>Email delivery is temporarily paused.</dd>
                  </div>
                ) : null}
                {reminderStatus.reminder?.delivered_at ? (
                  <div>
                    <dt className="text-zinc-500">Delivered</dt>
                    <dd>
                      {formatTime(reminderStatus.reminder.delivered_at)}
                    </dd>
                  </div>
                ) : null}
                {reminderStatus.reminder?.safe_reason_label ? (
                  <div>
                    <dt className="text-zinc-500">Explanation</dt>
                    <dd>{reminderStatus.reminder.safe_reason_label}</dd>
                  </div>
                ) : null}
              </dl>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-xs disabled:opacity-50"
                  disabled={pending}
                  onClick={loadReminderHistory}
                >
                  View reminder history
                </button>
              </div>
              {showReminderHistory ? (
                reminderHistory.length === 0 ? (
                  <p className="text-xs text-zinc-600">
                    No reminder delivery records yet.
                  </p>
                ) : (
                  <ul className="space-y-2 text-xs text-zinc-700">
                    {reminderHistory.map((item, index) => (
                      <li
                        key={`${item.created_at}-${item.state}-${index}`}
                        className="rounded-md border border-zinc-100 px-3 py-2"
                      >
                        <p className="font-medium">
                          {item.state.replaceAll("_", " ")}
                        </p>
                        <p className="text-zinc-600">
                          Due {formatTime(item.due_at)} · Created{" "}
                          {formatTime(item.created_at)}
                          {item.delivered_at
                            ? ` · Delivered ${formatTime(item.delivered_at)}`
                            : ""}
                        </p>
                        {item.owner ? (
                          <p className="text-zinc-600">
                            Owner:{" "}
                            {item.owner.display_name ?? "Organization member"}
                          </p>
                        ) : null}
                        {item.safe_reason_label ? (
                          <p className="text-zinc-600">
                            {item.safe_reason_label}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )
              ) : null}
            </div>
          ) : null}

          {timeline ? (
            <FindingActivityTimeline
              timeline={timeline}
              pending={pending}
              onLoadMore={loadMoreActivity}
            />
          ) : null}

          <div className="space-y-3 border-t border-zinc-100 pt-4">
            <div>
              <h4 className="text-sm font-medium text-zinc-800">
                Remediation record
              </h4>
              <p className="text-xs text-zinc-600">
                Customer-recorded remediation describes work performed; it is not
                verification. Only a passing retest confirms the condition is no
                longer present.
              </p>
            </div>

            <p className="text-xs text-zinc-500">
              {timeline?.remediation_revision_count
                ? `${timeline.remediation_revision_count} remediation revision${
                    timeline.remediation_revision_count === 1 ? "" : "s"
                  } recorded. Full history appears above.`
                : "No remediation has been recorded."}
            </p>

            {selected.status !== "resolved" ? (
              <div className="space-y-2">
                <label className="block text-xs font-medium text-zinc-700">
                  Record what changed
                  <textarea
                    value={remediationSummary}
                    disabled={pending}
                    rows={5}
                    className="mt-1 block w-full rounded-md border border-zinc-300 p-2 text-sm disabled:opacity-50"
                    onChange={(event) => setRemediationSummary(event.target.value)}
                  />
                </label>
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <p className="text-zinc-500">
                    Do not include passwords, API keys, tokens, or other secrets.
                  </p>
                  <p
                    className={
                      remediationCharacterCount > 4000
                        ? "text-red-700"
                        : "text-zinc-500"
                    }
                  >
                    {remediationCharacterCount}/4000
                  </p>
                </div>
                <button
                  type="button"
                  disabled={pending || !remediationCanSave}
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                  onClick={saveRemediationRevision}
                >
                  Record remediation
                </button>
              </div>
            ) : (
              <p className="text-xs text-zinc-500">
                Resolved findings cannot receive new remediation revisions.
              </p>
            )}
          </div>

          <div className="flex flex-wrap gap-2">
            {selected.status === "open" ? (
              <button
                type="button"
                disabled={pending}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                onClick={() =>
                  runAction(
                    startFindingRemediation,
                    "Remediation started.",
                    "Failed to start remediation",
                  )
                }
              >
                Start Remediation
              </button>
            ) : null}
            {selected.status === "in_progress" ? (
              <div>
                <button
                  type="button"
                  disabled={pending || readyForRetestBlocked}
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                  onClick={() =>
                    runAction(
                      markFindingReadyForRetest,
                      "Marked ready for retest.",
                      "Failed to mark ready for retest",
                    )
                  }
                >
                  Mark Ready for Retest
                </button>
                {readyForRetestBlocked ? (
                  <p className="mt-1 text-xs text-zinc-500">
                    Record what you changed before requesting a retest.
                  </p>
                ) : null}
              </div>
            ) : null}
            {selected.status === "ready_for_retest" ? (
              <button
                type="button"
                disabled={pending || retestActive}
                className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                onClick={() =>
                  runAction(
                    queueFindingRetest,
                    "Safe retest queued. Worker will recheck the original observable condition.",
                    "Failed to queue retest",
                  )
                }
              >
                {retestActive ? "Retest in progress" : "Run Retest"}
              </button>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}

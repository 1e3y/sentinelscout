"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchAuditEvents,
  type OrganizationAuditAction,
  type OrganizationAuditResourceKind,
  type OrganizationAuditRow,
  type OrganizationAuditEventsResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function actorLabel(row: OrganizationAuditRow): string {
  if (row.actor.kind === "system") return "System";
  if (row.actor.kind === "unavailable_user") {
    return row.actor.user_id
      ? `Unavailable user · ${row.actor.user_id.slice(0, 8)}…`
      : "Unavailable user";
  }
  return row.actor.display_name ?? row.actor.user_id?.slice(0, 8) ?? "Member";
}

function detailSummary(row: OrganizationAuditRow): string | null {
  const detail = row.detail;
  if (!detail) return null;
  const parts: string[] = [];
  for (const [key, value] of Object.entries(detail)) {
    if (key === "kind" || value == null || value === "") continue;
    parts.push(`${key}: ${String(value)}`);
  }
  return parts.length ? parts.join(" · ") : null;
}

export function AuditPanel({ enabled, isAdmin }: Props) {
  const { getToken } = useAuth();
  const [data, setData] = useState<OrganizationAuditEventsResponse | null>(null);
  const [action, setAction] = useState<OrganizationAuditAction | "">("");
  const [resourceType, setResourceType] = useState<
    OrganizationAuditResourceKind | ""
  >("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function refresh(nextCursor: string | null = null) {
    if (!enabled || !isAdmin) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const next = await fetchAuditEvents(token, {
          page_size: 20,
          cursor: nextCursor ?? undefined,
          action: action || undefined,
          resource_type: resourceType || undefined,
        });
        setData(next);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load audit events",
        );
      }
    });
  }

  useEffect(() => {
    refresh(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, isAdmin, action, resourceType]);

  if (!enabled) return null;

  if (!isAdmin) {
    return (
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Audit trail</h2>
        <p className="text-sm text-zinc-600">
          Organization admins can review administrative and workflow audit
          history for this organization.
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h2 className="text-lg font-medium">Audit trail</h2>
        <p className="text-sm text-zinc-600">
          Read-only history of administrative and workflow actions. Delivery
          email history is in Notification deliveries.
        </p>
      </div>

      <div className="flex flex-wrap gap-3 text-sm">
        <label className="flex items-center gap-2">
          <span className="text-zinc-500">Action</span>
          <select
            className="rounded border border-zinc-300 px-2 py-1"
            value={action}
            onChange={(event) =>
              setAction(event.target.value as OrganizationAuditAction | "")
            }
          >
            <option value="">All</option>
            <option value="target_created">Target created</option>
            <option value="target_verified">Target verified</option>
            <option value="target_scope_changed">Target scope changed</option>
            <option value="assessment_created">Assessment created</option>
            <option value="assessment_completed">Assessment completed</option>
            <option value="monitoring_changed">Monitoring changed</option>
            <option value="notification_settings_changed">
              Notification settings
            </option>
            <option value="finding_created">Finding created</option>
            <option value="finding_follow_up_changed">Follow-up changed</option>
            <option value="remediation_started">Remediation started</option>
            <option value="ready_for_retest">Ready for retest</option>
            <option value="retest_requested">Retest requested</option>
            <option value="finding_resolved">Finding resolved</option>
            <option value="report_generated">Report generated</option>
            <option value="report_share_created">Share created</option>
            <option value="report_share_revoked">Share revoked</option>
            <option value="organization_member_role_changed">
              Member role changed
            </option>
            <option value="organization_member_removed">Member removed</option>
            <option value="alert_acknowledged">Alert acknowledged</option>
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-zinc-500">Resource</span>
          <select
            className="rounded border border-zinc-300 px-2 py-1"
            value={resourceType}
            onChange={(event) =>
              setResourceType(
                event.target.value as OrganizationAuditResourceKind | "",
              )
            }
          >
            <option value="">All</option>
            <option value="target">Target</option>
            <option value="assessment">Assessment</option>
            <option value="monitoring">Monitoring</option>
            <option value="notification_settings">Notification settings</option>
            <option value="finding">Finding</option>
            <option value="retest">Retest</option>
            <option value="report">Report</option>
            <option value="report_share">Report share</option>
            <option value="candidate">Candidate</option>
            <option value="alert">Alert</option>
          </select>
        </label>
        <button
          type="button"
          className="rounded border border-zinc-300 px-3 py-1"
          disabled={pending}
          onClick={() => refresh(null)}
        >
          Refresh
        </button>
      </div>

      {error ? <p className="text-sm text-red-700">{error}</p> : null}

      <ul className="divide-y divide-zinc-200 border-y border-zinc-200 text-sm">
        {(data?.items ?? []).map((row, index) => (
          <li
            key={`${row.action}-${row.occurred_at}-${index}`}
            className="grid gap-1 py-3"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="font-medium text-zinc-900">{row.label}</p>
              <p className="text-zinc-500">{formatTime(row.occurred_at)}</p>
            </div>
            <p className="text-zinc-700">
              {actorLabel(row)} · {row.resource.label ?? row.resource.kind}
            </p>
            {detailSummary(row) ? (
              <p className="text-zinc-600">{detailSummary(row)}</p>
            ) : null}
          </li>
        ))}
        {!pending && data && data.items.length === 0 ? (
          <li className="py-3 text-zinc-500">No audit events match these filters.</li>
        ) : null}
      </ul>

      <div className="flex gap-3">
        <button
          type="button"
          className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-40"
          disabled={pending}
          onClick={() => refresh(null)}
        >
          First page
        </button>
        <button
          type="button"
          className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-40"
          disabled={pending || !data?.next_cursor}
          onClick={() => refresh(data?.next_cursor ?? null)}
        >
          Load older
        </button>
      </div>
    </section>
  );
}

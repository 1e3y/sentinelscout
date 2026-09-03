"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchNotificationDeliveries,
  type NotificationDeliveryClass,
  type NotificationDeliveryRow,
  type NotificationDeliveryState,
  type NotificationDeliveriesResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function classLabel(value: NotificationDeliveryClass): string {
  if (value === "alert_email") return "Alert email";
  if (value === "report_delivery") return "Report delivery";
  return "Follow-up reminder";
}

function detailSummary(row: NotificationDeliveryRow): string {
  const detail = row.detail;
  if (detail.delivery_class === "alert_email") {
    return `${detail.alert_type} · ${detail.priority}`;
  }
  if (detail.delivery_class === "report_delivery") {
    const version =
      detail.report_version != null ? `v${detail.report_version}` : "report";
    return `${version}${detail.generation_origin ? ` · ${detail.generation_origin}` : ""}`;
  }
  return detail.finding_title;
}

function recipientLabel(row: NotificationDeliveryRow): string {
  if (!row.recipient) return "—";
  if (row.recipient.kind === "external_recipient") {
    return "External recipient";
  }
  return row.recipient.display_name ?? row.recipient.user_id.slice(0, 8);
}

export function NotificationDeliveriesPanel({ enabled, isAdmin }: Props) {
  const { getToken } = useAuth();
  const [data, setData] = useState<NotificationDeliveriesResponse | null>(null);
  const [deliveryClass, setDeliveryClass] = useState<
    NotificationDeliveryClass | ""
  >("");
  const [state, setState] = useState<NotificationDeliveryState | "">("");
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
        const next = await fetchNotificationDeliveries(token, {
          page_size: 20,
          cursor: nextCursor ?? undefined,
          delivery_class: deliveryClass || undefined,
          state: state || undefined,
        });
        setData(next);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load notification deliveries",
        );
      }
    });
  }

  useEffect(() => {
    refresh(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, isAdmin, deliveryClass, state]);

  if (!enabled) {
    return null;
  }

  if (!isAdmin) {
    return (
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Notification deliveries</h2>
        <p className="text-sm text-zinc-600">
          Organization admins can review delivery history for alert emails,
          automatic report emails, and follow-up reminders.
        </p>
      </section>
    );
  }

  const configuration = data?.configuration;

  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h2 className="text-lg font-medium">Notification deliveries</h2>
        <p className="text-sm text-zinc-600">
          Read-only delivery ledger for this organization. Automatic report
          delivery is configured per target.
        </p>
      </div>

      {configuration ? (
        <dl className="grid gap-2 text-sm text-zinc-700 sm:grid-cols-3">
          <div>
            <dt className="text-zinc-500">Alert email</dt>
            <dd>{configuration.alert_email_enabled ? "Enabled" : "Disabled"}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">Follow-up reminders</dt>
            <dd>
              {configuration.follow_up_reminders_enabled
                ? "Enabled"
                : "Disabled"}
            </dd>
          </div>
          <div>
            <dt className="text-zinc-500">Environment email delivery</dt>
            <dd>
              {configuration.email_delivery_enabled ? "Enabled" : "Disabled"}
            </dd>
          </div>
        </dl>
      ) : null}

      <div className="flex flex-wrap gap-3 text-sm">
        <label className="flex items-center gap-2">
          <span className="text-zinc-500">Class</span>
          <select
            className="rounded border border-zinc-300 px-2 py-1"
            value={deliveryClass}
            onChange={(event) =>
              setDeliveryClass(
                event.target.value as NotificationDeliveryClass | "",
              )
            }
          >
            <option value="">All</option>
            <option value="alert_email">Alert email</option>
            <option value="report_delivery">Report delivery</option>
            <option value="follow_up_reminder">Follow-up reminder</option>
          </select>
        </label>
        <label className="flex items-center gap-2">
          <span className="text-zinc-500">State</span>
          <select
            className="rounded border border-zinc-300 px-2 py-1"
            value={state}
            onChange={(event) =>
              setState(event.target.value as NotificationDeliveryState | "")
            }
          >
            <option value="">All</option>
            <option value="pending">Pending</option>
            <option value="processing">Processing</option>
            <option value="retrying">Retrying</option>
            <option value="delivered">Delivered</option>
            <option value="skipped">Skipped</option>
            <option value="dead">Dead</option>
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

      {error ? (
        <p className="text-sm text-red-700">{error}</p>
      ) : null}

      <ul className="divide-y divide-zinc-200 border-y border-zinc-200 text-sm">
        {(data?.items ?? []).map((row, index) => (
          <li
            key={`${row.delivery_class}-${row.created_at}-${index}`}
            className="grid gap-1 py-3"
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="font-medium text-zinc-900">
                {classLabel(row.delivery_class)} · {row.state}
              </p>
              <p className="text-zinc-500">{formatTime(row.created_at)}</p>
            </div>
            <p className="text-zinc-700">{detailSummary(row)}</p>
            <p className="text-zinc-500">
              {row.target?.domain ?? "No target"} · {recipientLabel(row)}
              {row.delivered_at
                ? ` · delivered ${formatTime(row.delivered_at)}`
                : ""}
            </p>
            {row.safe_reason_label ? (
              <p className="text-zinc-600">{row.safe_reason_label}</p>
            ) : null}
          </li>
        ))}
        {!pending && data && data.items.length === 0 ? (
          <li className="py-3 text-zinc-500">No deliveries match these filters.</li>
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
          Next page
        </button>
      </div>
    </section>
  );
}

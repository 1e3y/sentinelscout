"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  acknowledgeAlert,
  dismissAlert,
  fetchAlertSummary,
  fetchAlerts,
  markAlertRead,
  type AlertResponse,
  type AlertSummaryResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function priorityLabel(priority: string): string {
  if (priority === "medium") return "Medium";
  if (priority === "low") return "Low";
  return "Info";
}

function categoryLabel(category: string): string {
  if (category === "security_regression") return "Security regression";
  if (category === "coverage_degradation") return "Coverage / evidence";
  return "Informational";
}

export function AlertsPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [alerts, setAlerts] = useState<AlertResponse[]>([]);
  const [summary, setSummary] = useState<AlertSummaryResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [includeDismissed, setIncludeDismissed] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const selected = alerts.find((item) => item.id === selectedId) ?? null;

  function refresh() {
    if (!enabled) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const [next, nextSummary] = await Promise.all([
          fetchAlerts(token, { include_dismissed: includeDismissed }),
          fetchAlertSummary(token),
        ]);
        setAlerts(next);
        setSummary(nextSummary);
        setSelectedId((current) => {
          if (current && next.some((item) => item.id === current)) return current;
          return next[0]?.id ?? null;
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load alerts");
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, includeDismissed]);

  function act(
    label: string,
    fn: (token: string, alertId: string) => Promise<AlertResponse>,
  ) {
    if (!selected) return;
    startTransition(async () => {
      setError(null);
      setMessage(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        await fn(token, selected.id);
        setMessage(label);
        refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : "Alert action failed");
      }
    });
  }

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Monitoring alerts</h2>
          <p className="text-sm text-zinc-600">
            In-app notifications from frozen monitoring comparisons. Zero alerts
            does not mean this application is secure.
          </p>
        </div>
        <button
          type="button"
          disabled={!enabled || pending}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
          onClick={() => refresh()}
        >
          Refresh
        </button>
      </div>

      {summary ? (
        <p className="text-sm text-zinc-600">
          Unread for you: {summary.unread_count}. Open episodes:{" "}
          {summary.open_episode_count}.
        </p>
      ) : null}

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
          {error}
        </p>
      ) : null}
      {message ? (
        <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
          {message}
        </p>
      ) : null}

      {!enabled ? (
        <p className="text-sm text-zinc-600">Select an organization to view alerts.</p>
      ) : (
        <>
          <label className="flex items-center gap-2 text-sm text-zinc-700">
            <input
              type="checkbox"
              checked={includeDismissed}
              onChange={(event) => setIncludeDismissed(event.target.checked)}
            />
            Include alerts you dismissed
          </label>
          {alerts.length === 0 ? (
            <p className="text-sm text-zinc-600">
              No monitoring alerts. Zero alerts does not mean this application is
              secure.
            </p>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <ul className="space-y-2">
                {alerts.map((item) => (
                  <li key={item.id}>
                    <button
                      type="button"
                      className={`w-full rounded-md border px-3 py-2 text-left text-sm ${
                        item.id === selectedId
                          ? "border-zinc-900 bg-zinc-50"
                          : "border-zinc-200"
                      }`}
                      onClick={() => setSelectedId(item.id)}
                    >
                      <span className="font-medium">{item.title}</span>
                      <span className="mt-1 block text-xs text-zinc-500">
                        {priorityLabel(item.priority)} · {categoryLabel(item.category)}
                        {item.read_at ? "" : " · Unread"}
                        {item.episode_status === "open" ? " · Open episode" : ""}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
              {selected ? (
                <div className="space-y-3 rounded-md border border-zinc-200 px-4 py-3 text-sm">
                  <p className="text-zinc-500">{selected.disclaimer}</p>
                  <dl className="grid gap-2">
                    <div>
                      <dt className="text-zinc-500">Target</dt>
                      <dd>{selected.target_domain ?? selected.target_id}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Type</dt>
                      <dd className="font-mono text-xs">{selected.alert_type}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Priority / category</dt>
                      <dd>
                        {priorityLabel(selected.priority)} ·{" "}
                        {categoryLabel(selected.category)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Summary</dt>
                      <dd>{selected.summary}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Operation</dt>
                      <dd className="font-mono text-xs">{selected.operation_id}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Created</dt>
                      <dd>{formatTime(selected.created_at)}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500">Acknowledged</dt>
                      <dd>
                        {selected.acknowledged_at
                          ? formatTime(selected.acknowledged_at)
                          : "Not acknowledged"}
                      </dd>
                    </div>
                  </dl>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={pending || Boolean(selected.read_at)}
                      className="rounded-md border border-zinc-300 px-3 py-1.5 disabled:opacity-50"
                      onClick={() => act("Marked read for you.", markAlertRead)}
                    >
                      Mark read
                    </button>
                    <button
                      type="button"
                      disabled={pending || Boolean(selected.acknowledged_at)}
                      className="rounded-md border border-zinc-300 px-3 py-1.5 disabled:opacity-50"
                      onClick={() =>
                        act(
                          "Acknowledged for the organization. The episode stays open.",
                          acknowledgeAlert,
                        )
                      }
                    >
                      Acknowledge
                    </button>
                    <button
                      type="button"
                      disabled={pending || Boolean(selected.dismissed_at)}
                      className="rounded-md border border-zinc-300 px-3 py-1.5 disabled:opacity-50"
                      onClick={() =>
                        act("Dismissed for you only.", dismissAlert)
                      }
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </>
      )}
    </section>
  );
}

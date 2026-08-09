"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchAuditEvents,
  type AuditEventResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function actorLabel(event: AuditEventResponse): string {
  if (event.actor_user_id) {
    return `${event.actor_type} · ${event.actor_user_id.slice(0, 8)}…`;
  }
  return event.actor_type;
}

export function AuditPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [events, setEvents] = useState<AuditEventResponse[]>([]);
  const [resourceType, setResourceType] = useState("");
  const [action, setAction] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

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
        const next = await fetchAuditEvents(token, {
          resource_type: resourceType.trim() || undefined,
          action: action.trim() || undefined,
          resource_id: resourceId.trim() || undefined,
          limit: 100,
        });
        setEvents(next);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load audit events");
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Audit</h2>
          <p className="text-sm text-zinc-600">
            Organization-scoped trail of who acted on targets, operations,
            findings, and monitoring.
          </p>
        </div>
        <button
          type="button"
          disabled={pending || !enabled}
          onClick={refresh}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {!enabled ? (
        <p className="text-sm text-zinc-600">
          Select an organization to view audit events.
        </p>
      ) : (
        <>
          <div className="flex flex-wrap items-end gap-3 text-sm">
            <label className="space-y-1">
              <span className="text-zinc-500">Action</span>
              <input
                value={action}
                onChange={(e) => setAction(e.target.value)}
                placeholder="operation.created"
                className="block w-48 rounded-md border border-zinc-300 px-2 py-1.5 font-mono text-xs"
              />
            </label>
            <label className="space-y-1">
              <span className="text-zinc-500">Resource type</span>
              <input
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                placeholder="operation"
                className="block w-40 rounded-md border border-zinc-300 px-2 py-1.5 font-mono text-xs"
              />
            </label>
            <label className="space-y-1">
              <span className="text-zinc-500">Resource id</span>
              <input
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                placeholder="uuid"
                className="block w-64 rounded-md border border-zinc-300 px-2 py-1.5 font-mono text-xs"
              />
            </label>
            <button
              type="button"
              disabled={pending}
              onClick={refresh}
              className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm disabled:opacity-50"
            >
              Apply filters
            </button>
          </div>

          {error ? (
            <p className="text-sm text-red-700">{error}</p>
          ) : null}

          {events.length === 0 ? (
            <p className="text-sm text-zinc-600">No audit events yet.</p>
          ) : (
            <div className="overflow-x-auto rounded-md border border-zinc-200">
              <table className="min-w-full text-left text-sm">
                <thead className="border-b border-zinc-200 bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                  <tr>
                    <th className="px-3 py-2 font-medium">Timestamp</th>
                    <th className="px-3 py-2 font-medium">Actor</th>
                    <th className="px-3 py-2 font-medium">Action</th>
                    <th className="px-3 py-2 font-medium">Resource</th>
                    <th className="px-3 py-2 font-medium">Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                  {events.map((event) => (
                    <tr key={event.id}>
                      <td className="whitespace-nowrap px-3 py-2 text-xs text-zinc-600">
                        {formatTime(event.created_at)}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {actorLabel(event)}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{event.action}</td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {event.resource_type}
                        {event.resource_id
                          ? ` · ${event.resource_id.slice(0, 8)}…`
                          : ""}
                      </td>
                      <td className="px-3 py-2 text-zinc-700">{event.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}

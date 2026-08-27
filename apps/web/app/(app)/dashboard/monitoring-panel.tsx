"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchTargetMonitoring,
  fetchTargets,
  updateTargetMonitoring,
  type MonitoringConfigurationResponse,
  type TargetResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export function MonitoringPanel({ enabled, isAdmin }: Props) {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<TargetResponse[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [monitoring, setMonitoring] =
    useState<MonitoringConfigurationResponse | null>(null);
  const [frequency, setFrequency] = useState<"daily" | "weekly">("weekly");
  const [expiresIn, setExpiresIn] = useState<"24h" | "7d" | "30d">("7d");
  const [recipientDraft, setRecipientDraft] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const verifiedTargets = targets.filter((t) => t.status === "verified");
  const selected = targets.find((t) => t.id === selectedId) ?? null;

  async function loadMonitoring(targetId: string) {
    const token = await getToken();
    if (!token) {
      setError("Missing session token");
      return;
    }
    const next = await fetchTargetMonitoring(token, targetId);
    setMonitoring(next);
    setFrequency(next.frequency === "daily" ? "daily" : "weekly");
    setExpiresIn(
      next.auto_deliver_expires_in === "24h" || next.auto_deliver_expires_in === "30d"
        ? next.auto_deliver_expires_in
        : "7d",
    );
  }

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
        const list = await fetchTargets(token);
        setTargets(list);
        const verified = list.filter((t) => t.status === "verified");
        const nextId =
          (selectedId && verified.some((t) => t.id === selectedId) && selectedId) ||
          verified[0]?.id ||
          null;
        setSelectedId(nextId);
        if (nextId) {
          await loadMonitoring(nextId);
        } else {
          setMonitoring(null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load monitoring");
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  const changes = monitoring?.latest_changes ?? {};

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-medium">Monitoring</h2>
          <p className="text-sm text-zinc-600">
            Recurring authorized discovery for verified targets. Scheduler creates
            operations; workers run the same safe pipeline.
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
        <p className="text-sm text-zinc-600">Select an organization to configure monitoring.</p>
      ) : verifiedTargets.length === 0 ? (
        <p className="text-sm text-zinc-600">
          Verify a target before enabling monitoring.
        </p>
      ) : (
        <div className="grid gap-4 md:grid-cols-[14rem_1fr]">
          <ul className="divide-y divide-zinc-100 rounded-md border border-zinc-200 bg-white">
            {verifiedTargets.map((target) => (
              <li key={target.id}>
                <button
                  type="button"
                  className={`w-full px-3 py-2 text-left text-sm ${
                    target.id === selectedId ? "bg-zinc-100" : ""
                  }`}
                  onClick={() => {
                    setSelectedId(target.id);
                    startTransition(async () => {
                      try {
                        await loadMonitoring(target.id);
                      } catch (err) {
                        setError(
                          err instanceof Error
                            ? err.message
                            : "Failed to load monitoring",
                        );
                      }
                    });
                  }}
                >
                  <div className="font-medium">{target.domain}</div>
                </button>
              </li>
            ))}
          </ul>

          {selected && monitoring ? (
            <div className="space-y-4 rounded-md border border-zinc-200 bg-white p-4 text-sm">
              <dl className="grid gap-2 text-zinc-700">
                <div>
                  <dt className="text-zinc-500">Target</dt>
                  <dd>{selected.domain}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Monitoring</dt>
                  <dd>{monitoring.enabled ? "Enabled" : "Disabled"}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Frequency</dt>
                  <dd className="capitalize">{monitoring.frequency}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Automatic reports</dt>
                  <dd>
                    {monitoring.auto_generate_reports ? "Enabled" : "Disabled"}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Automatic delivery</dt>
                  <dd>
                    {monitoring.auto_deliver_reports ? "Enabled" : "Disabled"}
                    {monitoring.auto_deliver_reports &&
                    !monitoring.email_delivery_enabled
                      ? " — Queued; email delivery is disabled in this environment"
                      : null}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Delivery expiry</dt>
                  <dd>{monitoring.auto_deliver_expires_in}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Delivery recipients</dt>
                  <dd>
                    {isAdmin && monitoring.recipients
                      ? monitoring.recipients.length > 0
                        ? monitoring.recipients.join(", ")
                        : "None"
                      : `${monitoring.recipient_count} configured`}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Last assessment</dt>
                  <dd>{formatTime(monitoring.last_run_at)}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Next assessment</dt>
                  <dd>{formatTime(monitoring.next_run_at)}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Latest changes</dt>
                  <dd>
                    <ul className="list-disc pl-4 text-xs text-zinc-600">
                      <li>
                        Comparability{" "}
                        {String(changes.comparability ?? "no_baseline")}
                      </li>
                      <li>
                        {Number(changes.hostname_newly_discovered ?? 0)} hostnames
                        newly discovered
                      </li>
                      <li>
                        {Number(changes.hostname_no_longer_discovered ?? 0)}{" "}
                        hostnames no longer discovered
                      </li>
                      <li>
                        {Number(changes.http_observation_gained ?? 0)} HTTP
                        observations gained
                      </li>
                      <li>
                        {Number(changes.http_observation_lost ?? 0)} HTTP
                        observations lost
                      </li>
                      <li>
                        {Number(changes.regressions ?? 0)} conservative
                        regressions
                      </li>
                    </ul>
                  </dd>
                </div>
                {monitoring.disabled_reason ? (
                  <div>
                    <dt className="text-zinc-500">Disabled reason</dt>
                    <dd>{monitoring.disabled_reason}</dd>
                  </div>
                ) : null}
              </dl>

              <div className="flex flex-wrap items-end gap-3">
                {isAdmin ? (
                  <>
                <label className="text-xs text-zinc-600">
                  Frequency
                  <select
                    className="mt-1 block rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                    value={frequency}
                    onChange={(event) =>
                      setFrequency(event.target.value as "daily" | "weekly")
                    }
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </label>
                <label className="flex max-w-sm items-start gap-2 text-xs text-zinc-600">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={Boolean(monitoring.auto_generate_reports)}
                    disabled={pending}
                    onChange={(event) => {
                      const next = event.target.checked;
                      startTransition(async () => {
                        setError(null);
                        setMessage(null);
                        try {
                          const token = await getToken();
                          if (!token) {
                            setError("Missing session token");
                            return;
                          }
                          const updated = await updateTargetMonitoring(
                            token,
                            selected.id,
                            {
                              enabled: monitoring.enabled,
                              frequency,
                              auto_generate_reports: next,
                            },
                          );
                          setMonitoring(updated);
                          setMessage(
                            next
                              ? "Automatic reports enabled for successful scheduled runs."
                              : "Automatic reports disabled.",
                          );
                        } catch (err) {
                          setError(
                            err instanceof Error
                              ? err.message
                              : "Failed to update automatic reports",
                          );
                        }
                      });
                    }}
                  />
                  <span>
                    Automatically generate assessment reports after successful
                    scheduled runs. Does not share or email. Reports are
                    immutable snapshots; members can read them.
                  </span>
                </label>
                <label className="flex max-w-sm items-start gap-2 text-xs text-zinc-600">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={Boolean(monitoring.auto_deliver_reports)}
                    disabled={pending}
                    onChange={(event) => {
                      const next = event.target.checked;
                      startTransition(async () => {
                        setError(null);
                        setMessage(null);
                        try {
                          const token = await getToken();
                          if (!token) {
                            setError("Missing session token");
                            return;
                          }
                          const updated = await updateTargetMonitoring(
                            token,
                            selected.id,
                            {
                              enabled: monitoring.enabled,
                              frequency,
                              auto_deliver_reports: next,
                            },
                          );
                          setMonitoring(updated);
                          setMessage(
                            next
                              ? "Automatic delivery enabled. Emails go out only after a successful automatic report, using a revocable expiring link. Disabling later does not recall sent mail."
                              : "Automatic delivery disabled. Already sent mail is not recalled; revoke links separately.",
                          );
                        } catch (err) {
                          setError(
                            err instanceof Error
                              ? err.message
                              : "Failed to update automatic delivery",
                          );
                        }
                      });
                    }}
                  />
                  <span>
                    Email a revocable, expiring report link after automatic
                    generation succeeds. Does not attach a PDF. Recipients added
                    later do not receive already-queued reports. Removing a
                    recipient before send skips that email.
                  </span>
                </label>
                <label className="text-xs text-zinc-600">
                  Link expiry
                  <select
                    className="mt-1 block rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                    value={expiresIn}
                    disabled={pending}
                    onChange={(event) => {
                      const next = event.target.value as "24h" | "7d" | "30d";
                      setExpiresIn(next);
                      startTransition(async () => {
                        setError(null);
                        setMessage(null);
                        try {
                          const token = await getToken();
                          if (!token) {
                            setError("Missing session token");
                            return;
                          }
                          const updated = await updateTargetMonitoring(
                            token,
                            selected.id,
                            {
                              enabled: monitoring.enabled,
                              frequency,
                              auto_deliver_expires_in: next,
                            },
                          );
                          setMonitoring(updated);
                          setMessage("Delivery link expiry updated.");
                        } catch (err) {
                          setError(
                            err instanceof Error
                              ? err.message
                              : "Failed to update delivery expiry",
                          );
                        }
                      });
                    }}
                  >
                    <option value="24h">24 hours</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                  </select>
                </label>
                <div className="w-full max-w-md space-y-2 text-xs text-zinc-600">
                  <p>External delivery recipients (max 10). Not shown to members.</p>
                  <ul className="space-y-1">
                    {(monitoring.recipients ?? []).map((email) => (
                      <li key={email} className="flex items-center justify-between gap-2">
                        <span className="break-all">{email}</span>
                        <button
                          type="button"
                          disabled={pending}
                          className="rounded-md border border-zinc-300 px-2 py-0.5 disabled:opacity-50"
                          onClick={() => {
                            const next = (monitoring.recipients ?? []).filter(
                              (item) => item !== email,
                            );
                            startTransition(async () => {
                              setError(null);
                              setMessage(null);
                              try {
                                const token = await getToken();
                                if (!token) {
                                  setError("Missing session token");
                                  return;
                                }
                                const updated = await updateTargetMonitoring(
                                  token,
                                  selected.id,
                                  {
                                    enabled: monitoring.enabled,
                                    frequency,
                                    recipients: next,
                                  },
                                );
                                setMonitoring(updated);
                                setMessage("Delivery recipients updated.");
                              } catch (err) {
                                setError(
                                  err instanceof Error
                                    ? err.message
                                    : "Failed to update recipients",
                                );
                              }
                            });
                          }}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                  <form
                    className="flex flex-wrap items-end gap-2"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const value = recipientDraft.trim();
                      if (!value) return;
                      const next = [...(monitoring.recipients ?? []), value];
                      startTransition(async () => {
                        setError(null);
                        setMessage(null);
                        try {
                          const token = await getToken();
                          if (!token) {
                            setError("Missing session token");
                            return;
                          }
                          const updated = await updateTargetMonitoring(
                            token,
                            selected.id,
                            {
                              enabled: monitoring.enabled,
                              frequency,
                              recipients: next,
                            },
                          );
                          setMonitoring(updated);
                          setRecipientDraft("");
                          setMessage("Delivery recipients updated.");
                        } catch (err) {
                          setError(
                            err instanceof Error
                              ? err.message
                              : "Failed to update recipients",
                          );
                        }
                      });
                    }}
                  >
                    <input
                      type="email"
                      className="min-w-[12rem] flex-1 rounded-md border border-zinc-300 px-2 py-1.5 text-sm"
                      placeholder="recipient@example.com"
                      value={recipientDraft}
                      onChange={(event) => setRecipientDraft(event.target.value)}
                      disabled={pending || (monitoring.recipients ?? []).length >= 10}
                    />
                    <button
                      type="submit"
                      disabled={pending || (monitoring.recipients ?? []).length >= 10}
                      className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                    >
                      Add
                    </button>
                  </form>
                </div>
                <button
                  type="button"
                  disabled={pending}
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                  onClick={() => {
                    startTransition(async () => {
                      setError(null);
                      setMessage(null);
                      try {
                        const token = await getToken();
                        if (!token) {
                          setError("Missing session token");
                          return;
                        }
                        const updated = await updateTargetMonitoring(
                          token,
                          selected.id,
                          { enabled: true, frequency },
                        );
                        setMonitoring(updated);
                        setMessage("Monitoring enabled.");
                      } catch (err) {
                        setError(
                          err instanceof Error
                            ? err.message
                            : "Failed to enable monitoring",
                        );
                      }
                    });
                  }}
                >
                  Enable
                </button>
                <button
                  type="button"
                  disabled={pending}
                  className="rounded-md border border-zinc-300 px-3 py-1.5 text-xs disabled:opacity-50"
                  onClick={() => {
                    startTransition(async () => {
                      setError(null);
                      setMessage(null);
                      try {
                        const token = await getToken();
                        if (!token) {
                          setError("Missing session token");
                          return;
                        }
                        const updated = await updateTargetMonitoring(
                          token,
                          selected.id,
                          { enabled: false, frequency },
                        );
                        setMonitoring(updated);
                        setMessage("Monitoring disabled.");
                      } catch (err) {
                        setError(
                          err instanceof Error
                            ? err.message
                            : "Failed to disable monitoring",
                        );
                      }
                    });
                  }}
                >
                  Disable
                </button>
                  </>
                ) : (
                  <p className="text-xs text-zinc-500">
                    Organization admins enable, disable, and change monitoring
                    cadence.
                  </p>
                )}
              </div>
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}

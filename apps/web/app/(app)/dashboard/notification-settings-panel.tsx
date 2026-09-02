"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchMe,
  fetchNotificationSettings,
  updateNotificationSettings,
  type NotificationMember,
  type NotificationSettingsResponse,
} from "@/lib/api";

type Props = {
  enabled: boolean;
};

export function NotificationSettingsPanel({ enabled }: Props) {
  const { getToken } = useAuth();
  const [settings, setSettings] = useState<NotificationSettingsResponse | null>(
    null,
  );
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [minPriority, setMinPriority] = useState("medium");
  const [followUpRemindersEnabled, setFollowUpRemindersEnabled] =
    useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [message, setMessage] = useState<string | null>(null);
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
        const me = await fetchMe(token);
        if (!me.active_organization_id) {
          setSettings(null);
          return;
        }
        const next = await fetchNotificationSettings(
          token,
          me.active_organization_id,
        );
        setSettings(next);
        setEmailEnabled(next.email_enabled);
        setMinPriority(next.email_min_priority);
        setFollowUpRemindersEnabled(next.finding_follow_up_reminders_enabled);
        setSelected(next.recipients.map((row) => row.user_id));
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load notification settings",
        );
      }
    });
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);

  function toggleMember(member: NotificationMember) {
    if (!member.email_verified) return;
    setSelected((current) =>
      current.includes(member.user_id)
        ? current.filter((id) => id !== member.user_id)
        : [...current, member.user_id],
    );
  }

  function save() {
    if (!settings?.can_manage) return;
    startTransition(async () => {
      setError(null);
      setMessage(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const next = await updateNotificationSettings(
          token,
          settings.organization_id,
          {
            email_enabled: emailEnabled,
            email_min_priority: minPriority,
            finding_follow_up_reminders_enabled: followUpRemindersEnabled,
            recipient_user_ids: selected,
          },
        );
        setSettings(next);
        setEmailEnabled(next.email_enabled);
        setMinPriority(next.email_min_priority);
        setFollowUpRemindersEnabled(next.finding_follow_up_reminders_enabled);
        setSelected(next.recipients.map((row) => row.user_id));
        setMessage("Notification settings saved.");
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to save settings",
        );
      }
    });
  }

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-medium">Alert email</h2>
      <p className="text-sm text-zinc-600">
        Email is off by default. Only current organization members with a
        verified primary email can be recipients. There is no digest.
      </p>
      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {message ? <p className="text-sm text-zinc-700">{message}</p> : null}
      {!enabled ? (
        <p className="text-sm text-zinc-600">Select an organization first.</p>
      ) : settings ? (
        <div className="space-y-3 rounded-md border border-zinc-200 px-4 py-3 text-sm">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={emailEnabled}
              disabled={pending || !settings.can_manage}
              onChange={(event) => setEmailEnabled(event.target.checked)}
            />
            Send email for new alerts at or above the minimum priority
          </label>
          <label className="block">
            <span className="text-zinc-500">Minimum priority</span>
            <select
              className="mt-1 block rounded-md border border-zinc-300 px-2 py-1"
              value={minPriority}
              disabled={pending || !settings.can_manage}
              onChange={(event) => setMinPriority(event.target.value)}
            >
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>
          <div>
            <p className="text-zinc-500">Recipients</p>
            <ul className="mt-1 space-y-1">
              {settings.members.map((member) => (
                <li key={member.user_id}>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={selected.includes(member.user_id)}
                      disabled={
                        pending ||
                        !settings.can_manage ||
                        !member.email_verified
                      }
                      onChange={() => toggleMember(member)}
                    />
                    <span>
                      {member.name ?? member.email}
                      {!member.email_verified
                        ? " (email not verified)"
                        : ""}
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          </div>
          <div className="border-t border-zinc-200 pt-3">
            <h3 className="font-medium">Finding follow-up reminders</h3>
            <p className="mt-1 text-zinc-600">
              Reminders use the human-chosen due date. They do not change
              severity. They stop if the Finding resolves or ownership/due
              changes. The assigned member must remain in the organization.
              This is separate from alert-email recipients.
            </p>
            <label className="mt-2 flex items-center gap-2">
              <input
                type="checkbox"
                checked={followUpRemindersEnabled}
                disabled={pending || !settings.can_manage}
                onChange={(event) =>
                  setFollowUpRemindersEnabled(event.target.checked)
                }
              />
              Email assigned members when a follow-up date is due
            </label>
            <p className="mt-2 text-xs text-zinc-500">
              Delivery status for each Finding is shown on the Finding detail
              page. Reminder delivery does not appear in Finding activity or
              assessment reports.
            </p>
          </div>
          {settings.can_manage ? (
            <button
              type="button"
              disabled={pending}
              className="rounded-md border border-zinc-300 px-3 py-1.5 disabled:opacity-50"
              onClick={save}
            >
              Save email settings
            </button>
          ) : (
            <p className="text-zinc-500">
              Organization admins can change these settings.
            </p>
          )}
        </div>
      ) : (
        <p className="text-sm text-zinc-600">No active organization.</p>
      )}
    </section>
  );
}

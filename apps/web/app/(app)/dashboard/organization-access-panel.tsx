"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition } from "react";
import {
  fetchOrganizationAccess,
  removeOrganizationMember,
  updateOrganizationMemberRole,
  type OrganizationAccessMember,
  type OrganizationAccessResponse,
  type OrganizationAccessRole,
} from "@/lib/api";

type Props = {
  enabled: boolean;
  isAdmin: boolean;
  currentUserId: string | null;
};

function roleLabel(member: OrganizationAccessMember): string {
  if (member.role_state === "unrecognized") {
    return "Current organization role is not recognized by Sentinel Scout.";
  }
  if (member.role === "admin") return "Admin";
  if (member.role === "member") return "Member";
  return "Current organization role is not recognized by Sentinel Scout.";
}

function mirrorLabel(member: OrganizationAccessMember): string {
  switch (member.local_mirror_state) {
    case "not_applicable":
      return member.account_link_state === "not_linked"
        ? "No linked account yet"
        : "Local access cache not compared";
    case "missing":
      return "Local access cache missing (expected for some current members)";
    case "role_matches":
      return "Local access cache matches";
    case "role_differs":
      return "Local access cache differs from current role";
    default:
      return "Local access cache";
  }
}

function canManageMember(member: OrganizationAccessMember): boolean {
  return (
    member.account_link_state === "linked" &&
    member.user_id != null &&
    member.role_state === "recognized" &&
    member.role === "member"
  );
}

export function OrganizationAccessPanel({
  enabled,
  isAdmin,
  currentUserId,
}: Props) {
  const { getToken } = useAuth();
  const [data, setData] = useState<OrganizationAccessResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [mutatingUserId, setMutatingUserId] = useState<string | null>(null);

  function load(nextCursor: string | null = null) {
    if (!enabled || !isAdmin) return;
    startTransition(async () => {
      setError(null);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const next = await fetchOrganizationAccess(token, {
          page_size: 50,
          cursor: nextCursor ?? undefined,
        });
        setData(next);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Current organization access could not be verified.",
        );
      }
    });
  }

  useEffect(() => {
    load(null);
    // Explicit initial load only — no polling / background refresh interval.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, isAdmin]);

  function refreshAfterMutation() {
    load(null);
  }

  function onPromote(member: OrganizationAccessMember) {
    if (!member.user_id || !canManageMember(member)) return;
    const label = member.display_name ?? "this member";
    if (
      !window.confirm(
        `Promote ${label} to organization admin? They will be able to manage organization access.`,
      )
    ) {
      return;
    }
    startTransition(async () => {
      setError(null);
      setNotice(null);
      setMutatingUserId(member.user_id);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const result = await updateOrganizationMemberRole(
          token,
          member.user_id!,
          "admin" satisfies OrganizationAccessRole,
        );
        if (result.local_recording_state === "audit_degraded") {
          setNotice(
            "Access was updated, but local activity recording is temporarily incomplete.",
          );
        }
        refreshAfterMutation();
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Organization access could not be updated.",
        );
      } finally {
        setMutatingUserId(null);
      }
    });
  }

  function onRemove(member: OrganizationAccessMember) {
    if (!member.user_id || !canManageMember(member)) return;
    if (member.user_id === currentUserId) {
      setError("Organization administrators cannot be demoted or removed.");
      return;
    }
    const label = member.display_name ?? "this member";
    if (
      !window.confirm(
        `Remove ${label} from this organization? Their account and historical work remain; only organization membership is removed.`,
      )
    ) {
      return;
    }
    startTransition(async () => {
      setError(null);
      setNotice(null);
      setMutatingUserId(member.user_id);
      try {
        const token = await getToken();
        if (!token) {
          setError("Missing session token");
          return;
        }
        const result = await removeOrganizationMember(token, member.user_id!);
        if (result.local_recording_state === "audit_degraded") {
          setNotice(
            "Access was updated, but local activity recording is temporarily incomplete.",
          );
        }
        refreshAfterMutation();
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Organization access could not be updated.",
        );
      } finally {
        setMutatingUserId(null);
      }
    });
  }

  if (!enabled) return null;

  if (!isAdmin) {
    return (
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Organization access</h2>
        <p className="text-sm text-zinc-600">
          Organization admins can review who currently has access to this
          organization.
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <div className="space-y-1">
        <h2 className="text-lg font-medium">Organization access</h2>
        <p className="text-sm text-zinc-600">
          Current members from the identity provider. Local access cache is
          diagnostic only and does not define who currently has access.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
          disabled={pending}
          onClick={() => load(null)}
        >
          Refresh
        </button>
        {data?.next_cursor ? (
          <button
            type="button"
            className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
            disabled={pending}
            onClick={() => load(data.next_cursor)}
          >
            Load more
          </button>
        ) : null}
      </div>

      {error ? <p className="text-sm text-red-700">{error}</p> : null}
      {notice ? <p className="text-sm text-amber-800">{notice}</p> : null}
      {pending && !data ? (
        <p className="text-sm text-zinc-500">Loading current access…</p>
      ) : null}

      {data ? (
        <div className="space-y-3">
          <p className="text-xs text-zinc-500">
            Source: current organization membership
            {data.total_members != null
              ? ` · ${data.total_members} total`
              : ""}
          </p>
          <ul className="divide-y divide-zinc-200 border border-zinc-200">
            {data.items.length === 0 ? (
              <li className="px-3 py-3 text-sm text-zinc-500">
                No current members on this page.
              </li>
            ) : (
              data.items.map((member, index) => {
                const busy =
                  pending && mutatingUserId != null && mutatingUserId === member.user_id;
                const manageable = canManageMember(member);
                return (
                  <li
                    key={member.user_id ?? `unlinked-${index}`}
                    className="space-y-2 px-3 py-3 text-sm"
                  >
                    <div className="font-medium text-zinc-900">
                      {member.display_name ?? "Organization member"}
                    </div>
                    <div className="text-zinc-600">{roleLabel(member)}</div>
                    <div className="text-xs text-zinc-500">
                      {member.account_link_state === "linked"
                        ? "Linked account"
                        : "Not yet linked in Sentinel Scout"}
                      {" · "}
                      {mirrorLabel(member)}
                    </div>
                    {member.role_state === "unrecognized" ? (
                      <p className="text-xs text-zinc-500">
                        Management is unavailable because this member&apos;s
                        current organization role is not recognized.
                      </p>
                    ) : null}
                    {member.account_link_state === "not_linked" ? (
                      <p className="text-xs text-zinc-500">
                        Management is unavailable until this member links an
                        account in Sentinel Scout.
                      </p>
                    ) : null}
                    {member.role_state === "recognized" &&
                    member.role === "admin" ? (
                      <p className="text-xs text-zinc-500">
                        Organization administrators cannot be demoted or removed
                        here.
                      </p>
                    ) : null}
                    {manageable ? (
                      <div className="flex flex-wrap gap-2 pt-1">
                        <button
                          type="button"
                          className="rounded border border-zinc-300 px-2 py-1 text-xs disabled:opacity-50"
                          disabled={busy || pending}
                          onClick={() => onPromote(member)}
                        >
                          Make admin
                        </button>
                        <button
                          type="button"
                          className="rounded border border-red-300 px-2 py-1 text-xs text-red-800 disabled:opacity-50"
                          disabled={busy || pending}
                          onClick={() => onRemove(member)}
                        >
                          Remove
                        </button>
                      </div>
                    ) : null}
                  </li>
                );
              })
            )}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

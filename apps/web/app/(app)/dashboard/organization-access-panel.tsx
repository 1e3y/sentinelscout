"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useTransition, type FormEvent } from "react";
import {
  createOrganizationInvitation,
  fetchOrganizationAccess,
  fetchOrganizationInvitations,
  removeOrganizationMember,
  revokeOrganizationInvitation,
  updateOrganizationMemberRole,
  type OrganizationAccessMember,
  type OrganizationAccessResponse,
  type OrganizationAccessRole,
  type OrganizationInvitation,
  type OrganizationInvitationsResponse,
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

function invitationRoleLabel(invite: OrganizationInvitation): string {
  if (invite.role_state === "unrecognized" || invite.role == null) {
    return "Role not recognized";
  }
  if (invite.role === "admin") return "Admin";
  return "Member";
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

function formatWhen(value: string | null): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "—";
  return parsed.toLocaleString();
}

export function OrganizationAccessPanel({
  enabled,
  isAdmin,
  currentUserId,
}: Props) {
  const { getToken } = useAuth();
  const [data, setData] = useState<OrganizationAccessResponse | null>(null);
  const [invites, setInvites] = useState<OrganizationInvitationsResponse | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [mutatingUserId, setMutatingUserId] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviting, setInviting] = useState(false);
  const [revokingRef, setRevokingRef] = useState<string | null>(null);

  function loadMembers(nextCursor: string | null = null) {
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

  function loadInvites(nextCursor: string | null = null) {
    if (!enabled || !isAdmin) return;
    startTransition(async () => {
      setInviteError(null);
      try {
        const token = await getToken();
        if (!token) {
          setInviteError("Missing session token");
          return;
        }
        const next = await fetchOrganizationInvitations(token, {
          page_size: 50,
          cursor: nextCursor ?? undefined,
        });
        setInvites(next);
      } catch (err) {
        setInviteError(
          err instanceof Error
            ? err.message
            : "Organization invitations could not be verified.",
        );
      }
    });
  }

  useEffect(() => {
    loadMembers(null);
    loadInvites(null);
    // Explicit initial load only — no polling / background refresh interval.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, isAdmin]);

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
        loadMembers(null);
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
        loadMembers(null);
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

  async function onInvite(event: FormEvent) {
    event.preventDefault();
    if (inviting || pending) return;
    const email = inviteEmail.trim();
    if (!email) return;
    setInviting(true);
    setInviteError(null);
    setNotice(null);
    try {
      const token = await getToken();
      if (!token) {
        setInviteError("Missing session token");
        return;
      }
      const result = await createOrganizationInvitation(token, email);
      setInviteEmail("");
      if (result.local_recording_state === "audit_degraded") {
        setNotice(
          "Invitation was created, but local activity recording is temporarily incomplete.",
        );
      }
      loadInvites(null);
    } catch (err) {
      setInviteError(
        err instanceof Error
          ? err.message
          : "Organization invitation could not be created.",
      );
      // After ambiguous failure, refresh so admin can see current provider state.
      loadInvites(null);
    } finally {
      setInviting(false);
    }
  }

  function onRevokeInvite(invite: OrganizationInvitation) {
    if (revokingRef || pending || inviting) return;
    if (
      !window.confirm(
        `Revoke the pending invitation for ${invite.recipient_hint}? They will no longer be able to join with this invitation.`,
      )
    ) {
      return;
    }
    startTransition(async () => {
      setInviteError(null);
      setNotice(null);
      setRevokingRef(invite.invitation_ref);
      try {
        const token = await getToken();
        if (!token) {
          setInviteError("Missing session token");
          return;
        }
        const result = await revokeOrganizationInvitation(
          token,
          invite.invitation_ref,
        );
        if (result.local_recording_state === "audit_degraded") {
          setNotice(
            "Invitation was revoked, but local activity recording is temporarily incomplete.",
          );
        }
        loadInvites(null);
      } catch (err) {
        setInviteError(
          err instanceof Error
            ? err.message
            : "Organization invitation could not be revoked.",
        );
        loadInvites(null);
      } finally {
        setRevokingRef(null);
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
    <section className="space-y-8">
      <div className="space-y-4">
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
            onClick={() => loadMembers(null)}
          >
            Refresh
          </button>
          {data?.next_cursor ? (
            <button
              type="button"
              className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
              disabled={pending}
              onClick={() => loadMembers(data.next_cursor)}
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
                    pending &&
                    mutatingUserId != null &&
                    mutatingUserId === member.user_id;
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
                          Organization administrators cannot be demoted or
                          removed here.
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
      </div>

      <div className="space-y-4">
        <div className="space-y-1">
          <h3 className="text-base font-medium">Pending invitations</h3>
          <p className="text-sm text-zinc-600">
            Invite someone as a Member. Invitation delivery is managed by your
            organization identity provider, separate from Sentinel Scout
            notification-delivery settings.
          </p>
        </div>

        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={onInvite}
        >
          <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-sm">
            <span className="text-zinc-500">Email</span>
            <input
              type="email"
              autoComplete="off"
              className="rounded border border-zinc-300 px-2 py-1"
              value={inviteEmail}
              disabled={inviting || pending}
              onChange={(event) => setInviteEmail(event.target.value)}
              placeholder="person@example.com"
            />
          </label>
          <button
            type="submit"
            className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
            disabled={inviting || pending || !inviteEmail.trim()}
          >
            Invite as Member
          </button>
        </form>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
            disabled={pending || inviting}
            onClick={() => loadInvites(null)}
          >
            Refresh invitations
          </button>
          {invites?.next_cursor ? (
            <button
              type="button"
              className="rounded border border-zinc-300 px-3 py-1 text-sm disabled:opacity-50"
              disabled={pending || inviting}
              onClick={() => loadInvites(invites.next_cursor)}
            >
              Load more invitations
            </button>
          ) : null}
        </div>

        {inviteError ? (
          <p className="text-sm text-red-700">{inviteError}</p>
        ) : null}

        {invites ? (
          <ul className="divide-y divide-zinc-200 border border-zinc-200">
            {invites.items.length === 0 ? (
              <li className="px-3 py-3 text-sm text-zinc-500">
                No pending invitations.
              </li>
            ) : (
              invites.items.map((invite, index) => (
                <li
                  key={invite.invitation_ref || `${invite.recipient_hint}-${index}`}
                  className="space-y-2 px-3 py-3 text-sm"
                >
                  <div className="font-medium text-zinc-900">
                    {invite.recipient_hint}
                  </div>
                  <div className="text-zinc-600">
                    {invitationRoleLabel(invite)}
                  </div>
                  <div className="text-xs text-zinc-500">
                    Invited {formatWhen(invite.created_at)}
                    {invite.expires_at
                      ? ` · Expires ${formatWhen(invite.expires_at)}`
                      : ""}
                  </div>
                  <div>
                    <button
                      type="button"
                      className="rounded border border-zinc-300 px-2 py-1 text-xs disabled:opacity-50"
                      disabled={
                        pending ||
                        inviting ||
                        (revokingRef != null &&
                          revokingRef === invite.invitation_ref)
                      }
                      onClick={() => onRevokeInvite(invite)}
                    >
                      {revokingRef === invite.invitation_ref
                        ? "Revoking…"
                        : "Revoke invitation"}
                    </button>
                  </div>
                </li>
              ))
            )}
          </ul>
        ) : null}
      </div>
    </section>
  );
}
